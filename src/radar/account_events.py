"""Account events for the live map's feed: password resets, MFA methods, reported MFA prompts, devices, accounts,
admin roles.

The directory audit watch reads the Entra audit log anyway; what it sees of these kinds is boiled down here to one
entry per real action (the log writes several lines for one action: a PIM activation is five) and kept in a small
file the map can read - the map itself never talks to Entra.

Pure functions plus one small file; no Graph, no UI.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

FILE = "account_events.json"
KEEP_DAYS = 7
CAP = 1500
PLUGIN = "directory_audit"

# lines that belong to one action lie this close together (same person / device, same kind of action)
COLLAPSE = {"password": 600, "password-failed": 900, "mfa": 120, "mfa-report": 120, "device-added": 600, "device-deleted": 120,
            "account": 180, "role": 300}

_PIM_APPS = {"ms-pim", "azure ad pim", "microsoft pim"}


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _target(audit: dict, kind: str) -> dict:
    return next((t for t in audit.get("targetResources") or [] if str(t.get("type", "")).lower() == kind), {})


def _prop(audit: dict, *names: str) -> tuple[str, str]:
    """(old, new) of the first modified property with one of these names."""
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            if p.get("displayName") in names:
                return (str(p.get("oldValue") or "").strip('[]" '), str(p.get("newValue") or "").strip('[]" '))
    return ("", "")


def _detail(audit: dict, key: str) -> str:
    return next((str(d.get("value") or "") for d in audit.get("additionalDetails") or [] if d.get("key") == key), "")


def _role_name(audit: dict) -> str:
    name = _target(audit, "role").get("displayName")
    if name:
        return name
    old, new = _prop(audit, "Role.DisplayName", "RoleDefinition.DisplayName")
    return new if new and new != "None" else old if old != "None" else ""


def classify(audit: dict) -> dict[str, Any] | None:
    """One audit line -> a feed event, or None when the line is not one of the kinds shown (or only a step of one)."""
    act = (audit.get("activityDisplayName") or "").strip().lower()
    ok = (audit.get("result") or "").lower() == "success"
    by = audit.get("initiatedBy") or {}
    by_user, by_app = by.get("user") or {}, by.get("app") or {}
    actor = by_user.get("userPrincipalName") or by_app.get("displayName") or by_app.get("servicePrincipalName") or ""
    user = _target(audit, "user")
    kind = title = group = detail = ""
    rank = 1  # of several lines for one action, the one with the highest rank tells it best
    person = user
    warn = False  # shown in the warning colour although the action itself succeeded

    if "security info" in act and "all required" not in act and "started" not in act:
        verb = ("registered" if "registered" in act else "removed" if "deleted" in act else
                "changed" if "changed" in act or "updated" in act else "")
        if not verb or not ok:
            return None
        kind, group = "mfa", "mfa"
        title = f"MFA method {verb}" + (" by an admin" if act.startswith("admin") else "")
        reason = (audit.get("resultReason") or "").strip()
        detail = reason if reason.lower() != act else ""
    elif act == "suspicious activity reported":
        if not ok:
            return None
        # the person said in Authenticator (or on the phone) that an MFA prompt was not theirs
        kind, group, warn = "mfa", "mfa-report", True
        title = "MFA prompt reported as not theirs"
        detail = {"phoneappnotification": "Authenticator notification", "twowayvoicemobile": "phone call",
                  "twowayvoiceoffice": "phone call"}.get(_detail(audit, "AuthenticationMethod").lower(),
                                                         _detail(audit, "AuthenticationMethod"))
    elif act == "self-service password reset flow activity progress":
        if ok:
            return None  # a step of a reset that also logs its completion
        kind, group, title = "password", "password-failed", "Self-service password reset failed"
        detail = (audit.get("resultReason") or "").strip()
    elif act in ("reset password (self-service)", "reset password (by admin)", "change password (self-service)",
                 "reset user password", "change user password"):
        if not ok:
            return None
        kind, group = "password", "password"
        title, rank = {
            "reset password (self-service)": ("Password reset (self-service)", 5),
            "reset password (by admin)": ("Password reset by an admin", 5),
            "change password (self-service)": ("Password changed", 5),
            "reset user password": ("Password reset", 3),
            "change user password": ("Password changed", 2),
        }[act]
        if act == "change user password" and "sync" in actor.lower():
            detail = "set on-premises, synced to Entra"
    elif act in ("register device", "add device"):
        if not ok:
            return None
        kind, group, person = "device", "device-added", by_user
        title, rank = ("Device registered", 5) if act == "register device" else ("Device added", 2)
        detail = " · ".join(p for p in (_detail(audit, "Device Trust Type"), _detail(audit, "Device OS")) if p and p != "Unknown")
    elif act in ("delete device", "hard delete device", "unregister device"):
        if not ok:
            return None
        kind, group, person = "device", "device-deleted", by_user
        title = "Device removed for good" if act.startswith("hard") else "Device deleted"
        detail = "automatic cleanup" if "garbage" in actor.lower() else ""
    elif act in ("add user", "delete user", "hard delete user", "restore user", "disable account", "enable account", "update user"):
        if not ok:
            return None
        if act == "update user":
            old, new = _prop(audit, "AccountEnabled")
            if not new or old == new:
                return None
            title, rank = ("Account enabled" if new.lower() == "true" else "Account disabled"), 2
        else:
            title = {"add user": "Account created", "delete user": "Account deleted", "hard delete user": "Account deleted for good",
                     "restore user": "Account restored", "disable account": "Account disabled", "enable account": "Account enabled"}[act]
            rank = 5
        kind, group = "account", "account"
        if act == "add user" and (_prop(audit, "CreationType")[1] == "Invitation" or "#EXT#" in (user.get("userPrincipalName") or "")):
            title = "Guest account created"
    elif act == "add member to role completed (pim activation)":
        if not ok:
            return None
        kind, group, rank = "role", "role", 5
        title = f"Admin role activated: {_role_name(audit) or 'a role'}"
        detail = (audit.get("resultReason") or "").strip()
    elif act in ("add member to role", "add scoped member to role", "add eligible member to role",
                 "remove member from role", "remove eligible member from role"):
        if not ok or (by_app.get("displayName") or "").lower() in _PIM_APPS:
            return None  # PIM carrying out an activation or its expiry: the activation itself is the entry
        kind, group, rank = "role", "role", 4
        what = ("made eligible for" if "eligible" in act and act.startswith("add") else "assigned" if act.startswith("add") else "removed")
        title = f"Admin role {what}: {_role_name(audit) or 'a role'}"
    else:
        return None

    if kind == "device":
        name = _target(audit, "device").get("displayName") or "a device"
        who, upn, user_id = name, by_user.get("userPrincipalName") or "", by_user.get("id") or ""
        subject = name.lower()
    else:
        upn = user.get("userPrincipalName") or ""
        who = user.get("displayName") or upn or "an account"
        user_id = user.get("id") or ""
        subject = user_id or upn.lower()
    if not audit.get("activityDateTime"):
        return None
    event = {"id": audit.get("id") or "", "ts": _time(audit["activityDateTime"]).isoformat(), "kind": kind, "title": title,
             "who": who, "upn": upn, "user_id": user_id, "by": actor, "detail": detail, "failed": not ok or warn,
             "_group": group + ("|" + title.split(":")[-1].strip() if kind == "role" else "") + "|" + subject, "_rank": rank}
    if kind == "account" and group == "account":
        event["_group"] = f"account|{title.replace('Guest account', 'Account')}|{subject}"
    return event


def collapse(events: Iterable[dict]) -> list[dict]:
    """One entry per action: of the lines of one action (same subject, same kind, close together) the telling one
    stays - at the time of the first line, with the details of all. Running it again changes nothing."""
    out: list[dict] = []
    last: dict[str, dict] = {}
    for e in sorted(events, key=lambda x: (x["ts"], x.get("id", ""))):
        group = e.get("_group") or e.get("id")
        window = COLLAPSE.get(str(group).split("|")[0], 120)
        kept = last.get(group)
        if kept is not None and (_time(e["ts"]) - _time(kept.get("_until", kept["ts"]))).total_seconds() <= window:
            kept["_until"] = e["ts"]
            if e.get("_rank", 1) > kept.get("_rank", 1):
                for f in ("title", "by", "failed", "_rank", "id"):
                    kept[f] = e[f]
                for f in ("who", "upn", "user_id"):
                    kept[f] = e.get(f) or kept.get(f, "")
            kept["detail"] = kept.get("detail") or e.get("detail", "")
            continue
        e = dict(e)
        last[group] = e
        out.append(e)
    return out


def normalise(audits: Iterable[dict]) -> list[dict]:
    return collapse(e for e in (classify(a) for a in audits) if e)


def load(path: Path) -> list[dict]:
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))
        return [r for r in rows if isinstance(r, dict) and r.get("ts") and r.get("title")]
    except (OSError, ValueError):
        return []


def merge(path: Path, new: Iterable[dict], now: datetime) -> list[dict]:
    """Add events to the file (the same audit lines come again: every run re-reads the last half hour)."""
    path = Path(path)
    cutoff = (now - timedelta(days=KEEP_DAYS)).isoformat()
    events = collapse([e for e in load(path) + list(new) if e["ts"] >= cutoff])[-CAP:]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(events, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return events


def public(event: dict) -> dict:
    """An event without the bookkeeping fields."""
    return {k: v for k, v in event.items() if not k.startswith("_")}
