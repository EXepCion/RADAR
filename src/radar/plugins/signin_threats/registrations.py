"""What a sign-in to the device registration service was, told by the audit log.

The sign-in log only shows that an account talked to the registration service. That is a new device being
registered - or an existing device setting up a Windows Hello key, or fetching something. The audit log has an entry
of the same account within seconds that says which: "Register device" with the device's name and id, or "Add Windows
Hello for Business credential". (The two logs rarely share a correlation id; account and time are what ties them.)

The audit entry may arrive a scan later than the sign-in: such sign-ins are remembered for a while and their alert
gets its device afterwards.

Pure logic: the audit log is asked through the callable given to :func:`settle`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

from . import netintel
from .models import SignIn, parse_time

REGISTERED, HELLO = "registered", "hello"
ACTIVITIES = {"register device": REGISTERED, "add windows hello for business credential": HELLO}
AROUND = timedelta(minutes=5)   # the two logs stamp the same operation seconds apart; minutes of slack
WAIT = timedelta(minutes=60)    # how long an audit entry is waited for


@dataclass(frozen=True)
class Match:
    kind: str            # REGISTERED or HELLO
    device: str = ""     # the registered device's name
    device_id: str = ""


@dataclass
class Outcome:
    matches: dict[str, Match] = field(default_factory=dict)  # sign-in id -> what it was
    state: dict[str, str] = field(default_factory=dict)      # sign-ins still waiting for their audit entry -> when
    again: list[SignIn] = field(default_factory=list)        # judged in an earlier scan, device known only now


def is_candidate(s: SignIn) -> bool:
    return bool(s.success and s.interactive and s.user_id and s.resource_id == netintel.DEVICE_REGISTRATION_RESOURCE)


def match(s: SignIn, entries: list[dict]) -> Match | None:
    """What the audit log says this sign-in was. A registration counts before a Hello key of the same minutes; the
    entry of the same operation (correlation id) before one that is merely nearer in time."""
    found = []
    for a in entries:
        kind = ACTIVITIES.get(str(a.get("activityDisplayName") or "").strip().lower())
        user = (a.get("initiatedBy") or {}).get("user") or {}
        if kind is None or not user.get("id") or user.get("id") != s.user_id:
            continue
        try:
            apart = abs((parse_time(a["activityDateTime"]) - s.created).total_seconds())
        except (KeyError, ValueError, TypeError):
            continue
        if apart > AROUND.total_seconds():
            continue
        same = bool(s.correlation_id) and a.get("correlationId") == s.correlation_id
        found.append((kind != REGISTERED, not same, apart, kind, a))
    if not found:
        return None
    _hello, _other, _apart, kind, a = min(found, key=lambda x: x[:3])
    if kind == HELLO:
        return Match(HELLO)
    name = next((clean for t in a.get("targetResources") or [] if str(t.get("type", "")).lower() == "device"
                 for clean in [str(t.get("displayName") or "").replace("\x00", "").strip()] if clean), "")
    device_id = next((str(d.get("value") or "").strip() for d in a.get("additionalDetails") or []
                      if isinstance(d, dict) and d.get("key") == "Device Id"), "")
    return Match(REGISTERED, name or device_id, device_id)


def settle(new: list[SignIn], history: Any, state: dict | None, now: datetime,
           entries: Callable[[datetime], list[dict]], wait: timedelta = WAIT) -> Outcome:
    """Match the registration-service sign-ins among ``new`` and those still waiting from earlier scans.
    ``entries(since)``: the audit entries of the registration service since then (may fail: nothing is matched)."""
    out = Outcome()
    waiting = dict(state or {})
    fresh = {s.id: s for s in new if is_candidate(s)}
    earlier: dict[str, SignIn] = {}
    for signin_id in list(waiting):
        s = history.get(signin_id, True) if signin_id not in fresh else None
        if s is not None and now - s.created < wait:
            earlier[signin_id] = s
    if not fresh and not earlier:
        return out
    pending = {**earlier, **fresh}
    try:
        audits = list(entries(min(s.created for s in pending.values()) - AROUND))
    except Exception:  # noqa: BLE001 - not readable now: the sign-ins wait
        audits = None
    for signin_id, s in pending.items():
        found = match(s, audits) if audits is not None else None
        if found is not None:
            out.matches[signin_id] = found
            if signin_id in earlier and found.kind == REGISTERED:
                out.again.append(s)
        elif now - s.created < wait:
            out.state[signin_id] = s.created.isoformat()
    return out
