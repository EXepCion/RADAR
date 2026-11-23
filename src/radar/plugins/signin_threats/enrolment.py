"""Corporate device enrolments: sign-ins made by the enrolment service, proven by the device that came out of them.

When somebody enrols a company device, the account signs in to the enrolment service before the device has an
identity. With Apple's automated enrolment that sign-in comes from the service's own address in a cloud - another
country, no device, password only; with Windows Autopilot from wherever the new computer is unpacked. The sign-in
rules see a stranger. That it is the service cannot be read from the sign-in: its address lies in ranges anybody can rent, and
every field of it can be imitated. What cannot be imitated is the result: right afterwards the account registers a
device that the directory knows as managed and as coming from the organisation's automated enrolment - a device
whose serial number the organisation owns.

So such a sign-in is held back for a while (``WAIT``). When the proof arrives it becomes a record, together with
the other sign-ins of the account from that address in those minutes, and none of them is judged as the user's
own. When it does not arrive, they are judged like any other sign-in - nothing is excused by the address or by the
look of the sign-in.

Pure logic: the audit log and the directory are asked through the two callables given to :func:`settle`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from ... import linkify
from ...plugin_api import Finding, Severity
from . import netintel
from .models import SignIn, parse_time

RULE_ID = "device_enrolment"
WAIT = timedelta(minutes=30)     # how long the registration and its management may take to show up
BEFORE = timedelta(minutes=5)    # the logs do not agree to the minute: a registration may be stamped earlier
TOGETHER = timedelta(minutes=5)  # other sign-ins of the account from the same address belong to the enrolment
KEEP = timedelta(days=31)        # as long as the sign-in history itself
#: What only a device the organisation owns can have (any case). Looked for in the directory's ``enrollmentType``
#: and among the marks of its ``physicalIds``:
#: "DEP"   - Apple's automated device enrolment: the serial number is assigned to the organisation
#: "ZTDID" - Windows Autopilot: the hardware was registered for the organisation, by it or by its supplier
CORPORATE_TYPES = ("DEP", "ZTDID")
MARK_NAMES = {"ztdid": "Windows Autopilot"}  # how a physical id mark is called in a record
DEVICE_SELECT = "id,deviceId,displayName,isManaged,deviceOwnership,enrollmentType,enrollmentProfileName,operatingSystem,physicalIds"
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class Outcome:
    new: list[SignIn]                 # what the rules judge in this scan
    excluded: set[str]                # sign-ins the rules do not see: part of a proven enrolment, or still waiting
    state: dict[str, dict[str, str]]  # to be remembered for the next scan
    records: list[Finding] = field(default_factory=list)


def is_candidate(s: SignIn) -> bool:
    """A successful sign-in to the enrolment service by something that has no device identity (yet)."""
    return bool(s.success and s.user_id and not s.device_id and s.resource_id == netintel.ENROLMENT_RESOURCE)


def proves(device: dict[str, Any] | None, types: Iterable[str] = CORPORATE_TYPES) -> str:
    """'' or what the directory says: the device is managed and came from an enrolment only the organisation's own
    devices can go through."""
    if not device or device.get("isManaged") is not True:
        return ""
    wanted = [str(t).strip().lower() for t in types or () if str(t).strip()]
    kind = str(device.get("enrollmentType") or "")
    # a physical id reads "[MARK]:value"
    marks = {str(p)[1:].split("]")[0].lower() for p in device.get("physicalIds") or [] if str(p).startswith("[")}
    by_mark = next((m for m in wanted if m in marks), "")
    if by_mark:
        said = MARK_NAMES.get(by_mark, by_mark.upper())
    elif any(t in kind.lower() for t in wanted):
        said = kind
    else:
        return ""
    profile = str(device.get("enrollmentProfileName") or "").strip()
    return said + (f", profile {profile}" if profile else "")


def _device_id(audit: dict) -> str:
    return next((str(d.get("value") or "").strip() for d in audit.get("additionalDetails") or []
                 if isinstance(d, dict) and d.get("key") == "Device Id"), "")


def _registered_by(audit: dict, s: SignIn) -> bool:
    user = (audit.get("initiatedBy") or {}).get("user") or {}
    return bool(user.get("id")) and user.get("id") == s.user_id or \
        bool(s.upn) and str(user.get("userPrincipalName") or "").lower() == s.upn.lower()


def _record(group: list[SignIn], device: dict, proof: str) -> Finding:
    lead = min(group, key=lambda s: s.created)
    who = lead.upn or lead.who
    name = str(device.get("displayName") or "").replace("\x00", "").strip() or "a device"
    places = ", ".join(sorted({f"{s.location} ({s.ip})" for s in group if is_candidate(s)}))
    rows = []
    for s in sorted(group, key=lambda s: s.created, reverse=True):
        row = s.evidence()
        row["_created"], row["_event"] = s.created.isoformat(), s.event_type
        rows.append(row)
    return Finding(
        key=f"enrol|{lead.user_id}|{device.get('deviceId') or name}", rule_id=RULE_ID, severity=Severity.INFO, score=0,
        subjects=[who.lower()] if "@" in who else [],
        title=f"Device enrolled by {who}: {name}",
        summary=(f"{who} enrolled {name} through the organisation's own device enrolment ({proof}). The enrolment "
                 f"service signed in for it from {places}: {len(group)} sign-in(s) that are not the user's own and "
                 "were not judged as such. Record only."),
        occurred_at=lead.created,
        fields={"User": who, "Device": name, **({linkify.DEVICE_ID_FIELD: device["deviceId"]} if device.get("deviceId") else {}),
                "Enrolment": proof},
        factors=[(0, f"Proven by the device it produced: managed, {proof}")],
        evidence=rows,
    )


def settle(new: list[SignIn], history: Any, state: dict | None, now: datetime,
           registrations: Callable[[datetime], list[dict]], device: Callable[[str], dict | None],
           types: Iterable[str] = CORPORATE_TYPES, wait: timedelta = WAIT) -> Outcome:
    """Sort out the enrolment-service sign-ins among ``new`` and those still waiting from earlier scans.

    ``registrations(since)``: the audit entries "Register device" since then. ``device(device id)``: the directory's
    record of a device, or None. Either may fail: then nothing is proven."""
    state = state or {}
    held = dict(state.get("held") or {})
    explained = {i: t for i, t in dict(state.get("explained") or {}).items() if _when(t) and now - _when(t) < KEEP}
    by_id = {s.id: s for s in new}
    pending = {s.id: s for s in new if is_candidate(s) and s.id not in explained}
    for signin_id in list(held):
        s = by_id.get(signin_id) or history.get(signin_id)
        if s is None:
            held.pop(signin_id)  # gone from the history: nothing left to judge
        elif is_candidate(s):
            pending[s.id] = s
    records: dict[str, Finding] = {}
    released: dict[str, SignIn] = {}
    audits: list[dict] = []
    if pending:
        try:
            audits = list(registrations(min(s.created for s in pending.values()) - BEFORE))
        except Exception:  # noqa: BLE001 - not readable: nothing is proven, the sign-ins wait and are then judged
            audits = []
    looked_up: dict[str, dict | None] = {}

    def lookup(device_id: str) -> dict | None:
        if device_id not in looked_up:
            try:
                looked_up[device_id] = device(device_id)
            except Exception:  # noqa: BLE001
                looked_up[device_id] = None
        return looked_up[device_id]

    for s in sorted(pending.values(), key=lambda x: x.created):
        found, proof = None, ""
        mine = []
        for audit in audits:
            try:
                when = parse_time(audit["activityDateTime"])
            except (KeyError, ValueError, TypeError):
                continue
            if _registered_by(audit, s) and s.created - BEFORE <= when <= s.created + wait and _device_id(audit):
                mine.append((abs((when - s.created).total_seconds()), audit))
        # the registration next to the sign-in first: somebody setting up two devices gets a record for each
        for _distance, audit in sorted(mine, key=lambda x: x[0]):
            proof = proves(lookup(_device_id(audit)), types)
            if proof:
                found = looked_up[_device_id(audit)]
                break
        group = {s.id: s}
        for o in history.query(s.created - TOGETHER, s.created + TOGETHER, user_id=s.user_id, ip=s.ip):
            if not o.device_id:
                group[o.id] = o
        if found:
            # what the service did for the enrolment is no habit of the user: not learned as their country, network ...
            fresh = [o for signin_id, o in group.items() if signin_id not in explained]
            if fresh and hasattr(history, "forget"):
                history.forget(fresh)
            for signin_id, o in group.items():
                explained[signin_id] = o.created.isoformat()
                held.pop(signin_id, None)
                released.pop(signin_id, None)
            record = _record(list(group.values()), found, proof)
            if record.key in records:  # the same device, a second sign-in of the service: one record
                record.evidence = records[record.key].evidence + [r for r in record.evidence
                                                                 if r not in records[record.key].evidence]
            records[record.key] = record
        elif now - s.created < wait:
            for signin_id, o in group.items():
                if signin_id not in explained:
                    held[signin_id] = o.created.isoformat()
        else:
            for signin_id, o in group.items():
                if signin_id in held or signin_id in by_id:
                    released[signin_id] = o
                held.pop(signin_id, None)
    excluded = set(explained) | set(held)
    judged = [s for s in new if s.id not in excluded]
    judged += [s for i, s in released.items() if i not in by_id and i not in excluded]
    return Outcome(sorted(judged, key=lambda s: s.created), excluded, {"held": held, "explained": explained},
                   list(records.values()))


def _when(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None

