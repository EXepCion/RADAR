"""What a sign-in to the device registration service was, told by the audit log.

The sign-in log only shows that an account talked to the registration service. That is a new device being
registered - or an existing device setting up a Windows Hello key, or fetching something. The audit log has an entry
of the same account within seconds that says which: "Register device" with the device's name and id, or "Add Windows
Hello for Business credential". (The two logs rarely share a correlation id; account and time are what ties them.)

A registered device that the directory then shows as managed and as coming from the organisation's own programme
(Windows Autopilot, Apple's automated enrolment) is a company device being set up - no way for an attacker to stay.
Both the audit entry and that mark take a moment: the sign-in waits for them (at most ``WAIT``) before it is judged.

Pure logic: the audit log is asked through the callable given to :func:`settle`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from . import enrolment, netintel
from .models import SignIn, parse_time

REGISTERED, HELLO = "registered", "hello"
ACTIVITIES = {"register device": REGISTERED, "add windows hello for business credential": HELLO}
AROUND = timedelta(minutes=5)   # the two logs stamp the same operation seconds apart; minutes of slack
WAIT = timedelta(minutes=30)    # how long the audit entry and the directory's word on the device are waited for


@dataclass(frozen=True)
class Match:
    kind: str            # REGISTERED or HELLO
    device: str = ""     # the registered device's name
    device_id: str = ""
    proof: str = ""      # what makes the device the organisation's own, by the directory ('' = nothing known)


@dataclass
class Outcome:
    matches: dict[str, Match] = field(default_factory=dict)  # sign-in id -> what it was
    state: dict[str, str] = field(default_factory=dict)      # sign-ins still waiting -> when they were
    hold: set[str] = field(default_factory=set)              # ... not judged by this scan
    release: list[SignIn] = field(default_factory=list)      # waited in an earlier scan, judged by this one


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
           entries: Callable[[datetime], list[dict]], device: Callable[[str], dict | None] | None = None,
           types: Iterable[str] = enrolment.CORPORATE_TYPES, wait: timedelta = WAIT) -> Outcome:
    """Sort out the registration-service sign-ins among ``new`` and those waiting from earlier scans.

    Such a sign-in is settled when the audit log says it was a Windows Hello key, or a registration whose device the
    directory proves to be the organisation's own (``device(device id)``, see enrolment.proves). Until then it waits -
    it is not judged - for at most ``wait``: the audit entry comes seconds after the sign-in, a new device is marked
    as managed some minutes after it was registered. Then it is judged with whatever is known.
    ``entries(since)``: the audit entries of the registration service since then. Either callable may fail."""
    out = Outcome()
    waiting = dict(state or {})
    fresh = {s.id: s for s in new if is_candidate(s)}
    earlier: dict[str, SignIn] = {}
    for signin_id in waiting:
        s = history.get(signin_id, True) if signin_id not in fresh else None
        if s is not None:
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
        if found is not None and found.kind == REGISTERED and found.device_id and device is not None:
            try:
                proof = enrolment.proves(device(found.device_id), types)
            except Exception:  # noqa: BLE001
                proof = ""
            if proof:
                found = Match(found.kind, found.device, found.device_id, proof)
        # nothing more to wait for: it was no registration, the device is proven the organisation's own - or nobody
        # can be asked whose it is
        settled = found is not None and (found.kind == HELLO or bool(found.proof) or device is None)
        if settled or now - s.created >= wait:
            if found is not None:
                out.matches[signin_id] = found
            if signin_id in earlier:
                out.release.append(s)
        else:
            out.state[signin_id] = s.created.isoformat()
            out.hold.add(signin_id)
    return out
