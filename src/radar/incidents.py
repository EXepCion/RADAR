"""Incidents: alerts that belong to one story, taken together.

Two alerts belong together when they are about the same account, or name the same known attacker address, and lie
no more than a few days apart. Chains of such pairs make an incident - so an attack that touches several accounts
through one address, or runs through one account for a week, is one thing to handle instead of six reminders.
Attack-chain alerts and responses (sessions revoked, password reset ...) join the incident of the accounts they are
about; they give it its name and show what was already done, but an incident needs two alerts of its own.
Findings that were only logged (below Low) are shown with the incident they are closest to, as context: they
neither make an incident nor join two - an administrator's routine work is no incident.

Pure functions over stored alerts; no UI, no Graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from . import chains
from .alerts import ACTIVE, MUTED, SNOOZED, Alert
from .correlation import NOT_A_PARTNER_RULES
from .plugin_api import Severity

LOOKBACK_DAYS = 30
GAP_DAYS = 7  # alerts further apart than this are not the same story, even about the same account
SYSTEM_PLUGINS = {"system"}


@dataclass
class Incident:
    id: str                      # stable: the key of its first alert
    alerts: list[Alert]          # everything in it, oldest first (chains and responses included)
    accounts: list[str]
    addresses: list[str]         # known attacker addresses its alerts name
    first: datetime
    last: datetime
    severity: Severity
    open: bool                   # something in it is still a reminder
    stage: int                   # furthest stage of an attack reached (see chains.STAGE_NAMES), 0 = none
    title: str
    own: int = 0                 # alerts of its own (without chain alerts and responses)
    responses: list[str] = field(default_factory=list)

    @property
    def stage_name(self) -> str:
        return chains.STAGE_NAMES.get(self.stage, "")

    @property
    def open_alerts(self) -> list[Alert]:
        return [a for a in self.alerts if a.status in (ACTIVE, SNOOZED)]

    @property
    def reminders(self) -> list[Alert]:
        """Its alerts that are or were reminders (not the logged-only context, not the responses)."""
        return [a for a in self.alerts if a.status != MUTED and not _is_response(a)]

    @property
    def state(self) -> str:
        """Short, for a table: 'open - 2 of 3' / 'closed - all dismissed'."""
        total, still = len(self.reminders), len(self.open_alerts)
        return f"open - {still} of {total}" if still else "closed - all dismissed"

    @property
    def state_text(self) -> str:
        """Why the incident is open or closed, in one sentence."""
        total, still = len(self.reminders), self.open_alerts
        if still:
            snoozed = sum(1 for a in still if a.status == SNOOZED)
            return (f"Open: {len(still)} of its {total} alerts {'is' if len(still) == 1 else 'are'} still "
                    f"{'a reminder' if len(still) == 1 else 'reminders'}"
                    + (f" ({snoozed} snoozed)" if snoozed else "") + ".")
        times = [a.dismissed_at for a in self.reminders if a.dismissed_at]
        when = f", the last on {max(times).astimezone():%d.%m. %H:%M}" if times else ""
        return (f"Closed: all {total} alerts were dismissed{when}. Nothing in it is a reminder any more; it opens "
                f"again by itself if one of them gets worse or a new alert joins.")


def _is_response(a: Alert) -> bool:
    return a.signal in chains.NOT_LINKS


def _is_chain(a: Alert) -> bool:
    return a.plugin_id == chains.CHAIN_PLUGIN


def _was_reminder(a: Alert) -> bool:
    """An alert of its own: shown to the user as a reminder at some point (not only logged), at least Low."""
    return not _is_response(a) and a.status != MUTED and (a.base_severity or a.severity) >= Severity.LOW


def _relevant(a: Alert) -> bool:
    return a.plugin_id not in SYSTEM_PLUGINS and a.rule_id not in NOT_A_PARTNER_RULES


def stage_of(a: Alert) -> int:
    if _is_chain(a) or _is_response(a):
        return 0
    return chains.stage_of(a.rule_id, a.factors) or 0


def group(alerts: Iterable[Alert], now: datetime, days: int = LOOKBACK_DAYS, gap_days: int = GAP_DAYS) -> list[Incident]:
    """The incidents among the alerts of the last ``days``: open ones first, then by severity and last activity."""
    since, gap = now - timedelta(days=days), timedelta(days=gap_days)
    items = sorted((a for a in alerts if _relevant(a) and a.when >= since), key=lambda a: (a.when, a.id))
    parent = {a.id: a.id for a in items}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def keys(a: Alert) -> list[tuple[str, str]]:
        return [("account", x) for x in a.subjects if "@" in x] + [("address", ip) for ip in chains.attacker_addresses(a)]

    # 1) what makes an incident: real reminders (at least Low) and the chain alerts that sum them up. Oldest first,
    #    each joins the latest earlier one that shares an account or an address.
    core = [a for a in items if _is_chain(a) or (_was_reminder(a))]
    last_by_key: dict[tuple[str, str], Alert] = {}
    for a in core:
        for key in keys(a):
            earlier = last_by_key.get(key)
            if earlier is not None and a.when - earlier.when <= gap:
                parent[find(a.id)] = find(earlier.id)
            last_by_key[key] = a
    groups: dict[int, list[Alert]] = {}
    for a in core:
        groups.setdefault(find(a.id), []).append(a)
    # 2) context: responses and "logged only" findings go with the incident of their account or address they are
    #    closest to in time - they never make an incident and never join two.
    by_key: dict[tuple[str, str], list[Alert]] = {}
    for a in core:
        for key in keys(a):
            by_key.setdefault(key, []).append(a)
    core_ids = {a.id for a in core}
    for a in items:
        if a.id in core_ids:
            continue
        near = [c for key in keys(a) for c in by_key.get(key, ()) if abs(a.when - c.when) <= gap]
        if near:
            groups[find(min(near, key=lambda c: abs(a.when - c.when)).id)].append(a)

    out = []
    for members in groups.values():
        own = [a for a in members if not _is_chain(a) and _was_reminder(a)]
        if len(own) < 2:
            continue
        members.sort(key=lambda a: (_is_chain(a), a.when, a.id))  # the steps in order, what sums them up last
        accounts = sorted({s for a in members for s in a.subjects if "@" in s})
        addresses = sorted({ip for a in members for ip in chains.attacker_addresses(a)})
        still_open = [a for a in members if a.status in (ACTIVE, SNOOZED)]
        severity = max((a.severity for a in (still_open or own)), default=Severity.INFO)
        named = ([a for a in members if a.rule_id == "attack_spread"] or [a for a in members if _is_chain(a)])
        shown = ", ".join(accounts[:3]) + (f" +{len(accounts) - 3}" if len(accounts) > 3 else "")
        title = named[-1].title if named else f"{len(own)} alerts about {shown or 'the same attacker address'}"
        out.append(Incident(
            id=own[0].key, alerts=members, accounts=accounts, addresses=addresses,
            first=min(a.when for a in members), last=max(a.last_seen for a in members), severity=severity, open=bool(still_open),
            stage=max((stage_of(a) for a in own), default=0), title=title, own=len(own),
            responses=sorted({a.title.split(":")[0] for a in members if _is_response(a)})))
    out.sort(key=lambda i: (not i.open, -int(i.severity), -i.last.timestamp()))
    return out
