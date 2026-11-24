"""Incidents: alerts that belong to one story, taken together.

Two alerts belong together when they are about the same account, or name the same known attacker address, and lie
no more than a few days apart. Chains of such pairs make an incident - so an attack that touches several accounts
through one address, or runs through one account for a week, is one thing to handle instead of six reminders.

"About an account" means the account it happened TO. An alert that only names an account as the one who did
something (an administrator consenting to an app, changing a policy, reading a key) joins an incident about that
account when it comes after an alert about the account itself - "odd sign-in, then a policy change" is a story;
two things an administrator did in one week are their work, not an incident. An application ties alerts together
through its own sign-ins: a new credential or consent, and the application then signing in from somewhere new,
belong together - a credential and a consent alone are an application being set up.
Attack-chain alerts and responses (sessions revoked, password reset ...) join the incident of the accounts they are
about; they give it its name and show what was already done, but an incident needs two alerts of its own.
Findings that were only logged (below Low) are shown with the incident they are closest to, as context: they
neither make an incident nor join two - an administrator's routine work is no incident.

Pure functions over stored alerts; no UI, no Graph.
"""
from __future__ import annotations

from . import timefmt
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
    def own_alerts(self) -> list[Alert]:
        """The findings it is made of: no chain alerts (they sum it up), no responses, nothing only logged."""
        return [a for a in self.alerts if not _is_chain(a) and _was_reminder(a)]

    @property
    def risk(self) -> int:
        """The highest risk score in it - of what is still open, else of everything."""
        return max((a.score for a in (self.open_alerts or self.reminders)), default=0)

    @property
    def summing_up(self) -> Alert | None:
        """The chain alert that sums it up (the one across accounts first), if there is one."""
        chain_alerts = [a for a in self.alerts if _is_chain(a)]
        return next((a for a in reversed(chain_alerts) if a.rule_id == "attack_spread"),
                    chain_alerts[-1] if chain_alerts else None)

    @property
    def strongest(self) -> Alert | None:
        """Its strongest single finding: an open one before a dismissed one, then by severity and score."""
        own = self.own_alerts
        return max(own, key=lambda a: (a.status in (ACTIVE, SNOOZED), int(a.severity), a.score), default=None)

    @property
    def leading(self) -> Alert | None:
        """The alert to open first: what sums the incident up, else its strongest finding."""
        return self.summing_up or self.strongest

    @property
    def stages(self) -> dict[int, tuple[datetime, bool]]:
        """The stages of an attack its findings stand for (see chains.STAGE_NAMES): when each was first reached, and
        whether a finding of that stage is still open. With one open, the time is that of the first open one."""
        out: dict[int, tuple[datetime, bool]] = {}
        for a in sorted(self.own_alerts, key=lambda a: a.when):
            stage = stage_of(a)
            if not stage:
                continue
            still = a.status in (ACTIVE, SNOOZED)
            if stage not in out or (still and not out[stage][1]):
                out[stage] = (a.when, still)
        return out

    @property
    def why(self) -> str:
        """What weighs most: the strongest finding with the reasons that count most for it."""
        a = self.strongest
        if a is None:
            return ""
        reasons = [str(text) for points, text in sorted(a.factors, key=lambda f: -int(f[0])) if int(points) > 0][:3]
        return f"{a.title} ({a.severity.label}, {a.score})" + (": " + "; ".join(reasons) if reasons else "")

    @property
    def advice(self) -> str:
        """What to do: what the alert that sums it up recommends, else the strongest finding."""
        return next((a.recommendation for a in (self.summing_up, self.strongest) if a is not None and a.recommendation), "")

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
        when = f", the last on {timefmt.stamp(max(times))}" if times else ""
        return (f"Closed: all {total} alerts were dismissed{when}. Nothing in it is a reminder any more; it opens "
                f"again by itself if one of them gets worse or a new alert joins.")


def _is_response(a: Alert) -> bool:
    return a.signal in chains.NOT_LINKS


def _is_chain(a: Alert) -> bool:
    return a.plugin_id == chains.CHAIN_PLUGIN


def _operational(a: Alert) -> bool:
    """Something that does not work (an application whose credential keeps failing) - to be fixed, but no step of an
    incident: it is shown with one as context and never makes one."""
    return str((a.fields or {}).get("Kind", "")).startswith("Operational") or a.title.startswith("App credential failing")


def _was_reminder(a: Alert) -> bool:
    """An alert of its own: shown to the user as a reminder at some point (not only logged), at least Low."""
    return (not _is_response(a) and not _operational(a) and a.status != MUTED
            and (a.base_severity or a.severity) >= Severity.LOW)


def _relevant(a: Alert) -> bool:
    if a.plugin_id in SYSTEM_PLUGINS or a.rule_id in NOT_A_PARTNER_RULES:
        return False
    if (a.fields or {}).get("Merged into"):
        return False  # its content is in the alert that took its place
    return not (_is_chain(a) and a.status == MUTED)  # a chain that no longer holds sums nothing up


VICTIM_FIELDS = ("User", "Account", "Member", "Guest", "Done to")
APP_SIGNIN_RULES = {"app_signins"}  # what an application itself did (its sign-ins), not what was done to it
Key = tuple[str, str]


def links(a: Alert) -> tuple[list[Key], list[Key]]:
    """What ties an alert to others: (what it is about, what it merely names).

    About: the accounts it happened to, the application whose own sign-ins it judges, known attacker addresses.
    Merely named: an account that only did something (Initiated by / Invited by), an application something was
    done to. Two alerts belong together through what one of them is about - never through what both merely name."""
    fields = a.fields or {}
    actors = {e for f in chains.ACTOR_FIELDS for e in chains._emails(fields.get(f))}
    victims = {e for f in VICTIM_FIELDS for e in chains._emails(fields.get(f))}
    about: list[Key] = [("address", ip) for ip in chains.attacker_addresses(a)]
    # the accounts an administrator's change was done TO are named by it: five people given a role do not become
    # one incident (a chain alert is about everybody in it)
    done_to = set() if _is_chain(a) else set(chains._emails(fields.get("Done to")))
    named: list[Key] = []
    for s in a.subjects:
        if "@" in s:
            merely = (s in actors and s not in victims and not _is_chain(a)) or s in done_to
            (named if merely else about).append(("account", s))
        elif s.startswith("app:"):
            (about if a.rule_id in APP_SIGNIN_RULES else named).append(("app", s))
    return about, named


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

    def join(a: Alert, earlier: Alert | None) -> None:
        if earlier is not None and a.when - earlier.when <= gap:
            parent[find(a.id)] = find(earlier.id)

    # 1) what makes an incident: real reminders (at least Low) and the chain alerts that sum them up. Oldest first,
    #    each joins the latest earlier one about the same account, application or address (see ``links``): what it
    #    is about ties it to anything earlier about the same; what it merely names ties it only to an earlier alert
    #    ABOUT that. (For an application also the other way round: its new credential comes before its odd sign-in.)
    core = [a for a in items if _is_chain(a) or (_was_reminder(a))]
    last_about: dict[Key, Alert] = {}
    named_before: dict[Key, list[Alert]] = {}
    for a in core:
        about, named = links(a)
        for key in about:
            join(a, last_about.get(key))
            if key[0] == "app":
                for earlier in named_before.get(key, ()):
                    join(a, earlier)
            last_about[key] = a
        for key in named:
            # ... which is still open, at least Medium, or a chain: a Low alert that was looked at and dismissed is
            # not reopened by somebody doing something for that account
            earlier = last_about.get(key)
            if earlier is not None and (earlier.status in (ACTIVE, SNOOZED) or earlier.severity >= Severity.MEDIUM
                                        or _is_chain(earlier)):
                join(a, earlier)
            named_before.setdefault(key, []).append(a)
    groups: dict[int, list[Alert]] = {}
    for a in core:
        groups.setdefault(find(a.id), []).append(a)
    # 2) context: responses and "logged only" findings go with the incident of their account or address they are
    #    closest to in time - they never make an incident and never join two.
    by_key: dict[Key, list[Alert]] = {}
    for a in core:
        for key in links(a)[0]:
            by_key.setdefault(key, []).append(a)
    core_ids = {a.id for a in core}
    for a in items:
        if a.id in core_ids:
            continue
        near = [c for part in links(a) for key in part for c in by_key.get(key, ()) if abs(a.when - c.when) <= gap]
        if near:
            groups[find(min(near, key=lambda c: abs(a.when - c.when)).id)].append(a)

    out = []
    for members in groups.values():
        own = [a for a in members if not _is_chain(a) and _was_reminder(a)]
        if len(own) < 2:
            continue
        members.sort(key=lambda a: (not _is_chain(a), a.when, a.id))  # what sums it up, then the steps as they happened
        accounts = sorted({s for a in members for s in a.subjects if "@" in s})
        addresses = sorted({ip for a in members for ip in chains.attacker_addresses(a)})
        still_open = [a for a in members if a.status in (ACTIVE, SNOOZED)]
        severity = max((a.severity for a in (still_open or own)), default=Severity.INFO)
        named = ([a for a in members if a.rule_id == "attack_spread"] or [a for a in members if _is_chain(a)])
        shown = ", ".join(accounts[:3]) + (f" +{len(accounts) - 3}" if len(accounts) > 3 else "")
        apps = sorted({str(a.fields.get("App")) for a in own if a.rule_id in APP_SIGNIN_RULES and a.fields.get("App")})
        about = shown or (f"the application {', '.join(apps[:2])}" if apps else "the same attacker address")
        title = named[-1].title if named else f"{len(own)} alerts about {about}"
        out.append(Incident(
            id=own[0].key, alerts=members, accounts=accounts, addresses=addresses,
            first=min(a.when for a in members), last=max(a.last_seen for a in members), severity=severity, open=bool(still_open),
            # how far it got: by what is still open - a step that was looked at and dismissed is not where it stands
            stage=max((stage_of(a) for a in ([a for a in own if a.status in (ACTIVE, SNOOZED)] or own)), default=0),
            title=title, own=len(own),
            responses=sorted({a.title.split(":")[0] for a in members if _is_response(a)})))
    out.sort(key=lambda i: (not i.open, -int(i.severity), -i.last.timestamp()))
    return out
