"""Attack-chain correlation: weak steps against the same account that, in order, look like a compromise.

Every alert - including dismissed ones, muted context signals and "logged only" Info findings - is a possible
link. Rules are mapped to the stages of an account takeover; a chain is a sequence of links about the same
account whose stages strictly increase in time order, e.g.

    password guessing -> password known (MFA stopped it) -> new MFA method -> admin role

It is raised only if it starts with targeting / a known password and goes further (1/2 -> 3+), or covers at
least three stages - so "travelled abroad, then registered a passkey" (3 -> 4) stays quiet.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from .plugin_api import Finding, Severity

CHAIN_PLUGIN = "correlation"
LOOKBACK_DAYS = 14
ORDER_TOLERANCE = timedelta(hours=2)  # audit / sign-in log latencies may swap neighbouring events
MAX_STEP_GAP = timedelta(days=3)      # an attack moves on within hours to days, not weeks
MIN_LINK_SCORE = 25                   # a step must be at least Low on its own (Info = judged harmless / recovery)
STEP_POINTS = 10

STAGE_NAMES = {1: "Targeted", 2: "Password known", 3: "Suspicious access", 4: "Persistence", 5: "Escalation"}
RULE_STAGES = {
    # 1 - someone is trying
    "distributed_attack": 1, "brute_force": 1, "password_spray": 1, "attack_tooling": 1, "mfa_exempt_watch": 1,
    # 2 - the password is known
    "password_not_completed": 2, "mfa_fatigue": 2,
    # 3 - a sign-in that may not be the user
    "risky_signin": 3, "new_country": 3, "impossible_travel": 3, "session_theft": 3, "aitm_replay": 3,
    "device_code": 3, "new_shared_ip": 3, "account_state": 3, "pinned_accounts": 3, "legacy_auth": 3,
    # 4 - staying in / getting data out
    "mfa_change": 4, "sensitive_app": 4, "consent_grant": 4, "app_credentials": 4, "guest_invites": 4,
    "mfa_exclusion_change": 4, "device_registration": 4, "app_owner_change": 4,
    # 5 - more power / weaker defences / lateral movement
    "role_assignment": 5, "conditional_access": 5, "domain_federation": 5, "elevate_access": 5, "sensitive_reads": 5,
}
# signals that are reactions / records, not attacker steps
NOT_LINKS = {"account_disabled", "account_enabled", "support_case", "sessions_revoked", "password_reset"}


@dataclass(frozen=True)
class Link:
    when: datetime    # first activity of the step
    stage: int
    score: int
    title: str
    status: str
    key: str
    until: datetime | None = None  # last activity (campaigns run for days)
    rule: str = ""

    @property
    def end(self) -> datetime:
        return self.until or self.when


def _only_failures(evidence) -> bool:
    """Sign-in evidence whose rows all failed (rows without a Result column - audit events - do not count)."""
    results = [str(r.get("Result", "")) for r in evidence or [] if r.get("Result")]
    return bool(results) and not any(r.startswith("Success") for r in results)


def _last_activity(alert) -> datetime:
    """Latest evidence time of an alert (a guessing campaign keeps running after its first attempt)."""
    times = []
    for row in alert.evidence or []:
        try:
            if row.get("_created"):
                times.append(datetime.fromisoformat(row["_created"]))
            elif row.get("Time"):
                times.append(datetime.strptime(row["Time"][:16], "%Y-%m-%d %H:%M").astimezone())
        except ValueError:
            continue
    return max(times + [alert.when])


def stage_of(rule_id: str, factors: Iterable[tuple[int, str]] = ()) -> int | None:
    stage = RULE_STAGES.get(rule_id)
    if stage == 1 and any(p > 0 and ("got past the password" in r or "successful sign-in(s) from" in r)
                          for p, r in factors):
        return 2  # a guessing campaign in which the password worked
    return stage


def links_by_subject(alerts: Iterable, now: datetime, lookback_days: int = LOOKBACK_DAYS) -> dict[str, list[Link]]:
    """Group the alerts of the last ``lookback_days`` by the accounts (UPNs) they are about."""
    since = now - timedelta(days=lookback_days)
    out: dict[str, list[Link]] = {}
    for a in alerts:
        if a.plugin_id == CHAIN_PLUGIN or a.signal in NOT_LINKS or a.when < since:
            continue
        stage = stage_of(a.rule_id, a.factors)
        score = int(getattr(a, "base_score", a.score) or 0)  # a step counts with the rule's own score
        if stage is None or score < MIN_LINK_SCORE:
            continue
        if stage == 3 and _only_failures(a.evidence):
            stage = 1  # blocked attempts (e.g. a risky sign-in that failed) are targeting, not access
        for subject in a.subjects:
            if "@" in subject:
                out.setdefault(subject, []).append(
                    Link(a.when, stage, score, a.title, a.status, a.key, _last_activity(a), a.rule_id))
    return out


def _follows(prev: Link, link: Link) -> bool:
    """``link`` can be the next step after ``prev``: a later stage, not before it, and soon after it."""
    return (prev.stage < link.stage and prev.when <= link.end + ORDER_TOLERANCE
            and link.when - prev.end <= MAX_STEP_GAP)


def best_chain(links: list[Link]) -> list[Link]:
    """Longest sequence with strictly increasing stages in time order, each step soon after the previous one."""
    links = sorted(links, key=lambda x: (x.when, x.stage))
    best: list[list[Link]] = []  # best[i]: longest chain ending with links[i]
    for i, link in enumerate(links):
        chain = [link]
        for j in range(i):
            prev = best[j]
            if _follows(prev[-1], link) and len(prev) + 1 > len(chain):
                chain = prev + [link]
        best.append(chain)
    return max(best, key=lambda c: (len(c), sum(x.score for x in c)), default=[])


def is_attack_chain(chain: list[Link]) -> bool:
    stages = [x.stage for x in chain]
    if len({x.rule for x in chain}) < 2:
        return False  # one rule seeing one thing evolve already reminds on its own (e.g. break-glass attempts + use)
    return len(stages) >= 2 and (stages[0] <= 2 and stages[-1] >= 3 or len(stages) >= 3)


def chain_score(chain: list[Link]) -> int:
    stages = {x.stage for x in chain}
    strongest = max(x.score for x in chain)
    score = strongest + STEP_POINTS * (len(chain) - 1)
    if 2 in stages and stages & {3, 4}:
        score += 10  # the password was known AND something happened afterwards
    if len(chain) == 2:
        score = min(score, max(69, strongest))  # two steps: Medium, unless one step is High on its own
    return max(25, min(100, score))


def chain_findings(alerts: Iterable, now: datetime) -> list[Finding]:
    alerts = list(alerts)
    revoked: dict[str, list[datetime]] = {}
    for a in alerts:
        if a.signal == "sessions_revoked":
            for subject in a.subjects:
                revoked.setdefault(subject, []).append(a.when)
    out = []
    for subject, links in links_by_subject(alerts, now).items():
        chain = best_chain(links)
        if not is_attack_chain(chain):
            continue
        score = chain_score(chain)
        steps = " -> ".join(STAGE_NAMES[x.stage] for x in chain)
        revs = sorted(t for t in revoked.get(subject, []) if t >= chain[0].when)
        handled = bool(revs) and revs[-1] >= chain[-1].end
        if handled:
            score = max(25, score - 15)
        out.append(Finding(
            key=f"chain|{subject}|{chain[0].when.astimezone():%Y-%m-%d}", rule_id="attack_chain",
            severity=_severity(score), score=score, subjects=[subject],
            title=f"Possible attack chain: {subject} ({steps})",
            summary=(f"{len(chain)} steps against {subject} within "
                     f"{max(1, (chain[-1].when - chain[0].when).days)} day(s), in the order of an account takeover: "
                     f"{steps}. Each step alone may look harmless or was dismissed; together they deserve a look."),
            occurred_at=chain[0].when,
            factors=[(max(x.score for x in chain), "Strongest single step")]
                    + [(STEP_POINTS, f"Step {i + 1}: {STAGE_NAMES[x.stage]} - {x.title}") for i, x in enumerate(chain[1:], 1)]
                    + ([(10, "Password known, then further activity")]
                       if 2 in {x.stage for x in chain} and {3, 4} & {x.stage for x in chain} else [])
                    + ([(-15, "Sessions were revoked after the last step (handled?)")] if handled else []),
            fields={"Account": subject, "Chain": steps,
                    "From / to": f"{chain[0].when.astimezone():%d.%m. %H:%M} - {chain[-1].end.astimezone():%d.%m. %H:%M}",
                    **({"Sessions revoked": revs[-1].astimezone().strftime("%d.%m. %H:%M")} if revs else {})},
            evidence=[{"Time": x.when.astimezone().strftime("%Y-%m-%d %H:%M"), "Stage": f"{x.stage} {STAGE_NAMES[x.stage]}",
                       "Step": x.title, "Score": str(x.score), "Reminder": x.status} for x in chain],
            recommendation=("Check whether these steps belong together. If the account was not used by its owner in "
                            "this way: revoke sessions, reset the password, review MFA methods, app consents, inbox "
                            "rules and recent role changes of the account."),
        ))
    return out


def _severity(score: int) -> Severity:
    return Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW
