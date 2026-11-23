"""What an attacker demonstrably used - remembered, so that one finding raises everything else that touches it.

Rules judge one account at a time. When one of them proves that an address was in an attacker's hands (a stolen
session came from it, a phishing proxy relayed through it, a guessed password was used from it, a user reported
its MFA prompt as not theirs ...), that address is kept here for a few days. Every later assessment of a sign-in
from it - to whatever account, by whatever rule - is raised, and the "known attacker address reused" rule reports
other accounts that were tried or signed in from it.

Only sign-ins that are foreign to their account mark an address (no office network; no device, network or address
the account used before), and never an address several people regularly sign in from (a hotel, a mobile carrier's
gateway). An indicator does not count against the sign-ins it was derived from.
"""
from __future__ import annotations

from ... import timefmt
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

HIGH, MEDIUM = 25, 15  # points an indicator adds to an assessment (proven access / attack traffic)
NETWORK, NETWORK_SOURCE = "asn", "guessing_network"  # a whole network (AS) that only guesses, see derive_networks
MIN_SCORE = 45         # a finding has to be at least Medium to mark anything
SHARED_USERS = 3       # an address this many accounts regularly sign in from is nobody's "attacker address"
OWN_PROMPT_MARK = "(probably their own sign-in)"

# rule -> (points, what the address was used in, which evidence rows count: "access" = the password was right)
SOURCES: dict[str, tuple[int, str, str]] = {
    "mfa_report": (HIGH, "a sign-in whose MFA prompt the user reported as not theirs", "access"),
    "session_theft": (HIGH, "a stolen session", "access"),
    "aitm_replay": (HIGH, "a phishing proxy / replayed session", "access"),
    "distributed_attack": (HIGH, "a password attack that got past the password", "access"),
    "brute_force": (HIGH, "a guessed password", "access"),
    "password_not_completed": (MEDIUM, "a sign-in with the right password that MFA stopped", "access"),
    "mfa_fatigue": (MEDIUM, "MFA prompts sent with the right password", "access"),
    "new_shared_ip": (MEDIUM, "a new address used on several accounts", "access"),
    "attack_tooling": (MEDIUM, "attack-tool sign-ins", "all"),
    "password_spray": (MEDIUM, "a password spray", "all"),
}


@dataclass(frozen=True)
class Indicator:
    kind: str          # "ip"
    value: str
    source: str        # rule id
    reason: str
    points: int
    user_id: str       # the account the finding was about
    upn: str
    when: datetime     # the latest sign-in it was derived from
    expires: datetime

    def to_json(self) -> str:
        data = asdict(self)
        data["when"], data["expires"] = self.when.isoformat(), self.expires.isoformat()
        return json.dumps(data)

    @classmethod
    def from_json(cls, text: str) -> "Indicator":
        data = json.loads(text)
        data["when"], data["expires"] = datetime.fromisoformat(data["when"]), datetime.fromisoformat(data["expires"])
        return cls(**data)

    def describe(self) -> str:
        if self.kind == NETWORK:
            return f"{self.reason} (last {timefmt.stamp(self.when)})"
        return f"{self.reason} ({self.upn or 'an account'}, {timefmt.stamp(self.when)})"


def settings(rc: Any) -> tuple[bool, float]:
    cfg = rc.cfg("hostile_indicators")
    return bool(cfg.get("enabled", True)), float(cfg.get("days", 7))


def _qualifies(finding: Any) -> bool:
    rule = finding.rule_id
    if rule not in SOURCES or int(finding.score or 0) < MIN_SCORE:
        return False
    text = " ".join(str(reason) for _points, reason in finding.factors or [])
    if rule == "mfa_report":
        return finding.key.startswith("mfa-report|") and OWN_PROMPT_MARK not in finding.title
    if rule == "distributed_attack":
        return "got past the password" in text or "successful sign-in(s) from unfamiliar" in text
    if rule == "brute_force":
        return finding.key.startswith("brute-success|")
    return True


def derive(rc: Any, findings: Iterable[Any]) -> list[Indicator]:
    """The addresses this run's findings prove to be an attacker's."""
    from . import rules  # (rules imports this module's types lazily too)

    enabled, days = settings(rc)
    if not enabled:
        return []
    found: dict[tuple[str, str, str], Indicator] = {}
    shared: dict[str, bool] = {}
    for f in findings:
        if not _qualifies(f):
            continue
        points, reason, rows = SOURCES[f.rule_id]
        for row in f.evidence or []:
            # (one id can stand for a sign-in by hand and a background record: the row says which one it shows)
            kind = {"interactiveUser": True, "nonInteractiveUser": False}.get(str(row.get("_event") or ""))
            sid = row.get("Sign-in ID") or ""
            s = (rc.history.get(sid, kind) or rc.history.get(sid)) if sid else None
            if s is None or not s.ip or rc.trusted(s) or s.ip in rc.ignore_ips or s.upn in rc.ignore_users:
                continue
            if rows == "access" and not (s.success or rules.password_proven(s)
                                         or s.error_code == rules.MFA_DENIED_CODE):
                continue
            if s.user_id and not rules._foreign_to_user(rc, s):
                continue
            if s.ip not in shared:
                shared[s.ip] = rc.history.ip_regular_users(s.ip, s.created - timedelta(days=3)) >= SHARED_USERS
            if shared[s.ip]:
                continue
            key = (s.ip, f.rule_id, s.user_id)
            old = found.get(key)
            if old is None or s.created > old.when:
                found[key] = Indicator("ip", s.ip, f.rule_id, reason, points, s.user_id, s.upn or s.who, s.created,
                                       s.created + timedelta(days=days))
    return list(found.values())


def derive_networks(rc: Any) -> list[Indicator]:
    """Networks that only guess: failed passwords for several accounts came from them, and nobody in the tenant has
    ever signed in from them. A guessing campaign changes its address with every attempt, so remembering addresses
    says nothing about its next one - the networks it rents its addresses in stay the same for weeks. The mark
    counts only against what gets past a password from such a network (see Assessor.assess), never against a
    network somebody signs in from: a mobile carrier or a home provider stops being one with the first person on it."""
    from . import rules

    enabled, days = settings(rc)
    minimum = int(rc.cfg("hostile_indicators").get("network_min_accounts", 3))
    if not enabled or minimum <= 0:
        return []
    by_network: dict[int, list] = {}
    for s in rc.keep(rc.history.query(rc.now - timedelta(days=days), rc.now, codes=rules.FAILED_PASSWORD_CODES)):
        if s.asn and s.user_id and not rc.trusted(s):
            by_network.setdefault(s.asn, []).append(s)
    out = []
    for asn, rows in by_network.items():
        accounts = {s.user_id for s in rows}
        if len(accounts) < minimum or rc.history.asn_user_count(asn, rc.now):
            continue
        last = max(rows, key=lambda s: s.created)
        out.append(Indicator(NETWORK, str(asn), NETWORK_SOURCE,
                             f"passwords of {len(accounts)} accounts were guessed at from it, nobody signs in from it",
                             MEDIUM, "", "", last.created, last.created + timedelta(days=days)))
    return out


def apply(rc: Any, findings: list, reuse: bool = True) -> list[Indicator]:
    """After the rules ran: remember what their findings prove, report what else came from those addresses, and
    name the addresses in the findings. Returns the address indicators of this run."""
    from . import rules

    marked = derive(rc, findings)
    rc.history.add_indicators(marked + derive_networks(rc))
    rc.history.purge_indicators(rc.now)
    rc._hostile = rc._hostile_nets = None
    if reuse and settings(rc)[0]:
        findings.extend(rules.hostile_reuse(rc))
    annotate(rc, findings)
    return marked


def annotate(rc: Any, findings: Iterable[Any]) -> None:
    """Name the known attacker addresses among a finding's evidence (also what groups alerts into one incident)."""
    index = rc.hostile_index()
    if not index:
        return
    for f in findings:
        seen: dict[str, Indicator] = {}
        for row in f.evidence or []:
            ip = row.get("IP address") or ""
            for ind in index.get(ip, ()):
                if ip not in seen or ind.points > seen[ip].points:
                    seen[ip] = ind
        if seen:
            f.fields[FIELD] = "; ".join(f"{ip} - {ind.describe()}" for ip, ind in list(seen.items())[:4])


FIELD = "Known attacker address"


def addresses_in(fields: dict[str, str]) -> list[str]:
    """The addresses named in an alert's 'Known attacker address' field."""
    return [part.split(" - ")[0].strip() for part in str(fields.get(FIELD) or "").split(";") if part.strip()]
