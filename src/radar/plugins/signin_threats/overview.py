"""Live overview of ongoing attacks (tray: "Ongoing attacks...").

Computed from the local sign-in history every time it is opened - independent of reminders: dismissing an alert
only silences it, the attack still shows up here as long as it runs. Every section is assessed by the very rules
that raise the alerts, run over the chosen period:

- password guessing: rotating-IP campaigns (+ repeated failures, MFA-excluded accounts from 3 failures);
- password known: correct password from an unusual place stopped by MFA/CA, MFA denials, fraud reports -
  the alert rule raises one reminder per account and DAY, so a pattern over many days is only visible here;
- stolen sessions: session theft / AiTM replay, with the last use from the suspicious side;
- attacking IPs: every source of the password-guessing attacks above (rotating proxies try an account only once or
  twice each - they are listed too, marked as such) plus any source that tried several accounts or several times.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ...plugin_api import Finding, Severity
from . import netintel, rules
from .models import SignIn, parse_time
from .rules import FAILED_PASSWORD_CODES, RuleContext

ACTIVE_HOURS = 6    # last attempt within -> "Active"
QUIET_HOURS = 24    # within -> "Quiet", older -> "Ended"
STATUS_ORDER = {"Active": 0, "Quiet": 1, "Ended": 2}


def mfa_state(acct) -> str:
    """MFA situation of an account for the overview: can the attacker who has the password get in?"""
    if acct is None:
        return "?"
    if acct.mfa_excluded:
        return "EXCLUDED"
    if acct.mfa_gap:
        return "NOT registered"
    return "registered" if acct.mfa_registered else "?"


def status_of(last: datetime, now: datetime) -> str:
    age = now - last
    return "Active" if age <= timedelta(hours=ACTIVE_HOURS) else "Quiet" if age <= timedelta(hours=QUIET_HOURS) else "Ended"


@dataclass
class TargetedAccount:
    user_id: str
    account: str
    kind: str                 # "Rotating IPs" | "Repeated failures"
    status: str
    attempts: int
    ips: int
    networks: int
    countries: str
    apps: str
    first: datetime
    last: datetime
    last_24h: int
    past_password: str        # "No" | "Yes: ..." | "" (not assessed)
    score: int | None
    mfa_excluded: bool
    also_targets: str = ""
    finding: Finding | None = None
    evidence: list[dict[str, str]] = field(default_factory=list)
    mfa: str = "?"

    def as_finding(self) -> Finding:
        """The live assessment (rotating-IP rule) or a plain summary for repeated failures."""
        if self.finding:
            return self.finding
        return Finding(
            key=f"overview|{self.user_id}", rule_id="brute_force", severity=Severity.LOW, score=None,
            title=f"Repeated failed passwords: {self.account}",
            summary=(f"{self.attempts} failed password attempts for {self.account} from {self.ips} IP(s) on networks the "
                     f"account does not use" + (" - the account is excluded from MFA" if self.mfa_excluded else "") + "."),
            occurred_at=self.first, evidence=self.evidence,
            fields={"Account": self.account, "Attempts": str(self.attempts), "IPs": str(self.ips),
                    "Countries": self.countries, "Apps": self.apps})


@dataclass
class AttackingIp:
    ip: str
    network: str
    country: str
    status: str
    accounts: int
    attempts: int
    first: datetime
    last: datetime
    targets: str
    pattern: str = ""         # "Several accounts (3)" | "Repeated (5 attempts)" | "Rotating IP (1 attempt)" ...
    network_type: str = ""    # "VPN / proxy" | "Hosting" | ... | "ISP / other"


NETWORK_TYPES = {"vpn": "VPN / proxy", "hosting": "Hosting", "cloud": "Cloud", "bulletproof": "Bulletproof hosting"}


def _merged(title: str, findings: list[Finding], extra_fields: dict[str, str]) -> Finding:
    """One finding combining several days of the same pattern (highest-scoring explanation, all evidence)."""
    top = max(findings, key=lambda f: f.score or 0)
    evidence = sorted((e for f in findings for e in f.evidence), key=lambda e: e.get("Time", ""), reverse=True)
    return Finding(key=top.key, rule_id=top.rule_id, severity=top.severity, score=top.score, title=title,
                   summary=top.summary, recommendation=top.recommendation, factors=top.factors,
                   fields={**extra_fields, **top.fields}, evidence=evidence[:rules.MAX_EVIDENCE], links=top.links,
                   occurred_at=min(f.occurred_at for f in findings if f.occurred_at))


def _last_time(f: Finding) -> datetime:
    times = [datetime.fromisoformat(e["_created"]) for e in f.evidence if e.get("_created")]
    return max(times) if times else f.occurred_at


@dataclass
class PasswordKnown:
    """An account whose correct password was used from an unusual place (MFA/CA stopped it) or that got MFA
    prompts it denied: the attacker is past the password stage."""
    user_id: str
    account: str
    status: str
    kinds: str            # "MFA stopped it", "MFA denials", "Fraud report"
    days: int
    events: int
    score: int
    first: datetime
    last: datetime
    networks: str
    clients: str
    findings: list[Finding] = field(default_factory=list)
    password_reset: str = "?"   # "NO (last change ...)" | "yes, ..." | "n/a (guest)" - is the known password still valid?
    mfa: str = "?"

    def as_finding(self) -> Finding:
        return _merged(f"Password known to someone else? {self.account} ({self.days} day(s))", self.findings,
                       {"Pattern": f"{self.kinds} on {self.days} day(s), {self.events} event(s)",
                        "Password reset since": self.password_reset, "Networks": self.networks,
                        "Clients": self.clients})


@dataclass
class SessionAbuse:
    """A session flagged as stolen / replayed, and whether the suspicious side still uses it."""
    account: str
    kind: str             # "Session theft" | "AiTM proxy" | "Session replay"
    status: str
    score: int
    first: datetime
    last: datetime        # last use from the suspicious side seen in the history
    suspicious: str       # where from
    session: str
    finding: Finding | None = None

    def as_finding(self) -> Finding:
        return self.finding


@dataclass
class AttackOverview:
    hours: float
    generated: datetime
    accounts: list[TargetedAccount]
    sources: list[AttackingIp]
    single_attempt_ips: int   # listed IPs that tried one account only once or twice (rotating proxies)
    password_known: list[PasswordKnown] = field(default_factory=list)
    sessions: list[SessionAbuse] = field(default_factory=list)

    @property
    def active(self) -> int:
        return sum(1 for a in self.accounts if a.status == "Active")

    @property
    def active_all(self) -> int:
        return self.active + sum(1 for x in self.password_known + self.sessions if x.status == "Active")


def _foreign_failures(rc: RuleContext, user_id: str, start: datetime) -> list[SignIn]:
    """Failed passwords from networks the user does not use (the same filter as the rotating-IP rule)."""
    attempts = rc.keep(rc.history.query(start, rc.now, user_id=user_id))
    familiar = rc.history.user_asns(user_id, start) | {s.asn for s in attempts if s.success and s.asn and s.device_id}
    return [s for s in attempts if not s.success and s.error_code in FAILED_PASSWORD_CODES and not rc.trusted(s)
            and (not s.asn or s.asn not in familiar)]


def _past_password(f: Finding) -> str:
    hits = [r for p, r in f.factors if p > 0 and ("got past the password" in r or "successful sign-in(s) from" in r)]
    return ("Yes: " + "; ".join(hits)) if hits else "No"


def ongoing_attacks(rc: RuleContext, hours: float = 72) -> AttackOverview:
    start = rc.now - timedelta(hours=hours)
    failures = [s for s in rc.keep(rc.history.query(start, rc.now, codes=FAILED_PASSWORD_CODES)) if s.user_id]
    prefetch = getattr(rc.asn_resolver, "prefetch", None)
    if prefetch:  # 100+ rotating-proxy networks get named below: look them up in parallel, not one by one
        prefetch(s.asn for s in failures if s.asn and not netintel.asn_info(s.asn, rc.assessor.extra_asns))

    # 1) rotating-IP campaigns: the alert rule itself over the chosen window, MFA-excluded accounts included
    settings = dict(rc.settings)
    settings["distributed_attack"] = {**rc.cfg("distributed_attack"), "window_hours": hours}
    enabled = frozenset(r.meta.id for r in rules.RULES) - {"mfa_exempt_watch"}
    sub = RuleContext.build(failures, rc.history, settings, rc.now, enabled_rules=enabled,
                            asn_resolver=rc.asn_resolver, accounts=rc.accounts)
    campaigns = {f.key.split("|")[1]: f for f in rules.distributed_attack(sub)}

    brute_min = int(rc.cfg("brute_force").get("min_failures", 10))
    exempt_min = int(rc.cfg("mfa_exempt_watch").get("min_failures", 3))
    accounts: list[TargetedAccount] = []
    foreign_by_user: dict[str, list[SignIn]] = {}
    for user_id in sorted({s.user_id for s in failures}):
        acct = rc.accounts.get(user_id) if rc.accounts else None
        excluded = bool(acct and acct.mfa_excluded)
        foreign = _foreign_failures(rc, user_id, start)
        foreign_by_user[user_id] = foreign
        f = campaigns.get(user_id)
        if not f and len(foreign) < (exempt_min if excluded else brute_min):
            continue
        if not foreign:
            continue
        first, last = min(s.created for s in foreign), max(s.created for s in foreign)
        accounts.append(TargetedAccount(
            user_id=user_id, account=foreign[0].who if foreign[0].upn else (acct.upn if acct else user_id),
            kind="Rotating IPs" if f else "Repeated failures", status=status_of(last, rc.now),
            attempts=len(foreign), ips=len({s.ip for s in foreign}), networks=len({s.asn for s in foreign if s.asn}),
            countries=", ".join(f"{c} ({n})" for c, n in Counter(s.country or "?" for s in foreign).most_common(4)),
            apps=", ".join(a for a, _ in Counter(s.app for s in foreign).most_common(2)),
            first=first, last=last, last_24h=sum(1 for s in foreign if rc.now - s.created <= timedelta(hours=24)),
            past_password=_past_password(f) if f else "", score=f.score if f else None, mfa_excluded=excluded,
            also_targets=(f.fields.get("Same campaign also targets", "") if f else ""), finding=f,
            evidence=[] if f else rules._evidence(foreign), mfa=mfa_state(acct)))
    accounts.sort(key=lambda a: (STATUS_ORDER[a.status], -a.last.timestamp()))

    # 2) attacking IPs: every source of the attacks above, and any source that tried several accounts / times
    by_ip: dict[str, list[SignIn]] = defaultdict(list)
    for foreign in foreign_by_user.values():
        for s in foreign:
            by_ip[s.ip].append(s)
    sources, single = [], 0
    kind_of = {a.user_id: a.kind for a in accounts}
    for ip, rows in by_ip.items():
        users = {s.user_id for s in rows}
        if len(users) < 2 and len(rows) < 3 and not users & set(kind_of):
            continue  # a stray failure from a network the user does not use - not part of an attack
        s0 = rows[0]
        last = max(s.created for s in rows)
        net = rc.assessor.network(s0)
        n = len(rows)
        if len(users) >= 2:
            pattern = f"Several accounts ({len(users)})"
        elif n >= 3:
            pattern = f"Repeated ({n} attempts)"
        else:
            single += 1
            rotating = any(kind_of.get(u) == "Rotating IPs" for u in users)
            pattern = ("Rotating IP" if rotating else "Single IP") + f" ({n} attempt{'s' if n > 1 else ''})"
        sources.append(AttackingIp(
            ip=ip, network=rc.assessor.asn_label(s0.asn) if s0.asn else "", country=s0.country or "?",
            status=status_of(last, rc.now), accounts=len(users), attempts=n,
            first=min(s.created for s in rows), last=last,
            targets=", ".join(sorted({s.who for s in rows})[:6]) + (" ..." if len(users) > 6 else ""),
            pattern=pattern, network_type=NETWORK_TYPES.get(net[1], net[1]) if net else "ISP / other"))
    sources.sort(key=lambda x: (STATUS_ORDER[x.status], -x.accounts, -x.attempts, -x.last.timestamp()))
    return AttackOverview(hours=hours, generated=rc.now, accounts=accounts, sources=sources, single_attempt_ips=single,
                          password_known=_password_known(rc, hours), sessions=_sessions(rc, hours))


def _sub(rc: RuleContext, new: list[SignIn], settings: dict | None = None) -> RuleContext:
    return RuleContext.build(new, rc.history, settings or rc.settings, rc.now, asn_resolver=rc.asn_resolver,
                             accounts=rc.accounts)


def _password_known(rc: RuleContext, hours: float) -> list[PasswordKnown]:
    """Correct password from an unusual place (MFA/CA stopped it), MFA denials and fraud reports - per account,
    over all days of the period (the alert rule raises one reminder per account and day)."""
    settings = dict(rc.settings)
    settings["password_not_completed"] = {**rc.cfg("password_not_completed"), "window_hours": hours}
    found = [f for f in rules.password_not_completed(_sub(rc, [], settings)) if (f.score or 0) >= 25]
    denials = rc.keep(rc.history.query(rc.now - timedelta(hours=hours), rc.now, codes=(rules.MFA_DENIED_CODE,)))
    if denials:
        found += rules.mfa_fatigue(_sub(rc, denials))
    by_user: dict[str, list[Finding]] = defaultdict(list)
    for f in found:
        by_user[(f.fields.get("User") or "?").lower()].append(f)
    rows = []
    for upn, fs in by_user.items():
        evidence = [e for f in fs for e in f.evidence]
        last = max(_last_time(f) for f in fs)
        asns = Counter(e.get("ASN") or "?" for e in evidence)
        user_id = next((f.key.split("|")[1] for f in fs if f.key.startswith(("pwok|", "mfa-fatigue|"))), "")
        acct = rc.accounts.get(user_id) if rc.accounts and user_id else None
        guest = bool(acct and acct.user_type.lower() == "guest") or "#ext#" in upn
        kinds = ", ".join(sorted({"MFA stopped it" if f.rule_id == "password_not_completed" else
                                  "Fraud report" if f.key.startswith("mfa-fraud|") else "MFA denials" for f in fs}))
        first = min(f.occurred_at for f in fs)
        changed = parse_time(acct.pwd_changed) if acct and acct.pwd_changed else None
        reset = ("n/a (guest)" if guest else "?" if not acct else
                 f"yes, {changed.astimezone():%d.%m.%Y}" if changed and changed > first else
                 f"NO (last change {changed.astimezone():%d.%m.%Y})" if changed else "NO")
        rows.append(PasswordKnown(
            user_id=user_id, account=upn, status=status_of(last, rc.now),
            kinds=kinds + (" (guest: password of the home tenant)" if guest else ""),
            days=len({e["Time"][:10] for e in evidence if e.get("Time")}), events=len(evidence),
            score=max(f.score or 0 for f in fs), first=min(f.occurred_at for f in fs), last=last,
            networks=", ".join(f"{a} ({n})" for a, n in asns.most_common(3)),
            clients=", ".join(c for c, _ in Counter(e.get("Device") or "?" for e in evidence).most_common(2)),
            findings=fs, password_reset=reset, mfa=mfa_state(acct)))
    rows.sort(key=lambda r: (STATUS_ORDER[r.status], -r.score, -r.last.timestamp()))
    return rows


_PAREN_IP = re.compile(r"\(([0-9A-Fa-f:.]+)[,)]")


def _sessions(rc: RuleContext, hours: float) -> list[SessionAbuse]:
    """Sessions flagged as stolen / replayed in the period, and the last use from the suspicious side."""
    start = rc.now - timedelta(hours=hours)
    # The rules query the history once per sign-in - fine for a 10-minute batch, far too slow for days of
    # sign-ins. Hand them only sessions that changed country / network (+ the context 24 h before) and fresh-MFA
    # sign-ins without device identity (AiTM proxy candidates).
    by_session: dict[str, list[SignIn]] = defaultdict(list)
    for s in rc.keep(rc.history.query(start - timedelta(hours=24), rc.now, success=True)):
        if s.session_id and not s.ms_backend and not rc.trusted(s):
            by_session[s.session_id].append(s)
    candidates: dict[str, SignIn] = {}
    for rows in by_session.values():
        if len({r.country for r in rows if r.country}) > 1 or (
                len({r.asn for r in rows if r.asn}) > 1 and any(r.interactive and r.fresh_mfa for r in rows)):
            candidates.update((r.id, r) for r in rows if r.created >= start)
    for s in rc.keep(rc.history.query(start, rc.now, success=True, interactive_only=True)):
        if s.fresh_mfa and not s.device_id:
            candidates[s.id] = s
    sub = _sub(rc, list(candidates.values()))
    found = [f for f in rules.session_theft(sub) + rules.aitm_replay(sub) if (f.score or 0) >= 25]
    rows = []
    for f in found:
        kind = ("Session theft" if f.rule_id == "session_theft" else
                "AiTM proxy" if f.key.startswith("aitm|") else "Session replay")
        where = f.fields.get("Judged side") or f.fields.get("Replayed from") or f.fields.get("IP", "")
        m = _PAREN_IP.search(where)
        ip = m.group(1) if m else f.fields.get("IP", "")
        sid = f.fields.get("Session ID", "")
        times = [datetime.fromisoformat(e["_created"]) for e in f.evidence if e.get("_created") and e.get("IP address") == ip]
        last = max(times) if times else _last_time(f)
        if sid and ip:  # still used from there after the detection?
            later = [s.created for s in rc.history.query(last, rc.now, session_id=sid, success=True) if s.ip == ip]
            last = max(later + [last])
        rows.append(SessionAbuse(account=f.fields.get("User", ""), kind=kind, status=status_of(last, rc.now),
                                 score=f.score or 0, first=f.occurred_at, last=last, suspicious=where, session=sid,
                                 finding=f))
    rows.sort(key=lambda r: (STATUS_ORDER[r.status], -r.score, -r.last.timestamp()))
    return rows
