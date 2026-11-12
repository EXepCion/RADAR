"""Detection rules. Each rule looks at the newly ingested sign-ins plus the local history.

Context-dependent rules (geo, sessions, risky sign-ins, ...) are scored by :mod:`.scoring`, which
explains its verdict; pure volume patterns (spray, brute force, MFA fatigue) use fixed scores.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from ...plugin_api import Finding, Rule, Severity
from . import indicators, netintel
from .history import SignInHistory
from .models import CHANGE_KINDS, REPORT_KIND, AccountChange, SignIn, os_family, parse_time  # noqa: F401  (os_family re-exported)
from .accounts import AccountDirectory  # noqa: F401  (type of RuleContext.accounts)
from .scoring import LABEL_HABITUAL_VPN, Assessment, Assessor, Factor, severity_for

SIGNIN_LOGS_URL = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns"
RISKY_SIGNINS_URL = "https://portal.azure.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskySignIns"

# Wrong password / locked / unknown user / disabled: what a spray or brute force produces.
SPRAY_CODES = (50126, 50053, 50056, 50034, 50057)
BRUTE_CODES = (50126, 50053, 50056)
MFA_DENIED_CODE = 500121
# Errors raised only AFTER the password was accepted (MFA required, CA block, device requirements ...).
PASSWORD_ACCEPTED_CODES = (50074, 50076, 50079, 50072, 50158, 53000, 53001, 53002, 53003, 530032)
LEGACY_CLIENT_APPS = netintel.LEGACY_CLIENT_APPS
RISK_LEVELS = {"low": 1, "medium": 2, "high": 3}
PIN_TO_TRUSTED = {"trusted_ips", "@trusted_ips", "offices"}
MAX_EVIDENCE = 50


def user_url(user_id: str) -> str:
    return f"https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


class IpMatcher:
    """Matches IPs against addresses / CIDR ranges: a list, or a dict {ip_or_cidr: "label"}."""

    def __init__(self, entries: Iterable[str] | dict[str, str]):
        self._nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        items = entries.items() if isinstance(entries, dict) else ((e, "") for e in entries or [])
        for e, label in items:
            try:
                self._nets.append((ipaddress.ip_network(str(e).strip(), strict=False), str(label or "")))
            except ValueError:
                pass

    def label(self, ip: str) -> str | None:
        """Label of the matching entry ('' if unnamed), or None if the IP does not match."""
        if not ip or not self._nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((label for net, label in self._nets if addr.version == net.version and addr in net), None)

    def __contains__(self, ip: str) -> bool:
        return self.label(ip) is not None


class UserMatcher:
    """Case-insensitive UPN list with shell wildcards, e.g. ``meetingroom-*@contoso.com``."""

    def __init__(self, patterns: Iterable[str]):
        self._patterns = [str(p).strip().lower() for p in patterns or [] if str(p).strip()]

    def __contains__(self, upn: str) -> bool:
        upn = (upn or "").lower()
        return bool(upn) and any(fnmatch.fnmatchcase(upn, p) for p in self._patterns)


@dataclass
class RuleContext:
    new: list[SignIn]
    history: SignInHistory
    settings: dict
    now: datetime
    ignore_users: UserMatcher = field(default_factory=lambda: UserMatcher([]))
    ignore_ips: IpMatcher = field(default_factory=lambda: IpMatcher([]))
    trusted_ips: IpMatcher = field(default_factory=lambda: IpMatcher([]))
    use_named_locations: bool = True
    pins: list[tuple[str, list[str], IpMatcher]] = field(default_factory=list)
    enabled_rules: frozenset[str] | None = None  # None = all rules
    asn_resolver: Callable[[int], str | None] | None = None  # AS number -> holder name (optional)
    accounts: "AccountDirectory | None" = None  # account context (roles, MFA exposure, state)
    breakglass: UserMatcher = field(default_factory=lambda: UserMatcher([]))
    virtual_hosts: Any = None  # hosts.HostMatcher: virtual desktops / shared hosts (their place is not the person's)
    learning: frozenset[str] = frozenset()  # MFA-excluded accounts whose pattern is not learned yet
    _assessor: Assessor | None = None
    _computer_nets: dict = field(default_factory=dict)  # user id -> networks the user's computers sign in from
    _hostile: dict | None = None  # address -> [Indicator] (see hostile_index)

    @classmethod
    def build(cls, new: list[SignIn], history: SignInHistory, settings: dict, now: datetime,
              enabled_rules: Iterable[str] | None = None,
              asn_resolver: Callable[[int], str | None] | None = None,
              accounts: "AccountDirectory | None" = None) -> "RuleContext":
        pinned = (settings.get("pinned_accounts") or {}).get("accounts") or {}
        from . import hosts, offices  # office addresses + other trusted addresses, each with its label

        trusted = offices.trusted_map(settings)

        def expand(ips: Iterable[str]) -> dict[str, str]:
            """'trusted_ips' in a pin list stands for every office IP in trusted_ips."""
            out: dict[str, str] = {}
            for ip in ips or []:
                out.update(trusted if str(ip).strip().lower() in PIN_TO_TRUSTED else {str(ip): ""})
            return out

        rc = cls(new=[], history=history, settings=settings, now=now,
                 ignore_users=UserMatcher(settings.get("ignore_users", [])),
                 ignore_ips=IpMatcher(settings.get("ignore_ips", [])),
                 trusted_ips=IpMatcher(trusted),
                 virtual_hosts=hosts.matcher(settings),
                 use_named_locations=bool(settings.get("trust_named_locations", True)),
                 pins=[(str(user).strip().lower(),
                        [f"{ip} ({label})" if label else ip for ip, label in expand(ips).items()],
                        IpMatcher(expand(ips)))
                       for user, ips in pinned.items() if str(user).strip()],
                 enabled_rules=frozenset(enabled_rules) if enabled_rules is not None else None,
                 asn_resolver=asn_resolver, accounts=accounts,
                 breakglass=UserMatcher(settings.get("breakglass_accounts", [])))
        rc.new = rc.keep(new)
        return rc

    @property
    def assessor(self) -> Assessor:
        if self._assessor is None:
            self._assessor = Assessor(self)
        return self._assessor

    def cfg(self, rule_id: str) -> dict:
        value = self.settings.get(rule_id)
        return value if isinstance(value, dict) else {}

    def hostile_index(self) -> dict[str, list]:
        """Addresses an attacker demonstrably used, from earlier findings (indicators.py): address -> indicators."""
        if self._hostile is None:
            self._hostile = {}
            if indicators.settings(self)[0]:
                for ind in self.history.indicators(self.now):
                    if ind.kind == "ip":
                        self._hostile.setdefault(ind.value, []).append(ind)
        return self._hostile

    def hostile(self, s: SignIn) -> "indicators.Indicator | None":
        """The strongest indicator that counts against this sign-in: its address was used in an attack - on another
        account, or on this one before this sign-in (never the sign-ins the indicator was derived from)."""
        if not s.ip or self.trusted(s):
            return None
        hits = [i for i in self.hostile_index().get(s.ip, ()) if i.user_id != s.user_id or s.created > i.when]
        return max(hits, key=lambda i: (i.points, i.when), default=None)

    def rule_on(self, rule_id: str) -> bool:
        return self.enabled_rules is None or rule_id in self.enabled_rules

    def pin_for(self, upn: str) -> tuple[list[str], IpMatcher] | None:
        """Allowed IPs of a pinned account (UPN patterns may use wildcards), or None if not pinned."""
        upn = (upn or "").lower()
        for pattern, ips, matcher in self.pins:
            if upn and fnmatch.fnmatchcase(upn, pattern):
                return ips, matcher
        return None

    def keep(self, signins: Iterable[SignIn]) -> list[SignIn]:
        return [s for s in signins if s.upn not in self.ignore_users and s.ip not in self.ignore_ips]

    def phone_on_own_network(self, s: SignIn) -> bool:
        """A phone or tablet outside the networks the person's computers use: on mobile data (or a foreign Wi-Fi).
        Its address is located at the carrier's gateway - often another city or country than the person is in -
        so it is no end of a "journey" (see presence.py, rank 5)."""
        from . import presence

        if not presence.is_mobile_os(s) or not s.user_id:
            return False
        nets = self._computer_nets.get(s.user_id)
        if nets is None:
            rows = self.history.query(self.now - timedelta(days=30), self.now, user_id=s.user_id, success=True)
            nets = self._computer_nets[s.user_id] = presence.computer_networks(
                [r for r in rows if not self.on_virtual_host(r)], self.trusted)
        e = presence.assess(s, self.trusted(s), nets, self.assessor.extra_asns)
        return e is not None and e.rank == 5

    def on_virtual_host(self, s: SignIn) -> bool:
        """Sign-in from a configured virtual desktop / shared host (Citrix, AVD ...): the country and city are
        those of the data centre, not of the person."""
        return bool(self.virtual_hosts) and s in self.virtual_hosts

    def trusted(self, s: SignIn) -> bool:
        """Sign-in from a corporate/VPN network: its geolocation says nothing about the user."""
        return s.ip in self.trusted_ips or (self.use_named_locations and s.trusted_network)

    def trusted_label(self, s: SignIn) -> str:
        """Human name of the trusted network, e.g. 'UK office' or the Entra named location."""
        label = self.trusted_ips.label(s.ip)
        if label:
            return label
        if self.use_named_locations and s.trusted_network and s.network_names:
            return ", ".join(s.network_names)
        return "trusted IP" if label is not None else "trusted location"

    def span(self, items: list[SignIn], before: timedelta) -> tuple[datetime, datetime]:
        return min(s.created for s in items) - before, max(s.created for s in items)


# ------------------------------------------------------------- helpers
def _report_prompt(rc: RuleContext, c: AccountChange) -> SignIn | None:
    """The sign-in that caused a reported MFA prompt: the account's sign-in that failed at the MFA step closest to
    the report (the two logs share no id; the audit entry is written seconds after the sign-in)."""
    cfg = rc.cfg("mfa_report")
    before = timedelta(seconds=float(cfg.get("match_seconds_before", 180)))
    after = timedelta(seconds=float(cfg.get("match_seconds_after", 60)))
    rows = rc.history.query(c.created - before, c.created + after, user_id=c.user_id, codes=(MFA_DENIED_CODE,),
                            interactive_only=True)
    return min(rows, key=lambda x: abs((x.created - c.created).total_seconds())) if rows else None


def _foreign_to_user(rc: RuleContext, s: SignIn) -> bool:
    """Not the user's own surroundings: no office network, no device, network or address the account used before."""
    h = rc.history
    if rc.trusted(s):
        return False
    if s.device_id and s.device_id in h.user_devices(s.user_id, s.created):
        return False
    if s.asn and s.asn in h.user_asns(s.user_id, s.created):
        return False
    known_ips = h.user_profile(s.user_id, "ip", s.created)
    return not (s.ip in known_ips or _ip_net(s.ip) in {_ip_net(i) for i in known_ips})


def _day(dt: datetime) -> str:
    return dt.astimezone().strftime("%Y-%m-%d")


def _evidence(signins: Iterable[SignIn]) -> list[dict[str, str]]:
    ordered = sorted(signins, key=lambda s: s.created, reverse=True)
    rows = []
    for s in ordered[:MAX_EVIDENCE]:
        row = s.evidence()
        row["_created"] = s.created.isoformat()  # hidden: lets the UI fetch the exact log entry quickly
        row["_event"] = s.event_type
        rows.append(row)
    return rows


def _ip_net(ip: str) -> str:
    """IPv6 -> its /64 (privacy addresses rotate inside the user's own prefix); IPv4 stays as is."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if addr.version == 6 else ip


def _user_links(s: SignIn) -> list[tuple[str, str]]:
    links = [("Entra: sign-in logs", SIGNIN_LOGS_URL)]
    if s.user_id:
        links.append(("Entra: user", user_url(s.user_id)))
    return links


def _scored(a: Assessment, **kw) -> Finding:
    fields = dict(kw.pop("fields", {}))
    fields["Risk score"] = f"{a.score}/100" + (f"  ({a.label})" if a.label else "")
    if a.context:
        fields["Account context"] = a.context
    return Finding(severity=a.severity, score=a.score, factors=a.as_tuples(), fields=fields, **kw)


def _best(assessed: list[tuple[SignIn, Assessment]]) -> tuple[SignIn, Assessment]:
    return max(assessed, key=lambda x: x[1].score)


def _max_in_window(items: list[SignIn], window: timedelta,
                   key: Callable[[SignIn], str] | None = None) -> tuple[int, list[SignIn]]:
    """Sliding time window with the most sign-ins (or most distinct ``key`` values), in O(n).

    Returns (count, sign-ins inside that window).
    """
    items = sorted(items, key=lambda s: s.created)
    counts: Counter = Counter()
    best, best_range, start = (0, 0), (0, 0), 0
    for end, s in enumerate(items):
        counts[key(s) if key else end] += 1
        while s.created - items[start].created > window:
            k = key(items[start]) if key else start
            counts[k] -= 1
            if counts[k] <= 0:
                del counts[k]
            start += 1
        score = (len(counts), end + 1 - start)  # most distinct first, then the fullest window as evidence
        if score > best:
            best, best_range = score, (start, end + 1)
    return best[0], items[best_range[0]:best_range[1]]


# ---------------------------------------------------------------- rules
def risky_signin(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("risky_signin")
    minimum = RISK_LEVELS.get(str(cfg.get("min_risk_level", "medium")).lower(), 2)
    include_remediated = bool(cfg.get("include_remediated", True))
    include_failed = bool(cfg.get("include_failed", False))
    groups: dict[tuple[str, str], list[tuple[SignIn, Assessment]]] = defaultdict(list)
    for s in rc.new:
        if not s.success and not include_failed:
            continue  # blocked attempts are attack evidence (distributed_attack / spray), not a risky sign-in
        if s.risk_state in ("dismissed", "confirmedSafe"):
            continue
        if s.risk_state == "remediated" and not include_remediated:
            continue
        level = max(RISK_LEVELS.get(s.risk_during, 0), RISK_LEVELS.get(s.risk_aggregated, 0))
        if s.risk_state == "confirmedCompromised":
            base, reason = 90, "Entra ID Protection: user confirmed compromised"
        elif level >= minimum:
            base = {1: 30, 2: 50, 3: 70}[level]
            reason = f"Entra ID Protection rated the sign-in {s.risk_during or s.risk_aggregated} risk"
        else:
            continue
        extra = [Factor(-15, "Risk remediated (MFA / password change completed)")] if s.risk_state == "remediated" else []
        # Entra flagged it: never drop below Low, but let context rank it.
        groups[(s.user_id or s.who, _day(s.created))].append((s, rc.assessor.assess(s, base, reason, extra, floor=30)))
    out = []
    for (user, day), items in groups.items():
        signins = [s for s, _ in items]
        s, a = _best(items)
        detections = sorted({e for x in signins for e in x.risk_events})
        out.append(_scored(
            a, key=f"risky|{user}|{day}", rule_id="risky_signin",
            title=f"Risky sign-in: {s.who}" + (f" ({a.label})" if a.label else ""),
            summary=(f"{len(signins)} sign-in(s) flagged by Entra ID Protection"
                     f"{' (' + ', '.join(detections) + ')' if detections else ''} from "
                     f"{', '.join(sorted({x.location for x in signins}))}. Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in signins),
            fields={"User": s.who, "Risk state": ", ".join(sorted({x.risk_state for x in signins})),
                    "Detections": ", ".join(detections) or "-",
                    "IP addresses": ", ".join(sorted({x.ip for x in signins}))},
            evidence=_evidence(signins),
            recommendation=(("Known pattern: the user habitually uses a commercial VPN on a device without company "
                             "identity, and passed MFA. Not an attack indicator - but company data is accessed from an "
                             "unmanaged device; consider requiring a compliant device or app-enforced restrictions for "
                             "browser access. " if a.label == LABEL_HABITUAL_VPN and not s.device_id else "")
                            + "Review the risky sign-in in Entra ID Protection. If it was not the user, confirm "
                              "compromise, revoke sessions and reset the password; otherwise confirm safe."),
            links=_user_links(s) + [("Entra: risky sign-ins", RISKY_SIGNINS_URL)],
        ))
    return out


def password_spray(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("password_spray")
    window = timedelta(minutes=float(cfg.get("window_minutes", 60)))
    min_users = int(cfg.get("min_distinct_users", 5))
    failures = [s for s in rc.new if s.error_code in SPRAY_CODES and s.ip]
    if not failures:
        return []
    start, end = rc.span(failures, window)
    out = []
    for ip in rc.history.candidates(start, end, SPRAY_CODES, "ip", min_users, distinct_users=True):
        if ip in rc.ignore_ips:
            continue
        rows = rc.keep(rc.history.query(start, end, ip=ip, codes=SPRAY_CODES))
        users, window_rows = _max_in_window(rows, window, key=lambda s: s.user_id or s.upn)
        if users < min_users:
            continue
        successes = rc.keep(rc.history.query(window_rows[0].created, end + window, ip=ip, success=True))
        if len(successes) > len(window_rows):  # mostly successful traffic: shared corporate egress, not a spray
            continue
        compromised = sorted({s.who for s in successes})
        first = window_rows[0]
        net = rc.assessor.network(first)
        out.append(Finding(
            key=f"spray|{ip}|{_day(first.created)}", rule_id="password_spray", severity=Severity.HIGH,
            score=90 if compromised else 80,
            title=f"Password spray from {ip}",
            summary=(f"{len(window_rows)} failed sign-ins against {users} different accounts from {ip} "
                     f"({first.location}{', ' + net[0] if net else ''}) within {int(window.total_seconds() // 60)} minutes."
                     + (f" Successful sign-ins from this IP: {', '.join(compromised)}." if compromised else "")),
            occurred_at=first.created,
            fields={"IP address": ip, "Location": first.location,
                    "Network": (f"{net[0]} ({net[1]})" if net else rc.assessor.asn_label(first.asn)) if first.asn else "-",
                    "Targeted accounts": str(users), "Failed attempts": str(len(window_rows)),
                    "Successful sign-ins from IP": ", ".join(compromised) or "none"},
            evidence=_evidence(window_rows + successes),
            recommendation="Block the IP (Conditional Access named location / firewall), make sure every targeted "
                           "account has MFA, and investigate any successful sign-in from this IP immediately.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL), ("Look up IP (AbuseIPDB)", f"https://www.abuseipdb.com/check/{ip}")],
        ))
    return out


def brute_force(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("brute_force")
    window = timedelta(minutes=float(cfg.get("window_minutes", 60)))
    minimum = int(cfg.get("min_failures", 10))
    relevant = [s for s in rc.new if s.user_id and (s.error_code in BRUTE_CODES or s.success)]
    if not relevant:
        return []
    start, end = rc.span(relevant, window)
    out = []
    for user_id in rc.history.candidates(start, end, BRUTE_CODES, "user_id", minimum):
        rows = rc.keep(rc.history.query(start, end, user_id=user_id, codes=BRUTE_CODES))
        count, window_rows = _max_in_window(rows, window)
        if count < minimum:
            continue
        first, last = window_rows[0], window_rows[-1]
        bad_ips = {s.ip for s in window_rows}
        followed = [s for s in rc.keep(rc.history.query(first.created, last.created + window, user_id=user_id,
                                                         success=True)) if s.ip in bad_ips]
        ips = Counter(s.ip for s in window_rows)
        fields = {"User": first.who, "Failed attempts": str(count),
                  "Source IPs": ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(10))}
        rec = ("Verify with the user, check that MFA is enforced, consider blocking the source IPs and "
               "resetting the password if any attempt could have succeeded.")
        out.append(Finding(
            key=f"brute|{user_id}|{_day(first.created)}", rule_id="brute_force", severity=Severity.MEDIUM, score=55,
            title=f"Brute force against {first.who}",
            summary=f"{count} failed password attempts for {first.who} within {int(window.total_seconds() // 60)} minutes.",
            occurred_at=first.created, fields=fields, evidence=_evidence(window_rows), recommendation=rec,
            links=_user_links(first),
        ))
        if followed:
            out.append(Finding(
                key=f"brute-success|{user_id}|{_day(first.created)}", rule_id="brute_force", severity=Severity.HIGH,
                score=85,
                title=f"Brute force followed by successful sign-in: {first.who}",
                summary=(f"{count} failed password attempts were followed by a successful sign-in from the same IP "
                         f"({', '.join(sorted({s.ip for s in followed}))}). The account may be compromised."),
                occurred_at=followed[0].created, fields=fields, evidence=_evidence(followed + window_rows),
                recommendation="Treat as a likely compromise: revoke sessions, reset the password, review MFA "
                               "methods and recent activity of the account.",
                links=_user_links(first),
            ))
    return out


FAILED_PASSWORD_CODES = (50126, 50053, 50056)
# 50055 = expired password (i.e. the right old password), 500121 = MFA step reached
PAST_PASSWORD_CODES = PASSWORD_ACCEPTED_CODES + (500121, 50055)


def _iso_week(dt: datetime) -> str:
    year, week, _ = dt.astimezone().isocalendar()
    return f"{year}-W{week:02d}"


def distributed_attack(rc: RuleContext) -> list[Finding]:
    """Low-and-slow password guessing against one account from rotating (residential proxy) IPs.

    Per-IP rules (spray) and per-hour rules (brute force) miss it: every IP tries ~once.
    """
    cfg = rc.cfg("distributed_attack")
    window = timedelta(hours=float(cfg.get("window_hours", 72)))
    min_failures = int(cfg.get("min_failures", 8))
    min_ips = int(cfg.get("min_distinct_ips", 6))
    users = {s.user_id for s in rc.new if s.user_id and s.error_code in FAILED_PASSWORD_CODES}
    if not users:
        return []
    start, end = rc.now - window, rc.now
    targeted = rc.history.candidates(start, end, FAILED_PASSWORD_CODES, "user_id", min_ips)  # cheap pre-filter
    scope: dict[str, str] = {}
    out = []
    for user_id in targeted:
        acct = rc.accounts.get(user_id) if rc.accounts else None
        if acct and acct.mfa_excluded and rc.rule_on("mfa_exempt_watch"):
            continue  # stricter thresholds for password-only accounts in mfa_exempt_watch
        attempts = rc.keep(rc.history.query(start, end, user_id=user_id))
        if not attempts:
            continue
        prior_asns = rc.history.user_asns(user_id, start)
        familiar = prior_asns | {s.asn for s in attempts if s.success and s.asn and s.device_id}  # + networks with his devices
        foreign = [s for s in attempts if not s.success and not rc.trusted(s) and (s.asn not in familiar or not s.asn)]
        failures = [s for s in foreign if s.error_code in FAILED_PASSWORD_CODES]
        ips = {s.ip for s in failures}
        if len(failures) < min_failures or len(ips) < min_ips:
            continue
        scope[user_id] = failures[0].who
        if user_id not in users:
            continue  # nothing new for this account in this run; only counted for campaign scope
        # A correct password from the user's own IP/network (or followed by his completed sign-in from the same
        # IP) is the user answering an MFA prompt, not the attacker - e.g. after a password reset. An unknown
        # ASN alone proves nothing: Entra logs some MFA interrupts first without network details.
        known_ips = rc.history.user_profile(user_id, "ip", start) | {s.ip for s in attempts if s.success and s.device_id}
        known_nets = {_ip_net(ip) for ip in known_ips}

        def own(s: SignIn) -> bool:
            if (s.asn and s.asn in familiar) or (s.ip and (s.ip in known_ips or _ip_net(s.ip) in known_nets)):
                return True
            return bool(rc.history.query(s.created - timedelta(minutes=5), s.created + timedelta(minutes=30),
                                         user_id=user_id, ip=s.ip, success=True, limit=1))

        accepted = [s for s in attempts if s.error_code in PAST_PASSWORD_CODES and not rc.trusted(s)]
        own_prompts = [s for s in accepted if own(s)]
        past_password = [s for s in accepted if s not in own_prompts]
        # A break-in has no company-registered device behind it and comes from a network the user never used
        # (his own phone/laptop on a new network carries its device id, e.g. Samsung on mobile data).
        break_ins = [s for s in attempts if s.success and not rc.trusted(s) and not s.device_id
                     and s.asn not in familiar]
        # Smart Lockout normally refuses only the attacker's unfamiliar addresses (their 50053 are counted above as
        # failed attempts). When the person's own office, network or device is refused as "locked" too, the attack
        # has become their problem: they cannot sign in.
        locked_out = [s for s in attempts if s.error_code == 50053
                      and (rc.trusted(s) or (s.asn and s.asn in familiar) or s.device_id)]
        networks = {s.asn for s in failures if s.asn}
        countries = {s.country for s in failures if s.country}
        flagged = sum(1 for s in failures if s.risk_during in ("medium", "high"))
        tools = Counter(rc.assessor.suspicious_agent(s) for s in failures if rc.assessor.suspicious_agent(s))
        factors = [Factor(40, f"{len(failures)} failed passwords from {len(ips)} IPs, {len(networks)} networks, "
                              f"{len(countries)} countries in {int(window.total_seconds() // 3600)} h")]
        if flagged:
            factors.append(Factor(10, f"Entra ID Protection flagged {flagged} attempt(s) as risky"))
        if tools:
            factors.append(Factor(10, "Attack-tool fingerprints: " + ", ".join(f"{t} x{n}" for t, n in tools.most_common(4))))
        if past_password:
            factors.append(Factor(30, f"Attacker got past the password {len(past_password)} time(s) "
                                      f"(error {', '.join(sorted({str(s.error_code) for s in past_password}))})"))
        if break_ins:
            factors.append(Factor(30, f"{len(break_ins)} successful sign-in(s) from unfamiliar networks without a known "
                                      f"device during the attack"))
        if not past_password and not break_ins:
            factors.append(Factor(-10, "Every attempt failed at the password (Smart Lockout is blocking)"))
        if locked_out:
            factors.append(Factor(30, f"The person is locked out too: {len(locked_out)} sign-in(s) from their own "
                                      f"network or device were refused as locked (50053)"))
        reported = [c for c in rc.history.changes(rc.now - window, rc.now, user_id) if c.kind == REPORT_KIND]
        if reported:
            factors.append(Factor(25, f"The person reported an MFA prompt as not theirs "
                                      f"({reported[-1].created.astimezone():%d.%m. %H:%M}): the password is known"))
        if acct:
            factors.extend(Assessor.account_factors(acct, failures[0]))
        score = max(0, min(100, sum(f.points for f in factors)))
        a = Assessment(score=score, factors=factors, label="", context=acct.context(rc.now) if acct else "")
        first = failures[0]
        apps = Counter(s.app for s in failures)
        fields = {"Account": first.who, "Failed attempts": str(len(failures)), "Distinct IPs": str(len(ips)),
                  "Top countries": ", ".join(f"{c} ({n})" for c, n in Counter(s.country for s in failures).most_common(6)),
                  "Targeted apps": ", ".join(f"{app} ({n})" for app, n in apps.most_common(4))}
        if own_prompts:
            fields["Not counted"] = (f"{len(own_prompts)} MFA prompt(s) from the user's own IP/network "
                                     f"({', '.join(sorted({f'{s.app} from {s.ip}' for s in own_prompts})[:3])}): "
                                     f"the user signing in, not the attacker")
        out.append(_scored(
            a, key=f"dpa|{user_id}|{_iso_week(rc.now)}", rule_id="distributed_attack",
            title=(f"Password attack {'got past the password' if past_password else 'with possible break-in' if break_ins else 'locked the person out' if locked_out else 'from rotating IPs'}: "
                   f"{first.who}"),
            summary=(f"{first.who} is targeted by password guessing from {len(ips)} different IPs in {len(countries)} "
                     f"countries (about one attempt per IP, typical of residential-proxy botnets). "
                     + ("Some attempts used the correct password! " if past_password else "")
                     + ("A sign-in from an unfamiliar network succeeded during the attack! " if break_ins else "")
                     + ("All attempts failed at the password." if not past_password and not break_ins else "")
                     + (f" The person was refused {len(locked_out)} time(s) from their own network or device: the "
                        f"account is locked for them as well." if locked_out else "")),
            occurred_at=min(s.created for s in failures),
            fields=fields,
            evidence=_evidence(break_ins + past_password + locked_out + failures),
            recommendation=("The attacker is guessing the password from rotating proxy IPs. Make sure MFA is enforced for "
                            "this account (ideally phishing-resistant), reset the password if it may be reused or leaked, "
                            "and consider blocking admin tools (Azure AD PowerShell / Azure CLI) for non-admins with "
                            "Conditional Access. Smart Lockout may also lock the user out from unfamiliar locations."),
            links=_user_links(first),
        ))
    if len(scope) > 1:
        for f in out:
            others = sorted(name for uid, name in scope.items() if name != f.fields["Account"])
            f.fields["Same campaign also targets"] = ", ".join(others)
    return out


def mfa_fatigue(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("mfa_fatigue")
    window = timedelta(minutes=float(cfg.get("window_minutes", 60)))
    minimum = int(cfg.get("min_denials", 3))
    denials = [s for s in rc.new if s.error_code == MFA_DENIED_CODE and s.user_id]
    if not denials:
        return []
    out = []
    for s in denials:
        if "fraud" in f"{s.additional_details} {s.failure_reason}".lower():
            out.append(Finding(
                key=f"mfa-fraud|{s.id}", rule_id="mfa_fatigue", severity=Severity.HIGH, score=90,
                title=f"MFA fraud reported by {s.who}",
                summary=f"{s.who} reported an MFA request as fraudulent ({s.additional_details}) - sign-in from "
                        f"{s.ip} ({s.location}) to {s.app}.",
                occurred_at=s.created, fields={"User": s.who, "IP address": s.ip, "Location": s.location},
                evidence=_evidence([s]),
                recommendation="Someone else knows the user's password. Reset it, revoke sessions and block the IP.",
                links=_user_links(s),
            ))
    start, end = rc.span(denials, window)
    for user_id in rc.history.candidates(start, end, (MFA_DENIED_CODE,), "user_id", minimum):
        rows = rc.keep(rc.history.query(start, end, user_id=user_id, codes=(MFA_DENIED_CODE,)))
        count, window_rows = _max_in_window(rows, window)
        if count < minimum:
            continue
        first = window_rows[0]
        matches = sorted({m for s in window_rows for m in s.number_match.split(",") if m})
        out.append(Finding(
            key=f"mfa-fatigue|{user_id}|{_day(first.created)}", rule_id="mfa_fatigue", severity=Severity.HIGH, score=75,
            title=f"Repeated MFA denials for {first.who}",
            summary=(f"{count} MFA requests denied or unanswered within {int(window.total_seconds() // 60)} minutes "
                     f"from {', '.join(sorted({s.ip for s in window_rows}))}. Typical of MFA fatigue / push bombing."
                     + (" The user DENIED the request in the Authenticator (number match)."
                        if any("Deny" in m for m in matches) else "")),
            occurred_at=first.created,
            fields={"User": first.who, "Denials": str(count),
                    "Locations": ", ".join(sorted({s.location for s in window_rows})),
                    **({"Number match": ", ".join(matches)} if matches else {})},
            evidence=_evidence(window_rows),
            recommendation="Contact the user. If they did not try to sign in, their password is known to an attacker: "
                           "reset it, revoke sessions, and enable number matching for push notifications.",
            links=_user_links(first),
        ))
    return out


def _previous_position(rc: RuleContext, s: SignIn, lookback: timedelta, interactive_only: bool,
                       ignore_phones: bool) -> SignIn | None:
    """The previous located sign-in that says where the person was: sign-ins from virtual desktops and from phones
    on mobile data are passed over (the one before them counts), so that such a sign-in right before an
    attacker's does not hide the jump."""
    prev = rc.history.previous_geo_success(s.user_id, s.created, s.created - lookback, s.id, interactive_only)

    def no_position(r: SignIn) -> bool:
        return rc.on_virtual_host(r) or (ignore_phones and rc.phone_on_own_network(r))

    if prev is None or not no_position(prev):
        return prev
    rows = rc.history.query(s.created - lookback, s.created, user_id=s.user_id, success=True, interactive_only=interactive_only)
    for r in reversed(rows):
        if r.id != s.id and r.lat is not None and r.lon is not None and not no_position(r):
            return r
    return None


def impossible_travel(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("impossible_travel")
    min_km = float(cfg.get("min_distance_km", 500))
    max_kmh = float(cfg.get("max_speed_kmh", 900))
    lookback = timedelta(hours=float(cfg.get("lookback_hours", 24)))
    same_device_ok = bool(cfg.get("ignore_same_device", True))
    same_country_ok = bool(cfg.get("ignore_same_country", True))
    interactive_only = not bool(cfg.get("include_non_interactive", False))
    ignore_phones = bool(cfg.get("ignore_phone_networks", True))
    out = []
    for s in sorted(rc.new, key=lambda x: x.created):
        if not (s.success and s.user_id and s.lat is not None) or (interactive_only and not s.interactive):
            continue
        if not s.city or rc.trusted(s):  # country-level geolocation only, or corporate/VPN egress
            continue
        if rc.on_virtual_host(s):  # a virtual desktop in a data centre: its place is not the person's
            continue
        # A phone on mobile data is located at its carrier's gateway: not an end of a journey. (A sign-in through a
        # VPN or hosting network stays one - 30-day replay: ignoring those would have dropped both High alerts.)
        if ignore_phones and rc.phone_on_own_network(s):
            continue
        prev = _previous_position(rc, s, lookback, interactive_only, ignore_phones)
        if not prev or prev.ip == s.ip or prev.ip in rc.ignore_ips or not prev.city or rc.trusted(prev):
            continue
        if same_device_ok and s.device_id and s.device_id == prev.device_id:
            continue
        if same_country_ok and s.country and s.country == prev.country:
            continue
        km = haversine_km(prev.lat, prev.lon, s.lat, s.lon)
        hours = max((s.created - prev.created).total_seconds() / 3600, 1 / 60)
        speed = km / hours
        if km < min_km or speed < max_kmh:
            continue
        a = rc.assessor.assess(s, 45, f"{km:,.0f} km from the previous sign-in in {hours * 60:,.0f} min")
        pair = "-".join(sorted({prev.country or "?", s.country or "?"}))
        out.append(_scored(
            a, key=f"travel|{s.user_id}|{_day(s.created)}|{pair}", rule_id="impossible_travel",
            title=f"Impossible travel: {s.who}" + (f" ({a.label})" if a.label else ""),
            summary=(f"{s.who} signed in from {prev.location} and {km:,.0f} km away from {s.location} "
                     f"{hours * 60:,.0f} minutes later (~{speed:,.0f} km/h). Assessment: {a.top_reasons()}."),
            occurred_at=s.created,
            fields={"User": s.who, "From": f"{prev.location} ({prev.ip})", "To": f"{s.location} ({s.ip})",
                    "Distance": f"{km:,.0f} km", "Time between": f"{hours * 60:,.0f} min",
                    "Implied speed": f"{speed:,.0f} km/h"},
            evidence=_evidence([prev, s]),
            recommendation="Check with the user whether they use a VPN / travelled. If not, revoke sessions and "
                           "reset the password.",
            links=_user_links(s),
        ))
    return out


def new_country(rc: RuleContext) -> list[Finding]:
    cfg = rc.cfg("new_country")
    min_baseline = int(cfg.get("min_baseline_signins", 5))
    allowed = {c.strip().upper() for c in cfg.get("allowed_countries", []) if c}
    interactive_only = not bool(cfg.get("include_non_interactive", False))
    out, seen = [], set()
    for s in sorted(rc.new, key=lambda x: x.created):
        if not (s.success and s.user_id and s.country) or (interactive_only and not s.interactive):
            continue
        if (s.user_id, s.country) in seen or rc.trusted(s) or rc.on_virtual_host(s):
            continue
        if allowed and s.country not in allowed:
            base, why = 55, f"{s.country} is not on the list of allowed countries"
        else:
            baseline = rc.history.user_countries(s.user_id, s.created, interactive_only)
            if sum(baseline.values()) < min_baseline or s.country in baseline:
                continue
            usual = ", ".join(c for c, _ in baseline.most_common(5))
            base, why = 35, f"First sign-in from {s.country} (usually {usual})"
        seen.add((s.user_id, s.country))
        extra = []
        other = rc.assessor.vpn_switch(s)
        if other:
            extra.append(Factor(-15, f"Same device also active from {other.country} within 60 min (VPN/proxy switch)"))
        a = rc.assessor.assess(s, base, why, extra)
        out.append(_scored(
            a, key=f"country|{s.user_id}|{s.country}", rule_id="new_country",
            title=f"Sign-in from new country ({s.country}): {s.who}" + (f" - {a.label}" if a.label else ""),
            summary=f"Successful sign-in for {s.who} from {s.location} ({s.ip}) to {s.app}. {why}. "
                    f"Assessment: {a.top_reasons()}.",
            occurred_at=s.created,
            fields={"User": s.who, "Country": s.country, "IP address": s.ip, "Application": s.app,
                    "Classification": a.label or "-"},
            evidence=_evidence([s] + ([other] if other else [])),
            recommendation="Confirm the user is travelling or using a VPN. If not, revoke sessions and reset the password.",
            links=_user_links(s),
        ))
    return out


def new_country_background(rc: RuleContext) -> list[Finding]:
    """Background activity (no sign-in by hand) from a country the account was not seen in: a phone or laptop
    travelling - or a sign-in token of the account in use somewhere else. new_country only sees sign-ins by hand."""
    from . import presence

    cfg = rc.cfg("new_country_background")
    min_baseline = int(cfg.get("min_baseline_signins", 5))
    groups: dict[tuple[str, str], list[SignIn]] = defaultdict(list)
    for s in rc.new:
        if s.success and not s.interactive and s.user_id and s.country and not rc.trusted(s) and not rc.on_virtual_host(s) \
                and presence.device_class(s) != presence.SERVICE:
            groups[(s.user_id, s.country)].append(s)
    out = []
    known: dict[str, tuple[Counter, set[str]]] = {}
    for (user_id, country), items in groups.items():
        first = min(items, key=lambda x: x.created)
        if user_id not in known:
            before = first.created - timedelta(hours=1)
            seen = {x.country for x, _b, _e, _n in rc.history.activity(rc.now - timedelta(days=30), before, user_id) if x.country}
            known[user_id] = (rc.history.user_countries(user_id, before, False), seen)
        baseline, active_in = known[user_id]
        if sum(baseline.values()) < min_baseline or country in baseline or country in active_in:
            continue
        if country in rc.history.user_countries(user_id, rc.now, True):
            continue  # signed in by hand from there as well: that is new_country's alert
        usual = ", ".join(c for c, _ in baseline.most_common(5))
        why = f"First activity from {country} (usually {usual}), in the background only"
        s, a = _best([(x, rc.assessor.assess(x, 25, why, floor=25)) for x in items])
        devices = sorted({x.device_name or " ".join(p for p in (x.os, x.browser) if p) or "unidentified device" for x in items})
        out.append(_scored(
            a, key=f"country-bg|{user_id}|{country}", rule_id="new_country_background",
            title=f"Background activity from new country ({country}): {s.who}" + (f" - {a.label}" if a.label else ""),
            summary=(f"{len(items)} background sign-in(s) of {s.who} from {s.location} on {', '.join(devices)[:80]}, "
                     f"without a sign-in by hand there. {why}. Assessment: {a.top_reasons()}."),
            occurred_at=first.created,
            fields={"User": s.who, "Country": country, "Usual countries": usual, "Device": ", ".join(devices)[:120],
                    "IP address": s.ip, "Classification": a.label or "-"},
            evidence=_evidence(sorted(items, key=lambda x: x.created)[:25]),
            recommendation=("Most often a phone or laptop travelling with its owner. Check that the device is one of the "
                            "person's own (registered long ago, their usual model); if it is not, or the person is not "
                            "travelling, revoke the sessions and reset the password."),
            links=_user_links(s),
        ))
    return out


def legacy_auth(rc: RuleContext) -> list[Finding]:
    allowed = UserMatcher(rc.cfg("legacy_auth").get("allowed_users", []))
    groups: dict[tuple, list[SignIn]] = defaultdict(list)
    for s in rc.new:
        if not s.success or s.client_app.lower() not in LEGACY_CLIENT_APPS or s.upn in allowed:
            continue
        pin = rc.pin_for(s.upn)
        if pin is not None and (s.ip in pin[1] or rc.rule_on("pinned_accounts")):
            continue  # expected from its pinned IP; from anywhere else the pinned_accounts rule reports it
        groups[(s.user_id or s.who, s.client_app, _day(s.created))].append(s)
    out = []
    for (user, client, day), items in groups.items():
        s, a = _best([(x, rc.assessor.assess(x, 45, f"Legacy protocol {client} (cannot enforce MFA)", floor=35))
                      for x in items])
        out.append(_scored(
            a, key=f"legacy|{user}|{client}|{day}", rule_id="legacy_auth",
            title=f"Legacy authentication ({client}): {s.who}",
            summary=(f"{len(items)} successful sign-in(s) for {s.who} using {client}, which cannot enforce MFA, "
                     f"from {', '.join(sorted({x.ip for x in items}))}."),
            occurred_at=min(x.created for x in items),
            fields={"User": s.who, "Client app": client, "Applications": ", ".join(sorted({x.app for x in items}))},
            evidence=_evidence(items),
            recommendation="Block legacy authentication with Conditional Access and move the client to modern auth "
                           "(or pin the account to its IP in pinned_accounts if it is an expected device).",
            links=_user_links(s),
        ))
    return out


def pinned_accounts(rc: RuleContext) -> list[Finding]:
    """Service accounts (scanners, printers, ...) that may only sign in from specific IPs."""
    groups: dict[tuple, list[SignIn]] = defaultdict(list)
    allowed_by_user: dict[str, list[str]] = {}
    for s in rc.new:
        if not s.success:
            continue
        pin = rc.pin_for(s.upn)
        if pin is None or s.ip in pin[1]:
            continue
        allowed_by_user[s.upn] = pin[0]
        groups[(s.user_id or s.who, s.ip, _day(s.created))].append(s)
    out = []
    for (user, ip, day), items in groups.items():
        first = items[0]
        allowed = ", ".join(allowed_by_user[first.upn]) or "(none)"
        clients = ", ".join(sorted({s.client_app or "-" for s in items}))
        out.append(Finding(
            key=f"pinned|{user}|{ip}|{day}", rule_id="pinned_accounts", severity=Severity.HIGH, score=85,
            title=f"Pinned account used from unexpected IP: {first.who}",
            summary=(f"{first.who} signed in {len(items)} time(s) from {ip} ({first.location}) via {clients} "
                     f"to {', '.join(sorted({s.app for s in items}))}. It is only allowed from {allowed}."),
            occurred_at=min(s.created for s in items),
            fields={"Account": first.who, "Unexpected IP": f"{ip} ({first.location})", "Allowed IPs": allowed,
                    "Client app": clients},
            evidence=_evidence(items),
            recommendation=("If this is not a known new location of the device, the account's credentials are "
                            "being used elsewhere: reset the password, revoke sessions and check what was sent."),
            links=_user_links(first) + [("Look up IP (AbuseIPDB)", f"https://www.abuseipdb.com/check/{ip}")],
        ))
    return out


def device_code(rc: RuleContext) -> list[Finding]:
    allowed = UserMatcher(rc.cfg("device_code").get("allowed_users", []))
    groups: dict[tuple, list[SignIn]] = defaultdict(list)
    for s in rc.new:
        # Only the authentication itself; token refreshes of a device-code session carry
        # originalTransferMethod=deviceCodeFlow too (e.g. Teams Rooms) and would be pure noise.
        protocol = s.auth_protocol.lower()
        if protocol == "ropc" and s.client_app.lower() in LEGACY_CLIENT_APPS:
            continue  # legacy auth is logged as ROPC; covered by legacy_auth / pinned_accounts
        if protocol in ("devicecode", "ropc") and s.success and s.upn not in allowed:
            groups[(s.user_id or s.who, protocol, _day(s.created))].append(s)
    out = []
    for (user, protocol, day), items in groups.items():
        what = "Device code" if protocol == "devicecode" else "ROPC (password-only)"
        s, a = _best([(x, rc.assessor.assess(x, 40, f"{what} sign-in", floor=30)) for x in items])
        out.append(_scored(
            a, key=f"devicecode|{user}|{day}" if protocol == "devicecode" else f"ropc|{user}|{day}",
            rule_id="device_code",
            title=f"{what} sign-in: {s.who}",
            summary=(f"{s.who} completed {len(items)} {what.lower()} sign-in(s) to "
                     f"{', '.join(sorted({x.app for x in items}))} from {', '.join(sorted({x.location for x in items}))}. "
                     + ("Device code phishing is a common way to steal tokens." if protocol == "devicecode"
                        else "ROPC bypasses MFA and is used by password-spray tools.")),
            occurred_at=min(x.created for x in items),
            fields={"User": s.who, "IP addresses": ", ".join(sorted({x.ip for x in items}))},
            evidence=_evidence(items),
            recommendation=("Confirm the user started this sign-in themselves (e.g. az login --use-device-code). "
                            "Consider blocking device code flow with Conditional Access authentication flows."
                            if protocol == "devicecode" else
                            "Find the application using ROPC and move it to a modern flow; block it otherwise."),
            links=_user_links(s),
        ))
    return out


def session_theft(rc: RuleContext) -> list[Finding]:
    """The same sign-in session (ESTS cookie / token) used from another country on another device."""
    cfg = rc.cfg("session_theft")
    lookback = timedelta(hours=float(cfg.get("lookback_hours", 24)))
    max_kmh = float(rc.cfg("impossible_travel").get("max_speed_kmh", 900))
    # Per session keep the closest-in-time cross-country/cross-device pair: it decides "simultaneous" vs "travel".
    pairs: dict[str, tuple[float, SignIn, SignIn]] = {}
    for s in rc.new:
        # Microsoft back-end services (e.g. 'Olympus') use the session on the user's behalf: never a second device
        if not (s.success and s.session_id and s.user_id and s.country) or rc.trusted(s) or s.ms_backend:
            continue
        others = [o for o in rc.history.query(s.created - lookback, s.created + timedelta(minutes=5),
                                              session_id=s.session_id, success=True)
                  if o.id != s.id and o.country and o.country != s.country and not rc.trusted(o)
                  and not o.ms_backend and (o.device_id or "") != (s.device_id or "")]
        if not others:
            continue
        o = min(others, key=lambda x: abs((x.created - s.created).total_seconds()))
        gap = abs((o.created - s.created).total_seconds())
        if s.session_id not in pairs or gap < pairs[s.session_id][0]:
            pairs[s.session_id] = (gap, s, o)
    out = []
    for _gap, s, o in pairs.values():
        # Judge the odd one out: the side without device identity (a replayed cookie/token has none).
        suspect, peer = (o, s) if (s.device_id and not o.device_id) else (s, o)
        peer_dev = peer.device_name or ("a registered device" if peer.device_id else "no device identity")
        extra = [Factor(0, f"Same session also used from {peer.location} ({peer.ip}, {peer_dev})")]
        if suspect.token_protection == "bound":
            extra.append(Factor(-25, "Session token is device-bound (token protection): it cannot be replayed on "
                                     "another device"))
        minutes = abs((s.created - o.created).total_seconds()) / 60
        platform_a, platform_b = os_family(suspect.os), os_family(peer.os)
        same_platform = bool(platform_a) and platform_a == platform_b
        if same_platform:
            # e.g. one iPhone: an app without device info going through a VPN / roaming egress
            extra.append(Factor(-25, f"Same platform on both sides ({platform_a}): likely one device on two network paths"))
            if minutes <= 10:
                extra.append(Factor(-20, f"Requests interleaved within {minutes:,.0f} min (VPN / split tunnel / roaming)"))
        elif platform_a and platform_b:
            extra.append(Factor(10, f"Different platforms ({platform_a} vs {platform_b})"))
        if s.lat is not None and o.lat is not None:
            km = haversine_km(s.lat, s.lon, o.lat, o.lon)
            speed = km / max(minutes / 60, 1 / 60)
            if speed > max_kmh:
                if not same_platform:
                    extra.append(Factor(15, f"Used {km:,.0f} km apart within {minutes:,.0f} min (simultaneous use)"))
            else:
                # no "two places at once": remaining risk comes from network/device (a VPS replay still scores high)
                extra.append(Factor(-30, f"Travel between both places is plausible ({km:,.0f} km in {minutes / 60:,.1f} h)"))
        a = rc.assessor.assess(suspect, 45, "Session reused from a different country on a different device", extra)
        out.append(_scored(
            a, key=f"session|{s.user_id}|{s.session_id}", rule_id="session_theft",
            title=f"Possible session token theft: {s.who}",
            summary=(f"Session of {s.who} was used from {o.location} ({o.ip}) and {s.location} ({s.ip}), "
                     f"{minutes:,.0f} min apart, on different devices. Typical of stolen session cookies / tokens "
                     f"(AiTM phishing, infostealer). Assessment: {a.top_reasons()}."),
            occurred_at=min(s.created, o.created),
            fields={"User": s.who, "Session ID": s.session_id, "First": f"{o.location} ({o.ip})",
                    "Second": f"{s.location} ({s.ip})", "Judged side": f"{suspect.location} ({suspect.ip})"},
            evidence=_evidence([o, s]),
            recommendation="Revoke the user's sessions (Revoke-MgUserSignInSession), reset the password and check "
                           "mailbox rules, MFA methods and registered devices for persistence.",
            links=_user_links(s),
        ))
    return out


def password_not_completed(rc: RuleContext) -> list[Finding]:
    """Password accepted but MFA/Conditional Access stopped the sign-in, in an unfamiliar context."""
    cfg = rc.cfg("password_not_completed")
    settle = timedelta(minutes=float(cfg.get("settle_minutes", 15)))
    window = timedelta(hours=float(cfg.get("window_hours", 3)))
    # Re-evaluate a settled window every run (dedup by key): the user may still finish MFA a bit later.
    candidates = rc.keep(rc.history.query(rc.now - window, rc.now - settle, codes=PASSWORD_ACCEPTED_CODES,
                                          interactive_only=True))
    groups: dict[tuple, list[tuple[SignIn, Assessment]]] = defaultdict(list)
    for s in candidates:
        if not s.user_id or rc.trusted(s) or (s.auth_methods and not s.password_ok):
            continue
        if rc.history.query(s.created - timedelta(minutes=5), s.created + timedelta(minutes=30),
                            user_id=s.user_id, ip=s.ip, success=True, limit=1):
            continue  # the user completed the sign-in from the same place: ordinary MFA prompt
        familiar_net = s.asn in rc.history.user_asns(s.user_id, s.created) if s.asn else False
        # countries of ALL the user's successful sign-ins (the phone's background sign-ins on holiday count)
        familiar_cc = s.country in (set(rc.history.user_countries(s.user_id, s.created, True))
                                    | rc.history.user_profile(s.user_id, "country", s.created))
        if familiar_net and familiar_cc:
            continue
        extra = []
        # successful sign-ins of the user from the same IP - also AFTER the attempt (the phone keeps using the holiday
        # Wi-Fi): that IP is the user's location. An attacker would need successes from there, which other rules flag.
        known_ips = rc.history.user_profile(s.user_id, "ip", rc.now)
        if s.ip and (s.ip in known_ips or _ip_net(s.ip) in {_ip_net(i) for i in known_ips}):
            extra.append(Factor(-30, "The user's own devices sign in successfully from this IP "
                                     "(the user's location, e.g. holiday Wi-Fi)"))
        if s.error_code == 53003:
            extra.append(Factor(10, "Blocked by Conditional Access after the password was accepted"))
        if s.untrusted_networks:
            extra.append(Factor(15, "Matched named location: " + ", ".join(s.untrusted_networks)))
        if not familiar_cc:
            extra.append(Factor(10, f"Country {s.country or '?'} not seen for this user"))
        a = rc.assessor.assess(s, 35, f"Correct password, sign-in stopped ({s.error_code}: {s.failure_reason[:60]})", extra)
        groups[(s.user_id, _day(s.created))].append((s, a))
    out = []
    for (user, day), items in groups.items():
        s, a = _best(items)
        signins = [x for x, _ in items]
        out.append(_scored(
            a, key=f"pwok|{user}|{day}", rule_id="password_not_completed",
            title=f"Correct password used, sign-in not completed: {s.who}",
            summary=(f"{len(signins)} sign-in attempt(s) for {s.who} from {', '.join(sorted({x.location for x in signins}))} "
                     f"passed the password check but were stopped by MFA / Conditional Access and never completed. "
                     f"Someone else may know the password. Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in signins),
            fields={"User": s.who, "IP addresses": ", ".join(sorted({x.ip for x in signins})),
                    "Errors": ", ".join(sorted({str(x.error_code) for x in signins}))},
            evidence=_evidence(signins),
            recommendation="Ask the user whether they tried to sign in. If not, reset the password (it is known to "
                           "someone else) and review recent MFA prompts.",
            links=_user_links(s),
        ))
    return out


def attack_tooling(rc: RuleContext) -> list[Finding]:
    """Interactive sign-ins sent by HTTP libraries / attack tools instead of a browser or Office app."""
    minimum = int(rc.cfg("attack_tooling").get("min_failures", 3))
    successes: dict[tuple, list[SignIn]] = defaultdict(list)
    failures: dict[tuple, list[SignIn]] = defaultdict(list)
    for s in rc.new:
        if not s.interactive or s.client_app.lower() in LEGACY_CLIENT_APPS:
            continue  # SaaS integrations refresh tokens with library agents; legacy auth shows up as BAV2ROPC
        agent = rc.assessor.suspicious_agent(s)
        if not agent:
            continue
        if s.success:
            successes[(s.user_id or s.who, _day(s.created))].append(s)
        elif s.ip:
            failures[(s.ip, _day(s.created))].append(s)
    out = []
    for (user, day), items in successes.items():
        s, a = _best([(x, rc.assessor.assess(x, 40, "Successful interactive sign-in by a script/tool")) for x in items])
        out.append(_scored(
            a, key=f"tool-ok|{user}|{day}", rule_id="attack_tooling",
            title=f"Sign-in by attack tool / script succeeded: {s.who}",
            summary=(f"{len(items)} interactive sign-in(s) for {s.who} succeeded with user agent "
                     f"'{s.user_agent[:80]}' from {s.location} ({s.ip}). Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in items),
            fields={"User": s.who, "User agent": s.user_agent[:200]},
            evidence=_evidence(items),
            recommendation="Unless this is a known automation account, treat as compromised: revoke sessions and "
                           "reset the password.",
            links=_user_links(s),
        ))
    for (ip, day), items in failures.items():
        if len(items) < minimum:
            continue
        users = {x.user_id or x.upn for x in items}
        s = items[0]
        a = rc.assessor.assess(s, 30, "Failed sign-ins sent by a script/tool",
                               [Factor(min(25, 5 * len(users)), f"{len(items)} attempts on {len(users)} account(s)")])
        out.append(_scored(
            a, key=f"tool-fail|{ip}|{day}", rule_id="attack_tooling",
            title=f"Attack tool sign-in attempts from {ip} ({len(users)} account(s))",
            summary=(f"{len(items)} failed interactive sign-ins from {ip} ({s.location}) with tool user agents "
                     f"({', '.join(sorted({rc.assessor.suspicious_agent(x) or '?' for x in items}))}) against "
                     f"{len(users)} account(s). Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in items),
            fields={"IP address": ip, "Accounts": ", ".join(sorted({x.who for x in items}))[:300]},
            evidence=_evidence(items),
            recommendation="Block the IP, make sure the targeted accounts use MFA and look for successful sign-ins "
                           "from the same IP.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL), ("Look up IP (AbuseIPDB)", f"https://www.abuseipdb.com/check/{ip}")],
        ))
    return out


def new_shared_ip(rc: RuleContext) -> list[Finding]:
    """A brand-new IP from which several accounts sign in (AiTM phishing proxy, mass compromise)."""
    cfg = rc.cfg("new_shared_ip")
    min_accounts = int(cfg.get("min_accounts", 2))
    new_for = timedelta(hours=float(cfg.get("new_ip_hours", 24)))
    by_ip: dict[str, list[SignIn]] = defaultdict(list)
    for s in rc.new:
        if s.success and s.interactive and s.ip and not rc.trusted(s):
            by_ip[s.ip].append(s)
    out = []
    for ip, items in by_ip.items():
        first_seen = rc.history.ip_first_seen(ip)
        if first_seen and first_seen < rc.now - new_for:
            continue  # established IP (office, home router, ...)
        rows = rc.keep(rc.history.query(rc.now - new_for, rc.now, ip=ip, success=True, interactive_only=True))
        users = {x.user_id for x in rows if x.user_id}
        if len(users) < min_accounts:
            continue
        s, a = _best([(x, rc.assessor.assess(x, 40, "New IP address shared by several accounts",
                                             [Factor(min(20, 5 * len(users)), f"{len(users)} accounts within "
                                                     f"{int(new_for.total_seconds() // 3600)} h")]))
                      for x in items])
        out.append(_scored(
            a, key=f"sharedip|{ip}|{_day(s.created)}", rule_id="new_shared_ip",
            title=f"New IP used by {len(users)} accounts: {ip}",
            summary=(f"{len(users)} accounts signed in from {ip} ({s.location}), an IP never seen before. "
                     f"Phishing proxies (AiTM) show up like this. Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in rows),
            fields={"IP address": ip, "Accounts": ", ".join(sorted({x.who for x in rows}))[:300]},
            evidence=_evidence(rows),
            recommendation="If the users are not together (event, hotel, new office link), check each account for "
                           "session theft: revoke sessions and reset passwords.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL), ("Look up IP (AbuseIPDB)", f"https://www.abuseipdb.com/check/{ip}")],
        ))
    return out


def sensitive_app(rc: RuleContext) -> list[Finding]:
    """First use of admin / recon tooling, and device registrations, in a risky context."""
    groups: dict[tuple, list[tuple[SignIn, Assessment]]] = defaultdict(list)
    for s in rc.new:
        if not (s.success and s.interactive and s.user_id):
            continue
        if s.app_id in netintel.SENSITIVE_APPS:
            if rc.history.user_used_app(s.user_id, s.app_id, s.created):
                continue
            what = netintel.SENSITIVE_APPS[s.app_id]
            a = rc.assessor.assess(s, 30, f"First use of {what} by this user (admin / recon tool)")
        elif s.resource_id == netintel.DEVICE_REGISTRATION_RESOURCE:
            what = "Device registration"
            a = rc.assessor.assess(s, 35, "Registered/joined a device to Entra ID (persistence after phishing)")
        else:
            continue
        groups[(s.user_id, what, _day(s.created))].append((s, a))
    out = []
    for (user, what, day), items in groups.items():
        s, a = _best(items)
        out.append(_scored(
            a, key=f"sensitive|{user}|{what}|{day}", rule_id="sensitive_app",
            title=f"{what}: {s.who}" + (f" ({a.label})" if a.label else ""),
            summary=(f"{s.who}: {what.lower()} from {s.location} ({s.ip}). Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x, _ in items),
            fields={"User": s.who, "Application": s.app, "Resource": s.resource},
            evidence=_evidence([x for x, _ in items]),
            recommendation="Confirm with the user. Attackers use these tools for reconnaissance and register devices "
                           "to keep access after a phishing attack.",
            links=_user_links(s),
        ))
    return out


def mfa_exempt_watch(rc: RuleContext) -> list[Finding]:
    """Accounts excluded from MFA: the password alone gives access, so they must stick to their learned pattern."""
    if not rc.accounts:
        return []
    cfg = rc.cfg("mfa_exempt_watch")
    min_failures = int(cfg.get("min_failures", 3))
    window = timedelta(hours=float(cfg.get("window_hours", 24)))
    deviations: dict[tuple, list[tuple[SignIn, Assessment]]] = defaultdict(list)
    pw_ok: dict[tuple, list[tuple[SignIn, Assessment]]] = defaultdict(list)
    attacked: set[str] = set()
    h = rc.history
    for s in rc.new:
        acct = rc.accounts.get(s.user_id)
        if not acct or not acct.mfa_excluded:
            continue
        before = s.created
        known_asn = h.user_asns(s.user_id, before)
        if s.success:
            if s.user_id in rc.learning:
                continue  # pattern still being learned (seeding): deviations would be guesses
            extra = _pattern_deviations(rc, s, before)
            if not extra:
                continue  # behaves exactly like in the last 30 days
            a = rc.assessor.assess(s, 35, "Successful password-only sign-in to an account excluded from MFA", extra)
            deviations[(s.user_id, _day(s.created))].append((s, a))
        elif s.error_code in PAST_PASSWORD_CODES and not rc.trusted(s) and (not s.asn or s.asn not in known_asn):
            a = rc.assessor.assess(s, 60, f"Correct password for an MFA-excluded account, then stopped "
                                          f"({s.error_code}: {s.failure_reason[:50]})")
            pw_ok[(s.user_id, _day(s.created))].append((s, a))
        elif s.error_code in FAILED_PASSWORD_CODES:
            attacked.add(s.user_id)
    out = []
    for (user, day), items in deviations.items():
        s, a = _best(items)
        signins = [x for x, _ in items]
        out.append(_scored(
            a, key=f"nomfa|{user}|{day}", rule_id="mfa_exempt_watch",
            title=f"MFA-excluded account used outside its pattern: {s.who}",
            summary=(f"{s.who} can sign in with a password only and just did so in a way it never did in the last 30 days: "
                     f"{'; '.join(f.text for f in _deviation_marker(a))}. "
                     f"Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x in signins),
            fields={"Account": s.who, "IP addresses": ", ".join(sorted({x.ip for x in signins})),
                    "Applications": ", ".join(sorted({x.app for x in signins})),
                    "Client apps": ", ".join(sorted({x.client_app or '-' for x in signins}))},
            evidence=_evidence(signins),
            recommendation=("If this was not a planned change of the device/integration using this account, treat the "
                            "password as compromised: reset it, revoke sessions and review what the account accessed. "
                            "Better: replace the MFA exclusion by a managed identity, certificate or app-specific restriction."),
            links=_user_links(s),
        ))
    for (user, day), items in pw_ok.items():
        s, a = _best(items)
        out.append(_scored(
            a, key=f"nomfa-pwok|{user}|{day}", rule_id="mfa_exempt_watch",
            title=f"Correct password for MFA-excluded account from unfamiliar network: {s.who}",
            summary=(f"Someone used the correct password of {s.who} from {s.location} ({s.ip}); only "
                     f"Conditional Access stopped it. Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x, _ in items), fields={"Account": s.who},
            evidence=_evidence([x for x, _ in items]),
            recommendation="The password is known to someone else: reset it immediately and check recent sign-ins.",
            links=_user_links(s),
        ))
    for user_id in attacked:
        rows = rc.keep(h.query(rc.now - window, rc.now, user_id=user_id, codes=FAILED_PASSWORD_CODES))
        known = h.user_asns(user_id, rc.now - window)
        foreign = [x for x in rows if not rc.trusted(x) and (not x.asn or x.asn not in known)]
        if len(foreign) < min_failures:
            continue
        first = foreign[0]
        ips = {x.ip for x in foreign}
        a = rc.assessor.assess(first, 40, "Password attack on an account that has no MFA",
                               [Factor(min(25, 3 * len(foreign)), f"{len(foreign)} failed passwords from {len(ips)} "
                                                                  f"unfamiliar IP(s) in {int(window.total_seconds() // 3600)} h")])
        out.append(_scored(
            a, key=f"nomfa-attack|{user_id}|{_day(rc.now)}", rule_id="mfa_exempt_watch",
            title=f"Password attack on MFA-excluded account: {first.who}",
            summary=(f"{len(foreign)} failed password attempts against {first.who}, which can sign in without MFA, "
                     f"from {', '.join(sorted({x.location for x in foreign}))[:150]}. One correct guess would be enough."),
            occurred_at=min(x.created for x in foreign), fields={"Account": first.who, "Distinct IPs": str(len(ips))},
            evidence=_evidence(foreign),
            recommendation="Make sure the password is long and unique; restrict the account to its known networks "
                           "with Conditional Access (named location) or remove the MFA exclusion.",
            links=_user_links(first),
        ))
    return out


DEVIATION_PREFIXES = ("New IP", "New network", "New application", "New protocol", "New country", "No successful sign-in")


def _deviation_marker(a: Assessment) -> list[Factor]:
    return [f for f in a.factors if f.text.startswith(DEVIATION_PREFIXES)]


def _pattern_deviations(rc: RuleContext, s: SignIn, before: datetime) -> list[Factor]:
    """How a sign-in differs from the account's own 30-day pattern (empty list = matches the pattern)."""
    h = rc.history
    ips = h.user_profile(s.user_id, "ip", before)
    if not ips and not h.user_profile(s.user_id, "asn", before):
        return [Factor(20, "No successful sign-in in the last 30 days (dormant account or new use)")]
    out = []
    pin = rc.pin_for(s.upn)
    if s.ip and s.ip not in ips and not (pin and s.ip in pin[1]):
        if s.asn and str(s.asn) in h.user_profile(s.user_id, "asn", before):
            out.append(Factor(5, f"New IP {s.ip} in a network this account already uses"))
        else:
            out.append(Factor(20, f"New IP {s.ip} in a new network for this account ({rc.assessor.asn_label(s.asn)})"))
    if s.app and s.app not in h.user_profile(s.user_id, "app", before):
        out.append(Factor(10, f"New application for this account: {s.app}"))
    proto = (s.client_app or "").lower()
    if proto and proto not in h.user_profile(s.user_id, "proto", before):
        out.append(Factor(15, f"New protocol/client for this account: {s.client_app}"))
    if s.country and s.country not in h.user_profile(s.user_id, "country", before):
        out.append(Factor(20, f"New country for this account: {s.country}"))
    return out


DISABLED_CODE = 50057  # "the user account is disabled"


def account_state(rc: RuleContext) -> list[Finding]:
    """Disabled accounts must not sign in; break-glass accounts should never be used (or even tried)."""
    out = []
    tried: dict[tuple, list[SignIn]] = defaultdict(list)
    used: dict[str, tuple[bool, list[SignIn]]] = {}
    refused: set[str] = set()  # disabled accounts with a refused sign-in in this run
    for s in rc.new:
        acct = rc.accounts.get(s.user_id) if rc.accounts else None
        breakglass = s.upn in rc.breakglass or bool(acct and acct.breakglass)
        if not s.success:
            if breakglass and s.error_code:
                tried[(s.user_id or s.who, _day(s.created))].append(s)
            elif s.error_code == DISABLED_CODE and s.user_id:
                refused.add(s.user_id)
            continue
        disabled = bool(acct and not acct.enabled and rc.accounts.synced_at and s.created > rc.accounts.synced_at)
        if not (disabled or breakglass):
            continue
        # break-glass: one reminder per week (a lingering session refreshes daily), disabled: per day
        key = (f"acctstate|bg|{s.user_id}|{_iso_week(s.created)}" if breakglass
               else f"acctstate|dis|{s.user_id}|{_day(s.created)}")
        used.setdefault(key, (breakglass, []))[1].append(s)
    for key, (breakglass, items) in used.items():
        s, a = _best([(x, rc.assessor.assess(x, 80 if breakglass else 60,
                                             "Emergency access account signed in" if breakglass
                                             else "Successful sign-in after the account was disabled (token/session still valid?)"))
                      for x in items])
        background = all(not x.interactive for x in items)
        what = "Break-glass account used" if breakglass else "Disabled account signed in"
        out.append(_scored(
            a, key=key, rule_id="account_state",
            title=f"{what}: {s.who}",
            summary=(f"{s.who}: {len(items)} successful sign-in(s) from {', '.join(sorted({x.location for x in items}))[:100]} "
                     f"to {', '.join(sorted({x.app for x in items}))[:80]}"
                     + (" in the background (a session/refresh token of this account is alive on some device)"
                        if background else "") + ". "
                     + ("Emergency accounts should only be used in a documented emergency."
                        if breakglass else "The account is disabled; revoke its sessions and refresh tokens.")),
            occurred_at=min(x.created for x in items), fields={"Account": s.who}, evidence=_evidence(items),
            recommendation=(("Revoke the account's sessions and remove it from the device it is signed in on; a "
                             "break-glass account must not keep a session. " if background else "")
                            + "Confirm the emergency with the owner and rotate the break-glass credentials afterwards."
                            if breakglass else "Revoke sessions (Revoke-MgUserSignInSession) and check what was accessed."),
            links=_user_links(s),
        ))
    # A disabled account that something keeps signing in to: one refused attempt is a leaver's phone, a steady
    # stream is a script, a device or a stranger still holding a sign-in of the account. Nothing gets in while the
    # account stays disabled - but that sign-in works again the moment the account is re-enabled.
    cfg = rc.cfg("account_state")
    window = timedelta(hours=float(cfg.get("disabled_attempts_window_hours", 3)))
    minimum = int(cfg.get("disabled_attempts_min", 10))
    for user in sorted(refused):
        items = [x for x in rc.keep(rc.history.query(rc.now - window, rc.now, user_id=user)) if x.error_code == DISABLED_CODE]
        if len(items) < minimum:
            continue
        s, a = _best([(x, rc.assessor.assess(x, 30, f"{len(items)} sign-in attempts on a disabled account in "
                                                    f"{int(window.total_seconds() // 3600)} h", floor=25)) for x in items])
        agents = sorted({x.user_agent[:40] for x in items if x.user_agent})
        by_code = any(x.transfer_method.lower() == "devicecodeflow" for x in items)
        hands = sum(1 for x in items if x.interactive)
        out.append(_scored(
            a, key=f"acctstate|dis-tried|{user}|{_iso_week(rc.now)}", rule_id="account_state",
            title=f"Disabled account keeps being tried: {s.who}",
            summary=(f"{len(items)} sign-in attempts on the disabled account {s.who} in the last "
                     f"{int(window.total_seconds() // 3600)} h, all refused, from {', '.join(sorted({x.location for x in items}))[:100]} "
                     f"to {', '.join(sorted({x.app for x in items}))[:80]}. "
                     + ("They come in the background at a steady pace: a script or device still holds a sign-in of this account"
                        if not hands else f"{hands} of them by hand")
                     + (" (one that was once approved with a device code)" if by_code else "") + "."),
            occurred_at=min(x.created for x in items),
            fields={"Account": s.who, "Attempts": str(len(items)), "IP addresses": ", ".join(sorted({x.ip for x in items})[:6]),
                    "Client": ", ".join(agents[:3]) or "-", "Application": ", ".join(sorted({x.app for x in items})[:4])},
            evidence=_evidence(items),
            recommendation=("Find out what is still signing in as this account (the client and address are in the evidence) "
                            "and whether it belongs to the former owner. Nothing gets in while the account is disabled, "
                            "but revoke its sessions (Revoke-MgUserSignInSession) before the account is ever re-enabled."),
            links=_user_links(s),
        ))
    for (user, day), items in tried.items():
        s, a = _best([(x, rc.assessor.assess(x, 40, "Failed sign-in on a break-glass account (nobody should be trying it)"))
                      for x in items])
        out.append(_scored(
            a, key=f"acctstate|bg-fail|{user}|{day}", rule_id="account_state",
            title=f"Sign-in attempts on break-glass account: {s.who}",
            summary=(f"{len(items)} failed sign-in(s) on emergency account {s.who} from "
                     f"{', '.join(sorted({x.location for x in items}))[:120]} "
                     f"({', '.join(sorted({str(x.error_code) for x in items}))})."),
            occurred_at=min(x.created for x in items), fields={"Account": s.who}, evidence=_evidence(items),
            recommendation="Find out who tried to use the emergency account. If nobody in IT did, someone is targeting "
                           "your highest-privileged accounts: check the source IPs and the account's MFA/YubiKey state.",
            links=_user_links(s),
        ))
    return out


def _under_attack(rc: RuleContext, user_id: str, days: int = 7, minimum: int = 5) -> int:
    """Failed passwords of the last days from networks the account does not use (0 = not targeted)."""
    start = rc.now - timedelta(days=days)
    familiar = rc.history.user_asns(user_id, start)
    fails = [s for s in rc.history.query(start, rc.now, user_id=user_id, codes=FAILED_PASSWORD_CODES)
             if not rc.trusted(s) and (not s.asn or s.asn not in familiar)]
    return len(fails) if len(fails) >= minimum else 0


def mfa_exposure_report(rc: RuleContext) -> list[Finding]:
    """Overview of every account that can sign in without MFA (excluded) or has none registered (anyone with the
    password can register one), with clean-up candidates - weekly reminder and on demand."""
    if not rc.accounts:
        return []
    excluded = rc.accounts.mfa_excluded()
    gaps = sorted((a for a in rc.accounts.accounts.values() if a.mfa_gap), key=lambda a: a.upn.lower())
    if not excluded and not gaps:
        return []
    cfg = rc.cfg("mfa_exposure_report")
    unused_days = int(cfg.get("unused_days", 90))
    password_days = int(cfg.get("password_max_days", 365))
    rows, flagged = [], Counter()
    attacked = 0
    for acct in excluded + gaps:
        flags = []
        hits = _under_attack(rc, acct.user_id)
        if hits:
            flags.append(f"UNDER PASSWORD ATTACK ({hits} attempts in 7 d)")
            attacked += 1
        last = acct.age_days(acct.last_signin, rc.now)
        if not acct.enabled:
            flags.append("disabled: remove from exclusion")
        elif acct.last_signin is None:
            flags.append("never signed in")
        elif last > unused_days:
            flags.append(f"unused > {unused_days} d")
        pwd = acct.age_days(acct.pwd_changed, rc.now)
        if pwd is not None and pwd > password_days:
            flags.append(f"password {pwd // 365}+ y old")
        if acct.person_like:
            flags.append("looks like a person")
        if acct.privileged_tier:
            flags.append("has admin role")
        for f in flags:
            flagged["old password" if f.startswith("password ") else f.split(" (")[0].split(":")[0].lower()] += 1
        protos = sorted(rc.history.user_profile(acct.user_id, "proto", rc.now))
        apps = sorted(rc.history.user_profile(acct.user_id, "app", rc.now))
        ips = rc.history.user_profile(acct.user_id, "ip", rc.now)
        rows.append({
            "Account": acct.upn,
            "Exposure": "excluded from MFA" if acct.mfa_excluded else "NO MFA registered",
            "Flags": ", ".join(flags) or "-",
            "Last sign-in": (parse_time(acct.last_signin).astimezone().strftime("%Y-%m-%d") if acct.last_signin else "never"),
            "Password changed": (parse_time(acct.pwd_changed).astimezone().strftime("%Y-%m-%d") if acct.pwd_changed else "-"),
            "Used in last 30 d": (f"{', '.join(protos) or '-'} | {', '.join(apps[:3])}{' ...' if len(apps) > 3 else ''} "
                                  f"| {len(ips)} IP(s)") if ips else "not used",
            "Excluded via": "; ".join(acct.mfa_excluded) or "-",
            "Enabled": "yes" if acct.enabled else "no",
        })
    rows.sort(key=lambda r: (not r["Flags"].startswith("UNDER"), r["Flags"] == "-", r["Exposure"], r["Account"]))
    candidates = sum(1 for r in rows if r["Flags"] != "-")
    groups = ", ".join(g.get("name", gid) for gid, g in rc.accounts.exclusion_groups.items()) or "direct exclusions"
    score = (35 if candidates else 15) + (20 if attacked else 0)
    year, week, _ = rc.now.astimezone().isocalendar()
    factors = [(35 if candidates else 15, f"{len(excluded)} accounts excluded from MFA, {len(gaps)} without any MFA "
                                          f"method registered, {candidates} clean-up candidate(s)")]
    if attacked:
        factors.append((20, f"{attacked} of them are under a password attack right now"))
    return [Finding(
        key=f"mfaexposure|{year}-W{week:02d}", rule_id="mfa_exposure_report", severity=severity_for(score), score=score,
        factors=factors,
        title=(f"MFA exposure report: {len(excluded)} excluded from MFA, {len(gaps)} without MFA registered, "
               f"{candidates} to review" + (f", {attacked} UNDER ATTACK" if attacked else "")),
        summary=(f"{len(excluded)} accounts are excluded from MFA ({groups}) and {len(gaps)} enabled accounts have no "
                 f"MFA method registered - whoever knows their password can register their own. Clean-up candidates: "
                 f"{candidates} ({', '.join(f'{n} {k}' for k, n in flagged.most_common())}). Open the item for the "
                 f"full list (the weekly reminder keeps the first {MAX_EVIDENCE} rows; tray > MFA exposure report... "
                 f"lists all)."),
        occurred_at=rc.now,
        fields={"Excluded via": groups, "Excluded from MFA": str(len(excluded)), "No MFA registered": str(len(gaps)),
                "To review": str(candidates), "Under password attack": str(attacked)},
        evidence=rows,
        recommendation=("Under attack without MFA: block sign-in (shared mailboxes, rooms) or set a new long password "
                        "and register MFA now. Disable accounts that never signed in. Remove unused or disabled accounts "
                        "from MFA exclusions, rotate old passwords; restrict technical accounts to their networks with "
                        "Conditional Access. Consider a Conditional Access policy that allows security-info "
                        "registration only from trusted networks / compliant devices."),
        links=[("Entra: Conditional Access", "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies")],
    )]


SECURITY_INFO_APPS = {
    "19db86c3-b2b9-44cc-b339-36da233a3be2",  # My Sign-ins (security info, password reset)
    "0000000c-0000-0000-c000-000000000000",  # Microsoft App Access Panel
    "8c59ead7-d703-4a27-9e55-c96a0054c8d2",  # My Profile
}
PROXY_CATEGORIES = ("hosting", "bulletproof")  # where AiTM kits run; "vpn"/"cloud" are scored, not anchors


def _context(rc: RuleContext, s: SignIn) -> tuple[int, Assessment]:
    """How unfamiliar a sign-in is for its user (network, device, client), without base and account factors."""
    a = rc.assessor.assess(s, 0, "")
    acct = rc.accounts.get(s.user_id) if rc.accounts else None
    skip = {f.text for f in Assessor.account_factors(acct, s)} if acct else set()
    factors = [f for f in a.factors[1:] if f.text not in skip]
    return sum(f.points for f in factors), Assessment(score=0, factors=factors, label=a.label)


def _where(rc: RuleContext, s: SignIn) -> str:
    net = (rc.trusted_label(s) if rc.trusted(s) else rc.assessor.asn_label(s.asn) if s.asn else "unknown network")
    dev = s.device_name or ("registered device" if s.device_id else " ".join(p for p in (s.os, s.browser) if p)
                            or "unknown device")
    return f"{s.location} ({s.ip}, {net}, {dev})"


def _collapse_changes(changes: list[AccountChange]) -> list[str]:
    """One line per change of the same kind/actor within 5 min (Entra logs one passkey registration as up to
    three events: 'Passkey', 'Fido2 Authentication Method', 'security info')."""
    lines: list[tuple[AccountChange, list[str]]] = []
    for c in changes:
        last = lines[-1] if lines else None
        if last and last[0].kind == c.kind and last[0].actor == c.actor \
                and c.created - last[0].created <= timedelta(minutes=5):
            if c.detail not in last[1]:
                last[1].append(c.detail)
        else:
            lines.append((c, [c.detail]))
    out = []
    for c, details in lines:
        specific = [d for d in details if d.lower() != "user registered security info"] or details
        out.append(f"{c.created.astimezone():%d.%m. %H:%M} {' / '.join(specific)}"
                   + (f" by {c.actor}" if c.by_admin else ""))
    return out


def _clamp(points: int, low: int, high: int) -> int:
    return max(low, min(high, points))


def mfa_change(rc: RuleContext) -> list[Finding]:
    """MFA method added/reset, TAP issued or password reset - judged by WHERE it was done and WHAT signed in after.

    Covers the attacker who registers his own authenticator after an AiTM phish, and the cloned-voice help-desk
    call (admin resets MFA / issues a TAP, then a "clean" MFA sign-in from a new device). A user adding a passkey
    on his known laptop, or a new phone signing in after he registered it there, stays below the pop-up threshold.
    """
    cfg = rc.cfg("mfa_change")
    lookback = timedelta(hours=float(cfg.get("lookback_hours", 24)))
    groups: dict[str, list[AccountChange]] = defaultdict(list)
    for c in rc.history.changes(rc.now - lookback, rc.now):
        if (c.guest and not cfg.get("include_guests", False)) or c.upn in rc.ignore_users or c.kind == REPORT_KIND:
            continue
        groups[c.user_id].append(c)
    out = []
    for user_id, changes in groups.items():
        t0 = changes[0].created
        acct = rc.accounts.get(user_id) if rc.accounts else None
        upn = (acct.upn if acct else "") or changes[0].upn or user_id
        top = max(changes, key=lambda c: c.points)
        factors = [Factor(top.points, f"{top.label}: {top.detail}" + (f" (by {top.actor})" if top.by_admin else ""))]
        kinds = {c.kind for c in changes} - {top.kind}
        if kinds:
            factors.append(Factor(5, "Also: " + ", ".join(sorted(CHANGE_KINDS[k][1] for k in kinds))))

        # 1) where the user made the change himself (an admin's change says nothing about the user's location)
        reg = None
        own = [c for c in changes if not c.by_admin]
        if own:
            c = own[0]
            rows = rc.keep(rc.history.query(c.created - timedelta(minutes=60), c.created + timedelta(minutes=5),
                                            user_id=user_id, success=True))
            pool = [s for s in rows if s.app_id in SECURITY_INFO_APPS or (c.app_id and s.app_id == c.app_id)] or rows
            if pool:
                reg = min(pool, key=lambda s: abs((s.created - c.created).total_seconds()))
                pts, ra = _context(rc, reg)
                factors.append(Factor(_clamp(pts, -30, 40), f"Change made from {_where(rc, reg)}"
                                      + (f": {ra.top_reasons(2)}" if ra.factors else "")))
            else:
                factors.append(Factor(0, "The user's sign-in at the time of the change is not in the local history"))

        # 2) what signed in afterwards from a device / network the user had not used before. "Before" ends 12 h
        # ahead of the change: an attacker's own session (phished shortly before he registers his method) must
        # not make his network/browser look familiar.
        cut = t0 - timedelta(hours=float(cfg.get("baseline_gap_hours", 12)))
        known_dev, known_asn = rc.history.user_devices(user_id, cut), rc.history.user_asns(user_id, cut)
        known_cli = rc.history.user_clients(user_id, cut)
        later = [s for s in rc.keep(rc.history.query(t0, min(rc.now, t0 + timedelta(hours=24)), user_id=user_id,
                                                     success=True)) if not rc.trusted(s)]
        fresh, continued = [], False
        for s in later:
            if reg and s.asn == reg.asn and (s.device_id or s.client) == (reg.device_id or reg.client):
                continued = True
                continue  # the device/session the change was made from: already judged above
            new_dev = bool(s.device_id and s.device_id not in known_dev) or bool(
                not s.device_id and s.client and s.client not in known_cli)
            new_net = bool(s.asn) and s.asn not in known_asn
            if new_dev or new_net:
                pts, sa = _context(rc, s)
                fresh.append((pts + (10 if new_dev and new_net else 0), s, new_dev, new_net, sa))
        if fresh:
            pts, s, new_dev, new_net, sa = max(fresh, key=lambda x: x[0])
            what = " and ".join(w for w, flag in (("device", new_dev), ("network", new_net)) if flag)
            factors.append(Factor(_clamp(pts, 0, 40), f"Afterwards: sign-in from a new {what} at "
                                                      f"{s.created.astimezone():%H:%M}: {_where(rc, s)}"
                                                      + (f" - {sa.top_reasons(2)}" if sa.factors else "")))
        elif continued and reg and _context(rc, reg)[0] > 0:
            factors.append(Factor(0, "Afterwards only the (unfamiliar) device the change was made from"))
        else:
            factors.append(Factor(-15, "No sign-in from a new device or network since the change"))

        if acct and acct.created:
            age = rc.now - parse_time(acct.created)
            if age < timedelta(days=float(cfg.get("new_account_days", 7))):
                factors.append(Factor(-20, f"New account ({age.days} day(s) old): onboarding"))
        if acct:
            factors.extend(Assessor.account_factors(acct, reg or (later[0] if later else SignIn(id="", created=t0))))
        score = _clamp(sum(f.points for f in factors), 0, 100)
        a = Assessment(score=score, factors=factors, context=acct.context(rc.now) if acct else "")
        admins = sorted({c.actor for c in changes if c.by_admin})
        fields = {"User": upn, "Changes": "; ".join(_collapse_changes(changes))}
        if admins:
            fields["Changed by"] = ", ".join(admins)
        if reg:
            fields["Change made from"] = _where(rc, reg)
        if fresh:
            seen_where: dict[tuple, str] = {}
            for x in sorted(fresh, key=lambda x: x[1].created):
                seen_where.setdefault((x[1].ip, x[1].device_id or x[1].client),
                                      f"{x[1].created.astimezone():%d.%m. %H:%M} {_where(rc, x[1])}")
            fields["New devices/networks afterwards"] = "; ".join(list(seen_where.values())[:5])
        out.append(_scored(
            a, key=f"mfachg|{user_id}|{_day(t0)}", rule_id="mfa_change",
            title=f"{top.label} for {upn}" + (", then new device/network" if fresh else ""),
            summary=(f"{top.label} for {upn}" + (f" by {top.actor}" if top.by_admin else "") + ". "
                     + ("Afterwards the account signed in from a device or network it had never used. " if fresh else "")
                     + f"Assessment: {a.top_reasons()}."),
            occurred_at=t0, fields=fields,
            evidence=[c.evidence() for c in reversed(changes)] + _evidence(([reg] if reg else []) + [x[1] for x in fresh]),
            recommendation=("Confirm with the user over a channel you already trust (known phone number, in person - "
                            "not the method that was just registered) that they made this change. If not: delete the "
                            "new method, revoke sessions, reset the password. Help desk: verify callers before resetting "
                            "MFA or issuing a Temporary Access Pass."),
            links=[("Entra: user authentication methods",
                    f"https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/UserAuthMethods/userId/{user_id}"),
                   ("Entra: audit logs", "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit")],
        ))
    return out


def aitm_replay(rc: RuleContext) -> list[Finding]:
    """Adversary-in-the-middle phishing (Evilginx-style kits).

    1. The proxy itself: a FRESH MFA sign-in (the kit cannot reuse the victim's cookies) from a hosting network,
       without device identity, on a network the user has not habitually used.
    2. The replay: the session of a fresh MFA sign-in shows up on another network shortly afterwards. The
       session_theft rule needs a different country AND a different device id; a replay where neither side has
       a device identity, or within the same country, is caught here.
    """
    cfg = rc.cfg("aitm_replay")
    window = timedelta(minutes=float(cfg.get("window_minutes", 180)))
    out: list[Finding] = []
    proxied: dict[tuple[str, str], list[tuple[SignIn, Assessment]]] = defaultdict(list)
    for s in rc.new:
        if not (s.success and s.interactive and s.user_id and s.fresh_mfa) or s.device_id or rc.trusted(s):
            continue
        net = rc.assessor.network(s)
        if not net or net[1] not in PROXY_CATEGORIES:
            continue
        a = rc.assessor.assess(s, 35, f"MFA completed through a {net[1]} network ({net[0]}) without device identity "
                                      f"(AiTM proxy pattern)")
        if any("habitual network" in f.text.lower() for f in a.factors):
            continue  # the user's own long-standing VPN/hosting exit, not a fresh phishing server
        proxied[(s.user_id, _day(s.created))].append((s, a))
    for (user_id, day), items in proxied.items():
        s, a = _best(items)
        out.append(_scored(
            a, key=f"aitm|{user_id}|{day}", rule_id="aitm_replay",
            title=f"Possible AiTM phishing: {s.who} completed MFA through a datacenter",
            summary=(f"{s.who} completed MFA from {s.location} ({s.ip}, {rc.assessor.asn_label(s.asn)}) without "
                     f"device identity. Phishing proxies (Evilginx, Tycoon 2FA ...) run in datacenters and complete "
                     f"the victim's MFA themselves to steal the session cookie. Assessment: {a.top_reasons()}."),
            occurred_at=min(x.created for x, _ in items), fields={"User": s.who, "IP": s.ip, "App": s.app},
            evidence=_evidence([x for x, _ in items]),
            recommendation="Ask the user whether they just signed in through a link (e-mail, Teams, QR code). If not "
                           "sure: revoke sessions, reset the password, check MFA methods and inbox rules. Long term: "
                           "phishing-resistant MFA (passkeys) and compliant-device Conditional Access stop AiTM.",
            links=_user_links(s),
        ))

    # 2) replay of a fresh-MFA session from another network
    pairs: dict[str, tuple[SignIn, SignIn]] = {}
    for r in rc.new:
        if not (r.success and r.session_id and r.user_id and r.asn) or rc.trusted(r) or r.ms_backend:
            continue
        anchors = [o for o in rc.history.query(r.created - window, r.created, session_id=r.session_id, success=True)
                   if o.id != r.id and o.interactive and o.fresh_mfa and o.asn and o.asn != r.asn
                   and o.ip != r.ip and not rc.trusted(o)]
        if not anchors:
            continue
        o = anchors[0]  # the MFA that created the session
        if r.device_id and (r.device_id == o.device_id or r.device_id in rc.history.user_devices(r.user_id, r.created)):
            continue  # the user's own registered device on another network
        if o.country and r.country and o.country != r.country and (o.device_id or "") != (r.device_id or ""):
            continue  # session_theft reports cross-country pairs with different devices
        if r.session_id not in pairs:
            pairs[r.session_id] = (o, r)
    for sid, (o, r) in pairs.items():
        minutes = (r.created - o.created).total_seconds() / 60
        extra = [Factor(0, f"MFA at {o.created.astimezone():%H:%M} from {_where(rc, o)}")]
        before = o.created
        familiar = rc.history.user_asns(r.user_id, before)
        if o.asn in familiar and r.asn in familiar:
            extra.append(Factor(-30, "Both networks are the user's usual ones (e.g. Wi-Fi / mobile data switch)"))
        net_o = rc.assessor.network(o)
        if net_o and net_o[1] in PROXY_CATEGORIES:
            extra.append(Factor(15, f"The MFA itself came from a {net_o[1]} network ({net_o[0]})"))
        if o.client and r.client and o.client != r.client:
            extra.append(Factor(10, f"Different client than at the MFA ({o.client.replace('|', ', ')} vs "
                                    f"{r.client.replace('|', ', ')})"))
        back = rc.history.query(r.created, r.created + timedelta(minutes=15), session_id=sid, success=True)
        if any(b.asn == o.asn for b in back if b.id != r.id):
            extra.append(Factor(-15, "Both networks used alternately (one device on two network paths)"))
        if r.token_protection == "bound":
            extra.append(Factor(-25, "Session token is device-bound (token protection): it cannot be replayed on "
                                     "another device"))
        a = rc.assessor.assess(r, 40, f"Session of a fresh MFA sign-in used from another network {minutes:,.0f} min "
                                      f"later", extra)
        out.append(_scored(
            a, key=f"replay|{r.user_id}|{sid}", rule_id="aitm_replay",
            title=f"Session replayed from another network after MFA: {r.who}",
            summary=(f"{r.who} completed MFA from {o.location} ({o.ip}); {minutes:,.0f} min later the same session was "
                     f"used from {r.location} ({r.ip}, {rc.assessor.asn_label(r.asn)}). An AiTM phishing kit steals the "
                     f"session cookie at the MFA and replays it elsewhere. Assessment: {a.top_reasons()}."),
            occurred_at=o.created,
            fields={"User": r.who, "Session ID": sid, "MFA from": _where(rc, o), "Replayed from": _where(rc, r)},
            evidence=_evidence([o, r] + [b for b in back if b.id != r.id][:10]),
            recommendation="Revoke the user's sessions (Revoke-MgUserSignInSession), reset the password, check MFA "
                           "methods (attackers register their own), inbox rules and recent mail/file access.",
            links=_user_links(r),
        ))
    return out


@dataclass(frozen=True)
class RuleDef:
    meta: Rule
    evaluate: Callable[[RuleContext], list[Finding]]


def mfa_report(rc: RuleContext) -> list[Finding]:
    """A user reported an MFA prompt as not theirs (Authenticator: "No, it's not me" > report; phone: the reporting
    code). The prompt only comes after the password was accepted, so a true report means someone else has it.

    The audit entry is the trigger; the sign-in that caused the prompt is a row of its own in the sign-in log -
    failed at the MFA step, same account, seconds before the report - and arrives up to 1-2 hours later. Until then
    the alert stands at Medium; with the row it is judged by where that sign-in came from: the account's own
    managed device and usual network (a prompt of their own, reported by mistake) ends low, an unfamiliar network
    or device high. No row after the waiting time: high.
    """
    cfg = rc.cfg("mfa_report")
    lookback = timedelta(hours=float(cfg.get("lookback_hours", 24)))
    wait = timedelta(minutes=float(cfg.get("wait_minutes", 120)))
    out = []
    for c in rc.history.changes(rc.now - lookback, rc.now):
        if c.kind != REPORT_KIND or c.upn in rc.ignore_users:
            continue
        acct = rc.accounts.get(c.user_id) if rc.accounts else None
        upn = (acct.upn if acct else "") or c.upn or c.user_id
        when = f"{c.created.astimezone():%d.%m. %H:%M}"
        near = rc.history.query(c.created - timedelta(minutes=10), c.created + timedelta(minutes=10),
                                user_id=c.user_id, interactive_only=True)
        s = _report_prompt(rc, c)
        fields = {"User": upn, "Reported": f"{when} - {c.detail}"}
        if s is not None:
            same = [x for x in near if x.success and ((s.device_id and x.device_id == s.device_id)
                                                      or (s.session_id and x.session_id == s.session_id))]
            extra = [Factor(-25, "The same device signed the account in successfully within minutes of the report")] if same else []
            a = rc.assessor.assess(s, 60, "The user reported the MFA prompt of this sign-in as not theirs", extra)
            a.score = max(a.score, 25)  # a report is never dropped: at least a low reminder
            own = a.score < 45
            fields.update({"IP address": s.ip, "Location": s.location, "Application": s.app})
            out.append(_scored(
                a, key=f"mfa-report|{c.user_id}|{c.id}", rule_id="mfa_report",
                title=f"MFA prompt reported as not theirs: {upn}" + (" (probably their own sign-in)" if own else ""),
                summary=(f"{upn} reported an MFA prompt as not theirs at {when}. The prompt was caused by a sign-in to "
                         f"{s.app or 'an application'} from {s.location} ({s.ip}) that had the right password. "
                         + ("It came from the account's own device and usual surroundings: most likely the user's own "
                            "sign-in, reported by mistake." if own else
                            "It did not come from the account's usual surroundings: someone else knows the password.")
                         + f" Assessment: {a.top_reasons()}."),
                occurred_at=c.created, fields=fields,
                evidence=[c.evidence()] + _evidence([s] + [x for x in near if x.id != s.id]),
                recommendation=("Ask the user whether they were signing in themselves. If so, nothing is wrong - but the "
                                "report set the account to high risk in Entra ID Protection: dismiss that risk there."
                                if own else
                                "Treat the password as known to someone else: reset it and revoke the sessions, block "
                                "the address, and look for successful sign-ins from it. The report also set the account "
                                "to high risk in Entra ID Protection."),
                links=_user_links(s),
            ))
            continue
        pending = rc.now - c.created < wait
        score = 50 if pending else 75
        factors = [(50, "The user reported an MFA prompt as not theirs (a prompt is only sent after the right password)")]
        if not pending:
            factors.append((25, f"No sign-in that caused the prompt was recorded within {int(wait.total_seconds() // 60)} minutes"))
        fields["Risk score"] = f"{score}/100"
        out.append(Finding(
            key=f"mfa-report|{c.user_id}|{c.id}", rule_id="mfa_report", severity=severity_for(score), score=score,
            factors=factors, title=f"MFA prompt reported as not theirs: {upn}",
            summary=(f"{upn} reported an MFA prompt as not theirs at {when}. "
                     + ("The sign-in that caused the prompt is not in the sign-in log yet (Entra delivers it up to "
                        "1-2 hours later); this alert is judged again when it arrives."
                        if pending else
                        "No sign-in that caused the prompt has appeared in the sign-in log.")
                     + (f" {len(near)} other sign-in(s) of the account around that time are listed below." if near else "")),
            occurred_at=c.created, fields=fields, evidence=[c.evidence()] + _evidence(near),
            recommendation="Ask the user whether they were signing in themselves. If not, someone else knows the "
                           "password: reset it and revoke the sessions.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL)],
        ))
    return out


def signin_wave(rc: RuleContext) -> list[Finding]:
    """Several accounts, within hours, each with one sign-in that is odd for it - and all of them share where it
    came from: a network nobody in the tenant used before (or a hosting / VPN network), or a client nobody used
    before. One such sign-in is a new phone or a trip and stays below every rule; several at once are a phishing
    wave (the proxy's network, the kit's client) or one attacker working through a list of passwords.

    Counted are sign-ins that got at least past the password, from outside the account's own surroundings (no
    office, no device, network or address it used before) - so a team at a conference on their own laptops is no
    wave."""
    cfg = rc.cfg("signin_wave")
    window = timedelta(hours=float(cfg.get("window_hours", 6)))
    minimum = int(cfg.get("min_accounts", 4))
    start = rc.now - window
    rows = [s for s in rc.keep(rc.history.query(start, rc.now, interactive_only=True))
            if s.user_id and not rc.trusted(s) and not rc.on_virtual_host(s)
            and (s.success or s.error_code in PASSWORD_ACCEPTED_CODES or s.error_code == MFA_DENIED_CODE)]
    foreign: dict[str, bool] = {}
    clusters: dict[tuple[str, str], dict[str, list[SignIn]]] = defaultdict(lambda: defaultdict(list))
    for s in rows:
        if s.id not in foreign:
            foreign[s.id] = _foreign_to_user(rc, s)
        if not foreign[s.id]:
            continue
        if s.asn:
            clusters[("network", str(s.asn))][s.user_id].append(s)
        if s.user_agent:
            clusters[("client", s.user_agent)][s.user_id].append(s)
    out, reported_users = [], []
    for (kind, value), by_user in sorted(clusters.items(), key=lambda kv: (kv[0][0] != "network", -len(kv[1]))):
        if len(by_user) < minimum:
            continue
        if any(set(by_user) <= users for users in reported_users):
            continue  # the same accounts already reported for their network: not again for their client
        signins = sorted((s for items in by_user.values() for s in items), key=lambda s: s.created)
        first = signins[0]
        if kind == "network":
            net = rc.assessor.network(first)
            new_to_tenant = rc.history.asn_user_count(int(value), start) == 0
            if not new_to_tenant and not (net and net[1] != "cloud"):
                continue  # an ordinary provider people already use: several new customers a day are normal
            what = f"the network {rc.assessor.asn_label(int(value))}"
            factors = [Factor(45, f"{len(by_user)} accounts signed in from {what} within "
                                  f"{int(window.total_seconds() // 3600)} h, each from outside its usual surroundings")]
            if net and net[1] != "cloud":
                factors.append(Factor(15, f"{net[1].capitalize()} network: {net[0]}"))
            if new_to_tenant:
                factors.append(Factor(10, "Nobody in the tenant used this network before"))
        else:
            if rc.history.user_agent_seen(value, start):
                continue
            what = f"the client '{value[:70]}'"
            factors = [Factor(45, f"{len(by_user)} accounts signed in with a client nobody used before, within "
                                  f"{int(window.total_seconds() // 3600)} h, each from outside its usual surroundings")]
            tool = rc.assessor.suspicious_agent(first)
            if tool:
                factors.append(Factor(15, f"Attack-tool fingerprint: {tool}"))
        if len(by_user) > minimum:
            factors.append(Factor(min(20, 5 * (len(by_user) - minimum)), f"{len(by_user)} accounts (from {minimum} it counts as a wave)"))
        successes = [s for s in signins if s.success]
        if successes:
            factors.append(Factor(15, f"{len({s.user_id for s in successes})} of them completed the sign-in"))
        known = [s for s in signins if rc.hostile(s)]
        if known:
            factors.append(Factor(15, f"Known attacker address among them: {known[0].ip}"))
        score = max(0, min(100, sum(f.points for f in factors)))
        accounts = sorted({s.who for s in signins})
        reported_users.append(set(by_user))
        out.append(Finding(
            key=f"wave|{kind}|{value[:60]}|{_day(first.created)}", rule_id="signin_wave", severity=severity_for(score),
            score=score, factors=[(f.points, f.text) for f in factors],
            title=f"Wave of unusual sign-ins: {len(accounts)} accounts from {what}"[:160],
            subjects=sorted({s.upn for s in signins if s.upn}),
            summary=(f"Within {int(window.total_seconds() // 3600)} hours {len(accounts)} accounts each had a sign-in that "
                     f"got past the password from outside their usual surroundings, all from {what}. Each one alone looks "
                     f"like a new phone or a trip; together they look like a phishing wave or one attacker using several "
                     f"stolen passwords."),
            occurred_at=first.created,
            fields={"Accounts": ", ".join(accounts)[:300], "Shared": what,
                    "Completed sign-ins": str(len(successes)), "Risk score": f"{score}/100"},
            evidence=_evidence(signins),
            recommendation="Ask two or three of these people what they did at that time (a phishing mail? a new app "
                           "rollout?). If it was not their own doing: revoke the sessions and reset the passwords of all "
                           "of them, and block the network or address.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL)],
        ))
    return out


def hostile_reuse(rc: RuleContext) -> list[Finding]:
    """What else came from an address another finding proved to be an attacker's (indicators.py): other accounts
    tried from it, and anybody who got in from it afterwards. Only addresses with proven access count (a stolen
    session, a phishing proxy, a password that worked, a reported MFA prompt) - not mere attack traffic. Sign-ins
    from a device the account already used are left out (a colleague on the same hotel or mobile network)."""
    days = indicators.settings(rc)[1]
    out = []
    for ip, marks in rc.hostile_index().items():
        proven = [m for m in marks if m.points >= indicators.HIGH]
        if not proven:
            continue
        first = min(proven, key=lambda m: m.when)
        victims = {m.user_id: m for m in proven}
        rows = rc.keep(rc.history.query(first.when - timedelta(days=days), rc.now, ip=ip))
        hits = []
        for s in rows:
            if not s.user_id or rc.trusted(s):
                continue
            mark = victims.get(s.user_id)
            if mark is not None and (not s.success or s.created <= mark.when):
                continue  # the sign-ins the address was marked for, and further attempts on that account
            if s.device_id and s.device_id in rc.history.user_devices(s.user_id, s.created):
                continue
            hits.append(s)
        if not hits:
            continue
        others = sorted({s.who for s in hits if s.user_id not in victims})
        successes = [s for s in hits if s.success]
        accepted = [s for s in hits if s.error_code in PASSWORD_ACCEPTED_CODES or s.error_code == MFA_DENIED_CODE]
        factors = [(45, f"Sign-ins from {ip}, an address used in {first.describe()}")]
        if len(others) > 1:
            factors.append((min(15, 5 * (len(others) - 1)), f"{len(others)} other accounts were tried from it"))
        if accepted:
            factors.append((20, f"The password was right for {', '.join(sorted({s.who for s in accepted}))} "
                                f"(stopped at MFA / Conditional Access)"))
        if successes:
            factors.append((35, f"{len(successes)} successful sign-in(s) from it: {', '.join(sorted({s.who for s in successes}))}"))
        score = min(100, sum(p for p, _ in factors))
        got_in = sorted({s.who for s in successes})
        title = (f"Signed in from a known attacker address: {', '.join(got_in)[:120]}" if got_in else
                 f"Known attacker address also used on {len(others)} other account(s): {ip}")
        s0 = hits[-1]
        out.append(Finding(
            key=f"hostile-ip|{ip}|{_day(first.when)}", rule_id="hostile_reuse", severity=severity_for(score), score=score,
            factors=factors, title=title, subjects=sorted({s.upn for s in hits if s.upn}),
            summary=(f"{ip} ({s0.location}) was used in {first.describe()}. From the same address there were "
                     f"{len(hits)} more sign-in(s)"
                     + (f" to {len(others)} other account(s)" if others else "")
                     + (f", {len(successes)} of them successful" if successes else ", none of them successful")
                     + ". Whoever is behind that address is working on more than one account."),
            occurred_at=min(s.created for s in hits),
            fields={"IP address": ip, "Accounts": ", ".join(sorted({s.who for s in hits}))[:300],
                    "Known from": first.describe(), "Risk score": f"{score}/100"},
            evidence=_evidence(hits),
            recommendation=("Treat every account that signed in successfully from this address as taken over: revoke its "
                            "sessions and reset its password. " if successes else "")
                           + "Block the address, reset the passwords the attacker got right, and make sure the other "
                             "accounts use MFA.",
            links=[("Entra: sign-in logs", SIGNIN_LOGS_URL), ("Look up IP (AbuseIPDB)", f"https://www.abuseipdb.com/check/{ip}")],
        ))
    return out


RULES: list[RuleDef] = [
    RuleDef(Rule("risky_signin", "Risky sign-ins (ID Protection)",
                 "Sign-ins Entra ID Protection rates medium/high risk"), risky_signin),
    RuleDef(Rule("password_spray", "Password spray", "One IP failing against many accounts"), password_spray),
    RuleDef(Rule("brute_force", "Brute force", "Many failed passwords for one account (+ success)"), brute_force),
    RuleDef(Rule("distributed_attack", "Password attack from rotating IPs",
                 "Low-and-slow guessing against one account from many proxy IPs"), distributed_attack),
    RuleDef(Rule("mfa_fatigue", "MFA fatigue", "Repeated MFA denials"), mfa_fatigue),
    RuleDef(Rule("mfa_report", "MFA prompt reported by the user",
                 "A user reported an MFA prompt as not theirs (needs 'Report suspicious activity' in Entra)"), mfa_report),
    RuleDef(Rule("signin_wave", "Wave of unusual sign-ins",
                 "Several accounts with an odd sign-in at the same time from the same new network or client"), signin_wave),
    RuleDef(Rule("hostile_reuse", "Known attacker address reused",
                 "An address proven to be an attacker's by another finding is used on other accounts"), hostile_reuse),
    RuleDef(Rule("password_not_completed", "Correct password, MFA not completed",
                 "Password accepted from an unfamiliar place but MFA/CA stopped it"), password_not_completed),
    RuleDef(Rule("session_theft", "Session token theft",
                 "Same session used from another country on another device"), session_theft),
    RuleDef(Rule("aitm_replay", "AiTM phishing / session replay",
                 "MFA completed through a datacenter, or a fresh-MFA session reused from another network"),
            aitm_replay),
    RuleDef(Rule("mfa_change", "MFA changes + new device",
                 "MFA method added/reset, TAP or password reset - judged by where it was done and what signed in "
                 "afterwards"), mfa_change),
    RuleDef(Rule("impossible_travel", "Impossible travel", "Consecutive sign-ins too far apart"), impossible_travel),
    RuleDef(Rule("new_country", "Sign-in from new country", "Country not seen for the user before"), new_country),
    RuleDef(Rule("new_shared_ip", "New IP shared by several accounts",
                 "Never-seen IP used by multiple accounts (AiTM proxy)"), new_shared_ip),
    RuleDef(Rule("attack_tooling", "Attack tools / scripted sign-ins",
                 "Interactive sign-ins from HTTP libraries and attack tools"), attack_tooling),
    RuleDef(Rule("new_country_background", "New country, background activity only",
                 "A device of the account active from a new country without a sign-in by hand (low)"), new_country_background),
    RuleDef(Rule("legacy_auth", "Legacy authentication", "Successful IMAP/POP/SMTP/EAS/... sign-ins"), legacy_auth),
    RuleDef(Rule("mfa_exempt_watch", "MFA-excluded accounts (strict)",
                 "Accounts that can sign in without MFA: any deviation from their 30-day pattern"), mfa_exempt_watch),
    RuleDef(Rule("mfa_exposure_report", "MFA exposure report: weekly reminder",
                 "Overview of accounts without MFA with clean-up candidates (on demand: tray > MFA exposure report...)"),
            mfa_exposure_report),
    RuleDef(Rule("account_state", "Disabled / break-glass account sign-ins",
                 "Sign-ins of disabled accounts and of emergency access accounts"), account_state),
    RuleDef(Rule("pinned_accounts", "Pinned accounts (IP restricted)",
                 "Accounts in pinned_accounts signing in from any other IP"), pinned_accounts),
    RuleDef(Rule("device_code", "Device code / ROPC sign-ins", "Successful device code or ROPC flow sign-ins"),
            device_code),
    RuleDef(Rule("sensitive_app", "Admin tools & device registration",
                 "First use of admin/recon tools or new device registration in a risky context"), sensitive_app),
]
