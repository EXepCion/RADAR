"""Contextual risk scoring of a sign-in: explains *why* something is (not) suspicious.

Each rule starts from a base score for its pattern and the assessor adds/subtracts points for
evidence in the sign-in and the local history (network, device, authentication strength, client).
Score -> severity: <25 Info (logged, no pop-up), <45 Low, <70 Medium, >=70 High.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

from ... import timefmt
from ...plugin_api import Severity
from . import netintel
from .models import SignIn

if TYPE_CHECKING:  # pragma: no cover
    from .rules import RuleContext

THRESHOLDS = ((70, Severity.HIGH), (45, Severity.MEDIUM), (25, Severity.LOW))

# Entra ID Protection detections (riskEventTypes_v2) and their weight
RISK_EVENT_POINTS = {
    "attackerinthemiddle": 35, "adversaryinthemiddle": 35, "anomaloustoken": 25, "tokenissueranomaly": 25,
    "maliciousipaddress": 30, "leakedcredentials": 25, "passwordspray": 20, "anonymizedipaddress": 20,
    "suspiciousbrowser": 15, "unfamiliarfeatures": 15, "unlikelytravel": 10, "impossibletravel": 10,
    "newcountry": 10, "mcasimpossibletravel": 10, "nationstateip": 35, "suspiciousapitraffic": 20,
}

# Detections that say "this does not look like the user's usual sign-in" - what a risk rating is usually made of.
# Where the rating itself is the base of an assessment they are named but not counted a second time.
GENERIC_RISK_EVENTS = {"unfamiliarfeatures", "unlikelytravel", "impossibletravel", "newcountry", "mcasimpossibletravel"}

LABEL_CORPORATE = "corporate network"
LABEL_VPN = "likely VPN / proxy"
LABEL_TRAVEL = "likely travel (known device)"
LABEL_HABITUAL_VPN = "user's habitual VPN"
HABIT_MIN_DAYS = 3
HABIT_MIN_SIGNINS = 3
HABIT_MIN_VPN_DAYS = 3
# A device, network or Authenticator counts as the account's own only once it has been in use for this long.
# What turned up moments ago cannot vouch for what follows it: an attacker who registers a device signs in with
# it seconds later, from the network he registered it from (setting: scoring > familiar_after_hours). A network
# is the exception when a device that IS the account's own used it (Assessor.asns).
FAMILIAR_AFTER_HOURS = 12
# A device that is old enough but was never seen where the account otherwise is (see Assessor._vouched) becomes the
# account's own after this many days all the same: a phone that only ever uses mobile data is no stranger for ever
# (setting: scoring > unvouched_after_days).
UNVOUCHED_AFTER_DAYS = 14
LABEL_UNKNOWN_DEVICE = "unknown device"


def severity_for(score: int) -> Severity:
    return next((sev for limit, sev in THRESHOLDS if score >= limit), Severity.INFO)


@dataclass
class Factor:
    points: int
    text: str

    def __str__(self) -> str:
        return f"{self.points:+d}  {self.text}"


@dataclass
class Assessment:
    score: int
    factors: list[Factor] = field(default_factory=list)
    label: str = ""
    context: str = ""  # account context line (role, MFA exposure, state)

    @property
    def severity(self) -> Severity:
        return severity_for(self.score)

    def top_reasons(self, n: int = 3) -> str:
        ranked = sorted((f for f in self.factors if f.points), key=lambda f: -abs(f.points))
        return "; ".join(f.text for f in ranked[:n])

    def as_tuples(self) -> list[tuple[int, str]]:
        return [(f.points, f.text) for f in self.factors]


class Assessor:
    def __init__(self, rc: "RuleContext"):
        self.rc = rc
        cfg = rc.settings.get("scoring") if isinstance(rc.settings.get("scoring"), dict) else {}
        self.extra_asns = cfg.get("extra_asns") or {}
        self.trusted_asns = {int(a) for a in cfg.get("trusted_asns", []) if str(a).isdigit()}
        self.ua_re = netintel.compile_user_agents(cfg.get("suspicious_user_agents"))
        self.resolver = rc.asn_resolver  # AS number -> registered holder name (optional, cached)
        try:
            hours = float(cfg.get("familiar_after_hours", FAMILIAR_AFTER_HOURS))
        except (TypeError, ValueError):
            hours = FAMILIAR_AFTER_HOURS
        self.familiar_after = timedelta(hours=max(0.0, hours))
        try:
            days = float(cfg.get("unvouched_after_days", UNVOUCHED_AFTER_DAYS))
        except (TypeError, ValueError):
            days = UNVOUCHED_AFTER_DAYS
        self.unvouched_after = max(self.familiar_after, timedelta(days=max(0.0, days)))
        self._cache: dict[tuple, object] = {}

    # ----------------------------------------------------------- helpers
    def _cached(self, key: tuple, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def network(self, s: SignIn) -> tuple[str, str] | None:
        """(name, category) when the sign-in comes from a non-ISP network (VPN, hosting, cloud ...)."""
        if not s.asn or s.asn in self.trusted_asns:
            return None
        known = netintel.asn_info(s.asn, self.extra_asns)
        if known:
            return known
        name = self.asn_name(s.asn)
        category = netintel.classify_asn_name(name) if name else None
        return (name, category) if category else None

    def asn_name(self, asn: int | None) -> str | None:
        if not asn:
            return None
        known = netintel.asn_info(asn, self.extra_asns)
        if known:
            return known[0]
        return self._cached(("asname", asn), lambda: self.resolver(asn) if self.resolver else None)

    def asn_label(self, asn: int | None) -> str:
        name = self.asn_name(asn)
        return f"{name} (AS{asn})" if name else f"AS{asn}"

    def suspicious_agent(self, s: SignIn) -> str | None:
        if not self.ua_re or not s.user_agent:
            return None
        m = self.ua_re.search(s.user_agent)
        return m.group(0) if m else None

    def vpn_switch(self, s: SignIn, minutes: int = 60) -> SignIn | None:
        """Same device signed in from another country within +-minutes: VPN/proxy toggling, not travel."""
        if not (s.device_id and s.country):
            return None
        window = timedelta(minutes=minutes)
        for o in self.rc.history.query(s.created - window, s.created + window, user_id=s.user_id,
                                       device_id=s.device_id, success=True):
            # (a device-code sign-in names the approving device, at the address of the machine that asked)
            if o.id != s.id and o.country and o.country != s.country and not self.rc.on_virtual_host(o):
                return o
        return None

    # --------------------------------------------- what the account knows
    def familiar_before(self, s: SignIn):
        """What the account used before this moment is its own at the time of ``s`` (see FAMILIAR_AFTER_HOURS)."""
        return s.created - self.familiar_after

    def devices(self, s: SignIn) -> set[str]:
        """Devices that are the account's own: in use for long enough AND seen where the account is otherwise
        (see _vouched) - a device registered through a datacenter and only ever used from there stays a stranger."""
        def find() -> set[str]:
            aged = self.rc.history.user_devices(s.user_id, self.familiar_before(s))
            return {d for d in aged if self._vouched(s.user_id, d, s.created)}
        return self._cached(("udev", s.user_id, s.created), find)

    def _vouched(self, user_id: str, device_id: str, at) -> bool:
        """Does something else speak for this device? It was used on an office network, on a network the account
        knew before the device appeared, or on one an older device of the account uses. The first devices of an
        account need nobody: there is nothing older to compare them with. Nor does a device that has been in use
        for weeks (UNVOUCHED_AFTER_DAYS)."""
        h = self.rc.history
        first = h.first_use(user_id, "device", device_id)
        if first is None:
            return False
        began = h.user_first_seen(user_id)
        before_it = first - self.familiar_after
        if began is None or began > before_it or first <= at - self.unvouched_after:
            return True
        runs = self.rc.runs(user_id)
        older = h.user_devices(user_id, before_it)
        mine, others = set(), set()
        for o, begin, _end, _n in runs:
            if begin >= at:
                continue
            if o.device_id == device_id:
                if self.rc.trusted(o):
                    return True
                mine.add(o.asn)
            elif o.device_id in older:
                others.add(o.asn)
        mine.discard(None)
        return bool(mine & (h.user_asns(user_id, before_it) | others))

    def asns(self, s: SignIn) -> set[int]:
        """Networks that are the account's own: in use for long enough, or new but used by a device that is the
        account's own - the phone on a hotel's Wi-Fi makes that network the user's at once. Not by age alone: a
        network on which a device nobody vouches for is at work and none of the account's own (a stranger's
        datacenter with the device he registered, however long he stays). Nor by what was done on a machine whose
        place is not the person's (machines.py: a virtual machine in a cloud, a remote desktop): only the account's
        other use of such a network counts."""
        def find() -> set[int]:
            h, cut = self.rc.history, self.familiar_before(s)
            machines = self.rc.machines.networks(s.user_id)
            aged = {asn for asn in h.user_asns(s.user_id, cut)
                    if asn not in machines or (machines[asn][0] is not None and machines[asn][0] < cut)}
            devices = self.devices(s)
            own, strangers = set(), set()
            for o, begin, _end, _n, machine in self.rc.machines.runs(s.user_id):
                if not o.asn or begin >= s.created:
                    continue
                if o.device_id in devices or self.rc.trusted(o):
                    if not machine:
                        own.add(o.asn)
                elif o.device_id:
                    strangers.add(o.asn)
            return (aged - (strangers - own)) | own
        return self._cached(("uasn", s.user_id, s.created), find)

    def network_stats(self, s: SignIn) -> tuple | None:
        """(first seen, successful sign-ins) of the sign-in's network for the account - of a network it used on a
        machine whose place is not the person's, only the rest of its use (see asns)."""
        def find():
            machines = self.rc.machines.networks(s.user_id)
            if s.asn in machines:
                first, n = machines[s.asn]
                return (first, n) if first is not None else None
            return self.rc.history.user_network_stats(s.user_id, s.asn)
        return self._cached(("ustat", s.user_id, s.asn), find)

    def colleagues(self, s: SignIn, net: tuple[str, str] | None) -> int:
        """How many other accounts use the sign-in's network - of a cloud or hosting network not those that use it
        only on a machine there (machines.Machines.colleagues)."""
        from .machines import CLOUD_CATEGORIES

        def find() -> int:
            if net and net[1].lower() in CLOUD_CATEGORIES:
                return self.rc.machines.colleagues(s.asn, s.created, s.user_id)
            return self.rc.history.asn_user_count(s.asn, s.created, s.user_id)
        return self._cached(("asnp", s.asn, s.user_id), find)

    def known_device(self, s: SignIn) -> bool:
        return bool(s.device_id) and s.device_id in self.devices(s)

    @staticmethod
    def _span(delta: timedelta) -> str:
        minutes = delta.total_seconds() / 60
        return "less than a minute" if minutes < 1 else f"{int(minutes)} min" if minutes < 60 else f"{int(minutes // 60)} h"

    # ------------------------------------------------------------ assess
    def assess(self, s: SignIn, base: int, base_reason: str, extra: list[Factor] | None = None,
               floor: int = 0, covers: tuple[str, ...] = (), office: tuple[int, str] | None = None,
               floor_reason: str = "") -> Assessment:
        """``covers``: what the base reason already says and counts, so it is not counted a second time - "flow"
        (device code / ROPC), "password_only", "risk_rating" (Entra's rating is the base: the detections it is
        made of are named, not added) and "device_identity" (a device that is just being registered has none).
        ``office``: (points, why) in place of the usual -30 for a corporate network, where being in the office says
        little about this sign-in. ``floor``: never rated lower; ``floor_reason`` says why when that applies."""
        rc, h = self.rc, self.rc.history
        f: list[Factor] = [Factor(base, base_reason)]
        f.extend(extra or [])
        acct = rc.accounts.get(s.user_id) if rc.accounts else None
        if acct:
            f.extend(self.account_factors(acct, s))

        # --- network
        net = self.network(s)
        trusted = rc.trusted(s) or (s.asn in self.trusted_asns)
        if trusted:
            name = rc.trusted_label(s) if rc.trusted(s) else f"trusted network AS{s.asn}"
            f.append(Factor(office[0], f"Corporate network: {name} - {office[1]}") if office
                     else Factor(-30, f"Corporate network: {name}"))
        if net:
            name, category = net
            f.append(Factor(netintel.ASN_CATEGORY_POINTS.get(category, 15), f"{category.capitalize()} network: {name} (AS{s.asn})"))
        events = [e.lower() for e in s.risk_events]
        # an anonymous-IP detection and a VPN/hosting network are the same evidence: count it once
        same_as_network = net is not None and net[1] != "cloud"
        in_rating = {e for e in events if "risk_rating" in covers and e in GENERIC_RISK_EVENTS}
        risk_points = sum(RISK_EVENT_POINTS.get(e, 10) for e in events
                          if not (e == "anonymizedipaddress" and same_as_network) and e not in in_rating)
        if events:
            f.append(Factor(min(40, risk_points), "Entra ID Protection detections: " + ", ".join(s.risk_events)
                            + (" (anonymous IP already counted as network)" if same_as_network and
                               "anonymizedipaddress" in events else "")
                            + (" (what the rating is made of: not counted again)" if in_rating else "")))
        anonymous = (net is not None and net[1] != "cloud") or "anonymizedipaddress" in events
        if anonymous and s.user_id and not (acct and acct.mfa_excluded):  # no excuses for password-only accounts
            vpn_days = self._cached(("vdays", s.user_id, s.created.date()), lambda: h.user_anon_days(s.user_id, s.created))
            if vpn_days >= HABIT_MIN_VPN_DAYS:
                f.append(Factor(-10, f"User regularly signs in through VPNs ({vpn_days} earlier days in 30)"))
        if s.asn and not trusted:
            stats = self.network_stats(s)
            habitual = bool(stats and stats[0] <= s.created - timedelta(days=HABIT_MIN_DAYS)
                            and stats[1] >= HABIT_MIN_SIGNINS and s.asn in self.asns(s))
            if habitual:
                f.append(Factor(-15, f"Habitual network of the user ({self.asn_label(s.asn)}: {stats[1]} sign-ins "
                                     f"since {stats[0].astimezone():%d.%m.})"))
            elif s.asn in self.asns(s):
                f.append(Factor(-10, f"User's usual network ({self.asn_label(s.asn)})"))
            else:
                peers = self.colleagues(s, net)
                if peers >= 3:
                    f.append(Factor(-10, f"Network {self.asn_label(s.asn)} also used by {peers} colleagues"))
                elif peers == 0:
                    f.append(Factor(10, f"Network {self.asn_label(s.asn)} never seen in the tenant"))

        # --- an address an attacker demonstrably used, known from another finding (indicators.py)
        mark = rc.hostile(s) if hasattr(rc, "hostile") else None
        if mark and not trusted and not self.known_device(s):
            f.append(Factor(mark.points, f"Known attacker address: used in {mark.describe()}"))
        elif not mark and not trusted and s.asn and hasattr(rc, "hostile_network"):
            # a network that only ever guesses passwords here (indicators.derive_networks) - counted for what got
            # past the password from it, on no device and no network the account knows
            net_mark = rc.hostile_network(s)
            if net_mark and self._past_password(s) and not self.known_device(s) \
                    and s.asn not in self.asns(s) \
                    and not h.asn_user_count(s.asn, s.created, s.user_id):
                f.append(Factor(net_mark.points, f"Network that only guesses passwords here: {net_mark.describe()}"))

        # --- device
        known = self.known_device(s)
        if s.device_id:
            if known:
                f.append(Factor(-20, f"Known device of the user ({s.device_name or s.device_id[:8]})"))
            if s.corp_device:
                f.append(Factor(-15, f"Company-managed device ({', '.join(p for p in (s.trust_type, 'compliant' if s.compliant else '') if p)})"))
            elif not known:
                first = h.first_use(s.user_id, "device", s.device_id) if s.user_id else None
                if first and first < self.familiar_before(s):  # old enough, but nothing else speaks for it
                    f.append(Factor(5, f"Device in use since {timefmt.stamp(first)} ({s.trust_type or 'unmanaged'}), but "
                                       "only on networks the account does not otherwise use: nothing vouches for it"))
                elif first and first < s.created:  # there, but only just: it cannot vouch for this sign-in yet
                    f.append(Factor(5, f"Device first used by this account {self._span(s.created - first)} before "
                                       f"({s.trust_type or 'unmanaged'}) - too new to count as the user's own"))
                else:
                    f.append(Factor(5, f"Device not seen before for this user ({s.trust_type or 'unmanaged'})"))
        elif "device_identity" not in covers:
            # (whether the account has registered devices at all: any device counts, however new)
            usual_devices = self._cached(("anydev", s.user_id, s.created), lambda: h.user_devices(s.user_id, s.created))
            if usual_devices:
                f.append(Factor(10, "No device identity although the user normally signs in with registered devices"))
            elif acct and acct.mfa_excluded:
                f.append(Factor(0, "No device identity (normal for this account)"))
            else:
                f.append(Factor(5, "No device identity (unregistered device or anonymous browser)"))
        if s.client and not (s.device_id and s.corp_device):
            # unmanaged devices: the same OS + browser family the user already used is a weak "same person" signal
            clients = self._cached(("ucli", s.user_id, s.created),
                                   lambda: h.user_clients(s.user_id, self.familiar_before(s)))
            if s.client in clients:
                f.append(Factor(-10, f"Known client of the user ({s.client.replace('|', ', ')})"))
            elif clients:
                f.append(Factor(5, f"Client never used by this user ({s.client.replace('|', ', ')})"))

        # --- which Authenticator approved the MFA (only meaningful when the sign-in succeeded)
        if s.success and s.mfa_device_id and s.user_id:
            approvers = self._cached(("umfadev", s.user_id, s.created),
                                     lambda: h.user_profile(s.user_id, "mfadev", self.familiar_before(s)))
            if s.mfa_device_id in approvers:
                f.append(Factor(-10, "MFA approved on the user's usual Authenticator device"))
            elif approvers:
                f.append(Factor(20, "MFA approved on an Authenticator device this user never used before "
                                    f"({s.mfa_device_os or 'unknown OS'}) - newly registered by someone else?"))

        # --- authentication
        if s.prt and (known or s.corp_device or not s.device_id):
            # (the token is bound to the device: it says as much as the device does - nothing, when that is new)
            f.append(Factor(-10, "Device-bound SSO token (Primary Refresh Token)"))
        if s.phishing_resistant:
            f.append(Factor(-15, "Phishing-resistant authentication (" + ", ".join(s.auth_methods) + ")"))
        elif (s.interactive and s.success and s.auth_requirement == "singleFactorAuthentication" and s.password_ok
              and "password_only" not in covers):
            f.append(Factor(10, "Password only, no MFA"))
        if any(m.lower() == "passwordless phone sign-in" for m in s.auth_methods):
            f.append(Factor(-5, "Passwordless sign-in with the user's registered Authenticator (no password typed)"))
        if any(w in m.lower() for m in s.auth_methods for w in netintel.WEAK_MFA_METHODS):
            f.append(Factor(5, "Weak MFA method (SMS/voice)"))

        # --- client (legacy protocols are logged as ROPC with user agent BAV2ROPC: not an attack tool per se)
        legacy = s.client_app.lower() in netintel.LEGACY_CLIENT_APPS
        agent = self.suspicious_agent(s) if s.interactive and not legacy else None
        if agent:
            f.append(Factor(25, f"Automation / attack-tool client ({agent})"))
        if s.auth_protocol.lower() in ("devicecode", "ropc") and not legacy and "flow" not in covers:
            f.append(Factor(15, f"{'Device code' if s.auth_protocol.lower() == 'devicecode' else 'ROPC (password-only)'} flow"))

        score = min(100, max(0, sum(x.points for x in f)))
        if score < floor:  # said, so that the score can be followed from the reasons
            f.append(Factor(0, f"Rated at least {severity_for(floor).label} ({floor}): "
                               + (floor_reason or "this kind of finding is always shown")))
            score = floor
        return Assessment(score=score, factors=f, label=self._label(s, f, net, trusted),
                          context=acct.context(rc.now) if acct else "")

    @staticmethod
    def _past_password(s: SignIn) -> bool:
        from . import rules  # (rules imports this module)

        return s.success or s.error_code == rules.MFA_DENIED_CODE or rules.password_proven(s)

    @staticmethod
    def account_factors(acct, s: SignIn) -> list[Factor]:
        """Account context: raises impact / strictness, never a blanket discount for an account type."""
        out = []
        if acct.breakglass:
            out.append(Factor(20, "Break-glass (emergency access) account - should not be used in normal operation"))
        if acct.mfa_excluded:
            out.append(Factor(15, "Account can sign in without MFA: " + "; ".join(acct.mfa_excluded[:2])))
        elif acct.mfa_gap:
            out.append(Factor(20, "No MFA method registered: whoever knows the password can register their own MFA"))
        roles = acct.roles + [r for r in acct.pim_roles if r not in acct.roles]
        if acct.privileged_tier == 2:
            out.append(Factor(20, "Highly privileged account (" + ", ".join(roles[:3]) + ")"))
        elif acct.privileged_tier == 1:
            out.append(Factor(10, "Admin account (" + ", ".join(roles[:3]) + ")"))
        if not acct.enabled:
            out.append(Factor(30, "Account is disabled - a successful sign-in should be impossible") if s.success
                       else Factor(0, "Account is disabled (attempts cannot succeed)"))
        return out

    @staticmethod
    def _label(s: SignIn, factors: list[Factor], net: tuple[str, str] | None, trusted: bool) -> str:
        texts = " ".join(x.text for x in factors).lower()
        if trusted:
            return LABEL_CORPORATE
        if net or "anonymizedipaddress" in texts or "vpn/proxy switch" in texts:
            return LABEL_HABITUAL_VPN if ("habitual network" in texts or "regularly signs in through vpns" in texts) \
                else LABEL_VPN
        if s.device_id and ("known device" in texts or s.corp_device):
            return LABEL_TRAVEL
        if not s.device_id or "device not seen before" in texts or "device first used by this account" in texts \
                or "nothing vouches for it" in texts:
            return LABEL_UNKNOWN_DEVICE
        return ""
