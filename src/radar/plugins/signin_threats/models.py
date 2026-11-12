"""Normalised, compact representation of a Graph signIn record."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

_FRACTION = re.compile(r"\.(\d+)")
# networkLocationDetails.networkType values meaning "a network the tenant marked as trusted"
TRUSTED_NETWORK_TYPES = {"trustednamedlocation", "trusted", "intranet"}


def parse_time(value: str) -> datetime:
    """Parse Graph timestamps such as 2026-11-09T10:11:12.1234567Z (7 fraction digits)."""
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    dt = datetime.fromisoformat(text)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def graph_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def os_family(os_name: str) -> str:
    """'Ios 27.2.0' -> 'iOS', 'Windows10' -> 'Windows' ... ('' if unknown)."""
    o = (os_name or "").lower()
    for key, name in (("ios", "iOS"), ("ipad", "iOS"), ("android", "Android"), ("windows", "Windows"),
                      ("mac", "macOS"), ("linux", "Linux"), ("chrome", "ChromeOS")):
        if o.startswith(key) or f" {key}" in o:
            return name
    return ""


_SENTENCE_END = re.compile(r"(?<=[.!?])\s")
# additionalDetails values that describe the MFA state or link to docs, not why the sign-in failed
_STATUS_NOISE = ("mfa requirement", "mfa completed", "mfa required in", "http")


def _first_sentence(text: str, limit: int = 110) -> str:
    text = " ".join((text or "").replace("\xa0", " ").split())
    first = _SENTENCE_END.split(text, maxsplit=1)[0]
    return first if len(first) <= limit else first[:limit - 3].rstrip() + "..."


def browser_family(browser: str) -> str:
    """'Firefox 159.0' -> 'Firefox', 'Rich Client 4.90.0.0' -> 'Rich Client'."""
    words = [w for w in (browser or "").split() if not any(ch.isdigit() for ch in w)]
    return " ".join(words[:2])


@dataclass
class SignIn:
    id: str
    created: datetime
    user_id: str = ""
    upn: str = ""
    user_name: str = ""
    user_type: str = ""
    app: str = ""
    app_id: str = ""
    resource: str = ""
    ip: str = ""
    city: str = ""
    state: str = ""
    country: str = ""
    lat: float | None = None
    lon: float | None = None
    error_code: int = 0
    failure_reason: str = ""
    additional_details: str = ""
    client_app: str = ""
    interactive: bool = True
    event_type: str = ""
    risk_during: str = ""
    risk_aggregated: str = ""
    risk_state: str = ""
    risk_events: list[str] = field(default_factory=list)
    auth_protocol: str = ""
    transfer_method: str = ""
    ca_status: str = ""
    device_id: str = ""
    device_name: str = ""
    os: str = ""
    browser: str = ""
    trust_type: str = ""
    compliant: bool = False
    managed: bool = False
    trusted_network: bool = False
    network_names: list[str] = field(default_factory=list)
    untrusted_networks: list[str] = field(default_factory=list)  # matched named locations NOT marked trusted
    asn: int | None = None
    user_agent: str = ""
    session_id: str = ""
    correlation_id: str = ""
    resource_id: str = ""
    auth_requirement: str = ""
    auth_methods: list[str] = field(default_factory=list)  # succeeded authentication steps
    password_ok: bool = False  # a "Password" step succeeded (the attacker knows the password)
    incoming_token: str = ""
    token_protection: str = ""
    app_owner_tenant: str = ""   # tenant that owns the client app (Microsoft for first-party apps)
    client_credential: str = ""  # none = public client (app on a device); clientAssertion etc. = a server
    mfa_device_id: str = ""      # the Authenticator installation that received / approved the MFA request
    mfa_device_os: str = ""
    number_match: str = ""       # number-matching outcome(s), e.g. numberMatchDeny

    # ------------------------------------------------------------ factory
    @classmethod
    def from_graph(cls, d: dict[str, Any], event_type: str = "") -> "SignIn":
        status = d.get("status") or {}
        loc = d.get("location") or {}
        geo = loc.get("geoCoordinates") or {}
        dev = d.get("deviceDetail") or {}
        lat, lon = geo.get("latitude"), geo.get("longitude")
        if lat in (None, 0) and lon in (None, 0):
            lat = lon = None
        types = d.get("signInEventTypes") or []
        risk_events = d.get("riskEventTypes_v2") or d.get("riskEventTypes") or []
        networks = [n for n in (d.get("networkLocationDetails") or []) if isinstance(n, dict)]
        trusted = any(str(n.get("networkType", "")).lower() in TRUSTED_NETWORK_TYPES for n in networks)
        net_names = sorted({str(x) for n in networks for x in (n.get("networkNames") or []) if x})
        untrusted = sorted({str(x) for n in networks if str(n.get("networkType", "")).lower() not in TRUSTED_NETWORK_TYPES
                            for x in (n.get("networkNames") or []) if x})
        steps = [s for s in (d.get("authenticationDetails") or []) if isinstance(s, dict)]
        methods = [str(s.get("authenticationMethod")) for s in steps if s.get("succeeded") and s.get("authenticationMethod")]
        asn = d.get("autonomousSystemNumber")
        return cls(
            id=d["id"],
            created=parse_time(d["createdDateTime"]),
            user_id=d.get("userId") or "",
            upn=(d.get("userPrincipalName") or "").lower(),
            user_name=d.get("userDisplayName") or "",
            user_type=d.get("userType") or "",
            app=d.get("appDisplayName") or "",
            app_id=d.get("appId") or "",
            resource=d.get("resourceDisplayName") or "",
            ip=d.get("ipAddress") or "",
            city=loc.get("city") or "",
            state=loc.get("state") or "",
            country=(loc.get("countryOrRegion") or "").upper(),
            lat=lat,
            lon=lon,
            error_code=int(status.get("errorCode") or 0),
            failure_reason=status.get("failureReason") or "",
            additional_details=status.get("additionalDetails") or "",
            client_app=d.get("clientAppUsed") or "",
            interactive=bool(d.get("isInteractive", event_type in ("", "interactiveUser"))),
            event_type=event_type or (types[0] if types else "interactiveUser"),
            risk_during=(d.get("riskLevelDuringSignIn") or "").lower(),
            risk_aggregated=(d.get("riskLevelAggregated") or "").lower(),
            risk_state=d.get("riskState") or "",
            risk_events=[str(x) for x in risk_events if x and x != "none"],
            auth_protocol=d.get("authenticationProtocol") or "",
            transfer_method=d.get("originalTransferMethod") or "",
            ca_status=d.get("conditionalAccessStatus") or "",
            device_id=dev.get("deviceId") or "",
            device_name=dev.get("displayName") or "",
            os=dev.get("operatingSystem") or "",
            browser=dev.get("browser") or "",
            trust_type=dev.get("trustType") or "",
            compliant=bool(dev.get("isCompliant")),
            managed=bool(dev.get("isManaged")),
            trusted_network=trusted,
            network_names=net_names,
            untrusted_networks=untrusted,
            asn=int(asn) if isinstance(asn, (int, float)) and asn > 0 else None,
            user_agent=(d.get("userAgent") or "")[:300],
            session_id=d.get("sessionId") or "",
            correlation_id=d.get("correlationId") or "",
            resource_id=d.get("resourceId") or "",
            auth_requirement=d.get("authenticationRequirement") or "",
            auth_methods=list(dict.fromkeys(methods)),
            password_ok=any(m.lower() == "password" for m in methods),
            incoming_token=d.get("incomingTokenType") or "",
            token_protection=str(d.get("signInTokenProtectionStatus") or ""),
            app_owner_tenant=d.get("appOwnerTenantId") or "",
            client_credential=d.get("clientCredentialType") or "",
            mfa_device_id=(d.get("authenticationAppDeviceDetails") or {}).get("deviceId") or "",
            mfa_device_os=(d.get("authenticationAppDeviceDetails") or {}).get("operatingSystem") or "",
            number_match=",".join(sorted({str(x.get("status")) for x in d.get("authenticationAppPolicyEvaluationDetails") or []
                                          if isinstance(x, dict) and str(x.get("status", "")).startswith("numberMatch")})),
        )

    # -------------------------------------------------------- persistence
    def to_json(self) -> str:
        data = asdict(self)
        data["created"] = self.created.isoformat()
        return json.dumps({k: v for k, v in data.items() if v not in ("", None, [], False) or k == "interactive"})

    @classmethod
    def from_json(cls, text: str) -> "SignIn":
        data = json.loads(text)
        data["created"] = datetime.fromisoformat(data["created"])
        return cls(**data)

    # ------------------------------------------------------------ helpers
    @property
    def success(self) -> bool:
        return self.error_code == 0

    @property
    def who(self) -> str:
        return self.upn or self.user_name or self.user_id or "(unknown user)"

    @property
    def corp_device(self) -> bool:
        """Compliant or Entra (hybrid) joined - i.e. a company-managed device, not just registered."""
        return bool(self.device_id) and (self.compliant or self.trust_type in ("Azure AD joined", "Hybrid Azure AD joined"))

    @property
    def prt(self) -> bool:
        return self.incoming_token.lower() == "primaryrefreshtoken"

    @property
    def mfa(self) -> bool:
        return self.auth_requirement == "multiFactorAuthentication"

    @property
    def client(self) -> str:
        """Client fingerprint (OS + browser family), e.g. 'Windows|Firefox' - stable across browser updates."""
        osf, bf = os_family(self.os), browser_family(self.browser)
        return f"{osf}|{bf}" if osf and bf else ""

    @property
    def ms_backend(self) -> bool:
        """A Microsoft cloud service fetching a token on the user's behalf (e.g. 'Olympus' reading Office policies
        when an Office app starts). Its IP is the one the request reached the service from - often another network
        path of the same device - and it frequently has no device id. Not a second device, not a replay."""
        from .netintel import MICROSOFT_BACKEND_APPS, MICROSOFT_TENANTS
        if self.app_id in MICROSOFT_BACKEND_APPS:
            return True
        return (not self.interactive and not self.user_agent and self.app_owner_tenant in MICROSOFT_TENANTS
                and self.client_credential not in ("", "none"))

    @property
    def fresh_mfa(self) -> bool:
        """A second factor was performed in THIS sign-in (not satisfied by an earlier cookie/token claim).
        An AiTM proxy always has to do a fresh MFA: the victim's real session cookies never reach it."""
        return any(m.lower() not in ("password", "previously satisfied") for m in self.auth_methods)

    @property
    def phishing_resistant(self) -> bool:
        from .netintel import PHISHING_RESISTANT_METHODS
        return any(p in m.lower() for m in self.auth_methods for p in PHISHING_RESISTANT_METHODS)

    @property
    def location(self) -> str:
        parts = [p for p in (self.city, self.country) if p]
        return ", ".join(parts) or "unknown location"

    @property
    def reason(self) -> str:
        """Short failure reason for tables: first sentence of Entra's failureReason, plus a short
        additionalDetails hint such as 'MFA denied; user declined' (the full texts are in the log entry)."""
        main = _first_sentence(self.failure_reason) or _first_sentence(self.additional_details)
        extra = " ".join(self.additional_details.replace("\xa0", " ").split())
        if self.failure_reason and extra and len(extra) <= 70 and not extra.lower().startswith(_STATUS_NOISE):
            main = f"{main} ({extra})"
        return main

    @property
    def result(self) -> str:
        if self.success:
            return "Success"
        return f"Failure {self.error_code}: {self.reason}" if self.reason else f"Failure {self.error_code}"

    def evidence(self) -> dict[str, str]:
        return {
            "Time": self.created.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "User": self.who,
            "Application": self.app,
            "IP address": self.ip,
            "Location": self.location,
            "Result": self.result,
            "Client app": self.client_app,
            "Type": "Interactive" if self.interactive else "Non-interactive",
            "Device": " / ".join(p for p in (self.device_name, self.os, self.browser) if p),
            "Network": ", ".join(self.network_names) + (" (trusted)" if self.trusted_network else ""),
            "ASN": f"AS{self.asn}" if self.asn else "",
            "Auth": " + ".join(self.auth_methods) or self.auth_requirement,
            "Device trust": ", ".join(p for p in (self.trust_type, "compliant" if self.compliant else "") if p),
            "User agent": self.user_agent[:120],
            "Risk": self.risk_during if self.risk_during not in ("", "none", "hidden") else "",
            "Sign-in ID": self.id,
        }


# ------------------------------------------------------------------ account changes (directory audit)
# kind -> (points, label). Admin-made changes weigh more: they are what a social-engineered help desk produces.
CHANGE_KINDS: dict[str, tuple[int, str]] = {
    "tap_issued": (30, "Temporary Access Pass issued"),
    "mfa_reset": (25, "MFA reset (re-registration required)"),
    "admin_method_added": (20, "MFA method added by an admin"),
    "admin_method_changed": (20, "MFA method changed by an admin"),
    "admin_method_deleted": (15, "MFA method deleted by an admin"),
    "password_reset_admin": (20, "Password reset by an admin"),
    "method_added": (15, "MFA method registered"),
    "method_changed": (10, "Default MFA method changed"),
    "method_deleted": (10, "MFA method deleted"),
    "password_reset_self": (10, "Self-service password reset"),
    "device_credential_added": (5, "Windows Hello for Business set up (device-bound)"),
    "mfa_prompt_reported": (0, "MFA prompt reported as not theirs"),  # not a change: see the mfa_report rule
}
REPORT_KIND = "mfa_prompt_reported"


def _change_kind(activity: str, reason: str) -> str | None:
    a, r = activity.lower(), reason.lower()
    if "temporary access pass" in r or "temporary access pass" in a:
        return "tap_issued"
    return {
        "user registered security info": "method_added",
        "user deleted security info": "method_deleted",
        "user changed default security info": "method_changed",
        "user updated security info": "method_changed",
        "admin registered security info": "admin_method_added",
        "admin updated security info": "admin_method_changed",
        "admin deleted security info": "mfa_reset" if "re-registration" in r else "admin_method_deleted",
        "reset password (by admin)": "password_reset_admin",
        "reset user password": "password_reset_admin",  # portal/Graph; the SSPR service variant is skipped below
        "reset password (self-service)": "password_reset_self",
        "user reset password": "password_reset_self",
        # Core Directory events (not in the "Authentication Methods" log)
        "add passwordless phone sign-in credential": "method_added",
        "add passkey (device-bound)": "method_added",
        "add windows hello for business credential": "device_credential_added",
        "delete passwordless phone sign-in credential": "method_deleted",
    }.get(a)


@dataclass
class AccountChange:
    """An MFA-method / password change of one user, from the directory audit log."""
    id: str
    created: datetime
    user_id: str
    upn: str = ""
    kind: str = ""
    detail: str = ""        # e.g. "User registered security info (Passkey)"
    actor: str = ""         # who did it (UPN, or app name)
    by_admin: bool = False  # done by someone else than the user
    actor_ip: str = ""      # NOTE: for IPv6 clients Entra logs a Microsoft gateway IPv4 here
    app_id: str = ""        # app the change was made in (My Sign-ins, App Access Panel, Entra portal ...)
    app: str = ""

    @classmethod
    def from_audit(cls, a: dict[str, Any], method: str = "") -> "AccountChange | None":
        if (a.get("result") or "").lower() != "success":
            return None
        activity, reason = (a.get("activityDisplayName") or "").strip(), (a.get("resultReason") or "").strip()
        kind = _change_kind(activity, reason)
        init = a.get("initiatedBy") or {}
        user, app = init.get("user") or {}, init.get("app") or {}
        target = next((t for t in a.get("targetResources") or [] if (t.get("type") or "").lower() == "user"
                       and t.get("id")), None)
        if not kind or not target:
            return None
        if activity.lower() == "reset user password" and not user:
            return None  # the password reset service's echo of a self-service reset (logged separately)
        upn = (target.get("userPrincipalName") or "").lower()
        actor_upn = (user.get("userPrincipalName") or "").lower()
        by_admin = bool(user) and (user.get("id") or actor_upn) not in ("", target["id"], upn) and actor_upn != upn
        if kind == "password_reset_admin" and not by_admin:
            kind = "password_reset_self"
        details = {str(d.get("key")): str(d.get("value") or "") for d in a.get("additionalDetails") or []
                   if isinstance(d, dict)}
        method = details.get("AuthenticationMethod") or method
        text = reason if reason and reason.lower() not in (activity.lower(), "none", "successfully completed reset.") \
            else activity
        if method and method.lower() not in text.lower():
            text += f" ({method})"
        return cls(id=a["id"], created=parse_time(a["activityDateTime"]), user_id=target["id"], upn=upn, kind=kind,
                   detail=text, actor=actor_upn or app.get("displayName") or "", by_admin=by_admin,
                   actor_ip=user.get("ipAddress") or "", app_id=app.get("appId") or "", app=app.get("displayName") or "")

    @classmethod
    def from_report(cls, a: dict[str, Any]) -> "AccountChange | None":
        """The audit entry Entra writes when a user reports an MFA prompt as not theirs ("Suspicious activity
        reported", service "Azure MFA"). It names the account, the time and the method - not where the prompt came
        from: that is in the sign-in log, in a row of its own that arrives up to 1-2 hours later."""
        if (a.get("result") or "").lower() != "success":
            return None
        user = (a.get("initiatedBy") or {}).get("user") or {}
        target = next((t for t in a.get("targetResources") or [] if (t.get("type") or "").lower() == "user"
                       and t.get("id")), None) or ({"id": user.get("id"), "userPrincipalName": user.get("userPrincipalName")}
                                                   if user.get("id") else None)
        if not target:
            return None
        details = {str(d.get("key")): str(d.get("value") or "") for d in a.get("additionalDetails") or []
                   if isinstance(d, dict)}
        method = details.get("AuthenticationMethod") or ""
        upn = (target.get("userPrincipalName") or "").lower()
        text = (a.get("activityDisplayName") or "Suspicious activity reported").strip() + (f" ({method})" if method else "")
        return cls(id=a["id"], created=parse_time(a["activityDateTime"]), user_id=target["id"], upn=upn,
                   kind=REPORT_KIND, detail=text, actor=upn)

    @property
    def points(self) -> int:
        return CHANGE_KINDS.get(self.kind, (10, ""))[0]

    @property
    def label(self) -> str:
        return CHANGE_KINDS.get(self.kind, (0, self.kind))[1]

    @property
    def guest(self) -> bool:
        return "#ext#" in self.upn

    def describe(self) -> str:
        who = f" by {self.actor}" if self.by_admin else ""
        return f"{self.created.astimezone():%d.%m. %H:%M} {self.detail}{who}"

    def evidence(self) -> dict[str, str]:
        return {"Time": self.created.astimezone().strftime("%Y-%m-%d %H:%M:%S"), "User": self.upn,
                "Application": self.app, "IP address": self.actor_ip, "Result": self.detail,
                "Type": f"Audit: change by {self.actor}" if self.by_admin else "Audit: change by the user",
                "Audit ID": self.id}

    def to_json(self) -> str:
        data = asdict(self)
        data["created"] = self.created.isoformat()
        return json.dumps({k: v for k, v in data.items() if v not in ("", None, False)})

    @classmethod
    def from_json(cls, text: str) -> "AccountChange":
        data = json.loads(text)
        data["created"] = datetime.fromisoformat(data["created"])
        return cls(**data)
