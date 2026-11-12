"""Entities in alert texts (users, IPs, apps, log entry IDs ...) and what clicking them does.

Pure functions - no Tk, no Graph - so they can be tested. The UI turns the entities into clickable links
(radar.ui.richtext); :mod:`radar.resolver` looks up the object IDs that some portal deep links need.

Entra has no documented deep-link scheme. The portal routes below are the ones the portal itself uses in its
address bar; if Microsoft renames a menu item the blade opens on its default page instead.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote

PORTAL = "https://portal.azure.com/#view/"
SIGNIN_LOGS_URL = PORTAL + "Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns"
AUDIT_LOGS_URL = PORTAL + "Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit"
XTENANT_URL = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/CrossTenantAccessSettings"
ROLES_URL = PORTAL + "Microsoft_AAD_IAM/AllRolesBlade"
ROLE_DOCS = "https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference"
PERMISSION_DOCS = "https://learn.microsoft.com/graph/permissions-reference"


@dataclass(frozen=True)
class Entity:
    """``kind``: user, app, group, device, policy, role, permission, ip, asn, url, signin, audit, correlation,
    tenant, partner, alert, guid (unknown directory id) or id (an id that can only be copied)."""

    kind: str
    value: str
    start: int = 0
    end: int = 0

    @property
    def short(self) -> str:
        return self.value if len(self.value) <= 48 else self.value[:45] + "..."


# ------------------------------------------------------------------ detection
_URL = re.compile(r"https?://[^\s<>\"')\]]+")
_EMAIL = re.compile(r"(?<![\w.%+'#-])[A-Za-z0-9][A-Za-z0-9._%+'#-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"(?<![\w./])(?:\d{1,3}\.){3}\d{1,3}(?!\w)(?!\.\d)")
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_GUID = re.compile(r"(?<![\w-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\w-])")
_ASN = re.compile(r"(?<!\w)AS\d{1,10}(?!\w)")
_COUNT_NOTE = re.compile(r"\s*\((?:\d+x?|[0-9a-fA-F-]{36}|\d{1,2}\.\d{1,2}\.\d{2,4})\)\s*$")  # "(18)", "(<guid>)", date

#: GUIDs in these fields (lower case, without ':') are of this kind
GUID_FIELD_KINDS = {
    "sign-in id": "signin", "audit id": "audit", "correlation id": "correlation", "user id": "user",
    "home tenant": "tenant", "support tenant": "tenant", "resource tenant": "tenant", "tenant": "tenant",
    "device id": "device", "application": "app", "resource": "app", "app id": "app",
    "request id": "id", "session id": "id", "unique token identifier": "id", "sign-in correlation id": "id",
}
#: the whole value is one entity (IDs that are not GUIDs)
WHOLE_VALUE_KINDS = {"audit id": "audit"}
#: names in these fields (comma separated) are directory objects / alerts of this kind
NAME_FIELD_KINDS = {
    "app": "app", "application": "app", "applications": "app", "targeted apps": "app", "resource": "app",
    "initiated by": "app", "group": "group", "excluded via": "group", "excluded from": "policy", "roles": "role",
    "device": "device", "device name": "device", "application permissions": "permission",
    "delegated permissions": "permission", "step": "alert", "correlated with": "alert", "related signals": "alert",
    "partner": "partner", "policy": "policy",
}
_NOT_NAMES = {"", "-", "unknown", "(blank)", "none", "n/a", "all users", "one user", "yes", "no"}


def _norm(field: str) -> str:
    return (field or "").strip().rstrip(":").strip().lower()


def _valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _name_tokens(text: str, kind: str) -> list[Entity]:
    out = []
    for m in re.finditer(r"[^\n]+" if kind == "alert" else r"[^,;\n]+", text):
        token, start = m.group(), m.start()
        start += len(token) - len(token.lstrip())
        token = token.strip()
        if kind == "device":
            token = token.split(" / ")[0].strip()  # evidence: "LT-TOR-00102 / Windows10 / Edge 18.26200"
        note = _COUNT_NOTE.search(token)
        if note:
            token = token[:note.start()]
        if token.lower() in _NOT_NAMES or ("@" in token and kind != "alert"):
            continue  # an address is a user (an alert title may contain one)
        out.append(Entity(kind, token, start, start + len(token)))
    return out


def find_entities(text: str, field: str = "") -> list[Entity]:
    """Clickable entities in ``text`` (a value of ``field``), sorted by position and not overlapping."""
    text = str(text or "")
    f = _norm(field)
    if f in WHOLE_VALUE_KINDS:
        value = text.strip()
        if value.lower() in _NOT_NAMES:
            return []
        start = text.index(value)
        return [Entity(WHOLE_VALUE_KINDS[f], value, start, start + len(value))]
    if NAME_FIELD_KINDS.get(f) == "alert":
        return _name_tokens(text, "alert")  # each line is the title of another alert
    found: list[Entity] = []

    def add(kind: str, start: int, end: int) -> None:
        if not any(start < e.end and e.start < end for e in found):
            found.append(Entity(kind, text[start:end], start, end))

    for m in _URL.finditer(text):
        add("url", m.start(), m.end() - len(m.group()) + len(m.group().rstrip(".,;:")))
    for m in _EMAIL.finditer(text):
        add("user", m.start(), m.end())
    if "agent" not in f:  # version numbers in user agents look like IPv4 addresses
        for m in _IPV4.finditer(text):
            if _valid_ip(m.group()):
                add("ip", m.start(), m.end())
        for m in _IPV6.finditer(text):
            if m.group().count(":") >= 2 and sum(c.isalnum() for c in m.group()) >= 2 and _valid_ip(m.group()):
                add("ip", m.start(), m.end())
    for m in _GUID.finditer(text):
        add(GUID_FIELD_KINDS.get(f, "guid"), m.start(), m.end())
    for m in _ASN.finditer(text):
        add("asn", m.start(), m.end())
    if f in NAME_FIELD_KINDS:
        for e in _name_tokens(text, NAME_FIELD_KINDS[f]):
            add(e.kind, e.start, e.end)
    return sorted(found, key=lambda e: e.start)


def row_entity(row: dict[str, str] | None) -> Entity | None:
    """What opening (double-clicking) an evidence / table row shows."""
    row = row or {}
    for column, kind in (("Sign-in ID", "signin"), ("Audit ID", "audit"), ("Correlation ID", "correlation"),
                         ("Step", "alert")):
        if str(row.get(column) or "").strip():
            return Entity(kind, str(row[column]).strip())
    for column in ("Account", "User"):
        found = [e for e in find_entities(str(row.get(column) or ""), column) if e.kind == "user"]
        if found:
            return Entity("user", found[0].value)
    for column in ("IP address", "IP"):
        found = [e for e in find_entities(str(row.get(column) or ""), column) if e.kind == "ip"]
        if found:
            return Entity("ip", found[0].value)
    return None


# -------------------------------------------------------------------- actions
ACTIONS: dict[str, list[tuple[str, str]]] = {
    "user": [("Open user in Entra", "user"), ("Sign-in logs of this user (Entra)", "user_signins"),
             ("Authentication methods of this user (Entra)", "user_methods"),
             ("Audit logs of this user (Entra)", "user_audit")],
    "app": [("Open enterprise app in Entra", "app"), ("Permissions of this app (Entra)", "app_permissions"),
            ("App registration: certificates & secrets (Entra)", "app_credentials"),
            ("App registration: owners (Entra)", "app_owners")],
    "group": [("Open group in Entra", "group"), ("Members of this group (Entra)", "group_members")],
    "device": [("Open device in Entra", "device")],
    "policy": [("Open Conditional Access policy (Entra)", "policy")],
    "role": [("What this role can do (Microsoft Learn)", "role_docs"), ("Roles and administrators (Entra)", "roles")],
    "permission": [("What this permission allows (Microsoft Learn)", "permission_docs")],
    "ip": [("Look up IP reputation (AbuseIPDB)", "abuseipdb"), ("IP owner and location (ipinfo.io)", "ipinfo")],
    "asn": [("Network owner (ipinfo.io)", "asn")],
    "url": [("Open link", "url")],
    "signin": [("View sign-in log entry", "view_signin")],
    "audit": [("View audit log entry", "view_audit")],
    "correlation": [("View the audit entries of this operation", "view_correlation")],
    "tenant": [("Which organisation is this tenant?", "tenant"), ("Cross-tenant access settings (Entra)", "xtenant")],
    "partner": [("Cross-tenant access settings (Entra)", "xtenant")],
    "alert": [("Open this alert", "open_alert")],
    "guid": [("Find this ID in Entra", "find_id")],
    "id": [],
}
IN_APP_ACTIONS = {"view_signin", "view_audit", "view_correlation", "open_alert"}
#: what a directory lookup of an unknown ID opens, by the kind of object found
PRIMARY_ACTION = {"user": "user", "app": "app", "group": "group", "device": "device", "policy": "policy",
                  "tenant": "tenant", "role": "role_docs", "application": "app_registration"}


def actions(entity: Entity) -> list[tuple[str, str]]:
    """(menu label, action id) for an entity; the first one is what a click does."""
    return list(ACTIONS.get(entity.kind, []))


def _slug(text: str, keep: str = "-") -> str:
    return re.sub(rf"[^a-z0-9{keep}]", "", text.strip().lower().replace(" ", "-"))


def static_url(entity: Entity, action: str) -> str:
    """URL of an action that needs no directory lookup ('' if it needs one or is not a link)."""
    v = entity.value.strip()
    return {
        "url": v,
        "abuseipdb": f"https://www.abuseipdb.com/check/{quote(v)}",
        "ipinfo": f"https://ipinfo.io/{quote(v)}",
        "asn": f"https://ipinfo.io/{quote(v.upper())}",
        "role_docs": f"{ROLE_DOCS}#{_slug(v)}",
        "roles": ROLES_URL,
        "permission_docs": f"{PERMISSION_DOCS}#{_slug(v, keep='')}",
        "xtenant": XTENANT_URL,
    }.get(action, "")


def resolve_kind(entity: Entity, action: str) -> str:
    """Kind of directory object to look up for ``action`` (e.g. a tenant id asked 'which organisation')."""
    return "guid" if action == "find_id" else entity.kind


def portal_url(action: str, info: dict) -> str:
    """Entra portal deep link for a looked-up object (``info`` from radar.resolver), '' if none."""
    oid, app_id = info.get("id", ""), info.get("appId", "")
    user = PORTAL + "Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/{page}/userId/" + oid
    sp = PORTAL + "Microsoft_AAD_IAM/ManagedAppMenuBlade/~/{page}/objectId/" + oid + "/appId/" + app_id
    reg = PORTAL + "Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/{page}/appId/" + app_id
    group = PORTAL + "Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/{page}/groupId/" + oid
    urls = {
        "user": user.format(page="overview"), "user_signins": user.format(page="SignIns"),
        "user_methods": user.format(page="UserAuthMethods"), "user_audit": user.format(page="AuditLogs"),
        "app": sp.format(page="Overview"), "app_permissions": sp.format(page="Permissions"),
        "app_registration": reg.format(page="Overview"), "app_credentials": reg.format(page="Credentials"),
        "app_owners": reg.format(page="Owners"),
        "group": group.format(page="Overview"), "group_members": group.format(page="Members"),
        "device": (PORTAL + "Microsoft_AAD_Devices/DeviceDetailsMenuBlade/~/Properties/objectId/" + oid
                   + "/deviceId/" + info.get("deviceId", "")),
        "policy": PORTAL + "Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/" + oid,
        "xtenant": XTENANT_URL,
        "role_docs": f"{ROLE_DOCS}#{_slug(info.get('name', ''))}",
    }
    needs = {"user": oid, "app": oid and app_id, "app_registration": app_id, "group": oid, "device": oid,
             "policy": oid}
    family = action.split("_")[0] if action != "app_registration" else action
    if action in ("app_credentials", "app_owners"):
        family = "app_registration"
        if not info.get("registered"):
            return ""
    if not needs.get(family, True):
        return ""
    return urls.get(action, "")


def describe(info: dict) -> str:
    """One line about a looked-up object, e.g. 'user Chris Kent (chris@..., guest)'."""
    kind = {"app": "enterprise app", "application": "app registration", "policy": "Conditional Access policy",
            "tenant": "tenant"}.get(info.get("kind", ""), info.get("kind", "object"))
    name = info.get("name") or info.get("id") or "?"
    detail = info.get("detail")
    return f"{kind} {name}" + (f" ({detail})" if detail else "")
