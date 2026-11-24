"""Directory audit watch: alerts on sensitive tenant changes (roles, app secrets, consent, CA, federation, guests).

In a typical tenant most audit events are provisioning/sync, role events are dominated by the
PIM activation lifecycle and app events by Microsoft-internal services. Those are filtered out; what remains
is scored (0-100) and grouped per actor, rule and day.
"""
from __future__ import annotations

from .. import linkify, timefmt
from pathlib import Path
import fnmatch
import json
import re
from collections import Counter, defaultdict
import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .. import entra
from ..graph import GraphError
from ..plugin_api import Finding, Plugin, PluginContext, Rule, Severity, StagedState
from .signin_threats.models import graph_time, parse_time
from .. import account_events
from .signin_threats.scoring import severity_for

# audit activities that give an account a new password WITHOUT needing the old one (see _password_signal)
PASSWORD_RESET_ACTIVITIES = {
    "reset password (self-service)": "self-service reset",
    "reset password (by admin)": "reset by an admin",
    "reset user password": "reset",
    "change user password": "changed",
}
AUDIT_URL = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit"
CATEGORIES = ("RoleManagement", "ApplicationManagement", "UserManagement", "Policy", "PolicyManagement",
              "DirectoryManagement", "GroupManagement", "CrossTenantAccessSettings", "KeyManagement", "Device",
              "AzureRBACRoleManagementElevateAccess", "ResourceManagement",
              "DelegatedAdminServiceProviderConstraints")

# ---- Microsoft 365 support cases (learn.microsoft.com/microsoft-365/admin/support-diagnostic-information-collection)
# Opening a case in the admin center adds the Microsoft Support tenant as cross-tenant service provider (actor: the
# admin); when an engineer works on it, Microsoft's Assist API adds support-tenant groups to the read-only
# "Microsoft 365 Support Engineer" role. Access ends when the case closes, at the latest 30 days after it was opened.
MS_SUPPORT_TENANT = "b4c546a4-7dac-46a6-a7dd-ed822a11efd3"
ASSIST_API_APP_ID = "2b8844d8-6c87-4fce-97a0-fbec9006e140"
SUPPORT_ENGINEER_ROLE = "00cf5c54-4693-4f59-a0ac-ab79ef0a974d"
SUPPORT_CASE_DAYS = 30
EXCLUSION_CACHE_HOURS = 6

# Microsoft-internal actors whose audit entries are consequences, not decisions (shell wildcards, lower case).
SYSTEM_INITIATORS = [
    "ms-pim", "azure ad pim", "aad app management", "azure ad application proxy",
    "microsoft azure ad internal - jit provisioning", "azure ad cloud sync", "microsoft approval management",
    "microsoft substrate management", "azure mfa strongauthenticationservice", "device registration service",
    "microsoft azure ad verified domain change*", "connectsyncprovisioning_*", "microsoft b2b admin worker",
    "azure credential configuration endpoint service", "intune *", "microsoft intune*",
]
PIM_LIFECYCLE = ("pim activation", "activation expired")
WEEKLY_RULES = {"app_credentials", "admin_credential_reset", "sensitive_reads", "app_owner_change", "tenant_changes"}

# ---- application consent: judged by WHAT is granted, not by who clicked "Accept" ----
CONSENT_ACTIVITIES = ("consent to application", "add delegated permission grant",
                      "add app role assignment to service principal")
# permissions that hand out control of the tenant (an app holding one can make itself/anyone an admin)
TIER0_PERMISSIONS = {
    "rolemanagement.readwrite.directory", "approleassignment.readwrite.all", "application.readwrite.all",
    "delegatedpermissiongrant.readwrite.all", "directory.readwrite.all", "domain.readwrite.all",
    "userauthenticationmethod.readwrite.all", "policy.readwrite.authenticationmethod",
    "policy.readwrite.conditionalaccess", "policy.readwrite.permissiongrant", "privilegedaccess.readwrite.azuread",
    "organization.readwrite.all", "group.readwrite.all", "groupmember.readwrite.all", "directory.accessasuser.all",
    "full_access_as_app", "exchange.manageasapp",
}
# content of mailboxes, files, chats, calendars ... and security data
CONTENT_PERMISSION = re.compile(r"^(mail|mailboxsettings|files|sites|calendars|contacts|chat|channelmessage|notes|"
                                r"tasks|onlinemeeting\w*|callrecords|ediscovery|threathunting|securityevents|"
                                r"auditlog|ews)\.", re.I)
BASIC_SCOPES = {"openid", "profile", "email", "offline_access", "user.read", "user.readbasic.all"}
USER_CONSENT_POLICY_PREFIX = "managepermissiongrantsforself"

TOP_ROLES = {"global administrator", "privileged role administrator", "privileged authentication administrator",
             "security administrator", "conditional access administrator", "hybrid identity administrator",
             "domain name administrator", "external identity provider administrator", "partner tier2 support"}

# rule id -> list of (lower-case activity substring, base score, reason)
WATCHLIST: dict[str, list[tuple[str, int, str]]] = {
    "role_assignment": [
        ("add eligible member to role", 45, "Made a user eligible for an admin role (PIM)"),
        ("add member to role in pim requested (timebound)", 55, "Assigned a time-bound admin role (PIM)"),
        ("add scoped member to role", 55, "Assigned a scoped admin role"),
        ("add member to role", 55, "Assigned an admin role directly (permanent)"),
        ("update role setting in pim", 55, "Changed PIM role settings (activation rules / approval / MFA)"),
    ],
    "app_credentials": [
        ("certificates and secrets management", 50, "Added/changed application secrets or certificates"),
        ("add service principal credentials", 55, "Added service principal credentials"),
    ],
    # consent_grant: scored by permission, see consent_findings()
    "conditional_access": [
        ("delete conditional access policy", 70, "Deleted a Conditional Access policy"),
        ("conditional access policy", 55, "Changed a Conditional Access policy"),
    ],
    "domain_federation": [
        ("set domain authentication", 80, "Changed domain authentication (federation)"),
        ("set federation settings on domain", 80, "Changed federation settings of a domain"),
    ],
    "admin_credential_reset": [
        ("reset password (by admin)", 30, "Admin reset a password"),
        ("admin registered security info", 35, "Admin registered MFA for a user"),
        ("admin deleted security info", 35, "Admin deleted MFA of a user"),
        ("admin updated security info", 35, "Admin changed MFA of a user"),
    ],
    # secrets that unlock devices: routine for the help desk, interesting in bulk or from an unusual reader
    "sensitive_reads": [
        ("read bitlocker key", 20, "Read a BitLocker recovery key (help-desk routine: logged; alert in bulk)"),
        ("recover device local administrator password", 25, "Read a device's local administrator password (LAPS)"),
    ],
    # an app owner can add secrets to the app and act with all its permissions
    "app_owner_change": [
        ("add owner to application", 40, "Added an owner to an application (owners can add secrets)"),
        ("add owner to service principal", 40, "Added an owner to an enterprise app (owners can add secrets)"),
    ],
    "elevate_access": [
        ("elevated their access", 80, "A Global Administrator elevated to User Access Administrator over ALL Azure "
                                      "subscriptions"),
    ],
    # the networks Conditional Access - and RADAR - take for the organisation's own
    "named_locations": [
        ("delete named location", 40, "Deleted a named location (policies that name it apply differently now)"),
        ("add named location", 45, "Added a named location"),
        ("update named location", 45, "Changed a named location"),
    ],
    # what counts as a sign-in method / as strong enough, for everybody
    "auth_methods_policy": [
        ("authentication methods policy", 50, "Changed which sign-in methods the tenant allows (authentication "
                                              "methods policy)"),
        ("authentication strength", 45, "Changed an authentication strength (what Conditional Access accepts as a "
                                        "strong sign-in)"),
        ("update security defaults", 60, "Changed the security defaults (the tenant's basic MFA protection)"),
    ],
}
TRUSTED_LOCATION_REASON = ("Marked as trusted: Conditional Access policies that leave out trusted locations no longer "
                           "apply to sign-ins from it, and they count as coming from the organisation's own network")

# ---- rare changes of the tenant itself: each is ordinary work once in a while, and a way to stay for an intruder ----
DOMAIN_ACTIVITIES = {
    "add unverified domain": (25, "Started adding a domain to the tenant"),
    "add verified domain": (35, "Added a verified domain (a domain can be federated: sign-ins for it are then decided "
                                "by whoever runs its identity provider)"),
    "verify domain": (35, "Verified a domain of the tenant (a domain can be federated: sign-ins for it are then decided "
                          "by whoever runs its identity provider)"),
    "promote sub domain to root domain": (35, "Made a sub-domain a domain of its own (it can then be federated "
                                              "separately)"),
}
CONNECTOR_ACTIVITIES = {
    "register connector": (35, "Registered a private network connector: a path from the internet to the network it "
                               "runs in"),
}
_ADDRESS = re.compile(r'"Address"\s*:\s*"([^"]+)"')
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def _reply_addresses(value) -> set[str]:
    return set(_ADDRESS.findall(str(value or "")))


def tenant_change_factors(audit: dict) -> list[tuple[int, str]] | None:
    """Score factors of a rare change of the tenant itself, or None when the entry is none: a domain added or
    verified, a private network connector registered, and on an application that exists already: a new reply
    address (where its sign-in tokens are sent) or public client flows switched on (sign-in with a password or a
    device code, without the application's secret)."""
    activity = (audit.get("activityDisplayName") or "").strip().lower()
    for table in (DOMAIN_ACTIVITIES, CONNECTOR_ACTIVITIES):
        if activity in table:
            return [table[activity]]
    if "authorization policy" in activity:
        if user_consent_enabled(audit):  # said by the consent watch, in its own words
            return None
        names = sorted({str(p.get("displayName")) for t in audit.get("targetResources") or []
                        for p in t.get("modifiedProperties") or []
                        if p.get("displayName") and not str(p.get("displayName")).startswith(_NOISE_PROPS)})
        return [(30, "Changed what every user may do without an admin (authorization policy: inviting guests, "
                     "registering applications, consenting to applications)"
                     + (": " + ", ".join(names[:5]) if names else ""))]
    if activity != "update application":  # ("Update service principal" repeats the same change)
        return None
    factors: list[tuple[int, str]] = []
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            name = p.get("displayName")
            if name == "AppAddress":
                added = sorted(_reply_addresses(p.get("newValue")) - _reply_addresses(p.get("oldValue")))
                if not added:
                    continue
                factors.append((20, "Added reply address(es) to an existing application - where its sign-in tokens "
                                    "are sent: " + ", ".join(added[:4]) + (" ..." if len(added) > 4 else "")))
                plain = [a for a in added if a.lower().startswith("http://")
                         and not a.lower().split("//", 1)[1].startswith(_LOCAL_HOSTS)]
                if plain:
                    factors.append((20, "Not encrypted (http://) to another machine: " + ", ".join(plain[:3])))
                if any("*" in a for a in added):
                    factors.append((20, "Wildcard address: any host that matches receives the tokens"))
            elif name == "PublicClient" and "true" in str(p.get("newValue") or "").lower() \
                    and "true" not in str(p.get("oldValue") or "").lower():
                factors.append((30, "Allowed public client flows for an existing application: sign-in with a password "
                                    "or a device code, without the application's secret"))
    return factors or None


# ---- outside organisations that can act as administrators here (partners, service providers) ----
# template ids of built-in roles: the same in every tenant
ROLE_TEMPLATES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    SUPPORT_ENGINEER_ROLE: "Microsoft 365 Support Engineer",
}
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def partner_access_factors(audit: dict) -> list[tuple[int, str]] | None:
    """Score factors when an outside organisation is given a way to act as administrator of this tenant, or None:
    a partner with delegated administration, or a service provider and the admin roles it may be given. Microsoft
    Support during a support case is not one (that is recorded with the case)."""
    activity = (audit.get("activityDisplayName") or "").strip().lower()
    if activity == "add partner to company":
        return [(70, "Gave a partner organisation delegated administration: its staff can act as administrators of "
                     "this tenant")]
    if (audit.get("category") or "").lower() != "delegatedadminserviceproviderconstraints":
        return None
    new: set[str] = set()
    tenant = ""
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            name = (p.get("displayName") or "").lower()
            if name == "allowedroletemplateids":
                new |= ({g.lower() for g in _GUID.findall(str(p.get("newValue") or ""))}
                        - {g.lower() for g in _GUID.findall(str(p.get("oldValue") or ""))})
            elif name == "tenantid":
                tenant = "".join(_GUID.findall(str(p.get("newValue") or ""))[:1]).lower() or tenant
        if not tenant and _GUID.fullmatch(str(t.get("id") or "")):  # (the entry names the organisation as its target)
            tenant = str(t["id"]).lower()
    if not new or tenant == MS_SUPPORT_TENANT:
        return None
    roles = sorted(ROLE_TEMPLATES.get(r, r) for r in new)
    factors = [(50, f"An outside organisation ({tenant or 'tenant not named'}) can now be given admin roles in this "
                    f"tenant as a service provider: {', '.join(roles[:6])}" + (" ..." if len(roles) > 6 else ""))]
    top = [r for r in roles if r.lower() in TOP_ROLES]
    if top:
        factors.append((25, f"Highly privileged: {', '.join(top)}"))
    return factors


# ---- many objects deleted at once: a clean-up, or someone destroying what they can reach ----
# activity -> (kind, deleted for good)
DELETIONS = {
    "delete user": ("users", False), "delete external user": ("users", False), "hard delete user": ("users", True),
    "delete group": ("groups", False), "hard delete group": ("groups", True),
    "delete application": ("applications", False), "hard delete application": ("applications", True),
    "remove service principal": ("applications", False), "hard delete service principal": ("applications", True),
}
MASS_DELETION = {"users": 5, "groups": 10, "applications": 5}  # by one actor in a day, from this count on (0 = off)


def mass_deletion_findings(deleted: dict[tuple[str, str], list[dict]], limits: dict,
                           automation: list[str]) -> list[Finding]:
    """One finding per actor and day that deleted many accounts, groups or applications. An application and its
    enterprise application, and an object deleted and then deleted for good, are one thing."""
    out: list[Finding] = []
    for (who, day), audits in deleted.items():
        things: dict[str, set[str]] = defaultdict(set)
        for_good: set[str] = set()
        for a in audits:
            kind, hard = DELETIONS[(a.get("activityDisplayName") or "").strip().lower()]
            for t in (a.get("targetResources") or [])[:1]:
                things[kind].add(str(t.get("displayName") or t.get("userPrincipalName") or t.get("id") or "").lower())
            if hard:
                for_good.add(kind)
        over = {k: len(v) for k, v in things.items()
                if int(limits.get(k, MASS_DELETION.get(k, 0)) or 0) and len(v) >= int(limits.get(k, MASS_DELETION[k]))}
        if not over:
            continue
        what = ", ".join(f"{n} {k}" for k, n in sorted(over.items(), key=lambda kv: -kv[1]))
        ratio = max(n / int(limits.get(k, MASS_DELETION[k])) for k, n in over.items())
        factors = [(70 if ratio >= 3 else 50, f"{what} deleted by one actor in a day")]
        if for_good & set(over):
            factors.append((10, "Deleted for good (hard delete): cannot be restored"))
        if len(over) > 1:
            factors.append((10, "Several kinds of objects"))
        if _matches(who, automation):
            factors.append((-30, f"Known automation of the tenant ({who})"))
        score = max(0, min(100, sum(p for p, _ in factors)))
        activities = sorted({a.get("activityDisplayName", "") for a in audits})
        out.append(Finding(
            key=f"diraudit|mass_deletion|{who}|{day}", rule_id="mass_deletion", severity=severity_for(score),
            score=score, factors=factors, subjects=_subject(who),
            title=f"Many objects deleted at once: {who} ({what})",
            summary=(f"{who} deleted {what} on {day}. A planned clean-up looks like this - and so does someone "
                     f"destroying what an account can reach."),
            occurred_at=min(parse_time(a["activityDateTime"]) for a in audits),
            fields={"Initiated by": who, "Deleted": what, "Activities": ", ".join(activities)},
            evidence=[{"Time": timefmt.sortable(parse_time(a["activityDateTime"]), seconds=True),
                       "Activity": a.get("activityDisplayName", ""), "Category": a.get("category", ""),
                       "Initiated by": _initiator(a), "Targets": _targets(a),
                       "Correlation ID": a.get("correlationId", "")}
                      for a in sorted(audits, key=lambda a: a["activityDateTime"], reverse=True)[:50]],
            recommendation=("Check that the clean-up was planned. If not: secure the account that did it, and restore "
                            "what was deleted - accounts, Microsoft 365 groups and applications can be restored for "
                            "30 days unless they were deleted for good."),
            links=[("Open audit logs", AUDIT_URL)]))
    return out


SENSITIVE_READS_BULK = 5  # secrets read by one person in a week from this count on: +25 (calibrated: IT reads 1-4/week)

# ---- cross-tenant access settings: whose MFA / devices / users this tenant trusts ----
TRUST_FLAGS = {"ismfaaccepted": "MFA", "iscompliantdeviceaccepted": "compliant-device",
               "ishybridazureadjoineddeviceaccepted": "hybrid-joined-device"}

# ---- app-only actions: the audit log names the app, not the person behind it ----
APP_ORIGIN_LOOKBACK = timedelta(minutes=75)  # app tokens live 60-90 min: the sign-in behind an action is in here
APP_ORIGIN_MAX_PER_RUN = 5
SELF_GRANT_USE_WINDOW = timedelta(minutes=10)
CREDENTIAL_KINDS = {"clientsecret": "client secret", "clientassertion": "certificate",
                    "federatedidentitycredential": "federated credential (workload identity)",
                    "managedidentity": "managed identity"}

FREEMAIL = ("gmail.", "googlemail.", "outlook.", "hotmail.", "live.", "msn.", "yahoo.", "ymail.", "icloud.", "me.com",
            "mac.com", "gmx.", "web.de", "proton.me", "protonmail.", "pm.me", "aol.", "yandex.", "mail.ru", "bluewin.ch",
            "hispeed.ch", "sunrise.ch", "zoho.", "tutanota.", "tuta.io", "qq.com", "163.com", "126.com", "foxmail.com",
            "fastmail.", "t-online.de", "freenet.de", "orange.fr", "free.fr", "laposte.net", "libero.it", "virgilio.it",
            "btinternet.com", "comcast.net", "verizon.net", "att.net", "shaw.ca", "rogers.com", "bigpond.com",
            "naver.com", "daum.net", "rediffmail.com", "seznam.cz", "wp.pl", "uol.com.br", "terra.com.br")


def guest_email(audit: dict) -> str:
    """Invited address from the guest UPN, e.g. 'jane_gmail.com#EXT#@contoso.onmicrosoft.com' -> 'jane@gmail.com'."""
    for t in audit.get("targetResources") or []:
        upn = t.get("userPrincipalName") or ""
        if "#EXT#" in upn:
            local = upn.split("#EXT#")[0]
            if "_" in local:
                head, _, domain = local.rpartition("_")
                return f"{head}@{domain}".lower()
    return ""


def _name_tokens(upn: str) -> set[str]:
    local = upn.split("@")[0].lower()
    return {t for t in local.replace("-", ".").replace("_", ".").split(".") if len(t) >= 3}


def classify_invite(inviter: str, email: str) -> tuple[int, str]:
    """(score, reason) for a guest invite: private mailbox of the inviter > private mailbox > business partner."""
    if not email:
        return 25, "Guest invited"
    domain = email.split("@")[-1]
    private = any(domain.startswith(f) or domain == f for f in FREEMAIL)
    own = private and len(_name_tokens(inviter) & {t.rstrip("0123456789") for t in _name_tokens(email)}) >= 2
    if own:
        return 65, "Invited what looks like their own private mailbox (possible data exfiltration channel)"
    if private:
        return 50, f"Invited a private mailbox ({domain})"
    return 20, f"Invited an external business contact ({domain})"


def _initiator(audit: dict) -> str:
    by = audit.get("initiatedBy") or {}
    user = by.get("user") or {}
    app = by.get("app") or {}
    return user.get("userPrincipalName") or app.get("displayName") or app.get("servicePrincipalName") or "unknown"


def _role(audit: dict) -> str:
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            if p.get("displayName") in ("Role.DisplayName", "RoleDefinition.DisplayName"):
                return str(p.get("newValue") or "").strip().strip('"')
    # PIM names the role as a target of its own (directory roles and the roles on Azure resources alike)
    return next((str(t.get("displayName")).strip() for t in audit.get("targetResources") or []
                 if str(t.get("type", "")).lower() == "role" and t.get("displayName")), "")


#: what a role can be given on outside the directory (PIM for Azure resources), by the target's type
AZURE_SCOPES = {"subscription": "Azure subscription", "managementgroup": "Azure management group",
                "resourcegroup": "Azure resource group", "resource": "Azure resource"}
#: roles on Azure resources that can hand out access to them - to others, and to themselves
GRANTING_ROLES = {"owner", "user access administrator", "role based access control administrator"}


def _scope(audit: dict) -> tuple[str, str] | None:
    """(kind, name) of the Azure resource a role was given on; None for a role in the directory."""
    for t in audit.get("targetResources") or []:
        kind = str(t.get("type", "")).replace(" ", "").lower()
        if kind in AZURE_SCOPES and t.get("displayName"):
            return AZURE_SCOPES[kind], str(t["displayName"]).strip()
    return None


def _role_text(audit: dict) -> str:
    """'Owner on Contoso Production (Azure subscription)', or just the directory role's name."""
    role, scope = _role(audit), _scope(audit)
    return f"{role} on {scope[1]} ({scope[0]})" if role and scope else role


def _receivers(audit: dict) -> list[str]:
    return sorted({str(t.get("userPrincipalName")).lower() for t in audit.get("targetResources") or []
                   if str(t.get("type", "")).lower() == "user" and "@" in str(t.get("userPrincipalName") or "")})


def _self_assigned(audit: dict) -> bool:
    """The one who made the change is among those it was made for."""
    user = (audit.get("initiatedBy") or {}).get("user") or {}
    upn, uid = str(user.get("userPrincipalName") or "").lower(), user.get("id")
    return any(str(t.get("type", "")).lower() == "user"
               and ((uid and t.get("id") == uid) or (upn and str(t.get("userPrincipalName") or "").lower() == upn))
               for t in audit.get("targetResources") or [])


def _targets(audit: dict) -> str:
    names = []
    for t in audit.get("targetResources") or []:
        name = t.get("userPrincipalName") or t.get("displayName") or t.get("id") or ""
        props = [p for p in (t.get("modifiedProperties") or []) if p.get("displayName") in
                 ("Role.DisplayName", "Role.TemplateId", "KeyDescription", "ConsentAction.Permissions")]
        extra = "; ".join(f"{p['displayName']}={str(p.get('newValue') or '').strip(chr(34))[:80]}" for p in props)
        names.append(f"{name} ({extra})" if extra else name)
    return ", ".join(n for n in names if n) or "-"


def _app_names(audits: list[dict]) -> list[str]:
    """Display names of the applications / service principals the audit events changed."""
    return sorted({t["displayName"] for a in audits for t in a.get("targetResources") or []
                   if str(t.get("type", "")).lower() in ("application", "serviceprincipal") and t.get("displayName")})


def _subject(who: str) -> list[str]:
    """The one who did it, as an alert's subject: an account by its name, anything else as an application."""
    who = (who or "").strip()
    if not who or who == "unknown":
        return []
    return [who.lower() if "@" in who else f"app:{who.lower()}"]


def _done_to(audits: list[dict], who: str = "") -> list[str]:
    """The accounts the audit events were done to (given a role, made an owner, their MFA reset ...)."""
    return sorted({str(t["userPrincipalName"]).lower() for a in audits for t in a.get("targetResources") or []
                   if str(t.get("type", "")).lower() == "user" and "@" in str(t.get("userPrincipalName") or "")}
                  - {(who or "").lower()})


# rules whose finding is also about the application it was done to
APP_TARGET_RULES = {"app_credentials", "app_owner_change", "role_assignment"}
ATTACKER_ADDRESS_POINTS = 30


DEVICE_REMOVALS = ("delete device", "unregister device")


def mark_attacker_addresses(findings: list[Finding], acted_from: dict[str, dict[str, datetime]],
                            hostile: dict[str, str]) -> None:
    """A change whose actor acted from a known attacker address around that time says so: the address is named
    (which ties the alert to everything else about that address) and the finding weighs more."""
    for f in findings:
        actors = {m.lower() for field in ("Initiated by", "Invited by")
                  for m in re.findall(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", str(f.fields.get(field) or ""))}
        hits = sorted({ip for actor in actors for ip, when in acted_from.get(actor, {}).items()
                       if ip in hostile and f.occurred_at is not None and abs(f.occurred_at - when) <= timedelta(days=1)})
        made_from = str(f.fields.get("Registered from") or "").strip()  # (a device registration names its address)
        if made_from in hostile:
            hits = sorted({*hits, made_from})
        if not hits:
            continue
        f.fields["Known attacker address"] = "; ".join(f"{ip} - {hostile[ip]}" for ip in hits[:4])
        if f.signal:
            continue  # a context signal stays one; the address is what connects it
        f.factors = list(f.factors) + [(ATTACKER_ADDRESS_POINTS, f"Made from a known attacker address: {hits[0]} - "
                                                                 f"{hostile[hits[0]]}")]
        f.score = max(0, min(100, int(f.score or 0) + ATTACKER_ADDRESS_POINTS))
        f.severity = severity_for(f.score)


def _group_id(audit: dict) -> str:
    """Group of an 'Add/Remove member to/from group' audit event."""
    for t in audit.get("targetResources") or []:
        if str(t.get("type", "")).lower() == "group" and t.get("id"):
            return t["id"]
        for p in t.get("modifiedProperties") or []:
            if p.get("displayName") == "Group.ObjectID":
                return str(p.get("newValue") or p.get("oldValue") or "").strip().strip('"')
    return ""


def _matches(name: str, patterns: list[str]) -> bool:
    name = (name or "").lower()
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


def score_audit(rid: str, audit: dict, automation: list[str]) -> tuple[int, list[tuple[int, str]]] | None:
    """(score, factors) for one audit event of a rule, or None if it does not match."""
    activity = (audit.get("activityDisplayName") or "").lower()
    for pattern, base, reason in WATCHLIST[rid]:
        if pattern in activity:
            break
    else:
        return None
    factors = [(base, reason)]
    if rid == "named_locations" and any('"istrusted":true' in str(v).lower().replace(" ", "")
                                        for v in _props(audit).values()):
        factors.append((20, TRUSTED_LOCATION_REASON))
    role = _role(audit)
    if rid == "role_assignment" and role:
        scope = _scope(audit)
        if scope and role.lower() in GRANTING_ROLES:
            factors.append((15, f"{role} on {scope[1]} ({scope[0]}): can give itself and others access to "
                                f"everything in it"))
        elif scope:
            factors.append((0, f"Role: {_role_text(audit)}"))
        elif role.lower() in TOP_ROLES:
            factors.append((25, f"Highly privileged role: {role}"))
        else:
            factors.append((0, f"Role: {role}"))
    if rid == "role_assignment" and _self_assigned(audit):
        factors.append((5, "Given to their own account"))
    who = _initiator(audit)
    if _matches(who, automation):
        factors.append((-30, f"Known automation of the tenant ({who})"))
    return max(0, min(100, sum(p for p, _ in factors))), factors


@dataclass
class ConsentEvent:
    """One permission grant to an app, from any of the three audit events a consent produces."""
    when: datetime
    actor: str
    client: str               # app receiving the permissions ('' if the event does not name it)
    client_id: str            # its service principal object id
    kind: str                 # "delegated" (acts as the signed-in user) | "application" (app-only, no user)
    scopes: set[str] = field(default_factory=set)
    all_principals: bool = True
    admin_consent: bool | None = None  # None = event does not say
    audit: dict = field(default_factory=dict)


def _props(audit: dict) -> dict[str, str]:
    return {p.get("displayName"): str(p.get("newValue") or "").strip().strip('"')
            for t in audit.get("targetResources") or [] for p in t.get("modifiedProperties") or []}


def _old_props(audit: dict) -> dict[str, str]:
    return {p.get("displayName"): str(p.get("oldValue") or "").strip().strip('"')
            for t in audit.get("targetResources") or [] for p in t.get("modifiedProperties") or []}


def _sp_id(audit: dict) -> str:
    """Service principal object id of an app-only actor ('' when a user made the change)."""
    by = audit.get("initiatedBy") or {}
    return "" if (by.get("user") or {}).get("userPrincipalName") else ((by.get("app") or {}).get("servicePrincipalId") or "")


def _user_agent(audit: dict) -> str:
    return next((str(d.get("value") or "") for d in audit.get("additionalDetails") or []
                 if isinstance(d, dict) and d.get("key") == "User-Agent"), "")


_NOISE_PROPS = ("Included Updated Properties", "TargetId.", "ServicePrincipal.", "AppRoleAssignment.", "Application.")


def _compact(value) -> str:
    """Readable audit value: JSON objects as their set entries ('IsMfaAccepted=true'), other values trimmed."""
    raw = str(value if value is not None else "").strip()
    try:
        parsed = json.loads(raw) if raw[:1] in "{[\"" else None
        if isinstance(parsed, str):
            parsed = json.loads(parsed) if parsed[:1] in "{[" else parsed
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        set_entries = [f"{k}={json.dumps(v) if not isinstance(v, str) else v}" for k, v in parsed.items()
                       if v not in (False, None, "", [], {})]
        return ", ".join(set_entries) or "all off"
    return (parsed if isinstance(parsed, str) else raw.strip('"'))[:110]


def _change_text(audit: dict, limit: int = 2) -> str:
    """'property: new value' of the first meaningful modified properties of an audit event."""
    bits = []
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            name, new = p.get("displayName") or "", str(p.get("newValue") or "").strip().strip('"')
            if name and new and new not in ("None", "[]") and not name.startswith(_NOISE_PROPS):
                bits.append(f"{name}: {_compact(p.get('newValue'))}")
    return "; ".join(bits[:limit])


def self_grant_usage(grant_audit: dict, batch: list[dict]) -> tuple[list[str], float | None]:
    """What an app did with a permission it gave itself: (actions until it removed it again, seconds until removal).

    Only actions of the same app *and the same client program* (User-Agent) count: an automation account usually
    has scheduled jobs running at the same time that have nothing to do with the grant.
    """
    sp, agent = _sp_id(grant_audit), _user_agent(grant_audit)
    role_id = _props(grant_audit).get("AppRole.Id", "")
    if not sp:
        return [], None
    t0 = parse_time(grant_audit["activityDateTime"])
    removed = min((parse_time(a["activityDateTime"]) for a in batch
                   if _sp_id(a) == sp and role_id and _old_props(a).get("AppRole.Id") == role_id
                   and (a.get("activityDisplayName") or "").lower() == "remove app role assignment from service principal"
                   and parse_time(a["activityDateTime"]) >= t0), default=None)
    end = removed or t0 + SELF_GRANT_USE_WINDOW
    used = []
    for a in sorted(batch, key=lambda a: a["activityDateTime"]):
        when, activity = parse_time(a["activityDateTime"]), (a.get("activityDisplayName") or "").lower()
        if _sp_id(a) != sp or not t0 < when <= end or activity in CONSENT_ACTIVITIES \
                or activity.startswith("remove app role assignment") or (agent and _user_agent(a) and _user_agent(a) != agent):
            continue
        target = next((t.get("displayName") for t in a.get("targetResources") or [] if t.get("displayName")
                       and not str(t.get("displayName")).startswith("CrossTenantAccessPolicy for")), "")
        detail = "; ".join(x for x in (target, _change_text(a)) if x)
        used.append(f"{a.get('activityDisplayName', '').strip()} after {int((when - t0).total_seconds())} s"
                    + (f" ({detail})" if detail else ""))
    return used[:5] + ([f"... and {len(used) - 5} more"] if len(used) > 5 else []), \
        ((removed - t0).total_seconds() if removed else None)


def _app_where(row: dict) -> str:
    """'203.0.113.166 (Toronto, CA; named location 'HQ' trusted)' from a service principal sign-in."""
    loc = row.get("location") or {}
    named = ", ".join(f"'{n}'" + (" trusted" if "trusted" in str(d.get("networkType") or "").lower() else "")
                      for d in row.get("networkLocationDetails") or [] for n in d.get("networkNames") or [])
    place = ", ".join(x for x in (loc.get("city"), loc.get("countryOrRegion")) if x)
    inner = "; ".join(x for x in (place, f"named location {named}" if named else "") if x)
    return f"{row.get('ipAddress') or '?'}" + (f" ({inner})" if inner else "")


def _json_value(value):
    """Audit property values are JSON strings (sometimes double-encoded); dict keys lower-cased."""
    v = value
    for _ in range(2):
        if not isinstance(v, str) or not v.strip():
            break
        try:
            v = json.loads(v)
        except ValueError:
            break
    return _lower_keys(v) if v not in ("", "null") else None


def _lower_keys(v):
    if isinstance(v, dict):
        return {str(k).lower(): _lower_keys(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_lower_keys(x) for x in v]
    return v


def cross_tenant_changes(audit: dict) -> dict[str, tuple]:
    """{property: (old, new)} of a cross-tenant access settings event (values parsed)."""
    return {p.get("displayName"): (_json_value(p.get("oldValue")), _json_value(p.get("newValue")))
            for t in audit.get("targetResources") or [] for p in t.get("modifiedProperties") or [] if p.get("displayName")}


def cross_tenant_factors(audit: dict) -> list[tuple[int, str]] | None:
    """Scored reasons for a cross-tenant access settings change (None: nothing visible changed).

    Trusting another tenant's MFA / device claims lets its users pass this tenant's Conditional Access with a sign-in
    at their home tenant - legitimate for close partners, but it hands part of the protection to their policies.
    """
    activity = (audit.get("activityDisplayName") or "").lower()
    default = "default" in activity
    scope = "ALL external organisations (default setting)" if default else "the partner organisation"
    changes = cross_tenant_changes(audit)
    factors: list[tuple[int, str]] = []
    if activity.startswith("delete"):
        factors.append((10, "Partner-specific settings removed: the default settings apply to it again"))
    elif activity.startswith("add a partner"):
        factors.append((20, "New partner organisation added to the cross-tenant access settings"))
    for name, (old, new) in changes.items():
        key = name.lower()
        if key == "inboundtrust":
            on = [label for flag, label in TRUST_FLAGS.items() if isinstance(new, dict) and new.get(flag) is True]
            was = [label for flag, label in TRUST_FLAGS.items() if isinstance(old, dict) and old.get(flag) is True]
            added = [x for x in on if x not in was]
            if added:
                factors.append((75 if default else 40 + 10 * (len(added) - 1),
                                f"Now trusts {' and '.join(added)} claims from {scope}: its users pass this tenant's "
                                f"Conditional Access with a sign-in at their home tenant - protection for them now "
                                f"depends on that tenant's policies"))
            elif was and not on:
                factors.append((10, f"Stopped trusting {', '.join(was)} claims from {scope}"))
        elif key.startswith("b2b"):
            factors.append((45 if default else 25, f"Changed who may collaborate ({name}) for {scope}"))
        elif key == "automaticuserconsentsettings":
            if isinstance(new, dict) and any(v is True for v in new.values()):
                factors.append((40, f"Consent prompt suppressed for users of {scope} (automatic redemption, used by "
                                    f"cross-tenant sync)"))
        elif "sync" in key or "identity sync" in activity:
            if json.dumps(new).lower().count("true"):
                factors.append((60, f"{scope[0].upper() + scope[1:]} may now create and update user accounts in this "
                                    f"tenant (cross-tenant synchronisation)"))
        elif key not in ("tenantid", "isserviceprovider", "serviceprovidertype"):
            factors.append((20, f"Changed cross-tenant setting '{name}'"))
    if not factors:
        return None
    best = max(range(len(factors)), key=lambda i: factors[i][0])  # the most significant change scores
    return [(p if i == best else 0, r) for i, (p, r) in enumerate(factors)]


def partner_matches(partner: dict, changes: dict[str, tuple]) -> bool:
    """Do a partner's CURRENT settings carry the new values of an update event? (update events name no tenant)"""
    current = _lower_keys(partner)
    compared = False
    for name, (_, new) in changes.items():
        if new is None:
            continue
        have = current.get(name.lower())
        if isinstance(new, dict):
            pairs = [(k, v) for k, v in new.items() if v is not None]
            if not isinstance(have, dict) or any(have.get(k) != v for k, v in pairs):
                return False
            compared = compared or bool(pairs)
        elif have != new:
            return False
        else:
            compared = True
    return compared


def parse_consent(audit: dict) -> ConsentEvent | None:
    activity = (audit.get("activityDisplayName") or "").lower()
    targets = audit.get("targetResources") or []
    p = _props(audit)
    base = dict(when=parse_time(audit["activityDateTime"]), actor=_initiator(audit), audit=audit)
    if activity == "consent to application":
        t = targets[0] if targets else {}
        granted = p.get("ConsentAction.Permissions", "").split("=>")[-1]  # "[before] => [after]"
        scopes = {s for m in re.findall(r"Scope:\s*([^,\]]*)", granted) for s in m.split()}
        if not scopes:
            return None  # consent revoked / nothing granted
        return ConsentEvent(**base, client=t.get("displayName") or "", client_id=t.get("id") or "",
                            kind="application" if p.get("ConsentContext.IsAppOnly", "").lower() == "true" else "delegated",
                            scopes=scopes, all_principals=p.get("ConsentContext.OnBehalfOfAll", "").lower() == "true",
                            admin_consent=p.get("ConsentContext.IsAdminConsent", "").lower() == "true")
    if activity == "add delegated permission grant":
        client_id = p.get("ServicePrincipal.ObjectID", "")
        name = p.get("ServicePrincipal.DisplayName") or next(
            (t.get("displayName") for t in targets if t.get("id") == client_id and t.get("displayName")), "")
        scopes = set(p.get("DelegatedPermissionGrant.Scope", "").split())
        return ConsentEvent(**base, client=name if name != "None" else "", client_id=client_id, kind="delegated",
                            scopes=scopes, all_principals=p.get("DelegatedPermissionGrant.ConsentType") == "AllPrincipals") \
            if scopes else None
    if activity == "add app role assignment to service principal":
        role = p.get("AppRole.Value", "")
        return ConsentEvent(**base, client=p.get("ServicePrincipal.DisplayName", ""),
                            client_id=p.get("ServicePrincipal.ObjectID", ""), kind="application",
                            scopes={role} if role else set())
    return None


def classify_permissions(kind: str, scopes: set[str]) -> tuple[int, str, bool]:
    """(points, reason, alert on its own) for permissions granted to an app."""
    tier0 = sorted(s for s in scopes if s.lower() in TIER0_PERMISSIONS)
    content = sorted(s for s in scopes if CONTENT_PERMISSION.match(s) and s not in tier0)
    write = sorted(s for s in scopes if (".readwrite" in s.lower() or s.lower().endswith(".send"))
                   and s not in tier0 and s not in content)
    if kind == "application":  # tenant-wide, no user involved
        if tier0:
            return 75, f"App-only permission that controls the tenant: {', '.join(tier0)}", True
        if content or write:
            what = ("App-only access to all users' data" if content else
                    "App-only write permission for the whole tenant")
            return 55, f"{what}, no user involved: {', '.join(content + write)}", True
        return 25, f"App-only read permission: {', '.join(sorted(scopes))}", False
    # delegated: the app acts with the signed-in user's own rights
    if tier0:
        return 35, f"Delegated permissions with directory control (within each user's own rights): {', '.join(tier0)}", False
    if content or write:
        return 25, f"Delegated access to user data: {', '.join(content + write)}", False
    rest = sorted(s for s in scopes if s.lower() not in BASIC_SCOPES)
    return (15, f"Delegated permissions: {', '.join(rest)}", False) if rest else \
        (5, f"Basic sign-in permissions only ({', '.join(sorted(scopes))})", False)


def consent_findings(events: list[ConsentEvent], automation: list[str], user_consent_allowed: bool,
                     granted: dict[str, str] | None = None, names: dict[str, str] | None = None,
                     batch: list[dict] | None = None) -> list[Finding]:
    """One finding per app and week. The FIRST grant of a dangerous permission alerts; everything else (admin
    consents, read-only app permissions, re-grants) is a signal (see correlation.py).

    ``granted`` ({"app|kind|permission": first seen}) remembers grants across runs and is updated in place;
    ``names`` maps service principal ids to names for events that do not carry one; ``batch`` (all audit events of
    the run) shows what an app did with a permission it gave itself and whether it removed it again.
    """
    granted = granted if granted is not None else {}
    names = dict(names or {})
    names.update({e.client_id: e.client for e in events if e.client and e.client_id})
    groups: dict[tuple, list[ConsentEvent]] = defaultdict(list)
    for e in events:
        app = e.client or names.get(e.client_id) or e.client_id or "unknown app"
        year, week, _ = e.when.astimezone().isocalendar()
        groups[(app, f"{year}-W{week:02d}")].append(e)
    out = []
    for (app, week), evs in sorted(groups.items(), key=lambda kv: min(e.when for e in kv[1])):
        start = min(e.when for e in evs).isoformat()
        actors = sorted({e.actor for e in evs})
        actor = ", ".join(actors)
        factors: list[tuple[int, str]] = []
        alert = False
        for kind in ("application", "delegated"):
            scopes = set().union(*(e.scopes for e in evs if e.kind == kind))
            keys = {s: f"{app.lower()}|{kind}|{s.lower()}" for s in scopes}
            known = {s for s in scopes if granted.get(keys[s], start) < start}
            if scopes - known:
                pts, reason, own = classify_permissions(kind, scopes - known)
                factors.append((pts, reason))
                alert |= own
            if known:
                factors.append((0, f"Granted to this app before as well (re-grant): {', '.join(sorted(known))}"))
            for s in scopes:
                granted[keys[s]] = min(granted.get(keys[s], start), start)
        if not factors:
            continue
        # only the most dangerous grant counts; the others are listed for information
        best = max(range(len(factors)), key=lambda i: factors[i][0])
        factors = [(p if i == best else 0, r) for i, (p, r) in enumerate(factors)]
        delegated = [e for e in evs if e.kind == "delegated"]
        if delegated and not any(e.all_principals for e in delegated) and not any(e.kind == "application" for e in evs):
            factors.append((-5, "Granted for a single user only"))
        if any(e.admin_consent is False for e in evs):
            if not user_consent_allowed:
                factors.append((70, "A NON-ADMIN consented although user consent is disabled in this tenant"))
                alert = True
            elif any(CONTENT_PERMISSION.match(s) for e in delegated for s in e.scopes):
                factors.append((20, "User consent to mail/file access (illicit consent grant pattern)"))
                alert = True
        usage: list[str] = []
        if app.lower() in {a.lower() for a in actors}:
            factors.append((0, "The app granted these permissions to itself (it can extend its own rights)"))
            for e in sorted((e for e in evs if e.kind == "application" and e.actor.lower() == app.lower()),
                            key=lambda e: e.when):
                used, removed = self_grant_usage(e.audit, batch or [])
                perm = ", ".join(sorted(e.scopes))
                usage.append(f"{perm}: " + ("; ".join(used) if used else "no change by the same program within "
                                                                         f"{int(SELF_GRANT_USE_WINDOW.total_seconds() // 60)} min")
                             + (f"; removed again after {int(removed)} s" if removed is not None else "; still assigned"))
                if removed is not None:
                    factors.append((0, f"Just-in-time use of {perm}: granted, used and removed within {int(removed)} s - "
                                       f"tidy, but an app that can grant itself permissions can do so at any time"))
        if all(_matches(a, automation) for a in actors):
            factors.append((-30, f"Known automation of the tenant ({actor})"))
        score = max(0, min(100, sum(p for p, _ in factors)))
        perms = {k: sorted(set().union(*(e.scopes for e in evs if e.kind == k))) for k in ("application", "delegated")}
        audits = [e.audit for e in evs]
        out.append(Finding(
            key=f"consent|{app}|{week}", rule_id="consent_grant", severity=severity_for(score), score=score,
            factors=factors, signal="" if alert else "app_consent",
            subjects=sorted({a.lower() if "@" in a else f"app:{a.lower()}" for a in actors} | {f"app:{app.lower()}"}),
            title=f"{'Permissions granted' if alert else 'Consent'} to {app} by {actor}",
            summary=(f"{actor} granted {app} " + " and ".join(
                f"{k} permissions ({', '.join(v[:8])}{' ...' if len(v) > 8 else ''})" for k, v in perms.items() if v)
                + ("." if alert else ". Context signal: alerts only together with other suspicious activity of the "
                                     "admin or the app.")
                + (f" What it did with it: {' | '.join(usage)}." if usage else "")),
            occurred_at=min(e.when for e in evs),
            fields={"Initiated by": actor, "App": app,
                    "Application permissions": ", ".join(perms["application"]) or "-",
                    "Delegated permissions": ", ".join(perms["delegated"]) or "-",
                    "For": "all users" if any(e.all_principals for e in delegated) or perms["application"] else "one user",
                    **({"Used for": " | ".join(usage)} if usage else {})},
            evidence=[{
                "Time": timefmt.sortable(parse_time(a["activityDateTime"]), seconds=True),
                "Activity": a.get("activityDisplayName", ""), "Initiated by": _initiator(a), "Targets": _targets(a),
                "Correlation ID": a.get("correlationId", ""), "Audit ID": a.get("id", ""),
            } for a in sorted(audits, key=lambda a: a["activityDateTime"], reverse=True)[:50]],
            recommendation=("Confirm the app and its permissions were requested and approved. App-only permissions "
                            "give the app's owner (and anyone holding its secret) this access to the whole tenant: "
                            "prefer narrower permissions (e.g. Sites.Selected, RBAC for Applications in Exchange) and "
                            "review the app's credentials and owners." if alert else
                            "No action needed on its own. If it became an alert: the admin who consented, or the app, "
                            "shows other suspicious activity - check the consent was really intended."),
            links=[("Open audit logs", AUDIT_URL),
                   ("Enterprise applications", "https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview")],
        ))
    return out


def support_case_opened(audit: dict) -> str | None:
    """UPN of the admin who opened a Microsoft 365 support case (= added the Microsoft Support tenant as partner)."""
    if (audit.get("activityDisplayName") or "").lower() != "add a partner to cross-tenant access setting" \
            or (audit.get("result") or "").lower() != "success":
        return None
    user = ((audit.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName")
    return user if user and _props(audit).get("tenantId") == MS_SUPPORT_TENANT else None


def support_access_factors(audit: dict, assist_sp_id: str | None, cases: list[dict]) -> list[tuple[int, str]] | None:
    """Score adjustment for 'Add member to role' events made by Microsoft's support flow, else None."""
    p = _props(audit)
    details = {d.get("key"): d.get("value") for d in audit.get("additionalDetails") or [] if isinstance(d, dict)}
    app = (audit.get("initiatedBy") or {}).get("app") or {}
    if p.get("Role.TemplateId") != SUPPORT_ENGINEER_ROLE or details.get("Principal Tenant ID") != MS_SUPPORT_TENANT:
        return None
    if not assist_sp_id or app.get("servicePrincipalId") != assist_sp_id:
        return [(20, f"Assigned by '{app.get('displayName') or _initiator(audit)}', which is NOT Microsoft's Assist API "
                     f"service principal")]
    when = parse_time(audit["activityDateTime"])
    opened = [c for c in cases if timedelta(0) <= when - parse_time(c["at"]) <= timedelta(days=SUPPORT_CASE_DAYS)]
    if opened:
        case = max(opened, key=lambda c: c["at"])
        return [(-55, f"Microsoft Support access for the support case {case['by']} opened on "
                      f"{timefmt.stamp_year(parse_time(case['at']))} (documented flow: read-only role, ends when "
                      f"the case closes, at the latest {SUPPORT_CASE_DAYS} days later)")]
    return [(-25, "Genuine Microsoft Support assignment (Assist API, Microsoft Support tenant) but no support case was "
                  f"opened by your admins in the {SUPPORT_CASE_DAYS} days before - check who requested support")]


def user_consent_enabled(audit: dict) -> str | None:
    """Reason text if an authorization-policy update switched on user consent to apps."""
    if "authorization policy" not in (audit.get("activityDisplayName") or "").lower():
        return None
    for t in audit.get("targetResources") or []:
        for p in t.get("modifiedProperties") or []:
            old, new = str(p.get("oldValue") or "").lower(), str(p.get("newValue") or "").lower()
            if USER_CONSENT_POLICY_PREFIX in new and USER_CONSENT_POLICY_PREFIX not in old:
                return "User consent to applications was enabled: users can now grant apps access to their data"
    return None


class DirectoryAuditPlugin(Plugin):
    id = "directory_audit"
    name = "Directory audit watch"
    description = "Watches the Entra ID audit log for admin role, app credential, consent, CA, federation and guest changes."
    default_enabled = False
    default_interval_minutes = 15
    permissions = ["AuditLog.Read.All"]
    rules = [
        Rule("role_assignment", "Admin role assignments (no PIM activations)"),
        Rule("app_credentials", "App / service principal credentials added"),
        Rule("consent_grant", "App consent: tenant-wide app permissions (others only with other activity)"),
        Rule("conditional_access", "Conditional Access policy changes"),
        Rule("domain_federation", "Domain federation changes"),
        Rule("admin_credential_reset", "Admin password / MFA resets", default_enabled=False),
        Rule("guest_invites", "Guest invitations (only with other suspicious activity)"),
        Rule("mfa_exclusion_change", "Members added to groups excluded from Conditional Access"),
        Rule("sensitive_reads", "BitLocker keys / local admin passwords read"),
        Rule("app_owner_change", "Owners added to apps"),
        Rule("elevate_access", "Azure root access elevation by a Global Administrator"),
        Rule("device_registration", "Device registrations (only as part of an attack chain)"),
        Rule("session_revocations", "Session revocations (context: attack handled)"),
        Rule("cross_tenant_access", "Cross-tenant trust / B2B access settings changed"),
        Rule("named_locations", "Named locations (trusted networks) changed"),
        Rule("auth_methods_policy", "Sign-in methods policy, authentication strengths, security defaults changed"),
        Rule("privileged_group", "Members / owners added to groups that can hold admin roles"),
        Rule("tenant_changes", "Rare tenant changes: domains, network connectors, app reply addresses, what users may do"),
        Rule("partner_access", "Outside organisations given admin access (partners, service providers)"),
        Rule("mass_deletion", "Many accounts, groups or applications deleted at once"),
    ]
    default_settings = {
        "initial_lookback_hours": 24,
        "overlap_minutes": 30,
        "ignore_initiators": [],
        # your own automation accounts/apps: their routine changes are logged without pop-up (-30 points)
        "automation_initiators": [],
        "system_initiators": SYSTEM_INITIATORS,
        "max_pages": 200,
        # alerts about app-only changes: look up where the app signed in, with which credential, who uses it
        "app_origin_lookup": True,
        # accounts / groups / applications deleted by one actor in a day, from this count on (0 = not watched)
        "mass_deletion": dict(MASS_DELETION),
    }

    def run(self, ctx: PluginContext) -> list[Finding]:
        """One scan. Its bookmark moves only when its findings are in the alert store: a scan that is stopped or
        fails after reading reads the same entries again (its findings have fixed keys: nothing is doubled)."""
        staged = StagedState(ctx.state)
        findings = self._scan(dataclasses.replace(ctx, state=staged))
        ctx.when_delivered(staged.commit)
        return findings

    def _scan(self, ctx: PluginContext) -> list[Finding]:
        s = ctx.settings
        now = ctx.now()
        checkpoint = ctx.state.get("checkpoint")
        since = (parse_time(checkpoint) - timedelta(minutes=float(s.get("overlap_minutes", 30))) if checkpoint
                 else now - timedelta(hours=float(s.get("initial_lookback_hours", 24))))
        skip = list(s.get("ignore_initiators", [])) + list(s.get("system_initiators", SYSTEM_INITIATORS))
        automation = list(s.get("automation_initiators", []))
        active = [rid for rid in WATCHLIST if ctx.rule_enabled(rid)]

        exclusion_groups = self._exclusion_groups(ctx, now) if ctx.rule_enabled("mfa_exclusion_change") else {}
        groups: dict[tuple, list[tuple[dict, int, list]]] = defaultdict(list)
        invites: list[dict] = []
        exclusion_changes: list[tuple[dict, str, str]] = []
        privileged: list[tuple[dict, str]] = []
        role_groups: dict[str, str] | None = None  # asked for when the first group change comes along
        disabled: list[dict] = []
        deleted: dict[tuple[str, str], list[dict]] = defaultdict(list)
        consents: list[dict] = []
        consent_policy: list[tuple[dict, str]] = []
        support_cases_opened: list[tuple[dict, str]] = []
        cross_tenant: list[tuple[dict, list]] = []
        context_signals: list[Finding] = []
        audits = list(self._fetch(ctx, since, int(s.get("max_pages", 200))))
        self._keep_account_events(ctx, audits, now)
        audits += self._enables_from_before(ctx, audits, now)
        # support cases first: the engineer's role assignment follows seconds later, often in the same batch
        cases = [c for c in ctx.state.get("support_cases") or []
                 if now - parse_time(c["at"]) < timedelta(days=3 * SUPPORT_CASE_DAYS)]
        for audit in audits:
            by = support_case_opened(audit)
            if by:
                support_cases_opened.append((audit, by))
                if audit.get("id") not in {c.get("id") for c in cases}:
                    cases.append({"id": audit.get("id"), "by": by,
                                  "at": parse_time(audit["activityDateTime"]).isoformat()})
        ctx.state.set("support_cases", cases)
        newest, count = None, 0
        acted_from: dict[str, dict[str, datetime]] = defaultdict(dict)  # account -> {address it acted from: when}
        for audit in audits:
            count += 1
            when = parse_time(audit["activityDateTime"])
            by_user = (audit.get("initiatedBy") or {}).get("user") or {}
            if by_user.get("ipAddress") and by_user.get("userPrincipalName"):
                acted_from[str(by_user["userPrincipalName"]).lower()][str(by_user["ipAddress"])] = when
            newest = when if newest is None or when > newest else newest
            activity = (audit.get("activityDisplayName") or "").lower()
            who = _initiator(audit)
            if activity == "disable account" and ctx.rule_enabled("guest_invites") \
                    and (audit.get("result") or "").lower() == "success":
                disabled.append(audit)  # context signal only (offboarding is routine); see radar.correlation
                continue
            if activity in PASSWORD_RESET_ACTIVITIES and ctx.rule_enabled("session_revocations") \
                    and (audit.get("result") or "").lower() == "success":
                context_signals.append(self._password_signal(audit))  # (no "continue": resets by admins are also watched)
            if activity == "enable account" and ctx.rule_enabled("guest_invites") \
                    and (audit.get("result") or "").lower() == "success":
                context_signals.append(self._enabled_signal(audit))  # takes back "account disabled" as a response
                continue
            if activity == "update stsrefreshtokenvalidfrom timestamp" and ctx.rule_enabled("session_revocations") \
                    and (audit.get("result") or "").lower() == "success":
                context_signals.append(self._revocation_signal(audit))  # also automatic ones (password change)
                continue
            if exclusion_groups and activity in ("add member to group", "remove member from group") \
                    and (audit.get("result") or "").lower() == "success":
                gid = _group_id(audit)
                if gid in exclusion_groups:  # checked before the system-actor filter: approvals count too
                    exclusion_changes.append((audit, gid, exclusion_groups[gid]))
                    continue
            if (audit.get("result") or "").lower() != "success" or _matches(who, skip):
                continue
            if any(p in activity for p in PIM_LIFECYCLE):
                continue  # just-in-time activations: routine admin work, the eligibility assignment is what matters
            if activity == "invite external user" and ctx.rule_enabled("guest_invites"):
                invites.append(audit)
                continue
            if activity in ("add member to group", "add owner to group") and ctx.rule_enabled("privileged_group"):
                if role_groups is None:
                    role_groups = self._role_groups(ctx, now)
                gid = _group_id(audit)
                if gid in role_groups:
                    privileged.append((audit, role_groups[gid]))
                    continue
            if activity in DELETIONS and ctx.rule_enabled("mass_deletion"):
                deleted[(who, when.astimezone().strftime("%Y-%m-%d"))].append(audit)
            if ctx.rule_enabled("partner_access"):
                factors = partner_access_factors(audit)
                if factors:
                    if _matches(who, automation):
                        factors = factors + [(-30, f"Known automation of the tenant ({who})")]
                    groups[("partner_access", who, when.astimezone().strftime("%Y-%m-%d"))].append(
                        (audit, max(0, min(100, sum(p for p, _ in factors))), factors))
                    continue
            if ctx.rule_enabled("tenant_changes"):
                factors = tenant_change_factors(audit)
                if factors:
                    if _matches(who, automation):
                        factors = factors + [(-30, f"Known automation of the tenant ({who})")]
                    year, week, _ = when.astimezone().isocalendar()
                    groups[("tenant_changes", who, f"{year}-W{week:02d}")].append(
                        (audit, max(0, min(100, sum(p for p, _ in factors))), factors))
                    continue
            if audit.get("category") == "CrossTenantAccessSettings" and ctx.rule_enabled("cross_tenant_access"):
                if not support_case_opened(audit):  # opening a support case is recorded separately
                    factors = cross_tenant_factors(audit)
                    if factors:
                        cross_tenant.append((audit, factors))
                continue
            if activity == "register device" and ctx.rule_enabled("device_registration") \
                    and (audit.get("initiatedBy") or {}).get("user"):
                context_signals.append(self._device_signal(audit))
                continue
            if activity in DEVICE_REMOVALS and ctx.rule_enabled("device_registration"):
                removed = self._device_removed_signal(audit)
                if removed is not None:
                    context_signals.append(removed)
            if ctx.rule_enabled("consent_grant"):
                if activity in CONSENT_ACTIVITIES:
                    consents.append(audit)
                    continue
                reason = user_consent_enabled(audit)
                if reason:
                    consent_policy.append((audit, reason))
                    continue
            for rid in active:
                scored = score_audit(rid, audit, automation)
                if scored and rid == "role_assignment" and _props(audit).get("Role.TemplateId") == SUPPORT_ENGINEER_ROLE:
                    extra = support_access_factors(audit, self._assist_sp_id(ctx, now), cases)
                    if extra:
                        factors = scored[1] + extra
                        scored = (max(0, min(100, sum(p for p, _ in factors))), factors)
                if scored:
                    local = when.astimezone()
                    if rid in WEEKLY_RULES:  # routine admin work: one reminder per person and week
                        year, week, _ = local.isocalendar()
                        period = f"{year}-W{week:02d}"
                    else:
                        period = local.strftime("%Y-%m-%d")
                    groups[(rid, who, period)].append((audit, *scored))
                    break
        ctx.state.set("checkpoint", (newest or now).isoformat())

        findings = [self._invite_finding(a) for a in invites]
        findings += [self._exclusion_finding(a, gid, name) for a, gid, name in exclusion_changes]
        findings += [self._privileged_group_finding(a, name, automation) for a, name in privileged]
        findings += [self._disabled_signal(a) for a in disabled]
        findings += mass_deletion_findings(deleted, dict(s.get("mass_deletion") or {}), automation)
        findings += [self._support_case_record(a, by) for a, by in support_cases_opened]
        findings += [self._cross_tenant_finding(ctx, a, factors) for a, factors in cross_tenant]
        findings += context_signals
        if consents:
            events = [e for e in (parse_consent(a) for a in consents) if e]
            granted = dict(ctx.state.get("consent_granted") or {})
            findings += consent_findings(events, automation, self._user_consent_allowed(ctx, now), granted,
                                         self._app_names(ctx, events), batch=audits)
            ctx.state.set("consent_granted", granted)
        findings += [self._consent_policy_finding(a, reason) for a, reason in consent_policy]
        rule_names = {r.id: r.name for r in self.rules}
        for (rid, who, day), items in groups.items():
            audits = [a for a, _, _ in items]
            score, factors = max(((sc, f) for _, sc, f in items), key=lambda x: x[0])
            if rid == "sensitive_reads" and len(audits) >= SENSITIVE_READS_BULK:
                factors = factors + [(25, f"{len(audits)} device secrets read by the same person in one week")]
                score = min(69, score + 25)
            activities = sorted({a.get("activityDisplayName", "") for a in audits})
            roles = sorted({_role_text(a) for a in audits} - {""})
            done_to = _done_to(audits, who)
            said = (f"{who} made {len(audits)} change(s) in {day}: {', '.join(activities)}. "
                    f"Targets: {_targets(audits[0])}" + (" ..." if len(audits) > 1 else ""))
            if rid == "role_assignment" and roles:
                # one assignment is logged several times (requested, completed, the directory's own entry): what
                # was given to whom is said once
                given: dict[str, set[str]] = {}
                for a in audits:
                    if _role_text(a):
                        given.setdefault(_role_text(a), set()).update(_receivers(a) or [""])
                count = sum(len(v) for v in given.values())
                own = any(_self_assigned(a) for a in audits)
                said = (f"{who} made {count} role assignment(s) in {day}: "
                        + "; ".join(f"{role} for {', '.join(sorted(x for x in to if x)) or 'an account'}"
                                    for role, to in sorted(given.items()))[:500]
                        + (" - among them their own account" if own else "") + ".")
            findings.append(Finding(
                key=f"diraudit|{rid}|{who}|{day}", rule_id=rid, severity=severity_for(score), score=score,
                factors=factors,
                title=(f"{rule_names[rid]}: {who}" + (f" ({', '.join(roles[:3])})" if roles else "")),
                summary=said,
                occurred_at=min(parse_time(a["activityDateTime"]) for a in audits),
                fields={"Initiated by": who, "Activities": ", ".join(activities), "Roles": ", ".join(roles) or "-",
                        **({"Done to": ", ".join(done_to[:10]) + (" ..." if len(done_to) > 10 else "")} if done_to else {})},
                # everybody it is about: who did it, the accounts it was done to, the application it was done to
                subjects=_subject(who) + done_to + ([f"app:{n.lower()}" for n in _app_names(audits)]
                                                    if rid in APP_TARGET_RULES else []),
                evidence=[{
                    "Time": timefmt.sortable(parse_time(a["activityDateTime"]), seconds=True),
                    "Activity": a.get("activityDisplayName", ""),
                    "Category": a.get("category", ""),
                    "Initiated by": _initiator(a),
                    "Targets": _targets(a),
                    "Correlation ID": a.get("correlationId", ""),
                } for a in sorted(audits, key=lambda a: a["activityDateTime"], reverse=True)[:50]],
                recommendation="Verify the change was planned and made by the right person. Revert it and "
                               "investigate the initiating account if not.",
                links=[("Open audit logs", AUDIT_URL)],
            ))
        if findings:
            hostile = self._attacker_addresses(ctx, now)
            if hostile:
                mark_attacker_addresses(findings, acted_from, hostile)
        if s.get("app_origin_lookup", True):
            self._add_app_origins(ctx, findings, audits)
        ctx.set_status(f"{count} audit event(s) checked, {len(findings)} finding(s)")
        return findings

    @staticmethod
    def _attacker_addresses(ctx: PluginContext, now) -> dict[str, str]:
        """{address: what it was used in} - the addresses the sign-in checks proved to be an attacker's (their
        history, read only). Nothing when the sign-in checks never ran here."""
        import sqlite3

        path = ctx.data_dir.parent / "signin_threats" / "signins.db"
        if not path.exists():
            return {}
        try:
            from .signin_threats.indicators import Indicator

            conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
            try:
                rows = conn.execute("SELECT data FROM indicators WHERE kind='ip' AND expires>? AND ts<=?",
                                    (now.timestamp(), now.timestamp())).fetchall()
            finally:
                conn.close()
            return {i.value: i.describe() for i in (Indicator.from_json(data) for (data,) in rows)}
        except Exception as exc:  # noqa: BLE001 - a missing table, a locked file: the audit watch goes on without
            ctx.log.info("Known attacker addresses not readable: %s", exc)
            return {}

    # ---- app-only actions: who / where / which credential ----
    def _add_app_origins(self, ctx: PluginContext, findings: list[Finding], audits: list[dict]) -> None:
        """Alerts about changes an app made with its own credentials: the audit log names only the app. Add where
        it signed in from, which credential it used, and who uses the app themselves (the closest to 'who did it')."""
        by_corr: dict[str, list[dict]] = defaultdict(list)
        for a in audits:
            by_corr[a.get("correlationId") or ""].append(a)
        cache: dict = {}
        done = 0
        for f in sorted(findings, key=lambda f: -(f.score or 0)):
            if f.signal or (f.score or 0) < 25 or done >= APP_ORIGIN_MAX_PER_RUN:
                continue
            src = next((a for row in f.evidence for a in by_corr.get(row.get("Correlation ID") or "", []) if _sp_id(a)),
                       None)
            if not src:
                continue
            origin = self._app_origin(ctx, src, cache)
            done += 1
            if not origin:
                continue
            f.fields.update(origin)
            app = ((src.get("initiatedBy") or {}).get("app") or {}).get("displayName") or "The app"
            where = origin.get("App signed in from", "")
            cred = origin.get("App credential", "")
            f.factors = list(f.factors) + [(0, f"App-only change: Entra logs no person for it. {app} signed in from "
                                               f"{where}" + (f" with its {cred}" if cred else "")
                                               + " - whoever holds that credential there made the change")]
            f.summary += (f" App-only change (no person in the audit log): signed in from {where}"
                          + (f", {cred}" if cred else "") + ".")

    def _app_origin(self, ctx: PluginContext, audit: dict, cache: dict) -> dict[str, str] | None:
        sp = _sp_id(audit)
        when = parse_time(audit["activityDateTime"])
        key = (sp, when.replace(second=0, microsecond=0))
        if key in cache:
            return cache[key]
        cache[key] = None
        try:
            rows = ctx.graph.get("/beta/auditLogs/signIns", {
                "$filter": (f"createdDateTime ge {graph_time(when - APP_ORIGIN_LOOKBACK)} and "
                            f"createdDateTime le {graph_time(when + timedelta(seconds=30))} and "
                            f"servicePrincipalId eq '{sp}' and signInEventTypes/any(t: t eq 'servicePrincipal')"),
                "$orderby": "createdDateTime desc", "$top": "25"}).get("value") or []
        except Exception as exc:  # no access / throttled / test double: the alert simply stays as it is
            ctx.log.info("App sign-in lookup for %s failed: %s", sp, exc)
            return None
        ok = [r for r in rows if not (r.get("status") or {}).get("errorCode")
              and parse_time(r["createdDateTime"]) <= when + timedelta(seconds=30)]
        out: dict[str, str] = {}
        if not ok:
            out["App signed in from"] = (f"no sign-in of the app in the {int(APP_ORIGIN_LOOKBACK.total_seconds() // 60)} "
                                         f"min before (managed identity, or the sign-in log is delayed)")
        else:
            first_per_ip = {}
            for r in ok:
                first_per_ip.setdefault(r.get("ipAddress") or "?", r)
            out["App signed in from"] = "; ".join(_app_where(r) for r in list(first_per_ip.values())[:3])
            out["App credential"] = self._credential(ctx, ok[0], sp, cache)
            if len(first_per_ip) == 1 and ok[0].get("ipAddress"):
                out["People on that IP then"] = self._people_on_ip(ctx, ok[0]["ipAddress"], when)
        app_id = (ok[0].get("appId") if ok else "") or ((audit.get("initiatedBy") or {}).get("app") or {}).get("appId")
        if app_id:
            out["People using the app themselves"] = self._app_users(ctx, app_id, when, cache)
        cache[key] = out
        return out

    @staticmethod
    def _credential(ctx: PluginContext, row: dict, sp: str, cache: dict) -> str:
        kind = CREDENTIAL_KINDS.get(str(row.get("clientCredentialType") or "").lower(), row.get("clientCredentialType") or "")
        key_id = row.get("servicePrincipalCredentialKeyId") or ""
        if not key_id:
            return kind or "unknown credential"
        app_id = row.get("appId") or ""
        if ("creds", app_id) not in cache:
            creds = []
            try:
                apps = ctx.graph.get("/v1.0/applications", {"$filter": f"appId eq '{app_id}'",
                                                            "$select": "passwordCredentials,keyCredentials"}).get("value") or []
                obj = apps[0] if apps else ctx.graph.get(f"/v1.0/servicePrincipals/{sp}",
                                                         {"$select": "passwordCredentials,keyCredentials"})
                creds = (obj.get("passwordCredentials") or []) + (obj.get("keyCredentials") or [])
            except Exception as exc:
                ctx.log.info("Credential lookup for %s failed: %s", app_id, exc)
            cache[("creds", app_id)] = creds
        cred = next((c for c in cache[("creds", app_id)] if c.get("keyId") == key_id), None)
        if not cred:
            return f"{kind} {key_id[:8]} (no longer on the app)"
        start, end = parse_time(cred["startDateTime"]), parse_time(cred["endDateTime"])
        long_lived = " - long-lived secret" if kind == "client secret" and end - start > timedelta(days=370) else ""
        return f"{kind} '{cred.get('displayName') or key_id[:8]}' (valid {start:%d.%m.%Y} - {end:%d.%m.%Y}{long_lived})"

    @staticmethod
    def _people_on_ip(ctx: PluginContext, ip: str, when) -> str:
        """Users signing in interactively from the app's IP around the time: an attribution only on quiet networks."""
        try:
            rows = ctx.graph.get("/beta/auditLogs/signIns", {
                "$filter": (f"createdDateTime ge {graph_time(when - timedelta(minutes=15))} and "
                            f"createdDateTime le {graph_time(when + timedelta(minutes=15))} and ipAddress eq '{ip}' "
                            f"and signInEventTypes/any(t: t eq 'interactiveUser')"),
                "$select": "userPrincipalName", "$top": "999"}).get("value") or []
        except Exception as exc:
            ctx.log.info("Same-IP lookup failed: %s", exc)
            return "-"
        users = sorted({r.get("userPrincipalName") for r in rows if r.get("userPrincipalName")})
        if not users:
            return "nobody signed in interactively from it within ±15 min (server / automation host?)"
        if len(users) > 3:
            return f"shared network: {len(users)} people signed in from it within ±15 min - no attribution by IP"
        return ", ".join(users) + " (signed in interactively from the same IP within ±15 min)"

    @staticmethod
    def _app_users(ctx: PluginContext, app_id: str, when, cache: dict) -> str:
        """Who signs in to the app interactively (delegated) - typically its builder/operator."""
        if ("users", app_id) in cache:
            return cache[("users", app_id)]
        try:
            rows = ctx.graph.get("/beta/auditLogs/signIns", {
                "$filter": (f"createdDateTime ge {graph_time(when - timedelta(days=30))} and appId eq '{app_id}' "
                            f"and signInEventTypes/any(t: t eq 'interactiveUser')"),
                "$select": "userPrincipalName,createdDateTime", "$top": "200"}).get("value") or []
        except Exception as exc:
            ctx.log.info("App user lookup failed: %s", exc)
            rows = None
        if rows is None:
            text = "-"
        elif not rows:
            text = "nobody signed in to it interactively in 30 days (used only with its own credentials)"
        else:
            count = Counter(r.get("userPrincipalName") for r in rows if r.get("userPrincipalName"))
            last = {}
            for r in rows:
                last[r.get("userPrincipalName")] = max(last.get(r.get("userPrincipalName"), ""), r["createdDateTime"])
            text = ", ".join(f"{u} ({n}x, last {parse_time(last[u]).astimezone():%d.%m.})" for u, n in count.most_common(3))
        cache[("users", app_id)] = text
        return text

    # ---- cross-tenant access ----
    def _cross_tenant_finding(self, ctx: PluginContext, audit: dict, factors: list[tuple[int, str]]) -> Finding:
        who, when = _initiator(audit), parse_time(audit["activityDateTime"])
        partner, tenant_id = self._partner(ctx, audit)
        users = self._partner_users(ctx, tenant_id, when) if tenant_id else ""
        score = max(0, min(100, sum(p for p, _ in factors)))
        main = max(factors, key=lambda f: f[0])[1]
        changed = "; ".join(f"{p.get('displayName')}: {_compact(p.get('oldValue')) or '-'} -> {_compact(p.get('newValue'))}"
                            for t in audit.get("targetResources") or [] for p in t.get("modifiedProperties") or []
                            if p.get("displayName") not in (None, "isServiceProvider", "serviceProviderType")) or "-"
        default = "default" in (audit.get("activityDisplayName") or "").lower()
        return Finding(
            key=f"xtenant|{audit.get('id')}", rule_id="cross_tenant_access", severity=severity_for(score), score=score,
            factors=factors, subjects=[who.lower() if "@" in who else f"app:{who.lower()}"],
            title=(f"Cross-tenant trust changed by {who}: " + ("ALL external organisations" if default
                                                                 else partner or "partner organisation")),
            summary=(f"{who} changed the cross-tenant access settings"
                     + (f" for {partner}" if partner and not default else " (default for all organisations)" if default else "")
                     + f". {main}." + (f" Users of that tenant seen here recently: {users}." if users else "")),
            occurred_at=when,
            fields={"Initiated by": who, "Partner": "ALL (default setting)" if default else partner or "not identifiable",
                    "Change": changed, **({"Partner users seen (14 d)": users} if users else {})},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", ""),
                       "Audit ID": audit.get("id", "")}],
            recommendation=("Confirm the change was requested (ticket / partner agreement) and who made it. Trusting a "
                            "partner's MFA is common for close partners and avoids double prompts, but a compromised or "
                            "weakly protected partner tenant then passes your MFA policy. Trusting their device "
                            "compliance or allowing them to sync users needs a stronger reason."),
            links=[("Open audit logs", AUDIT_URL),
                   ("Cross-tenant access settings", "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/"
                                                    "CompanyRelationshipsMenuBlade/~/CrossTenantAccessSettings")],
        )

    def _partner(self, ctx: PluginContext, audit: dict) -> tuple[str, str]:
        """(name, tenant id) of the partner a cross-tenant event is about. Add events name the tenant; update events
        only name this tenant's policy, so the partner is the one whose current settings carry the new values."""
        tenant_id = _props(audit).get("tenantId") or _old_props(audit).get("tenantId") or ""
        if not tenant_id and "default" not in (audit.get("activityDisplayName") or "").lower():
            changes = cross_tenant_changes(audit)
            try:
                partners = ctx.graph.get("/v1.0/policies/crossTenantAccessPolicy/partners").get("value") or []
            except Exception as exc:
                ctx.log.info("Cross-tenant partner lookup failed: %s", exc)
                return "", ""
            hits = [p.get("tenantId") for p in partners if partner_matches(p, changes)]
            if len(hits) != 1:
                return (f"one of {len(hits)} partners with these settings" if hits else ""), ""
            tenant_id = hits[0]
        return (self._tenant_name(ctx, tenant_id), tenant_id) if tenant_id else ("", "")

    @staticmethod
    def _tenant_name(ctx: PluginContext, tenant_id: str) -> str:
        names = dict(ctx.state.get("tenant_names") or {})
        if tenant_id not in names:
            try:
                info = ctx.graph.get(f"/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')")
                names[tenant_id] = f"{info.get('displayName') or '?'} ({info.get('defaultDomainName') or tenant_id})"
            except Exception as exc:
                ctx.log.info("Tenant name lookup failed: %s", exc)
                return f"tenant {tenant_id}"
            ctx.state.set("tenant_names", names)
        return names[tenant_id]

    @staticmethod
    def _partner_users(ctx: PluginContext, tenant_id: str, when) -> str:
        """Users from the partner tenant who signed in here recently (the people the change affects)."""
        try:
            rows = ctx.graph.get("/beta/auditLogs/signIns", {
                "$filter": f"createdDateTime ge {graph_time(when - timedelta(days=14))} and homeTenantId eq '{tenant_id}'",
                "$select": "userPrincipalName", "$top": "500"}).get("value") or []
        except Exception as exc:
            ctx.log.info("Partner user lookup failed: %s", exc)
            return ""
        users = sorted({str(r.get("userPrincipalName") or "").lower() for r in rows} - {""})
        return ", ".join(users[:8]) + (f" (+{len(users) - 8})" if len(users) > 8 else "") if users else "none in 14 days"

    @staticmethod
    def _assist_sp_id(ctx: PluginContext, now) -> str | None:
        """Object id of Microsoft's Assist API service principal in this tenant (cached for a day)."""
        cached = ctx.state.get("assist_sp")
        if cached and now - parse_time(cached["at"]) < timedelta(days=1):
            return cached["id"]
        try:
            found = ctx.graph.get("/v1.0/servicePrincipals", {"$filter": f"appId eq '{ASSIST_API_APP_ID}'",
                                                              "$select": "id"}).get("value") or []
        except Exception as exc:
            ctx.log.warning("Could not look up the Assist API service principal: %s", exc)
            return cached["id"] if cached else None
        sp_id = found[0]["id"] if found else None
        ctx.state.set("assist_sp", {"at": now.isoformat(), "id": sp_id})
        return sp_id

    @staticmethod
    def _support_case_record(audit: dict, by: str) -> Finding:
        """A Microsoft 365 support case was opened: kept as a record (context for the engineer's role assignment)."""
        when = parse_time(audit["activityDateTime"])
        return Finding(
            key=f"supportcase|{audit.get('id')}", rule_id="role_assignment", severity=Severity.INFO, score=0,
            signal="support_case", subjects=[by],
            title=f"Microsoft 365 support case opened by {by}",
            summary=(f"{by} opened a support case in the Microsoft 365 admin center: the Microsoft Support tenant was "
                     f"added as cross-tenant service provider. Microsoft engineers get the read-only 'Microsoft 365 "
                     f"Support Engineer' role while they work on it (record only, no alert)."),
            occurred_at=when, fields={"Initiated by": by, "Support tenant": MS_SUPPORT_TENANT},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": by, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", "")}],
            links=[("Open audit logs", AUDIT_URL),
                   ("About support case access", "https://learn.microsoft.com/microsoft-365/admin/"
                                                 "support-diagnostic-information-collection")],
        )

    @staticmethod
    def _app_names(ctx: PluginContext, events: list[ConsentEvent]) -> dict[str, str]:
        """Names of service principals that a grant event identifies only by id (looked up once, cached)."""
        names = dict(ctx.state.get("sp_names") or {})
        named = {e.client_id for e in events if e.client}
        for sp in sorted({e.client_id for e in events if e.client_id and e.client_id not in named} - set(names))[:20]:
            try:
                names[sp] = ctx.graph.get(f"/v1.0/servicePrincipals/{sp}", {"$select": "displayName"}).get("displayName") or sp
            except Exception:  # deleted app or no access: keep the id
                names[sp] = sp
        ctx.state.set("sp_names", names)
        return names

    @staticmethod
    def _user_consent_allowed(ctx: PluginContext, now) -> bool:
        """Can users consent to apps themselves? (authorization policy, cached; unknown -> no)."""
        cached = ctx.state.get("user_consent")
        if cached and now - parse_time(cached["at"]) < timedelta(hours=EXCLUSION_CACHE_HOURS):
            return bool(cached["allowed"])
        try:
            policy = ctx.graph.get("/v1.0/policies/authorizationPolicy")
            policy = (policy.get("value") or [policy])[0]
            assigned = (policy.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or []
            allowed = any(str(p).lower().startswith(USER_CONSENT_POLICY_PREFIX) for p in assigned)
        except Exception as exc:
            ctx.log.warning("Could not read the user consent setting: %s", exc)
            return bool(cached["allowed"]) if cached else False
        ctx.state.set("user_consent", {"at": now.isoformat(), "allowed": allowed})
        return allowed

    @staticmethod
    def _consent_policy_finding(audit: dict, reason: str) -> Finding:
        who, when = _initiator(audit), parse_time(audit["activityDateTime"])
        return Finding(
            key=f"consentpolicy|{audit.get('id')}", rule_id="consent_grant", severity=Severity.HIGH, score=75,
            factors=[(75, reason)], title=f"User consent to apps enabled by {who}",
            summary=f"{who} changed the authorization policy. {reason}. This is how illicit consent grant phishing "
                    f"gets mailbox/file access without an admin.",
            occurred_at=when, fields={"Initiated by": who},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", "")}],
            recommendation="Revert unless this was a decided policy change (Entra ID > Enterprise apps > Consent and "
                           "permissions > Do not allow user consent).",
            links=[("Open audit logs", AUDIT_URL)],
        )

    @staticmethod
    def _exclusion_groups(ctx: PluginContext, now) -> dict[str, dict]:
        """{group id: {name, policies, mfa}} of groups excluded from any enforced CA policy (cached a few hours)."""
        cached = ctx.state.get("ca_exclusion_groups")
        if cached and now - parse_time(cached["at"]) < timedelta(hours=EXCLUSION_CACHE_HOURS):
            return cached["groups"]
        try:
            groups = entra.ca_exclusion_groups(ctx.graph)
        except Exception as exc:
            ctx.log.warning("Could not read Conditional Access exclusions: %s", exc)
            return cached["groups"] if cached else {}
        ctx.state.set("ca_exclusion_groups", {"at": now.isoformat(), "groups": groups})
        return groups

    @staticmethod
    def _role_groups(ctx: PluginContext, now) -> dict[str, str]:
        """{group id: name} of the groups that can hold admin roles (cached a few hours)."""
        cached = ctx.state.get("role_groups")
        if cached and now - parse_time(cached["at"]) < timedelta(hours=EXCLUSION_CACHE_HOURS):
            return cached["groups"]
        try:
            groups = entra.role_groups(ctx.graph)
        except Exception as exc:
            ctx.log.warning("Could not read the groups that can hold admin roles: %s", exc)
            return cached["groups"] if cached else {}
        ctx.state.set("role_groups", {"at": now.isoformat(), "groups": groups})
        return groups

    @staticmethod
    def _privileged_group_finding(audit: dict, group: str, automation: list[str]) -> Finding:
        who, when = _initiator(audit), parse_time(audit["activityDateTime"])
        owner = "owner" in (audit.get("activityDisplayName") or "").lower()
        member = next((t.get("userPrincipalName") or t.get("displayName") for t in audit.get("targetResources") or []
                       if str(t.get("type", "")).lower() in ("user", "serviceprincipal", "device")), None) or "an account"
        if owner:
            factors = [(55, f"{member} was made an owner of {group}, a group that can hold admin roles - an owner "
                            f"decides who its members are")]
        else:
            factors = [(60, f"{member} was added to {group}, a group that can hold admin roles - its roles are now "
                            f"this account's, and no role assignment is logged for it")]
        if _matches(who, automation):
            factors.append((-30, f"Known automation of the tenant ({who})"))
        score = max(0, min(100, sum(p for p, _ in factors)))
        subjects = _subject(who) + ([str(member).lower()] if "@" in str(member) else [])
        return Finding(
            key=f"privgroup|{audit.get('id')}", rule_id="privileged_group", severity=severity_for(score), score=score,
            factors=factors, subjects=subjects,
            title=f"{'Owner' if owner else 'Member'} added to a group that can hold admin roles: {member} -> {group}",
            summary=f"{factors[0][1]}. Initiated by {who}.",
            occurred_at=when,
            fields={"Group": group, "Owner" if owner else "Member": member, "Initiated by": who},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", "")}],
            recommendation=("Confirm it was requested and approved. Look at which roles the group holds (Entra ID > "
                            "Roles and administrators) - they apply to the new member at once."),
            links=[("Open audit logs", AUDIT_URL)],
        )

    @staticmethod
    def _device_removed_signal(audit: dict) -> Finding | None:
        """A device was removed from the directory: the answer to an alert about its registration (matched by the
        device's id - without one in the entry there is nothing to tie it to)."""
        details = {str(d.get("key")).replace(" ", "").lower(): str(d.get("value") or "").strip()
                   for d in audit.get("additionalDetails") or [] if isinstance(d, dict)}
        device_id = details.get("deviceid", "")
        if not _GUID.fullmatch(device_id):
            return None
        who, when = _initiator(audit), parse_time(audit["activityDateTime"])
        device = next((clean for t in audit.get("targetResources") or []
                       if str(t.get("type", "")).lower() == "device"
                       for clean in [str(t.get("displayName") or "").replace("\x00", "").strip()] if clean), "") or "a device"
        return Finding(
            key=f"devdel|{audit.get('id')}", rule_id="device_registration", severity=Severity.INFO, score=0,
            signal="device_removed", subjects=[],
            title=f"Device removed: {device}",
            summary=f"{device} was removed from Entra ID by {who}. The sign-in tokens it held are gone with it.",
            occurred_at=when, fields={"Device": device, linkify.DEVICE_ID_FIELD: device_id, "Initiated by": who},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": device, "Correlation ID": audit.get("correlationId", "")}],
        )

    @staticmethod
    def _device_signal(audit: dict) -> Finding:
        """A user registered a device: persistence step of device-code phishing - only a chain link on its own."""
        who, when = _initiator(audit), parse_time(audit["activityDateTime"])
        # (the log pads some device names with NUL characters)
        device = next((clean for t in audit.get("targetResources") or []
                       if str(t.get("type", "")).lower() == "device"
                       for clean in [str(t.get("displayName") or "").replace("\x00", "").strip()] if clean), "") or "a device"
        details = {str(d.get("key")): str(d.get("value") or "").strip() for d in audit.get("additionalDetails") or []
                   if isinstance(d, dict)}
        device_id = details.get("Device Id", "")
        kind = ", ".join(v for v in (details.get("Device Trust Type", ""), details.get("Device OS", ""))
                         if v and v.lower() != "unknown")
        address = str(((audit.get("initiatedBy") or {}).get("user") or {}).get("ipAddress") or "").strip()
        who = who.lower() if "@" in who else who
        return Finding(
            key=f"devreg|{audit.get('id')}", rule_id="device_registration", severity=Severity.LOW, score=30,
            signal="device_registered", subjects=[who],
            title=f"Device registered by {who}: {device}",
            summary=(f"{who} registered {device} in Entra ID" + (f" from {address}" if address else "")
                     + ". A registered device gets long-lived sign-in tokens - "
                     "after a phished session this is how attackers stay in. Recorded as a step for attack chains."),
            occurred_at=when,
            fields={"User": who, "Device": device, **({linkify.DEVICE_ID_FIELD: device_id} if device_id else {}),
                    **({"Kind": kind} if kind else {}), **({"Registered from": address} if address else {})},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": device, "Correlation ID": audit.get("correlationId", "")}],
            recommendation=("If the user did not set up this device: remove it (Entra ID > Devices), revoke the "
                            "user's sessions and reset the password - the device keeps its tokens otherwise."),
            links=[("Open audit logs", AUDIT_URL)],
        )

    @staticmethod
    def _revocation_signal(audit: dict) -> Finding:
        """Sessions of a user were revoked (manually or by a password change): remediation context."""
        when = parse_time(audit["activityDateTime"])
        upn = next((t.get("userPrincipalName") for t in audit.get("targetResources") or [] if t.get("userPrincipalName")), "")
        return Finding(
            key=f"revoked|{audit.get('id')}", rule_id="session_revocations", severity=Severity.INFO, score=0,
            signal="sessions_revoked", subjects=[upn],
            title=f"Sessions revoked: {upn or 'unknown'}",
            summary=f"All refresh tokens / sessions of {upn} were revoked by {_initiator(audit)} (context, no alert).",
            occurred_at=when, fields={"Account": upn, "Initiated by": _initiator(audit)},
        )

    @staticmethod
    def _password_signal(audit: dict) -> Finding:
        """The password of an account was reset - by an admin, through self-service reset (which asks for the
        person's MFA methods) or on-premises: remediation context, linked to the alerts about the account
        (radar.correlation.RESPONSES). A plain self-service CHANGE is left out on purpose: it only needs the current
        password, so whoever knows the password can do it - that is no response."""
        upn = next((t.get("userPrincipalName") for t in audit.get("targetResources") or [] if t.get("userPrincipalName")), "")
        when = parse_time(audit["activityDateTime"])
        how = PASSWORD_RESET_ACTIVITIES[(audit.get("activityDisplayName") or "").lower()]
        by = _initiator(audit)
        if "sync" in by.lower():
            how = "changed on-premises, synced to Entra"
        return Finding(
            key=f"pwreset|{audit.get('id')}", rule_id="session_revocations", severity=Severity.INFO, score=0,
            signal="password_reset", subjects=[upn],
            title=f"Password reset: {upn or 'unknown'}",
            summary=f"The password of {upn} was reset ({how}) by {by} (context, no alert).",
            occurred_at=when, fields={"Account": upn, "Initiated by": by, "How": how},
        )

    @staticmethod
    def _enabled_signal(audit: dict) -> Finding:
        """'Account enabled' as silent context: a disabled account that is enabled again can sign in again, so
        "the account was disabled" no longer lowers the risk of alerts about it (radar.correlation.RESPONSES)."""
        upn = next((t.get("userPrincipalName") for t in audit.get("targetResources") or [] if t.get("userPrincipalName")), "")
        when = parse_time(audit["activityDateTime"])
        return Finding(
            key=f"enabled|{audit.get('id')}", rule_id="guest_invites", severity=Severity.INFO, score=0,
            signal="account_enabled", subjects=[upn],
            title=f"Account enabled: {upn or 'unknown'}",
            summary=f"{upn} was enabled by {_initiator(audit)} (context signal, no alert on its own).",
            occurred_at=when, fields={"Account": upn, "Initiated by": _initiator(audit)},
        )

    @staticmethod
    def _disabled_signal(audit: dict) -> Finding:
        """'Account disabled' as a silent context signal (correlates with earlier private-mailbox guest invites)."""
        upn = next((t.get("userPrincipalName") for t in audit.get("targetResources") or [] if t.get("userPrincipalName")), "")
        when = parse_time(audit["activityDateTime"])
        return Finding(
            key=f"disabled|{audit.get('id')}", rule_id="guest_invites", severity=Severity.INFO, score=0,
            signal="account_disabled", subjects=[upn],
            title=f"Account disabled: {upn or 'unknown'}",
            summary=f"{upn} was disabled by {_initiator(audit)} (context signal, no alert on its own).",
            occurred_at=when, fields={"Account": upn, "Initiated by": _initiator(audit)},
        )

    @staticmethod
    def _exclusion_finding(audit: dict, group_id: str, info: dict | str) -> Finding:
        info = info if isinstance(info, dict) else {"name": info, "policies": [], "mfa": True}
        group, mfa = info.get("name", group_id), bool(info.get("mfa"))
        policies = ", ".join(info.get("policies") or []) or "Conditional Access"
        added = (audit.get("activityDisplayName") or "").lower().startswith("add")
        who = _initiator(audit)
        member = next((t.get("userPrincipalName") or t.get("displayName") for t in audit.get("targetResources") or []
                       if str(t.get("type", "")).lower() == "user"), None) or "an account"
        score = (80 if mfa else 60) if added else 15
        if mfa:
            reason = (f"{member} was added to {group}, which is excluded from MFA - it can now sign in with a password only"
                      if added else f"{member} was removed from MFA exclusion group {group} (MFA applies again)")
        else:
            reason = (f"{member} was added to {group}, which is excluded from the Conditional Access policy/policies "
                      f"{policies} - those protections no longer apply to the account"
                      if added else f"{member} was removed from {group} ({policies} apply again)")
        kind = "MFA exclusion group" if mfa else "CA exclusion group"
        when = parse_time(audit["activityDateTime"])
        return Finding(
            key=f"mfaexcl|{audit.get('id')}", rule_id="mfa_exclusion_change", severity=severity_for(score), score=score,
            factors=[(score, reason)],
            title=(f"Added to {kind} {group}: {member}" if added else f"Removed from {kind} {group}: {member}"),
            summary=f"{reason}. Initiated by {who}.",
            occurred_at=when,
            fields={"Group": group, "Excluded from": policies, "Member": member, "Initiated by": who},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", "")}],
            recommendation=("Confirm this exclusion was approved and is needed. Every MFA exclusion is a password-only "
                            "door into the tenant - prefer restricting the account to its networks instead."
                            if added else "No action needed."),
            links=[("Open audit logs", AUDIT_URL)],
        )

    @staticmethod
    def _enables_from_before(ctx: PluginContext, audits: list[dict], now) -> list[dict]:
        """Once each: the "Enable account" events and the password resets of the last 30 days. They are context for
        the alerts already on record: which disabled accounts were enabled again ("account disabled" is then no
        lasting response), and which accounts got a new password since."""
        wanted = {"enables_backfilled": ["Enable account"],
                  "resets_backfilled": ["Reset password (self-service)", "Reset password (by admin)", "Reset user password",
                                        "Change user password"]}
        have, out = {a.get("id") for a in audits}, []
        for flag, names in wanted.items():
            if ctx.state.get(flag):
                continue
            try:
                which = " or ".join(f"activityDisplayName eq '{n}'" for n in names)
                flt = f"activityDateTime ge {graph_time(now - timedelta(days=30))} and ({which})"
                got = list(ctx.graph.get_all("/v1.0/auditLogs/directoryAudits", {"$filter": flt, "$top": "500"}, max_pages=5))
            except Exception:  # noqa: BLE001 - tried again with the next run
                ctx.log.warning("Earlier events not readable (%s)", ", ".join(names), exc_info=True)
                continue
            ctx.state.set(flag, now.isoformat())
            out += [a for a in got if a.get("id") not in have]
            have |= {a.get("id") for a in got}
        return out

    def _keep_account_events(self, ctx: PluginContext, audits: list[dict], now) -> None:
        """Password resets, MFA methods, devices, accounts and admin roles for the live map's feed (account_events).
        Never in the way of the alerts: whatever goes wrong here is logged and left."""
        try:
            path = Path(ctx.data_dir) / account_events.FILE
            if not path.exists():  # first time: the feed starts with the last two days, not empty
                audits = list(self._fetch(ctx, now - timedelta(hours=48), 20)) + audits
            account_events.merge(path, account_events.normalise(audits), now)
        except Exception:  # noqa: BLE001 - a feed nicety must not cost an alert
            ctx.log.warning("Account events for the live map not kept", exc_info=True)

    @staticmethod
    def _fetch(ctx: PluginContext, since, max_pages: int):
        """Only the categories the rules need (provisioning/sync is most of the volume)."""
        base = f"activityDateTime ge {graph_time(since)}"
        cats = " or ".join(f"category eq '{c}'" for c in CATEGORIES)
        try:
            yield from ctx.graph.get_all("/v1.0/auditLogs/directoryAudits", {"$filter": f"{base} and ({cats})", "$top": "999"},
                                         max_pages=max_pages)
        except GraphError as exc:
            if exc.status != 400:
                raise
            ctx.log.warning("Category filter not accepted (%s); fetching all audit events", exc.message)
            yield from ctx.graph.get_all("/v1.0/auditLogs/directoryAudits", {"$filter": base, "$top": "999"},
                                         max_pages=max_pages)

    @staticmethod
    def _invite_finding(audit: dict) -> Finding:
        who, email = _initiator(audit), guest_email(audit)
        score, reason = classify_invite(who, email)
        guest_id = next((t.get("id") for t in audit.get("targetResources") or [] if t.get("id")), audit.get("id"))
        when = parse_time(audit["activityDateTime"])
        return Finding(
            key=f"guest|{guest_id}", rule_id="guest_invites", severity=severity_for(score), score=score,
            factors=[(score, reason)], signal="guest_invite", subjects=[who, email],
            title=f"Guest invited by {who}: {email or 'external user'}",
            summary=f"{who} invited {email or 'an external user'} as a guest into the tenant. {reason}.",
            occurred_at=when,
            fields={"Invited by": who, "Guest": email or "-", "Assessment": reason},
            evidence=[{"Time": timefmt.sortable(when, seconds=True), "Activity": audit.get("activityDisplayName", ""),
                       "Initiated by": who, "Targets": _targets(audit), "Correlation ID": audit.get("correlationId", "")}],
            recommendation=("Check why a private mailbox needs guest access. Guests can receive shared files and Teams "
                            "content; remove the guest if not justified and review what was shared with it."
                            if score >= 45 else "Business guest - verify the sponsor still needs it."),
            links=[("Open audit logs", AUDIT_URL)],
        )
