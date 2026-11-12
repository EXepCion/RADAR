"""Account context: state, roles, MFA exposure - synced from Entra ID about once a day.

Used to judge accounts against the right expectations: admin accounts weigh more, accounts that can
sign in with a password only (excluded from MFA) are watched more strictly, disabled accounts must not
sign in. No account type gets an automatic discount.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ... import entra
from .models import graph_time, parse_time

log = logging.getLogger(__name__)

TOP_ROLES = {"global administrator", "privileged role administrator", "privileged authentication administrator",
             "security administrator", "conditional access administrator", "hybrid identity administrator",
             "domain name administrator", "external identity provider administrator", "partner tier2 support",
             "directory synchronization accounts", "on premises directory sync account"}
NON_PERSON_HINTS = ("admin", "support", "info", "service", "svc", "sync", "bot", "test", "noreply", "no-reply",
                    "bounce", "room", "scanner", "calibration", "subscription", "onedrive", "production", "crm",
                    "jira", "confluence", "gitlab", "poc", "frameworks", "reception", "meeting", "helpdesk", "mailbox")


@dataclass
class AccountInfo:
    user_id: str
    upn: str
    display_name: str = ""
    enabled: bool = True
    user_type: str = "Member"
    created: str | None = None
    pwd_changed: str | None = None
    last_signin: str | None = None
    synced_onprem: bool = False
    roles: list[str] = field(default_factory=list)       # active directory role assignments
    pim_roles: list[str] = field(default_factory=list)   # roles activated via PIM in the last 30 days
    mfa_excluded: list[str] = field(default_factory=list)  # why the account can sign in without MFA
    phishing_resistant: bool = False
    breakglass: bool = False  # member of a break-glass group (see settings breakglass_groups)
    mfa_registered: bool | None = None  # any MFA method registered (registration report); None = unknown
    mfa_methods: list[str] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)  # product names of the assigned licences (skuPartNumber)

    @property
    def room(self) -> bool:
        """A meeting room: the account holds a Microsoft Teams Rooms licence (assigned in Entra to the resource
        account a room system signs in with) - Entra's own statement, no guessing from names or devices."""
        return any("ROOM" in (name or "").upper() for name in self.licenses)

    @property
    def mfa_gap(self) -> bool:
        """MFA is required but nothing is registered: whoever knows the password can register their own MFA.
        Members only - guests register MFA in their home organisation."""
        return (self.enabled and self.mfa_registered is False and not self.mfa_excluded
                and (self.user_type or "Member").lower() == "member")

    @property
    def privileged_tier(self) -> int:
        names = {r.lower() for r in self.roles + self.pim_roles}
        if names & TOP_ROLES:
            return 2
        return 1 if names else 0

    @property
    def person_like(self) -> bool:
        """first.last style name without service hints - a human behind an MFA exclusion?"""
        local = self.upn.split("@")[0].lower()
        if any(h in local for h in NON_PERSON_HINTS) or re.search(r"\d", local):
            return False
        return bool(re.fullmatch(r"[a-z]+[._][a-z]+", local)) and len((self.display_name or "").split()) >= 2

    def age_days(self, value: str | None, now: datetime) -> int | None:
        return (now - parse_time(value)).days if value else None

    def context(self, now: datetime | None = None) -> str:
        now = now or datetime.now(timezone.utc)
        parts = ["BREAK-GLASS account"] if self.breakglass else []
        if self.mfa_excluded:
            parts.append("excluded from MFA (" + self.mfa_excluded[0].split(" (", 1)[-1].rstrip(")") + ")")
        elif self.mfa_gap:
            parts.append("NO MFA method registered")
        elif self.phishing_resistant:
            parts.append("phishing-resistant MFA required")
        roles = self.roles + [f"{r} (PIM)" for r in self.pim_roles if r not in self.roles]
        if roles:
            parts.append("admin: " + ", ".join(roles[:3]))
        parts.append("enabled" if self.enabled else "DISABLED")
        if self.user_type and self.user_type != "Member":
            parts.append(self.user_type.lower())
        if self.created:
            parts.append(f"created {parse_time(self.created):%Y}")
        pwd_age = self.age_days(self.pwd_changed, now)
        if pwd_age is not None and pwd_age > 365:
            parts.append(f"password {pwd_age // 365}+ y old")
        return " · ".join(parts)


class AccountDirectory:
    def __init__(self, accounts: dict[str, AccountInfo] | None = None, synced_at: datetime | None = None,
                 exclusion_groups: dict[str, Any] | None = None, policies: list[str] | None = None,
                 breakglass_groups: list[str] | None = None):
        self.accounts = accounts or {}
        self.synced_at = synced_at
        self.exclusion_groups = exclusion_groups or {}
        self.policies = policies or []
        self.breakglass_groups = breakglass_groups or []  # groups that were resolved in this snapshot
        self.licenses_synced = True  # False for a copy saved before licences were read (-> read again)

    def get(self, user_id: str) -> AccountInfo | None:
        return self.accounts.get(user_id or "")

    def mfa_excluded(self) -> list[AccountInfo]:
        return sorted((a for a in self.accounts.values() if a.mfa_excluded), key=lambda a: a.upn.lower())

    # -------------------------------------------------------- persistence
    @classmethod
    def load(cls, path: Path) -> "AccountDirectory":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        directory = cls({k: AccountInfo(**v) for k, v in data.get("accounts", {}).items()},
                        parse_time(data["synced_at"]) if data.get("synced_at") else None,
                        data.get("exclusion_groups", {}), data.get("policies", []), data.get("breakglass_groups", []))
        directory.licenses_synced = bool(data.get("licenses_synced"))
        return directory

    def save(self, path: Path) -> None:
        tmp = Path(path).with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "exclusion_groups": self.exclusion_groups, "policies": self.policies,
            "breakglass_groups": self.breakglass_groups, "licenses_synced": True,
            "accounts": {k: asdict(v) for k, v in self.accounts.items()},
        }), encoding="utf-8")
        tmp.replace(path)


def sync_directory(graph, now: datetime, breakglass_groups: list[str] | None = None) -> AccountDirectory:
    """Read users, role assignments, PIM activations and MFA exclusions (all read-only)."""
    select = ("id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,lastPasswordChangeDateTime,"
              "onPremisesSyncEnabled,assignedLicenses")
    skus: dict[str, str] = {}
    try:  # names of the tenant's licences (to recognise e.g. meeting rooms by their Teams Rooms licence)
        for sku in graph.get_all("/v1.0/subscribedSkus", {"$select": "skuId,skuPartNumber"}):
            skus[sku.get("skuId")] = sku.get("skuPartNumber") or ""
    except Exception:
        log.warning("Licence names not readable", exc_info=True)
    try:
        users = list(graph.get_all("/v1.0/users", {"$select": select + ",signInActivity", "$top": "999"}))
    except Exception as exc:  # signInActivity needs AuditLog.Read.All; fall back without it
        log.warning("Users with signInActivity not readable (%s); retrying without", exc)
        users = list(graph.get_all("/v1.0/users", {"$select": select, "$top": "999"}))
    accounts: dict[str, AccountInfo] = {}
    for u in users:
        activity = u.get("signInActivity") or {}
        accounts[u["id"]] = AccountInfo(
            user_id=u["id"], upn=(u.get("userPrincipalName") or "").lower(), display_name=u.get("displayName") or "",
            enabled=bool(u.get("accountEnabled", True)), user_type=u.get("userType") or "Member",
            created=u.get("createdDateTime"), pwd_changed=u.get("lastPasswordChangeDateTime"),
            last_signin=activity.get("lastSuccessfulSignInDateTime") or activity.get("lastSignInDateTime"),
            synced_onprem=bool(u.get("onPremisesSyncEnabled")),
            licenses=sorted({skus[lic.get("skuId")] for lic in u.get("assignedLicenses") or [] if skus.get(lic.get("skuId"))}))

    try:  # MFA registration state per user (reports/authenticationMethods - readable as Global Reader)
        for r in graph.get_all("/v1.0/reports/authenticationMethods/userRegistrationDetails",
                               {"$select": "id,isMfaRegistered,methodsRegistered", "$top": "999"}):
            acct = accounts.get(r.get("id"))
            if acct:
                acct.mfa_registered = bool(r.get("isMfaRegistered"))
                acct.mfa_methods = list(r.get("methodsRegistered") or [])
    except Exception:
        log.warning("MFA registration details not readable", exc_info=True)

    role_names: dict[str, str] = {}
    try:
        for d in graph.get_all("/v1.0/roleManagement/directory/roleDefinitions", {"$select": "id,displayName,templateId"}):
            role_names[d["id"]] = d.get("displayName") or d["id"]
            if d.get("templateId"):
                role_names[d["templateId"]] = d.get("displayName") or d["id"]
        role_members: dict[str, list[str]] = {}
        for a in graph.get_all("/v1.0/roleManagement/directory/roleAssignments", {"$select": "principalId,roleDefinitionId"}):
            name = role_names.get(a.get("roleDefinitionId"), a.get("roleDefinitionId"))
            role_members.setdefault(a.get("roleDefinitionId"), []).append(a.get("principalId"))
            acct = accounts.get(a.get("principalId"))
            if acct and name not in acct.roles:
                acct.roles.append(name)
    except Exception:
        log.warning("Directory role assignments not readable", exc_info=True)
        role_members = {}

    try:  # PIM eligibilities need RoleEligibilitySchedule.Read.Directory: use 30 days of activations instead
        since = graph_time(now - timedelta(days=30))
        for audit in graph.get_all("/v1.0/auditLogs/directoryAudits", {
                "$filter": f"activityDateTime ge {since} and "
                           f"activityDisplayName eq 'Add member to role completed (PIM activation)'"}):
            user = (audit.get("initiatedBy") or {}).get("user") or {}
            acct = accounts.get(user.get("id"))
            role = next((t.get("displayName") for t in audit.get("targetResources") or []
                         if str(t.get("type", "")).lower() == "role" and t.get("displayName")), None)
            if acct and role and role not in acct.pim_roles:
                acct.pim_roles.append(role)
    except Exception:
        log.warning("PIM activations not readable", exc_info=True)

    exclusions = entra.mfa_exclusions(graph)
    for uid, reasons in exclusions["users"].items():
        if uid in accounts:
            accounts[uid].mfa_excluded = sorted(set(reasons))
    for role, policies in exclusions["roles"].items():
        for uid in role_members.get(role, []):
            if uid in accounts:
                accounts[uid].mfa_excluded = sorted(set(accounts[uid].mfa_excluded) |
                                                    {f"{p} (role {role_names.get(role, role)})" for p in policies})
    for uid in exclusions["phishing_resistant_users"]:
        if uid in accounts:
            accounts[uid].phishing_resistant = True
    for gid in breakglass_groups or []:
        try:
            for uid in entra.group_user_ids(graph, gid):
                if uid in accounts:
                    accounts[uid].breakglass = True
        except Exception:
            log.warning("Break-glass group %s not readable", gid, exc_info=True)
    log.info("Account directory synced: %d accounts, %d excluded from MFA, %d without any MFA method, %d with admin "
             "roles, %d break-glass", len(accounts), sum(1 for a in accounts.values() if a.mfa_excluded),
             sum(1 for a in accounts.values() if a.mfa_gap),
             sum(1 for a in accounts.values() if a.roles or a.pim_roles), sum(1 for a in accounts.values() if a.breakglass))
    return AccountDirectory(accounts, now, exclusions["groups"], exclusions["policies"], list(breakglass_groups or []))
