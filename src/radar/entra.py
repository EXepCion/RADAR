"""Entra ID helpers shared by plugins: who is covered by (or excluded from) Conditional Access MFA."""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

PHISHING_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004"  # built-in "Phishing-resistant MFA"


def mfa_policies(graph) -> list[dict[str, Any]]:
    """Enforced (state=enabled) CA policies that require MFA or an authentication strength."""
    out = []
    for p in graph.get("/v1.0/identity/conditionalAccess/policies").get("value", []):
        if p.get("state") != "enabled":
            continue  # report-only / disabled policies do not protect anything
        grant = p.get("grantControls") or {}
        controls = [str(c).lower() for c in grant.get("builtInControls") or []]
        strength = grant.get("authenticationStrength") or {}
        if "mfa" not in controls and not strength:
            continue
        users = (p.get("conditions") or {}).get("users") or {}
        out.append({
            "id": p.get("id"),
            "name": p.get("displayName") or p.get("id"),
            "all_users": "All" in (users.get("includeUsers") or []),
            "include_groups": list(users.get("includeGroups") or []),
            "exclude_users": list(users.get("excludeUsers") or []),
            "exclude_groups": list(users.get("excludeGroups") or []),
            "exclude_roles": list(users.get("excludeRoles") or []),
            "phishing_resistant": strength.get("id") == PHISHING_RESISTANT_STRENGTH
                                  or "phish" in str(strength.get("displayName", "")).lower(),
        })
    return out


def ca_exclusion_groups(graph) -> dict[str, dict[str, Any]]:
    """Groups excluded from ANY enforced Conditional Access policy: {gid: {"name", "policies", "mfa"}}.
    Adding someone to such a group switches a protection off for them (MFA, blocked countries, compliant
    device, legacy-auth block ...); "mfa" marks groups that bypass an all-user MFA policy."""
    mfa_ids = {p["id"] for p in mfa_policies(graph) if p["all_users"]}
    out: dict[str, dict[str, Any]] = {}
    for p in graph.get("/v1.0/identity/conditionalAccess/policies").get("value", []):
        if p.get("state") != "enabled":
            continue
        users = (p.get("conditions") or {}).get("users") or {}
        for gid in users.get("excludeGroups") or []:
            entry = out.setdefault(gid, {"name": group_name(graph, gid), "policies": [], "mfa": False})
            entry["policies"].append(p.get("displayName") or p.get("id"))
            entry["mfa"] = entry["mfa"] or p.get("id") in mfa_ids
    return out


def group_name(graph, group_id: str) -> str:
    try:
        return graph.get(f"/v1.0/groups/{group_id}", {"$select": "displayName"}).get("displayName") or group_id
    except Exception:
        return group_id


def group_user_ids(graph, group_id: str) -> list[str]:
    members = graph.get_all(f"/v1.0/groups/{group_id}/transitiveMembers", {"$select": "id"})
    return [m["id"] for m in members if str(m.get("@odata.type", "")).endswith("user")]


def mfa_exclusions(graph, resolve_members: bool = True) -> dict[str, Any]:
    """Exclusions from enforced MFA policies that otherwise apply to *all* users (= real MFA exposure).

    Returns {"policies": [...], "groups": {gid: {"name", "policies"}}, "users": {uid: [reason, ...]},
             "roles": {role_template_id: [policy, ...]}, "phishing_resistant_users": [uid, ...]}.
    """
    policies = mfa_policies(graph)
    result: dict[str, Any] = {"policies": [p["name"] for p in policies], "groups": {}, "users": {}, "roles": {},
                              "phishing_resistant_users": []}
    for p in policies:
        if p["phishing_resistant"] and resolve_members:
            for gid in p["include_groups"]:
                result["phishing_resistant_users"].extend(group_user_ids(graph, gid))
        if not p["all_users"]:
            continue
        for uid in p["exclude_users"]:
            result["users"].setdefault(uid, []).append(f"{p['name']} (excluded directly)")
        for gid in p["exclude_groups"]:
            entry = result["groups"].setdefault(gid, {"name": group_name(graph, gid), "policies": []})
            entry["policies"].append(p["name"])
            if resolve_members:
                for uid in group_user_ids(graph, gid):
                    result["users"].setdefault(uid, []).append(f"{p['name']} (group {entry['name']})")
        for role in p["exclude_roles"]:
            result["roles"].setdefault(role, []).append(p["name"])
    return result
