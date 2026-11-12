"""Looks up the directory objects behind names / IDs shown in alerts (for portal deep links), and fetches
audit log entries for the in-app viewer. Read-only Graph calls; results are cached for the session."""
from __future__ import annotations

import logging
import re
import threading
from typing import Any, Callable
from urllib.parse import quote

from .graph import GraphError

log = logging.getLogger(__name__)

GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
USER_SELECT = "id,displayName,userPrincipalName,userType,accountEnabled"
SP_SELECT = "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId"
NOT_FOUND = {400, 404}


def _q(value: str) -> str:
    """OData string literal content."""
    return value.replace("'", "''")


class Resolver:
    def __init__(self, graph_factory: Callable[[], Any]):
        self._graph_factory = graph_factory
        self._graph = None
        self._cache: dict[tuple[str, str], dict | None] = {}
        self._lock = threading.Lock()

    @property
    def graph(self):
        if self._graph is None:
            self._graph = self._graph_factory()
        return self._graph

    def resolve(self, kind: str, value: str) -> dict | None:
        """{"kind", "id", "name", "detail", ...} of the object, or None if it is not in the directory."""
        value = (value or "").strip()
        key = (kind, value.lower())
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        lookup = getattr(self, f"_{kind}", None)
        info = lookup(value) if lookup and value else None
        with self._lock:
            self._cache[key] = info
        return info

    # ------------------------------------------------------------ helpers
    def _get(self, path: str, params: dict | None = None) -> dict | None:
        try:
            return self.graph.get(path, params)
        except GraphError as exc:
            if exc.status in NOT_FOUND:
                return None
            raise

    def _first(self, path: str, flt: str, select: str = "") -> dict | None:
        params = {"$filter": flt, "$top": "5"}
        if select:
            params["$select"] = select
        data = self._get(path, params)
        values = (data or {}).get("value") or []
        return values[0] if values else None

    # -------------------------------------------------------------- kinds
    def _user(self, value: str) -> dict | None:
        obj = self._get(f"/v1.0/users/{quote(value, safe='@')}", {"$select": USER_SELECT})
        if obj is None and "@" in value:
            obj = self._first("/v1.0/users", f"mail eq '{_q(value)}'", USER_SELECT)
            if obj is None:  # a guest: name_domain#EXT#@tenant
                guest = value.replace("@", "_") + "#EXT#"
                obj = self._first("/v1.0/users", f"startswith(userPrincipalName,'{_q(guest)}')", USER_SELECT)
        return self._user_info(obj) if obj else None

    @staticmethod
    def _user_info(obj: dict) -> dict:
        notes = [obj.get("userPrincipalName") or ""]
        if obj.get("userType") == "Guest":
            notes.append("guest")
        if obj.get("accountEnabled") is False:
            notes.append("disabled")
        return {"kind": "user", "id": obj.get("id", ""), "name": obj.get("displayName") or obj.get("userPrincipalName"),
                "detail": ", ".join(n for n in notes if n)}

    def _app(self, value: str) -> dict | None:
        if GUID.match(value):
            obj = (self._first("/v1.0/servicePrincipals", f"appId eq '{value}'", SP_SELECT)
                   or self._get(f"/v1.0/servicePrincipals/{value}", {"$select": SP_SELECT}))
        else:
            obj = self._first("/v1.0/servicePrincipals", f"displayName eq '{_q(value)}'", SP_SELECT)
        return self._app_info(obj) if obj else None

    def _app_info(self, obj: dict) -> dict:
        app_id = obj.get("appId", "")
        registered = bool(app_id and self._first("/v1.0/applications", f"appId eq '{app_id}'", "id"))
        kind = obj.get("servicePrincipalType") or "Application"
        detail = ("managed identity" if kind == "ManagedIdentity" else
                  "registered in this tenant" if registered else "registered by another organisation")
        return {"kind": "app", "id": obj.get("id", ""), "appId": app_id, "name": obj.get("displayName"),
                "registered": registered, "detail": f"app id {app_id}, {detail}"}

    def _group(self, value: str) -> dict | None:
        obj = (self._get(f"/v1.0/groups/{value}", {"$select": "id,displayName"}) if GUID.match(value)
               else self._first("/v1.0/groups", f"displayName eq '{_q(value)}'", "id,displayName"))
        return {"kind": "group", "id": obj["id"], "name": obj.get("displayName")} if obj else None

    def _device(self, value: str) -> dict | None:
        select = "id,deviceId,displayName,operatingSystem,approximateLastSignInDateTime"
        if GUID.match(value):
            obj = (self._first("/v1.0/devices", f"deviceId eq '{value}'", select)
                   or self._get(f"/v1.0/devices/{value}", {"$select": select}))
        else:
            data = self._get("/v1.0/devices", {"$filter": f"displayName eq '{_q(value)}'", "$select": select})
            found = sorted((data or {}).get("value") or [], key=lambda d: d.get("approximateLastSignInDateTime") or "",
                           reverse=True)
            obj = found[0] if found else None
        if not obj:
            return None
        return {"kind": "device", "id": obj.get("id", ""), "deviceId": obj.get("deviceId", ""),
                "name": obj.get("displayName"), "detail": obj.get("operatingSystem") or ""}

    def _policy(self, value: str) -> dict | None:
        if GUID.match(value):
            obj = self._get(f"/v1.0/identity/conditionalAccess/policies/{value}")
        else:
            data = self._get("/v1.0/identity/conditionalAccess/policies") or {}
            obj = next((p for p in data.get("value") or []
                        if str(p.get("displayName", "")).strip().lower() == value.lower()), None)
        return {"kind": "policy", "id": obj["id"], "name": obj.get("displayName"),
                "detail": obj.get("state", "")} if obj else None

    def _tenant(self, value: str) -> dict | None:
        if not GUID.match(value):
            return None
        obj = self._get(f"/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{value}')")
        if not obj or not obj.get("displayName"):
            return None
        return {"kind": "tenant", "id": value, "name": obj.get("displayName"),
                "detail": obj.get("defaultDomainName") or ""}

    def _guid(self, value: str) -> dict | None:
        """An ID of unknown type: any directory object, an app id, a tenant, a role template, a CA policy."""
        if not GUID.match(value):
            return None
        obj = self._get(f"/v1.0/directoryObjects/{value}")
        if obj:
            kind = str(obj.get("@odata.type", "")).rsplit(".", 1)[-1]
            if kind == "user":
                return self._user_info(obj)
            if kind == "servicePrincipal":
                return self._app_info(obj)
            if kind == "application":
                sp = self._first("/v1.0/servicePrincipals", f"appId eq '{obj.get('appId', '')}'", SP_SELECT)
                return self._app_info(sp) if sp else {
                    "kind": "application", "id": obj.get("id", ""), "appId": obj.get("appId", ""),
                    "name": obj.get("displayName"), "registered": True}
            if kind == "group":
                return {"kind": "group", "id": obj["id"], "name": obj.get("displayName")}
            if kind == "device":
                return {"kind": "device", "id": obj["id"], "deviceId": obj.get("deviceId", ""),
                        "name": obj.get("displayName")}
            if kind in ("directoryRoleTemplate", "directoryRole"):
                return {"kind": "role", "id": value, "name": obj.get("displayName"), "detail": "directory role"}
            return {"kind": kind or "object", "id": value, "name": obj.get("displayName")}
        for lookup in (self._app, self._tenant):
            info = lookup(value)
            if info:
                return info
        role = self._get(f"/v1.0/directoryRoleTemplates/{value}")
        if role:
            return {"kind": "role", "id": value, "name": role.get("displayName"), "detail": "directory role"}
        return self._policy(value)


def fetch_audit_entries(graph, audit_id: str = "", correlation_id: str = "", limit: int = 50) -> list[dict]:
    """Directory audit records: the entry ``audit_id`` plus every entry of its operation (same correlation id)."""
    records: dict[str, dict] = {}
    if audit_id:
        try:
            rec = graph.get(f"/v1.0/auditLogs/directoryAudits/{quote(audit_id, safe='')}")
        except GraphError as exc:
            if exc.status not in NOT_FOUND:
                raise
            rec = None
        if rec:
            records[rec.get("id", audit_id)] = rec
            correlation_id = correlation_id or rec.get("correlationId", "")
    if correlation_id:
        data = graph.get("/v1.0/auditLogs/directoryAudits",
                         {"$filter": f"correlationId eq '{_q(correlation_id)}'", "$top": str(limit)})
        for rec in data.get("value") or []:
            records.setdefault(rec.get("id", ""), rec)
    return sorted(records.values(), key=lambda r: r.get("activityDateTime") or "")
