"""App-only audit actions: where the app signed in / which credential / what a self-granted permission was used for,
and the cross-tenant trust rule (an automation app grants itself Policy.ReadWrite.CrossTenantAccess, sets inbound
MFA trust for a partner tenant seconds later and removes the permission again right after)."""
import threading

from radar.config import ConfigManager
from radar.plugin_manager import PluginManager
from radar.plugins.directory_audit import cross_tenant_factors, partner_matches, self_grant_usage
from radar.store import Store

SP = "9a660719-sp"
PS = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.33648"
SERVER_PS = "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.20348; en-US) PowerShell/5.1.20348.5756"
ROLE = "00000000-0000-4000-8000-000000000002"
PARTNER = "ba3b31d8-partner"
MFA_TRUST = '{"IsMfaAccepted":true,"IsCompliantDeviceAccepted":false,"IsHybridAzureADJoinedDeviceAccepted":false,' \
            '"IsCompliantNetworkAccepted":null}'


def ev(sec, activity, category, props, ua=PS, sp=SP, corr=None, target="Microsoft Graph"):
    return {"id": f"Directory_{corr or sec}", "activityDateTime": f"2026-11-10T10:02:{sec:02d}Z", "activityDisplayName": activity,
            "category": category, "result": "success", "correlationId": corr or f"corr{sec}",
            "initiatedBy": {"user": None, "app": {"appId": None, "displayName": "Ops Automation", "servicePrincipalId": sp}},
            "targetResources": [{"id": "x", "displayName": target, "type": "ServicePrincipal",
                                 "modifiedProperties": [{"displayName": k, "oldValue": o, "newValue": n} for k, o, n in props]}],
            "additionalDetails": [{"key": "User-Agent", "value": ua}]}


GRANT = ev(9, "Add app role assignment to service principal", "ApplicationManagement",
           [("AppRole.Id", None, f'"{ROLE}"'), ("AppRole.Value", None, '"Policy.ReadWrite.CrossTenantAccess"'),
            ("ServicePrincipal.ObjectID", None, f'"{SP}"'), ("ServicePrincipal.DisplayName", None, '"Ops Automation"')],
           corr="e58d83dc")
TRUST = ev(20, "Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
           [("inboundTrust", None, MFA_TRUST)], corr="69f24b46", target="CrossTenantAccessPolicy for ourtenant")
JOB = ev(25, "Update user", "UserManagement", [("DisplayName", '"a"', '"b"')], ua=SERVER_PS)
REMOVE = ev(33, "Remove app role assignment from service principal", "ApplicationManagement",
            [("AppRole.Id", f'"{ROLE}"', None), ("ServicePrincipal.ObjectID", f'"{SP}"', None)])


def test_cross_tenant_scoring():
    assert [p for p, _ in cross_tenant_factors(TRUST)] == [40]
    both = ev(1, "Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
              [("inboundTrust", None, '{"IsMfaAccepted":true,"IsCompliantDeviceAccepted":true}')])
    assert cross_tenant_factors(both)[0][0] == 50
    default = ev(1, "Update the company default cross-tenant access setting", "CrossTenantAccessSettings",
                 [("inboundTrust", None, MFA_TRUST)])
    assert cross_tenant_factors(default)[0][0] == 75 and "ALL external" in cross_tenant_factors(default)[0][1]
    removed = ev(1, "Update a partner cross-tenant access setting", "CrossTenantAccessSettings",
                 [("inboundTrust", MFA_TRUST, '{"IsMfaAccepted":false}')])
    assert cross_tenant_factors(removed)[0][0] == 10
    # the admin portal's follow-up update when opening a support case carries no changed property
    assert cross_tenant_factors(ev(1, "Update a partner cross-tenant access setting", "CrossTenantAccessSettings", [])) is None


def test_partner_is_found_by_its_current_settings():
    changes = {"inboundTrust": (None, {"ismfaaccepted": True, "iscompliantdeviceaccepted": False,
                                       "ishybridazureadjoineddeviceaccepted": False, "iscompliantnetworkaccepted": None})}
    northwind = {"tenantId": PARTNER, "inboundTrust": {"isMfaAccepted": True, "isCompliantDeviceAccepted": False,
                                                       "isHybridAzureADJoinedDeviceAccepted": False}}
    assert partner_matches(northwind, changes)
    assert not partner_matches({"tenantId": "other", "inboundTrust": None}, changes)


def test_self_grant_usage_ignores_other_programs_of_the_same_app():
    used, removed = self_grant_usage(GRANT, [GRANT, TRUST, JOB, REMOVE])
    assert removed == 24
    assert used == ["Update a partner cross-tenant access setting after 11 s (inboundTrust: IsMfaAccepted=true)"]


class OriginGraph:
    def __init__(self, events, office_users=5):
        self.events, self.office_users, self.calls = events, office_users, []

    def get_all(self, path, params=None, max_pages=None):
        yield from self.events

    def get(self, path, params=None):
        flt = (params or {}).get("$filter", "")
        self.calls.append((path, flt))
        if path == "/beta/auditLogs/signIns" and "servicePrincipalId" in flt:
            return {"value": [{"createdDateTime": "2026-11-10T10:02:19Z", "ipAddress": "203.0.113.166", "appId": "app-it",
                               "location": {"city": "Montreal", "countryOrRegion": "CA"}, "status": {"errorCode": 0},
                               "networkLocationDetails": [{"networkType": "trustedNamedLocation", "networkNames": ["HQ"]}],
                               "clientCredentialType": "clientSecret", "servicePrincipalCredentialKeyId": "key-1"}]}
        if path == "/beta/auditLogs/signIns" and "ipAddress eq" in flt:
            return {"value": [{"userPrincipalName": f"u{i}@contoso.com"} for i in range(self.office_users)]}
        if path == "/beta/auditLogs/signIns" and "appId eq" in flt:
            return {"value": [{"userPrincipalName": "chris@contoso.com", "createdDateTime": "2026-11-05T13:00:00Z"}] * 3}
        if path == "/beta/auditLogs/signIns" and "homeTenantId" in flt:
            return {"value": [{"userPrincipalName": "mp@fabrikam.com"}, {"userPrincipalName": "hb@northwind.com"}]}
        if path == "/v1.0/applications":
            return {"value": [{"passwordCredentials": [{"keyId": "key-1", "displayName": "automation-secret",
                                                        "startDateTime": "2025-10-01T10:00:00Z",
                                                        "endDateTime": "2027-10-01T10:00:00Z"}], "keyCredentials": []}]}
        if path == "/v1.0/policies/crossTenantAccessPolicy/partners":
            return {"value": [{"tenantId": "other", "inboundTrust": None},
                              {"tenantId": PARTNER, "inboundTrust": {"isMfaAccepted": True, "isCompliantDeviceAccepted": False,
                                                                     "isHybridAzureADJoinedDeviceAccepted": False}}]}
        if "findTenantInformationByTenantId" in path:
            return {"displayName": "Northwind Traders AG", "defaultDomainName": "northwind.onmicrosoft.com"}
        if "authorizationPolicy" in path:
            return {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}}
        raise RuntimeError(path)


def run(tmp_path, graph):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    cfg.set("plugins", "directory_audit", "settings", "automation_initiators", value=["Ops Automation"])
    return {f.rule_id: f for f in pm.run("directory_audit") if not f.signal}


def test_app_only_alerts_show_origin_usage_and_partner(tmp_path):
    out = run(tmp_path, OriginGraph([GRANT, TRUST, JOB, REMOVE]))
    grant, trust = out["consent_grant"], out["cross_tenant_access"]
    assert "Update a partner cross-tenant access setting after 11 s" in grant.fields["Used for"]
    assert "removed again after 24 s" in grant.fields["Used for"]
    assert any("Just-in-time use" in r for _, r in grant.factors)
    for f in (grant, trust):
        assert f.fields["App signed in from"] == "203.0.113.166 (Montreal, CA; named location 'HQ' trusted)"
        assert f.fields["App credential"].startswith("client secret 'automation-secret' (valid 01.10.2025 - 01.10.2027")
        assert "long-lived secret" in f.fields["App credential"]
        assert f.fields["People on that IP then"].startswith("shared network: 5 people")
        assert f.fields["People using the app themselves"].startswith("chris@contoso.com (3x")
        assert any(r.startswith("App-only change") for _, r in f.factors)
    assert trust.score == 40 and trust.severity.label == "Low"
    assert trust.fields["Partner"] == "Northwind Traders AG (northwind.onmicrosoft.com)"
    assert trust.fields["Change"] == "inboundTrust: - -> IsMfaAccepted=true"
    assert "write permission for the whole tenant" in grant.factors[0][1]
    assert "mp@fabrikam.com" in trust.fields["Partner users seen (14 d)"]


def test_quiet_network_names_the_people_and_lookups_are_cached(tmp_path):
    graph = OriginGraph([GRANT, TRUST, REMOVE], office_users=1)
    out = run(tmp_path, graph)
    assert out["consent_grant"].fields["People on that IP then"].startswith("u0@contoso.com (signed in")
    # same app, same minute: one sign-in lookup for both alerts
    assert sum(1 for p, f in graph.calls if "servicePrincipalId" in f) == 1


def test_lookup_failures_leave_the_alert_unchanged(tmp_path):
    class Broken(OriginGraph):
        def get(self, path, params=None):
            if "auditLogs/signIns" in path or "partners" in path:
                raise RuntimeError("403")
            return super().get(path, params)

    out = run(tmp_path, Broken([GRANT, TRUST, REMOVE]))
    assert "App signed in from" not in out["consent_grant"].fields
    assert out["cross_tenant_access"].fields["Partner"] == "not identifiable"
