"""Directory audit watch: what is filtered out (PIM lifecycle, system actors, automation) and what is scored."""
import threading

from radar.config import ConfigManager
from radar.plugin_api import Severity
from radar.plugin_manager import PluginManager
from radar.plugins.directory_audit import DirectoryAuditPlugin
from radar.store import Store


def audit(i, activity, who, role="", app=False, target_upn="", day="2026-11-03"):
    by = {"app": {"displayName": who}} if app else {"user": {"userPrincipalName": who}}
    props = [{"displayName": "Role.DisplayName", "newValue": f'"{role}"'}] if role else []
    return {"id": f"a{i}", "activityDateTime": f"{day}T10:{i % 60:02d}:00Z", "activityDisplayName": activity,
            "category": "RoleManagement", "result": "success", "initiatedBy": by, "correlationId": f"c{i}",
            "targetResources": [{"id": f"t{i}", "userPrincipalName": target_upn, "modifiedProperties": props}]}


EVENTS = [
    audit(1, "Add member to role requested (PIM activation)", "admin1@contoso.com"),
    audit(2, "Add member to role completed (PIM activation)", "admin1@contoso.com"),
    audit(3, "Add member to role", "MS-PIM", role="Intune Administrator", app=True),
    audit(4, "Remove member from role (PIM activation expired)", "MS-PIM", app=True),
    audit(5, "Update service principal", "AAD App Management", app=True),
    audit(6, "Add member to role", "admin2@contoso.com", role="Global Administrator"),
    audit(7, "Add eligible member to role in PIM completed (permanent)", "admin2@contoso.com", role="User Administrator"),
    audit(8, "Update application – Certificates and secrets management ", "Ops Automation", app=True),
    audit(9, "Consent to application", "admin3@contoso.com"),
    audit(10, "Add delegated permission grant", "admin3@contoso.com"),
    audit(11, "Invite external user", "jane.doe@contoso.com", target_upn="jane.doe7_gmail.com#EXT#@contoso.onmicrosoft.com"),
    audit(12, "Invite external user", "jane.doe@contoso.com", target_upn="bob_partner.cz#EXT#@contoso.onmicrosoft.com"),
]


class Graph:
    def __init__(self, fail_category_filter=False):
        self.filters = []
        self.fail = fail_category_filter

    def get_all(self, path, params=None, max_pages=None):
        from radar.graph import GraphError

        self.filters.append(params["$filter"])
        if self.fail and "category eq" in params["$filter"]:
            raise GraphError(400, "BadRequest", "unsupported filter")
        yield from EVENTS


def run(tmp_path, graph):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    cfg.set("plugins", "directory_audit", "settings", "automation_initiators", value=["Ops Automation"])
    return {f.key.split("|")[1] if f.key.startswith("diraudit") else f.key: f for f in pm.run("directory_audit")}


def test_pim_lifecycle_and_system_actors_are_ignored(tmp_path):
    out = run(tmp_path, Graph())
    role = out["role_assignment"]  # only admin2's day group remains
    assert role.fields["Initiated by"] == "admin2@contoso.com"
    assert "MS-PIM" not in " ".join(f.fields.get("Initiated by", "") for f in out.values())
    assert role.severity == Severity.HIGH and role.score == 80
    assert any("Highly privileged role: Global Administrator" in r for _, r in role.factors)


def test_automation_and_grouping(tmp_path):
    out = run(tmp_path, Graph())
    creds = out["app_credentials"]
    assert creds.severity == Severity.INFO and any("Known automation" in r for _, r in creds.factors)
    assert "consent_grant" not in out  # consent events without permissions grant nothing (see test_consent.py)


def test_guest_invites_scored(tmp_path):
    out = run(tmp_path, Graph())
    guests = {f.fields["Guest"]: f for f in out.values() if f.rule_id == "guest_invites"}
    assert guests["jane.doe7@gmail.com"].score == 65 and guests["jane.doe7@gmail.com"].severity == Severity.MEDIUM
    assert guests["bob@partner.cz"].severity == Severity.INFO


def test_category_filter_and_fallback(tmp_path):
    g = Graph()
    run(tmp_path, g)
    assert "category eq 'RoleManagement'" in g.filters[0]
    g2 = Graph(fail_category_filter=True)
    out = run(tmp_path / "b", g2)
    assert "category" in g2.filters[0] and "category" not in g2.filters[1] and out
    # (once, at the first run: the "Enable account" events of the last 30 days - see _enables_from_before)
    assert len(g2.filters) == 4 and g2.filters[2].endswith("(activityDisplayName eq 'Enable account')")
    assert "activityDisplayName eq 'Reset password (by admin)'" in g2.filters[3]  # ... and the password resets


def test_score_audit_unit():
    from radar.plugins.directory_audit import score_audit
    sc, _ = score_audit("conditional_access", audit(1, "Delete conditional access policy", "x@y"), [])
    assert sc == 70
    assert score_audit("conditional_access", audit(2, "Update user", "x@y"), []) is None
    assert DirectoryAuditPlugin.rules[0].id == "role_assignment"


# ------------------------------------------------------------- Microsoft 365 support cases
ASSIST_SP = "00000000-0000-4000-8000-000000000006"
SUPPORT_TENANT = "b4c546a4-7dac-46a6-a7dd-ed822a11efd3"


def case_opened(i, by="chris@contoso.com", day="2026-10-31", minute=23):
    return {"id": f"case{i}", "activityDateTime": f"{day}T22:{minute:02d}:26Z", "result": "success",
            "activityDisplayName": "Add a partner to cross-tenant access setting", "category": "CrossTenantAccessSettings",
            "initiatedBy": {"user": {"userPrincipalName": by}}, "correlationId": "x",
            "additionalDetails": [{"key": "User-Agent", "value": "O365AdminPortal"}],
            "targetResources": [{"type": "Policy", "displayName": "CrossTenantAccessPolicy", "modifiedProperties": [
                {"displayName": "tenantId", "newValue": f'"{SUPPORT_TENANT}"'},
                {"displayName": "isServiceProvider", "newValue": "true"}]}]}


def engineer_added(i, sp=ASSIST_SP, day="2026-10-31", tenant=SUPPORT_TENANT):
    return {"id": f"eng{i}", "activityDateTime": f"{day}T22:23:4{i}Z", "result": "success",
            "activityDisplayName": "Add member to role", "category": "RoleManagement", "correlationId": "y",
            "initiatedBy": {"app": {"displayName": "AssistAPI", "servicePrincipalId": sp}},
            "additionalDetails": [{"key": "Principal Tenant ID", "value": tenant}],
            "targetResources": [{"type": "Group", "id": f"g{i}", "modifiedProperties": [
                {"displayName": "Role.DisplayName", "newValue": '"Microsoft 365 Support Engineer"'},
                {"displayName": "Role.TemplateId", "newValue": '"00cf5c54-4693-4f59-a0ac-ab79ef0a974d"'}]}]}


class SupportGraph:
    def __init__(self, events):
        self.events = events

    def get_all(self, path, params=None, max_pages=None):
        yield from self.events

    def get(self, path, params=None):
        if path == "/v1.0/servicePrincipals":
            return {"value": [{"id": ASSIST_SP}]}
        raise RuntimeError(path)


def support_run(tmp_path, *batches):
    cfg = ConfigManager(tmp_path / "config.json")
    graph = SupportGraph([])
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    out = []
    for events in batches:
        graph.events = events
        out = pm.run("directory_audit")
    return {f.key.split("|")[0] + ("|" + f.key.split("|")[2] if f.key.startswith("diraudit") else ""): f for f in out}


def test_support_engineer_access_after_admin_opened_a_case_is_info(tmp_path):
    out = support_run(tmp_path, [engineer_added(2), engineer_added(6), case_opened(1)])  # API order: newest first
    role = out["diraudit|AssistAPI"]
    assert role.severity == Severity.INFO and role.score == 0
    assert any("support case chris@contoso.com opened on" in r for _, r in role.factors)
    record = out["supportcase"]
    assert record.signal == "support_case" and "chris@contoso.com" in record.title


def test_case_from_an_earlier_run_still_counts(tmp_path):
    out = support_run(tmp_path, [case_opened(1)], [engineer_added(2, day="2026-11-03")])
    assert out["diraudit|AssistAPI"].severity == Severity.INFO


def test_support_access_without_a_case_or_from_an_impostor(tmp_path):
    no_case = support_run(tmp_path, [engineer_added(2)])["diraudit|AssistAPI"]
    assert no_case.severity == Severity.LOW and no_case.score == 30
    assert any("no support case was opened" in r for _, r in no_case.factors)
    fake = support_run(tmp_path / "f", [case_opened(1), engineer_added(3, sp="evil-sp")])["diraudit|AssistAPI"]
    assert fake.severity == Severity.HIGH and any("NOT Microsoft's Assist API" in r for _, r in fake.factors)


def test_password_resets_and_enabled_accounts_are_context_signals(tmp_path, monkeypatch):
    """A new password given WITHOUT needing the old one (admin reset, self-service reset, changed on-premises) is
    recorded as remediation context. A plain self-service change is not: whoever knows the password can do that."""
    import test_directory_audit as me

    events = [
        audit(20, "Reset password (by admin)", "helpdesk@contoso.com", target_upn="eve@contoso.com"),
        audit(21, "Reset password (self-service)", "bea@contoso.com", target_upn="bea@contoso.com"),
        audit(22, "Change user password", "ConnectSyncProvisioning_DC1", app=True, target_upn="cy@contoso.com"),
        audit(23, "Change password (self-service)", "dan@contoso.com", target_upn="dan@contoso.com"),
        audit(24, "Enable account", "helpdesk@contoso.com", target_upn="eve@contoso.com"),
        dict(audit(25, "Reset password (by admin)", "helpdesk@contoso.com", target_upn="fay@contoso.com"), result="failure"),
    ]
    monkeypatch.setattr(me, "EVENTS", events)
    out = run(tmp_path, Graph())
    resets = {f.subjects[0]: f for f in out.values() if f.signal == "password_reset"}
    assert set(resets) == {"eve@contoso.com", "bea@contoso.com", "cy@contoso.com"}  # not dan (plain change), not fay (failed)
    assert resets["eve@contoso.com"].fields == {"Account": "eve@contoso.com", "Initiated by": "helpdesk@contoso.com", "How": "reset by an admin"}
    assert resets["cy@contoso.com"].fields["How"] == "changed on-premises, synced to Entra"
    assert all(f.severity == Severity.INFO and f.score == 0 for f in resets.values())
    enabled = [f for f in out.values() if f.signal == "account_enabled"]
    assert [f.subjects for f in enabled] == [["eve@contoso.com"]]
