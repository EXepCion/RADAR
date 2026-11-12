"""Clickable entities in the detail views: detection, deep links, directory lookups and the windows using them."""
import time
import json
import tkinter as tk
from types import SimpleNamespace

import pytest

from radar import linkify
from radar.app import App
from radar.graph import GraphError
from radar.linkify import Entity, find_entities, row_entity
from radar.plugin_api import Finding, Severity
from radar.resolver import Resolver, fetch_audit_entries


def kinds(text, field=""):
    return [(e.kind, e.value) for e in find_entities(text, field)]


# ------------------------------------------------------------------ detection
def test_ips_users_and_asns_are_found_but_not_version_numbers_or_times():
    assert kinds("203.0.113.166 (Toronto, CA; named location 'Contoso HQ' trusted)", "App signed in from") == [
        ("ip", "203.0.113.166")]
    assert kinds("CN (2001:db8:3326:b37a:bda4:4c1d:422e:1775, CHINAMOBILE-CN (AS9808), iPhone 15 Pro)") == [
        ("ip", "2001:db8:3326:b37a:bda4:4c1d:422e:1775"), ("asn", "AS9808")]
    assert kinds("signed in from 203.0.113.166.") == [("ip", "203.0.113.166")]
    assert kinds("09.11. 05:43 User registered Passkey; 10:02:09") == []
    assert kinds("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36", "User agent") == []
    assert kinds("Chrome/120.0.0.0") == []  # not an IP even without the field hint
    assert kinds("chris.kent@contoso.com (3x, last 05.11.)") == [
        ("user", "chris.kent@contoso.com")]
    assert kinds("see https://learn.microsoft.com/x?y=1.") == [("url", "https://learn.microsoft.com/x?y=1")]


def test_names_are_typed_by_their_field():
    assert kinds("Ops Automation, chris.kent@contoso.com", "Initiated by") == [
        ("app", "Ops Automation"), ("user", "chris.kent@contoso.com")]
    assert kinds("Azure Active Directory PowerShell (18), Azure Portal (11)", "Targeted apps") == [
        ("app", "Azure Active Directory PowerShell"), ("app", "Azure Portal")]
    assert kinds("Policy.ReadWrite.CrossTenantAccess, User.Read.All", "Application permissions") == [
        ("permission", "Policy.ReadWrite.CrossTenantAccess"), ("permission", "User.Read.All")]
    assert kinds("-", "Delegated permissions") == []
    assert kinds("Require MFA for All Apps (exluding MFA_Exempt)", "Excluded from") == [
        ("policy", "Require MFA for All Apps (exluding MFA_Exempt)")]  # a policy name keeps its parenthesis
    assert kinds("LT-TOR-00102 / Windows10 / Edge 18.26200", "Device") == [("device", "LT-TOR-00102")]
    assert kinds("MFA_Exempt", "Group") == [("group", "MFA_Exempt")]
    assert kinds("Microsoft 365 Support Engineer", "Roles") == [("role", "Microsoft 365 Support Engineer")]
    assert kinds("Microsoft Teams (1fec8e78-bce4-4aaf-ab1b-5451cc387264)", "Application") == [
        ("app", "Microsoft Teams"), ("app", "1fec8e78-bce4-4aaf-ab1b-5451cc387264")]


def test_ids_and_alert_titles():
    guid = "00000000-0000-4000-8000-000000000003"
    assert kinds(guid, "Correlation ID") == [("correlation", guid)]
    assert kinds(guid, "Session ID") == [("id", guid)]
    assert kinds(guid, "Support tenant") == [("tenant", guid)]
    assert kinds(f"CrossTenantAccessPolicy for {guid}", "Targets") == [("guid", guid)]
    audit = "Authentication Methods_2488afb8-54a7-444d-af3c-fca3f93be460_MBFPL_187712444"
    assert kinds(audit, "Audit ID") == [("audit", audit)]
    step = "Risky sign-in: chen.lee@contoso.com (likely VPN / proxy)"
    assert kinds(step, "Step") == [("alert", step)]  # the whole title, not the address inside
    assert kinds("Guest invited: a@b.com (09.11.2026)\nOther alert", "Related signals") == [
        ("alert", "Guest invited: a@b.com"), ("alert", "Other alert")]


def test_row_entity_picks_what_double_click_opens():
    assert row_entity({"Sign-in ID": "abc", "User": "a@b.com"}) == Entity("signin", "abc")
    assert row_entity({"Correlation ID": "c1", "Activity": "x"}) == Entity("correlation", "c1")
    assert row_entity({"Audit ID": "a1", "Correlation ID": "c1"}) == Entity("audit", "a1")
    assert row_entity({"Step": "Some alert", "Stage": "1"}) == Entity("alert", "Some alert")
    assert row_entity({"Account": "x@contoso.com", "Exposure": "NO MFA"}) == Entity("user", "x@contoso.com")
    assert row_entity({"IP address": "1.2.3.4", "Network": "AS1"}) == Entity("ip", "1.2.3.4")
    assert row_entity({"Time": "t"}) is None and row_entity(None) is None


# ------------------------------------------------------------------ deep links
def test_portal_and_static_urls():
    user = {"kind": "user", "id": "u1"}
    assert linkify.portal_url("user", user).endswith("UserProfileMenuBlade/~/overview/userId/u1")
    assert "~/UserAuthMethods/userId/u1" in linkify.portal_url("user_methods", user)
    app = {"kind": "app", "id": "sp1", "appId": "a1", "registered": False}
    assert linkify.portal_url("app", app).endswith("ManagedAppMenuBlade/~/Overview/objectId/sp1/appId/a1")
    assert linkify.portal_url("app_credentials", app) == ""  # not registered here: no secrets blade
    assert linkify.portal_url("app_credentials", {**app, "registered": True}).endswith(
        "ApplicationMenuBlade/~/Credentials/appId/a1")
    assert linkify.portal_url("device", {"id": "o1", "deviceId": "d1"}).endswith("objectId/o1/deviceId/d1")
    assert linkify.portal_url("policy", {"id": "p1"}).endswith("PolicyBlade/policyId/p1")
    assert linkify.portal_url("user", {"kind": "user"}) == ""  # no id, no link
    assert linkify.static_url(Entity("permission", "Policy.ReadWrite.CrossTenantAccess"), "permission_docs").endswith(
        "#policyreadwritecrosstenantaccess")
    assert linkify.static_url(Entity("role", "Global Administrator"), "role_docs").endswith("#global-administrator")
    assert linkify.static_url(Entity("ip", "1.2.3.4"), "abuseipdb") == "https://www.abuseipdb.com/check/1.2.3.4"
    assert linkify.static_url(Entity("user", "a@b.com"), "user") == ""  # needs a lookup first
    assert linkify.actions(Entity("id", "x")) == []  # copy only


# ------------------------------------------------------------------ resolver
class FakeGraph:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, path, params=None):
        key = path + ("?" + params["$filter"] if params and "$filter" in params else "")
        self.calls.append(key)
        for prefix, result in self.routes.items():
            if key.startswith(prefix):
                if isinstance(result, Exception):
                    raise result
                return result
        raise GraphError(404, "Request_ResourceNotFound", "not found", path)


def test_resolver_finds_guests_apps_and_role_templates_and_caches():
    g = FakeGraph({
        "/v1.0/users?startswith(userPrincipalName,'helen_northwind.com#EXT#')": {"value": [
            {"id": "g1", "displayName": "Helen", "userPrincipalName": "helen_northwind.com#EXT#@t", "userType": "Guest"}]},
        "/v1.0/users?mail eq": {"value": []},
        "/v1.0/servicePrincipals?displayName eq 'Ops Automation'": {"value": [
            {"id": "sp1", "appId": "a1", "displayName": "Ops Automation"}]},
        "/v1.0/applications?appId eq 'a1'": {"value": [{"id": "app1"}]},
        "/v1.0/directoryObjects/00cf5c54-4693-4f59-a0ac-ab79ef0a974d": {
            "@odata.type": "#microsoft.graph.directoryRoleTemplate", "displayName": "Microsoft 365 Support Engineer"},
    })
    r = Resolver(lambda: g)
    guest = r.resolve("user", "helen@northwind.com")
    assert guest["id"] == "g1" and "guest" in guest["detail"]
    app = r.resolve("app", "Ops Automation")
    assert app == {"kind": "app", "id": "sp1", "appId": "a1", "name": "Ops Automation", "registered": True,
                   "detail": "app id a1, registered in this tenant"}
    role = r.resolve("guid", "00cf5c54-4693-4f59-a0ac-ab79ef0a974d")
    assert role["kind"] == "role" and linkify.PRIMARY_ACTION["role"] == "role_docs"
    n = len(g.calls)
    r.resolve("app", "ops automation")  # cached (case-insensitive)
    assert len(g.calls) == n
    assert r.resolve("group", "Nope") is None


def test_resolver_raises_access_errors_but_not_not_found():
    g = FakeGraph({"/v1.0/groups": GraphError(403, "Authorization_RequestDenied", "denied")})
    with pytest.raises(GraphError):
        Resolver(lambda: g).resolve("group", "Admins")


def test_fetch_audit_entries_adds_the_rest_of_the_operation():
    g = FakeGraph({
        "/v1.0/auditLogs/directoryAudits/Directory_x": {"id": "Directory_x", "correlationId": "c1",
                                                        "activityDateTime": "2026-11-10T10:02:20Z"},
        "/v1.0/auditLogs/directoryAudits?correlationId eq 'c1'": {"value": [
            {"id": "Directory_x", "activityDateTime": "2026-11-10T10:02:20Z"},
            {"id": "Directory_y", "activityDateTime": "2026-11-10T10:02:09Z"}]},
    })
    recs = fetch_audit_entries(g, "Directory_x")
    assert [r["id"] for r in recs] == ["Directory_y", "Directory_x"]


# ------------------------------------------------------------------ app routing
def fake_app(resolver=None):
    calls = []
    fake = SimpleNamespace(
        calls=calls, resolver=resolver,
        open_link=lambda url: calls.append(("open", url)),
        view_entry=lambda alert, row: calls.append(("signin", row)),
        view_audit=lambda audit_id, corr, row: calls.append(("audit", audit_id, corr)),
        open_alert_titled=lambda title: calls.append(("alert", title)) or True,
        ui_call=lambda fn, *args: fn(*args),
        _background=lambda fn, name="": fn(),
    )
    fake._resolve_and_open = lambda entity, action, say: App._resolve_and_open(fake, entity, action, say)
    return fake


def test_entity_action_routes_to_browser_in_app_views_or_lookup():
    said = []
    say = lambda text, error=False: said.append((text, error))  # noqa: E731
    g = FakeGraph({"/v1.0/users/a@b.com": {"id": "u1", "userPrincipalName": "a@b.com", "displayName": "A"}})
    app = fake_app(Resolver(lambda: g))
    App.entity_action(app, Entity("ip", "1.2.3.4"), "abuseipdb", status=say)
    App.entity_action(app, Entity("signin", "s1"), "view_signin", row={"Sign-in ID": "s1", "_event": "x"})
    App.entity_action(app, Entity("correlation", "c1"), "view_correlation")
    App.entity_action(app, Entity("alert", "T"), "open_alert")
    App.entity_action(app, Entity("user", "a@b.com"), "user_methods", status=say)
    App.entity_action(app, Entity("user", "x@y.com"), "user", status=say)
    assert app.calls[:4] == [("open", "https://www.abuseipdb.com/check/1.2.3.4"),
                             ("signin", {"Sign-in ID": "s1", "_event": "x"}), ("audit", "", "c1"), ("alert", "T")]
    assert app.calls[4][1].endswith("~/UserAuthMethods/userId/u1")
    assert said[-1][1] is True and "not found" in said[-1][0]


# ------------------------------------------------------------------ windows
@pytest.fixture(scope="module")
def root():
    from radar.ui import theme

    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    theme.init(r)
    yield r
    r.destroy()


def links_in(text):
    """(entity kind, linked text) of every link in a RichText."""
    out = []
    for tag, (entity, _row) in text.targets.items():
        ranges = text.tag_ranges(tag)
        out.append((entity.kind, text.get(ranges[0], ranges[1])))
    return out


def test_details_window_links_fields_and_shows_the_selected_row_in_full(root):
    from test_ui import FakeApp

    from radar.ui.details import DetailsWindow

    app = FakeApp()
    alert = app.alerts.ingest("directory_audit", [Finding(
        key="k", title="Cross-tenant trust changed", severity=Severity.LOW, score=40, factors=[(40, "MFA trust")],
        summary="Signed in from 203.0.113.166 with a client secret.",
        fields={"Initiated by": "Ops Automation", "People using the app themselves": "c@contoso.com (3x)",
                "Application permissions": "Policy.ReadWrite.CrossTenantAccess", "Correlated with": "Other alert"},
        evidence=[{"Time": "2026-11-10 11:02:20", "Activity": "Update a partner cross-tenant access setting",
                   "Initiated by": "Ops Automation", "Targets": "x" * 400, "Correlation ID": "c1"}])])[0]
    win = DetailsWindow(root, app, alert, on_dismiss=lambda a: None)
    root.update()
    found = links_in(win.info)
    for expected in [("ip", "203.0.113.166"), ("app", "Ops Automation"), ("user", "c@contoso.com"),
                     ("permission", "Policy.ReadWrite.CrossTenantAccess"), ("alert", "Other alert")]:
        assert expected in found
    assert "x" * 400 in win.row_text.get("1.0", "end")  # a long cell is shown in full below the table
    assert win.view_btn.cget("text") == "View the audit entries of this operation"
    win._view_selected()
    entity, action = app.actions[-1][:2]
    assert entity == Entity("correlation", "c1") and action == "view_correlation"
    win.links.default(Entity("id", "abc"))  # copy-only ids go to the clipboard
    assert root.clipboard_get() == "abc" and "Copied" in win.status.text
    win.top.destroy()


def test_audit_entry_rendering():
    from radar.ui.entry import pretty_value

    assert pretty_value('["{\\"IsMfaAccepted\\":true}"]') == '{\n  "IsMfaAccepted": true\n}'
    assert pretty_value('["a", "b"]') == "a, b" and pretty_value("[]") == "" and pretty_value(None) == ""


def test_audit_window_shows_targets_properties_and_app_only_note(root):
    from test_ui import FakeApp

    from radar.ui.entry import AuditWindow

    rec = {"id": "Directory_1", "correlationId": "c1", "activityDateTime": "2026-11-10T10:02:20Z",
           "activityDisplayName": "Update a partner cross-tenant access setting", "category": "CrossTenantAccessSettings",
           "result": "success", "loggedByService": "Core Directory",
           "initiatedBy": {"app": {"displayName": "Ops Automation", "servicePrincipalId": "00000000-0000-4000-8000-000000000007"}},
           "targetResources": [{"type": "User", "id": "00000000-0000-4000-8000-000000000005",
                                "userPrincipalName": "c@contoso.com", "modifiedProperties": [
                                    {"displayName": "inboundTrust", "oldValue": None,
                                     "newValue": json.dumps([json.dumps({"IsMfaAccepted": True})])}]}],
           "additionalDetails": [{"key": "User-Agent", "value": "WindowsPowerShell/5.1.26100.33648"}]}
    win = AuditWindow(root, FakeApp(), "subtitle", highlight="Directory_1")
    win.show_records([dict(rec, id="Directory_0", activityDisplayName="Add app role assignment"), rec])
    root.update()
    body = win.text.get("1.0", "end")
    assert "Update a partner cross-tenant access setting" in body  # the highlighted entry is shown
    assert '"IsMfaAccepted": true' in body and "App-only" in body and "WindowsPowerShell/5.1.26100.33648" in body
    found = links_in(win.text)
    assert ("app", "Ops Automation") in found and ("user", "00000000-0000-4000-8000-000000000005") in found
    assert ("ip", "5.1.26100") not in found
    assert len(win.list.get_children()) == 2
    win.list.selection_set("0")
    root.update()
    assert "Add app role assignment" in win.text.get("1.0", "end")
    win.top.destroy()


def test_signin_entry_window_links(root):
    from test_ui import FakeApp

    from radar.ui.entry import EntryWindow

    record = {"id": "r1", "createdDateTime": "2026-11-09T17:10:42Z", "correlationId": "00000000-0000-4000-8000-000000000009",
              "status": {"errorCode": 0}, "userPrincipalName": "z@contoso.com", "userDisplayName": "Z",
              "userId": "00000000-0000-4000-8000-000000000010", "appDisplayName": "CRM Connect",
              "appId": "00000000-0000-4000-8000-000000000004", "ipAddress": "2001:db8:4801:6ca7:7461:2fab:7af4:3718",
              "userAgent": "python-requests/2.33.1",
              "appliedConditionalAccessPolicies": [{"id": "p1", "displayName": "Require MFA", "result": "success"}]}
    win = EntryWindow(root, "r1", "sub", app=FakeApp())
    win.show_record(record)
    root.update()
    texts = [w for page in win.tabs.pages for w in page.winfo_children()
             if w.winfo_class() == "Text" and hasattr(w, "targets")]
    found = [x for t in texts for x in links_in(t)]
    assert ("user", "z@contoso.com") in found and ("user", "00000000-0000-4000-8000-000000000010") in found
    assert ("app", "CRM Connect") in found and ("ip", "2001:db8:4801:6ca7:7461:2fab:7af4:3718") in found
    assert ("id", "00000000-0000-4000-8000-000000000009") in found  # a sign-in correlation id is copy-only
    win.top.destroy()


def test_find_alert_by_title():
    from radar.alerts import AlertCenter
    from radar.store import Store

    ac = AlertCenter(Store(":memory:"))
    ac.ingest("p", [Finding(key="a", title="Risky sign-in: a_b@contoso.com (VPN)", severity=Severity.HIGH),
                    Finding(key="b", title="Risky sign-in: aXb@contoso.com", severity=Severity.HIGH)])
    assert ac.find_by_title("Risky sign-in: a_b@contoso.com (VPN)").key == "a"
    assert ac.find_by_title("Risky sign-in: a_b@contoso.com").key == "a"  # prefix; '_' is not a wildcard
    assert ac.find_by_title("nothing") is None and ac.find_by_title("") is None


def _places(top, *widgets):
    """Where the widgets are inside their window (the window itself is put on the mouse's screen just before it
    appears; that move is not a layout change)."""
    top.update()
    x0, y0 = top.winfo_rootx(), top.winfo_rooty()
    return [(w.winfo_rootx() - x0, w.winfo_rooty() - y0, w.winfo_width(), w.winfo_height()) for w in widgets]


def _settle(top):
    """Wait until the new window has appeared: just before that it is put on the mouse's screen and, on a small
    screen, made to fit - a change of the window, not of its layout."""
    end = time.monotonic() + 3
    while time.monotonic() < end and float(top.attributes("-alpha")) < 1.0:
        top.update()
        time.sleep(0.02)
    top.update()


def test_log_windows_do_not_move_when_the_record_arrives(root):
    """Status lines keep their height and nothing is inserted: the layout is the same before and after loading."""
    from test_ui import FakeApp

    from radar.ui.entry import AuditWindow, EntryWindow

    rec = {"id": "Directory_1", "correlationId": "c1", "activityDateTime": "2026-11-10T10:02:20Z",
           "activityDisplayName": "Update a partner cross-tenant access setting " * 3, "result": "success",
           "initiatedBy": {"app": {"displayName": "Ops Automation"}}, "targetResources": []}
    win = AuditWindow(root, FakeApp(), "subtitle", highlight="Directory_1")
    _settle(win.top)
    widgets = (win.status_label, win.list, win.text, win.copy_json_btn)
    before = _places(win.top, *widgets)
    widths = [win.list.column(c, "width") for c in win.list["columns"]]
    win.show_records([dict(rec, id="Directory_0"), rec, dict(rec, id="Directory_2")])
    assert _places(win.top, *widgets) == before
    assert [win.list.column(c, "width") for c in win.list["columns"]] == widths
    win.status.show("x " * 600, error=True)  # hover texts and errors stay inside the reserved lines
    assert _places(win.top, *widgets) == before
    win.top.destroy()

    entry = EntryWindow(root, "r1", "sub", app=FakeApp())
    _settle(entry.top)
    widgets = (entry.status_label, entry.tabs, entry.copy_json_btn)
    before = _places(entry.top, *widgets)
    entry.show_record({"id": "r1", "createdDateTime": "2026-11-09T17:10:42Z", "status": {"errorCode": 0},
                       "userPrincipalName": "z@contoso.com", "ipAddress": "203.0.113.5"})
    assert _places(entry.top, *widgets) == before
    entry.status.show(entry._portal_hint("User sign-ins (non-interactive)", "2026-11-09"))
    assert _places(entry.top, *widgets) == before
    assert entry.status_label.winfo_reqheight() <= entry.status_label.winfo_height()  # the long hint is not cut off
    entry.top.destroy()
