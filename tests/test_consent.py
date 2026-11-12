"""App consent: judged by what is granted. Tenant-wide app permissions alert; admin consents are signals."""
import threading
from datetime import timedelta

from radar.alerts import AlertCenter
from radar.config import ConfigManager
from radar.plugin_api import Finding, Severity
from radar.plugin_manager import PluginManager
from radar.plugins.directory_audit import (classify_permissions, consent_findings, parse_consent,
                                            user_consent_enabled)
from radar.store import Store

GRAPH_SP = "00000000-0000-4000-8000-000000000008"


def _a(i, activity, actor, targets, day="2026-11-03", app_actor=False):
    by = {"app": {"displayName": actor}} if app_actor else {"user": {"userPrincipalName": actor}}
    return {"id": f"x{i}", "activityDateTime": f"{day}T09:{i % 60:02d}:00Z", "activityDisplayName": activity,
            "category": "ApplicationManagement", "result": "success", "initiatedBy": by, "correlationId": f"c{i}",
            "targetResources": targets}


def consent(i, actor, app, scopes, *, sp="sp1", all_users=True, app_only=False, admin=True, day="2026-11-03"):
    perms = f"[] => [[Id: abc, ClientId: {sp}, PrincipalId: , ResourceId: {GRAPH_SP}, ConsentType: AllPrincipals, " \
            f"Scope: {scopes}, CreatedDateTime: , LastModifiedDateTime ]]; "
    props = [("ConsentContext.IsAdminConsent", admin), ("ConsentContext.IsAppOnly", app_only),
             ("ConsentContext.OnBehalfOfAll", all_users), ("ConsentAction.Permissions", perms)]
    return _a(i, "Consent to application", actor, [{"id": sp, "type": "ServicePrincipal", "displayName": app,
              "modifiedProperties": [{"displayName": k, "newValue": f'"{v}"'} for k, v in props]}], day)


def delegated(i, actor, sp, scopes, day="2026-11-03"):
    props = [("DelegatedPermissionGrant.Scope", scopes), ("DelegatedPermissionGrant.ConsentType", "AllPrincipals"),
             ("ServicePrincipal.ObjectID", sp)]
    return _a(i, "Add delegated permission grant", actor,
              [{"id": GRAPH_SP, "type": "ServicePrincipal", "displayName": "Microsoft Graph",
                "modifiedProperties": [{"displayName": k, "newValue": f'"{v}"'} for k, v in props]},
               {"id": sp, "type": "ServicePrincipal", "displayName": None}], day)


def app_role(i, actor, app, sp, role, day="2026-11-03", app_actor=False):
    props = [("AppRole.Value", role), ("ServicePrincipal.ObjectID", sp), ("ServicePrincipal.DisplayName", app)]
    return _a(i, "Add app role assignment to service principal", actor,
              [{"id": GRAPH_SP, "type": "ServicePrincipal", "displayName": "Microsoft Graph",
                "modifiedProperties": [{"displayName": k, "newValue": f'"{v}"'} for k, v in props]}], day, app_actor)


def findings(*audits, automation=(), user_consent=False):
    return {f.fields["App"]: f for f in consent_findings([e for e in map(parse_consent, audits) if e],
                                                         list(automation), user_consent)}


def test_routine_admin_consents_are_signals():
    out = findings(consent(1, "chris@contoso.com", "HubSpot", "offline_access OnlineMeetings.ReadWrite User.Read openid"),
                   consent(2, "chris@contoso.com", "Telnyx", "openid email profile User.Read", sp="sp2"),
                   consent(3, "chris@contoso.com", "Graph Explorer",
                           "openid User.ReadWrite.All Directory.ReadWrite.All Group.ReadWrite.All", sp="sp3"))
    assert all(f.signal == "app_consent" for f in out.values())
    assert out["Telnyx"].score == 5 and "Basic sign-in" in out["Telnyx"].factors[0][1]
    assert out["HubSpot"].score == 25
    assert out["Graph Explorer"].score == 35 and "within each user's own rights" in out["Graph Explorer"].factors[0][1]
    assert out["HubSpot"].subjects == ["app:hubspot", "chris@contoso.com"]


def test_tenant_wide_app_permissions_alert_on_their_own():
    out = findings(app_role(1, "pat@contoso.com", "Veeam Office 365 Backup", "sp9", "Files.ReadWrite.All"),
                   app_role(2, "pat@contoso.com", "Veeam Office 365 Backup", "sp9", "ChannelMember.ReadWrite.All"),
                   app_role(3, "chris@contoso.com", "Cronofy", "sp8", "User.Read.All"),
                   app_role(4, "chris@contoso.com", "Cronofy", "sp8", "Calendars.ReadWrite"))
    veeam, cronofy = out["Veeam Office 365 Backup"], out["Cronofy"]
    assert not veeam.signal and veeam.severity == Severity.MEDIUM and veeam.score == 55
    assert "Files.ReadWrite.All" in veeam.factors[0][1] and veeam.fields["For"] == "all users"
    assert not cronofy.signal and "Calendars.ReadWrite" in cronofy.factors[0][1]
    readonly = findings(app_role(5, "chris@contoso.com", "Reporting", "sp7", "User.Read.All"))["Reporting"]
    assert readonly.signal == "app_consent" and readonly.score == 25


def test_tier0_self_grant_by_automation_still_alerts():
    f = findings(app_role(1, "Ops Automation", "Ops Automation", "sp5", "DelegatedPermissionGrant.ReadWrite.All",
                          app_actor=True), automation=["Ops Automation"])["Ops Automation"]
    assert not f.signal and f.score == 45 and f.severity == Severity.MEDIUM
    texts = " ".join(r for _, r in f.factors)
    assert "controls the tenant" in texts and "granted these permissions to itself" in texts and "Known automation" in texts


def test_non_admin_consent_when_user_consent_is_disabled():
    f = findings(consent(1, "bob@contoso.com", "PDF Tool", "Mail.Read User.Read", admin=False))["PDF Tool"]
    assert not f.signal and f.severity == Severity.HIGH
    allowed = findings(consent(2, "bob@contoso.com", "Notes", "User.Read", admin=False), user_consent=True)["Notes"]
    assert allowed.signal == "app_consent"


def test_delegated_grant_takes_the_app_name_from_the_consent_and_week_grouping():
    out = consent_findings([e for e in map(parse_consent, [
        consent(1, "c@contoso.com", "Cronofy", "openid email profile", sp="sp8", day="2026-11-03"),
        delegated(2, "c@contoso.com", "sp8", "openid email profile", day="2026-11-03"),
        delegated(3, "c@contoso.com", "sp8", "Calendars.Read", day="2026-11-05"),     # same ISO week
        delegated(4, "c@contoso.com", "sp8", "Calendars.Read", day="2026-11-10"),     # next week
    ]) if e], [], False)
    assert sorted(f.key for f in out) == ["consent|Cronofy|2026-W45", "consent|Cronofy|2026-W46"]
    w45 = next(f for f in out if f.key.endswith("W45"))
    assert w45.fields["Delegated permissions"] == "Calendars.Read, email, openid, profile" and len(w45.evidence) == 3
    w46 = next(f for f in out if f.key.endswith("W46"))
    assert "re-grant" in w46.factors[0][1] and w46.score == 0


def test_only_the_first_grant_of_a_dangerous_permission_alerts():
    granted: dict[str, str] = {}
    first = consent_findings([parse_consent(app_role(1, "Ops Automation", "Ops Automation", "sp5",
                                                     "DelegatedPermissionGrant.ReadWrite.All", day="2026-10-20",
                                                     app_actor=True))], ["Ops Automation"], False, granted)
    assert not first[0].signal  # first time: Medium alert
    again = consent_findings([parse_consent(app_role(2, "Ops Automation", "Ops Automation", "sp5",
                                                     "DelegatedPermissionGrant.ReadWrite.All", day="2026-10-30",
                                                     app_actor=True)),
                              parse_consent(app_role(3, "Ops Automation", "Ops Automation", "sp5",
                                                     "ThreatHunting.Read.All", day="2026-10-30", app_actor=True))],
                             ["Ops Automation"], False, granted)
    f = again[0]
    assert not f.signal and "ThreatHunting.Read.All" in f.factors[0][1]  # a NEW powerful permission still alerts
    assert any("re-grant" in r and "DelegatedPermissionGrant" in r for _, r in f.factors)
    later = consent_findings([parse_consent(app_role(4, "Ops Automation", "Ops Automation", "sp5",
                                                     "DelegatedPermissionGrant.ReadWrite.All", day="2026-11-04",
                                                     app_actor=True))], ["Ops Automation"], False, granted)
    assert later[0].signal == "app_consent"  # just-in-time re-grant: no reminder


def test_one_onboarding_by_two_actors_is_one_finding():
    out = consent_findings([e for e in map(parse_consent, [
        app_role(1, "Ops Automation", "Cronofy", "sp8", "Calendars.ReadWrite", app_actor=True),
        app_role(2, "chris@contoso.com", "Cronofy", "sp8", "Calendars.ReadWrite"),
        consent(3, "chris@contoso.com", "Cronofy", "openid email profile", sp="sp8")]) if e],
        ["Ops Automation"], False)
    assert len(out) == 1 and out[0].score == 55  # no automation discount: a person was involved too
    assert out[0].subjects == ["app:cronofy", "app:ops automation", "chris@contoso.com"]


def test_revoked_or_empty_consent_is_ignored():
    revoke = consent(1, "c@contoso.com", "X", "User.Read")
    revoke["targetResources"][0]["modifiedProperties"][-1]["newValue"] = '"[[Id: a, Scope: User.Read, ]] => []"'
    assert parse_consent(revoke) is None


def test_classify_permissions_tiers():
    assert classify_permissions("application", {"RoleManagement.ReadWrite.Directory"})[0] == 75
    assert classify_permissions("application", {"Mail.Read"})[2] is True
    assert classify_permissions("application", {"Organization.Read.All", "Place.Read.All"})[2] is False
    assert classify_permissions("delegated", {"Mail.Send"})[0] == 25


def test_user_consent_switched_on_is_detected():
    a = _a(1, "Update authorization policy", "admin@contoso.com", [{"modifiedProperties": [
        {"displayName": "PermissionGrantPoliciesAssigned", "oldValue": '["ManagePermissionGrantsForOwnedResource.x"]',
         "newValue": '["ManagePermissionGrantsForSelf.microsoft-user-default-low"]'}]}])
    assert "enabled" in user_consent_enabled(a)
    a["targetResources"][0]["modifiedProperties"][0]["oldValue"] = a["targetResources"][0]["modifiedProperties"][0]["newValue"]
    assert user_consent_enabled(a) is None


def test_consent_signal_activates_with_suspicious_sign_in_of_the_admin_but_not_with_app_onboarding():
    ac = AlertCenter(Store(":memory:"))
    sig = findings(consent(1, "chris@contoso.com", "AnythingMCP", "openid email profile"))["AnythingMCP"]
    assert ac.ingest("directory_audit", [sig]) == []
    onboarding = Finding(key="diraudit|app_credentials|chris@contoso.com|2026-W45", rule_id="app_credentials",
                         severity=Severity.MEDIUM, score=55, title="App credentials added: chris@contoso.com",
                         occurred_at=sig.occurred_at, fields={"Initiated by": "chris@contoso.com"},
                         subjects=["chris@contoso.com", "app:anythingmcp"])
    assert [a.title for a in ac.ingest("directory_audit", [onboarding]) if a.signal] == []
    replay = Finding(key="replay|u|s", rule_id="aitm_replay", severity=Severity.HIGH, score=80,
                     title="Session replayed from another network after MFA: chris@contoso.com",
                     occurred_at=sig.occurred_at + timedelta(days=1), fields={"User": "chris@contoso.com"})
    popped = ac.ingest("signin_threats", [replay])
    activated = [a for a in popped if a.signal]
    assert len(activated) == 1 and activated[0].score == 30 and "Session replayed" in activated[0].fields["Correlated with"]


def test_plugin_routes_consents_and_reads_the_consent_setting(tmp_path):
    events = [consent(1, "chris@contoso.com", "HubSpot", "User.Read openid"),
              app_role(2, "pat@contoso.com", "Veeam", "sp9", "Files.ReadWrite.All")]

    class Graph:
        calls = []

        def get_all(self, path, params=None, max_pages=None):
            yield from events

        def get(self, path, params=None):
            self.calls.append(path)
            if "authorizationPolicy" in path:
                return {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [
                    "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat"]}}
            raise RuntimeError(path)

    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=Graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    out = {f.fields.get("App"): f for f in pm.run("directory_audit") if f.rule_id == "consent_grant"}
    assert out["HubSpot"].signal == "app_consent" and not out["Veeam"].signal
