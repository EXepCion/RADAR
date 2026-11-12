"""Account context: MFA exclusions from Conditional Access, roles, state, strict watch of password-only accounts."""
import threading
from datetime import timedelta

from radar import entra
from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo, sync_directory
from radar.plugins.signin_threats.rules import RuleContext
from radar.plugins.signin_threats.scoring import Assessor

from conftest import T0, make_signin

POLICIES = [
    {"id": "p1", "displayName": "Require MFA for All Apps", "state": "enabled",
     "grantControls": {"builtInControls": ["mfa"]},
     "conditions": {"users": {"includeUsers": ["All"], "excludeGroups": ["g-nomfa"], "excludeUsers": ["u-direct"]}}},
    {"id": "p2", "displayName": "Report only", "state": "enabledForReportingButNotEnforced",
     "grantControls": {"builtInControls": ["mfa"]}, "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["u-x"]}}},
    {"id": "p3", "displayName": "Phish resistant", "state": "enabled",
     "grantControls": {"authenticationStrength": {"id": entra.PHISHING_RESISTANT_STRENGTH}},
     "conditions": {"users": {"includeGroups": ["g-admins"]}}},
]


class FakeGraph:
    def __init__(self):
        self.pages = {
            "/v1.0/groups/g-nomfa/transitiveMembers": [{"@odata.type": "#microsoft.graph.user", "id": "u-scanner"},
                                                        {"@odata.type": "#microsoft.graph.user", "id": "u-joan"}],
            "/v1.0/groups/g-admins/transitiveMembers": [{"@odata.type": "#microsoft.graph.user", "id": "u-admin"}],
            "/v1.0/users": [
                {"id": "u-scanner", "userPrincipalName": "scan-device@contoso.com", "displayName": "Scanner",
                 "accountEnabled": True, "lastPasswordChangeDateTime": "2022-08-16T11:45:59Z",
                 "signInActivity": {"lastSuccessfulSignInDateTime": "2026-11-09T08:00:00Z"}},
                {"id": "u-joan", "userPrincipalName": "joan.blank@contoso.com", "displayName": "Joan Blank",
                 "accountEnabled": True, "lastPasswordChangeDateTime": "2026-01-01T00:00:00Z"},
                {"id": "u-admin", "userPrincipalName": "chrisadmin@contoso.com", "displayName": "Chris Admin",
                 "accountEnabled": True},
                {"id": "u-direct", "userPrincipalName": "old.account@contoso.com", "displayName": "Old Account",
                 "accountEnabled": False},
            ],
            "/v1.0/roleManagement/directory/roleDefinitions": [{"id": "r-ga", "displayName": "Global Administrator",
                                                                 "templateId": "t-ga"},
                                                                {"id": "r-ua", "displayName": "User Administrator"}],
            "/v1.0/roleManagement/directory/roleAssignments": [{"principalId": "u-admin", "roleDefinitionId": "r-ga"}],
            "/v1.0/auditLogs/directoryAudits": [{"initiatedBy": {"user": {"id": "u-joan"}},
                                                 "targetResources": [{"type": "Role", "displayName": "User Administrator"}]}],
        }

    def get(self, path, params=None):
        if path == "/v1.0/identity/conditionalAccess/policies":
            return {"value": POLICIES}
        if path.startswith("/v1.0/groups/"):
            return {"displayName": {"g-nomfa": "MFA_Exempt", "g-admins": "Admins"}[path.rsplit("/", 1)[-1]]}
        raise AssertionError(path)

    def get_all(self, path, params=None, max_pages=None):
        yield from self.pages[path]


def directory():
    return sync_directory(FakeGraph(), T0)


def test_mfa_exclusions_from_enforced_all_user_policies_only():
    ex = entra.mfa_exclusions(FakeGraph())
    assert set(ex["users"]) == {"u-scanner", "u-joan", "u-direct"}  # report-only policy ignored
    assert ex["groups"]["g-nomfa"]["name"] == "MFA_Exempt"
    assert ex["users"]["u-scanner"] == ["Require MFA for All Apps (group MFA_Exempt)"]
    assert ex["phishing_resistant_users"] == ["u-admin"]


def test_sync_directory_builds_account_context():
    d = directory()
    scanner, jo, admin, old = (d.get(u) for u in ("u-scanner", "u-joan", "u-admin", "u-direct"))
    assert scanner.mfa_excluded and not scanner.person_like
    assert jo.person_like and jo.pim_roles == ["User Administrator"] and jo.privileged_tier == 1
    assert admin.roles == ["Global Administrator"] and admin.privileged_tier == 2 and admin.phishing_resistant
    assert not old.enabled and old.mfa_excluded == ["Require MFA for All Apps (excluded directly)"]
    ctx = scanner.context(T0)
    assert "excluded from MFA (group MFA_Exempt)" in ctx and "password 4+ y old" in ctx


def test_directory_round_trip(tmp_path):
    d = directory()
    d.save(tmp_path / "accounts.json")
    again = AccountDirectory.load(tmp_path / "accounts.json")
    assert again.get("u-admin").roles == ["Global Administrator"] and again.synced_at == d.synced_at


SCANNER = dict(user_id="u-scanner", upn="scan-device@contoso.com", ip="198.51.100.177", asn=5413, country="GB",
               city="London", app="Office 365 Exchange Online", client_app="Authenticated SMTP")


def ctx(history, new, settings=None, d=None, now=None):
    history.add(new)
    return RuleContext.build(new, history, settings or {}, now or T0 + timedelta(hours=1), accounts=d or directory())


def test_mfa_excluded_account_matching_its_pattern_is_quiet(history):
    history.add([make_signin(-60 * 24 * d, **SCANNER) for d in range(1, 20)])
    assert rules.mfa_exempt_watch(ctx(history, [make_signin(0, **SCANNER)])) == []


def test_mfa_excluded_account_deviation_is_high(history):
    history.add([make_signin(-60 * 24 * d, **SCANNER) for d in range(1, 20)])
    odd = make_signin(0, **{**SCANNER, "ip": "185.220.101.5", "asn": 60068, "country": "NL", "city": "Amsterdam",
                            "client_app": "Browser", "app": "OfficeHome"})
    out = rules.mfa_exempt_watch(ctx(history, [odd]))
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    texts = " ".join(r for _, r in out[0].factors)
    for part in ("New IP", "New protocol/client", "New country", "can sign in without MFA"):
        assert part in texts
    assert "excluded from MFA" in out[0].fields["Account context"]
    assert out[0].fields["Account"] == "scan-device@contoso.com"


def test_new_ip_in_known_network_alone_is_low_but_reported(history):
    history.add([make_signin(-60 * 24 * d, **SCANNER) for d in range(1, 20)])
    out = rules.mfa_exempt_watch(ctx(history, [make_signin(0, **{**SCANNER, "ip": "198.51.100.178"})]))
    assert len(out) == 1 and out[0].severity == Severity.LOW  # still a reminder, but not an emergency
    assert any("in a network this account already uses" in r for _, r in out[0].factors)


def test_seed_patterns_learns_background_signins_once(tmp_path):
    from radar.config import ConfigManager
    from radar.plugin_manager import PluginManager
    from radar.plugins.signin_threats import SignInThreatsPlugin
    from radar.plugins.signin_threats.history import SignInHistory
    from radar.store import Store

    pm = PluginManager(ConfigManager(tmp_path / "c.json"), Store(":memory:"), graph_factory=lambda: None,
                       user_dir=tmp_path / "none", stop_event=threading.Event())
    pm.discover()
    c = pm.build_context("signin_threats")
    filters = []

    class Graph:
        def get_pages(self, path, params=None, max_pages=None):
            filters.append(params["$filter"])
            yield [{"id": "bg1", "createdDateTime": "2026-11-01T10:00:00Z", "userId": "u-scanner",
                    "userPrincipalName": "scan-device@contoso.com", "ipAddress": "198.51.100.177",
                    "autonomousSystemNumber": 5413, "clientAppUsed": "Authenticated SMTP", "status": {"errorCode": 0}}]

    c.graph = Graph()
    h = SignInHistory(c.data_dir / "signins.db")
    plugin = SignInThreatsPlugin()
    plugin._seed_patterns(c, h, directory(), T0)
    assert len(filters) == 2  # u-scanner and u-joan (u-direct is disabled)
    assert any("userId eq 'u-scanner'" in f for f in filters) and all("nonInteractiveUser" in f for f in filters)
    assert h.user_profile("u-scanner", "proto", T0) == {"authenticated smtp"}
    plugin._seed_patterns(c, h, directory(), T0)
    assert len(filters) == 2  # already seeded: no second fetch
    h.close()


def test_accounts_still_learning_are_not_judged_on_deviations(history):
    history.add([make_signin(-60 * 24 * d, **SCANNER) for d in range(1, 20)])
    odd = make_signin(0, **{**SCANNER, "ip": "185.220.101.5", "asn": 60068, "country": "NL", "client_app": "Browser"})
    c = ctx(history, [odd])
    c.learning = frozenset({"u-scanner"})
    assert rules.mfa_exempt_watch(c) == []


def test_dormant_mfa_excluded_account_waking_up(history):
    out = rules.mfa_exempt_watch(ctx(history, [make_signin(0, **SCANNER)]))
    assert out and "No successful sign-in in the last 30 days" in " ".join(r for _, r in out[0].factors)


def test_correct_password_from_foreign_network_and_low_threshold_attack(history):
    history.add([make_signin(-60 * 24 * d, **SCANNER) for d in range(1, 5)])
    pwok = make_signin(0, **{**SCANNER, "ip": "45.1.1.1", "asn": 9009, "error_code": 53003, "failure_reason": "Blocked by CA"})
    fails = [make_signin(1 + i, **{**SCANNER, "ip": f"45.2.2.{i}", "asn": 20000 + i, "error_code": 50126}) for i in range(3)]
    out = {f.key.split("|")[0]: f for f in rules.mfa_exempt_watch(ctx(history, [pwok] + fails))}
    assert out["nomfa-pwok"].severity == Severity.HIGH
    assert out["nomfa-attack"].severity >= Severity.MEDIUM


def test_distributed_attack_leaves_mfa_excluded_accounts_to_strict_rule(history):
    fails = [make_signin(-60 + i, **{**SCANNER, "ip": f"45.3.3.{i}", "asn": 30000 + i, "error_code": 50053}) for i in range(10)]
    assert rules.distributed_attack(ctx(history, fails)) == []


def test_account_factors_in_assessment(history):
    d = directory()
    s = make_signin(0, user_id="u-admin", upn="chrisadmin@contoso.com")
    a = Assessor(ctx(history, [s], d=d)).assess(s, 30, "base")
    assert any(f.points == 20 and "Highly privileged" in f.text for f in a.factors)
    assert "admin: Global Administrator" in a.context and "phishing-resistant" in a.context


def test_no_habitual_vpn_discount_for_password_only_accounts(history):
    rows = [make_signin(-60 * 24 * d, **{**SCANNER, "asn": 212238, "risk_events": ["anonymizedIPAddress"]})
            for d in (3, 10, 17, 24)]
    history.add(rows)
    s = make_signin(0, **{**SCANNER, "asn": 212238, "risk_events": ["anonymizedIPAddress"]})
    a = Assessor(ctx(history, [s])).assess(s, 30, "base")
    assert not any("regularly signs in through VPNs" in f.text for f in a.factors)


def test_disabled_and_breakglass_accounts(history):
    d = directory()
    late = make_signin(30, user_id="u-direct", upn="old.account@contoso.com")
    early = make_signin(-30, user_id="u-direct", upn="old.account@contoso.com")
    out = rules.account_state(ctx(history, [late, early], d=d))
    assert len(out) == 1 and out[0].severity == Severity.HIGH  # only after the sync that saw it disabled
    bg = make_signin(0, user_id="u-bg", upn="breakglass1@contoso.com")
    out = rules.account_state(ctx(history, [bg], {"breakglass_accounts": ["breakglass*@contoso.com"]}, d=d))
    assert out and out[0].title.startswith("Break-glass account used")


def test_weekly_mfa_exposure_report(history):
    history.add([make_signin(-60, **SCANNER)])
    out = rules.mfa_exposure_report(ctx(history, []))
    assert len(out) == 1
    report = out[0]
    assert report.key.startswith("mfaexposure|") and report.severity == Severity.LOW
    rows = {r["Account"]: r for r in report.evidence}
    assert "password 4+ y old" in rows["scan-device@contoso.com"]["Flags"]
    assert "Authenticated SMTP".lower() in rows["scan-device@contoso.com"]["Used in last 30 d"]
    assert "looks like a person" in rows["joan.blank@contoso.com"]["Flags"]
    assert "disabled" in rows["old.account@contoso.com"]["Flags"]


def test_audit_alert_when_someone_is_added_to_mfa_exclusion_group(tmp_path):
    from radar.config import ConfigManager
    from radar.plugin_manager import PluginManager
    from radar.store import Store

    class AuditGraph(FakeGraph):
        def get_all(self, path, params=None, max_pages=None):
            if path == "/v1.0/auditLogs/directoryAudits":
                yield {"id": "e1", "activityDateTime": "2026-11-09T10:00:00Z", "activityDisplayName": "Add member to group",
                       "category": "GroupManagement", "result": "success",
                       "initiatedBy": {"app": {"displayName": "Microsoft Approval Management"}},
                       "targetResources": [{"type": "User", "userPrincipalName": "new.person@contoso.com", "id": "u9"},
                                           {"type": "Group", "id": "g-nomfa", "displayName": "MFA_Exempt"}]}
            else:
                yield from super().get_all(path, params, max_pages)

    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=AuditGraph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    out = [f for f in pm.run("directory_audit") if f.rule_id == "mfa_exclusion_change"]
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    assert "new.person@contoso.com" in out[0].title and "MFA_Exempt" in out[0].title


def test_profile_remembers_pattern_kinds(history):
    history.add([make_signin(-60, **SCANNER)])
    later = T0 + timedelta(hours=1)
    assert history.user_profile("u-scanner", "proto", later) == {"authenticated smtp"}
    assert history.user_profile("u-scanner", "ip", later) == {"198.51.100.177"}
    assert history.user_profile("u-scanner", "country", later) == {"GB"}


def test_account_info_defaults():
    a = AccountInfo(user_id="x", upn="info-europe@contoso.com", display_name="Info Europe")
    assert not a.person_like and a.privileged_tier == 0


# ------------------------------------------------ MFA registration gap
def test_no_mfa_registered_is_a_risk_factor_and_in_the_exposure_report(history):
    d = directory()
    d.accounts["u-gap"] = AccountInfo(user_id="u-gap", upn="info-east@contoso.com", display_name="Info East",
                                      mfa_registered=False, pwd_changed="2021-03-01T08:00:00Z",
                                      last_signin="2026-11-09T19:00:00Z")
    d.accounts["u-ok"] = AccountInfo(user_id="u-ok", upn="anna.k@contoso.com", mfa_registered=True)
    gap = d.accounts["u-gap"]
    assert gap.mfa_gap and not d.accounts["u-ok"].mfa_gap and "NO MFA method registered" in gap.context(T0)
    assert any("No MFA method registered" in f.text for f in Assessor.account_factors(gap, make_signin(0)))
    # the rotating-IP attack against it is visible in the report
    history.add([make_signin(-60 * i, user_id="u-gap", upn="info-east@contoso.com", ip=f"45.0.0.{i}", asn=20000 + i,
                             country="US", error_code=50053) for i in range(6)])
    report = rules.mfa_exposure_report(ctx(history, [], d=d))[0]
    rows = {r["Account"]: r for r in report.evidence}
    assert rows["info-east@contoso.com"]["Exposure"] == "NO MFA registered"
    assert rows["info-east@contoso.com"]["Flags"].startswith("UNDER PASSWORD ATTACK (6 attempts")
    assert report.evidence[0]["Account"] == "info-east@contoso.com"  # attacked accounts first
    assert report.fields["No MFA registered"] == "1" and report.fields["Under password attack"] == "1"
    assert "UNDER ATTACK" in report.title and report.severity == Severity.MEDIUM


def test_sync_reads_mfa_registration():
    g = FakeGraph()
    g.pages["/v1.0/reports/authenticationMethods/userRegistrationDetails"] = [
        {"id": "u-joan", "isMfaRegistered": False, "methodsRegistered": []},
        {"id": "u-admin", "isMfaRegistered": True, "methodsRegistered": ["microsoftAuthenticatorPush"]}]
    d = sync_directory(g, T0)
    assert d.accounts["u-admin"].mfa_registered and d.accounts["u-admin"].mfa_methods == ["microsoftAuthenticatorPush"]
    assert d.accounts["u-joan"].mfa_registered is False
    assert not d.accounts["u-joan"].mfa_gap  # excluded from MFA: reported as excluded, not as a gap


def test_guests_are_no_mfa_gap():
    guest = AccountInfo(user_id="g", upn="bob_partner.cz#ext#@contoso.onmicrosoft.com", user_type="Guest",
                        mfa_registered=False)
    assert not guest.mfa_gap


def test_disabled_account_that_keeps_being_tried(history):
    """One refused attempt on a disabled account is a leaver's phone; a steady stream is something still holding a
    sign-in of the account. Reported once a week, at least Low."""
    d = directory()
    poll = dict(user_id="u-direct", upn="old.account@contoso.com", interactive=False, error_code=50057,
                failure_reason="The user account is disabled.", ip="203.0.113.99", asn=64500, country="US", city="",
                app="Microsoft Office", user_agent="node", transfer_method="deviceCodeFlow")
    few = [make_signin(-10 * i, **poll) for i in range(3)]
    assert rules.account_state(ctx(history, few, d=d)) == []
    many = [make_signin(-12 * i - 1, **poll) for i in range(12)]
    out = rules.account_state(ctx(history, many, d=d))
    assert len(out) == 1
    f = out[0]
    assert f.title == "Disabled account keeps being tried: old.account@contoso.com" and f.severity >= Severity.LOW
    assert f.key.startswith("acctstate|dis-tried|u-direct|") and f.fields["Client"] == "node"
    assert "steady pace" in f.summary and "device code" in f.summary and f.fields["Attempts"] == "13"  # the ones of the last 3 hours
    # the next run brings one more attempt: same alert (same key), not a new one
    again = rules.account_state(ctx(history, [make_signin(5, **poll)], d=d))
    assert [x.key for x in again] == [f.key]
