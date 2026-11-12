"""A user reports an MFA prompt as not theirs: the audit entry triggers, the sign-in row (which arrives later) decides."""
import threading
from datetime import timedelta
from types import SimpleNamespace

from conftest import T0, make_signin
from radar import setup_check, tenant_settings
from radar.config import ConfigManager
from radar.correlation import RESPONSE_SIGNALS
from radar.graph import GraphError
from radar.plugin_api import Severity
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.models import REPORT_KIND, AccountChange
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

USER = dict(user_id="u1", upn="alice@contoso.com")
HOME = dict(ip="198.51.100.10", asn=812, country="CA", city="Toronto", device_id="lap1", device_name="LT-YYZ-1",
            trust_type="Azure AD joined", compliant=True, managed=True)


def audit(minute, user="u1", upn="alice@contoso.com", result="success", name="Suspicious activity reported"):
    when = (T0 + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"id": f"Azure MFA_{user}_{minute}", "category": "UserManagement", "result": result,
            "resultReason": "Successfully reported suspicious activity", "activityDisplayName": name,
            "activityDateTime": when, "loggedByService": "Azure MFA", "operationType": "Update",
            "initiatedBy": {"user": {"id": user, "userPrincipalName": upn}},
            "targetResources": [{"id": user, "type": "User", "userPrincipalName": upn}],
            "additionalDetails": [{"key": "AuthenticationMethod", "value": "PhoneAppNotification"},
                                  {"key": "RequestId", "value": "00000000-0000-4000-8000-000000000001"}]}


def baseline(history):
    history.add([make_signin(-60 * 24 * d, **USER, **HOME) for d in range(1, 12)])


def run(history, minutes_after_report, settings=None):
    rc = RuleContext.build([], history, settings or {}, T0 + timedelta(minutes=minutes_after_report))
    return rules.mfa_report(rc)


def test_the_audit_entry_is_read_as_a_report():
    c = AccountChange.from_report(audit(0))
    assert (c.kind, c.user_id, c.upn, c.detail) == (REPORT_KIND, "u1", "alice@contoso.com",
                                                    "Suspicious activity reported (PhoneAppNotification)")
    assert AccountChange.from_report(audit(0, result="failure")) is None
    assert AccountChange.from_json(c.to_json()) == c
    assert c.evidence()["Result"].startswith("Suspicious activity reported")


def test_report_first_stands_at_medium_then_the_late_sign_in_decides(history):
    baseline(history)
    history.add_changes([AccountChange.from_report(audit(0))])
    # 10 minutes later: the sign-in that caused the prompt is not in the log yet
    first = run(history, 10)
    assert len(first) == 1 and first[0].severity == Severity.MEDIUM and first[0].score == 50
    assert "not in the sign-in log yet" in first[0].summary and first[0].fields["User"] == "alice@contoso.com"
    key = first[0].key

    # it arrives an hour later: password accepted on a network and device the account never used, 17 s before the report
    attacker = make_signin(-0.3, **USER, ip="203.0.113.77", asn=64999, country="NL", city="Amsterdam", error_code=500121,
                           os="Linux", browser="Firefox 140.0")
    history.add([attacker])
    later = run(history, 70)
    assert [f.key for f in later] == [key]  # the same alert, judged again
    assert later[0].severity == Severity.HIGH and "someone else knows the password" in later[0].summary
    assert later[0].fields["IP address"] == "203.0.113.77" and "reset it" in later[0].recommendation
    assert later[0].evidence[0]["Type"].startswith("Audit") and len(later[0].evidence) == 2


def test_a_prompt_of_their_own_reported_by_mistake_ends_low(history):
    """The measured case: sign-in from the account's own managed computer on its usual network; the MFA step failed
    17 seconds before the report, and the same computer was signed in around it."""
    baseline(history)
    history.add_changes([AccountChange.from_report(audit(0))])
    own_prompt = make_signin(-0.3, **USER, **HOME, error_code=500121, session_id="S1")
    signed_in = make_signin(-0.8, **USER, **HOME, session_id="S1")
    history.add([own_prompt, signed_in])
    out = run(history, 90)
    assert len(out) == 1 and out[0].severity == Severity.LOW and out[0].score >= 25
    assert out[0].title.endswith("(probably their own sign-in)") and "dismiss that risk" in out[0].recommendation
    assert any("same device signed the account in" in reason for _, reason in out[0].factors)


def test_no_sign_in_after_the_waiting_time_is_high_and_old_reports_are_left_alone(history):
    baseline(history)
    history.add_changes([AccountChange.from_report(audit(0))])
    out = run(history, 121)
    assert out[0].severity == Severity.HIGH and out[0].score == 75
    assert "No sign-in that caused the prompt has appeared" in out[0].summary
    # a failed MFA step of the account that is not close to the report is not taken for its cause
    history.add([make_signin(-8, **USER, ip="203.0.113.77", asn=64999, country="NL", error_code=500121)])
    out = run(history, 121)
    assert out[0].score == 75 and len(out[0].evidence) == 2  # listed as context, not matched
    assert run(history, 60 * 25) == []                                   # outside the rule's window
    assert run(history, 30, {"ignore_users": ["alice@contoso.com"]}) == []


def test_other_rules_and_responses_know_about_a_report(history):
    baseline(history)
    history.add_changes([AccountChange.from_report(audit(0))])
    assert rules.mfa_change(RuleContext.build([], history, {}, T0 + timedelta(minutes=30))) == []  # not an MFA change
    assert "mfa_report" in RESPONSE_SIGNALS["password_reset"].rules          # a new password answers it
    assert "mfa_report" not in RESPONSE_SIGNALS["sessions_revoked"].rules    # cutting sessions does not: the password is known
    assert "mfa_report" in RESPONSE_SIGNALS["account_disabled"].rules
    assert "mfa_report" in {r.meta.id for r in rules.RULES}


# ------------------------------------------------------------ the setting
class PolicyGraph:
    def __init__(self, settings=None, error=None):
        self.settings, self.error, self.asked = settings, error, 0

    def get(self, path, params=None):
        assert path == "/beta/policies/authenticationMethodsPolicy"
        self.asked += 1
        if self.error:
            raise self.error
        return {"reportSuspiciousActivitySettings": self.settings} if self.settings is not None else {}


def test_tenant_setting_is_read_and_explained_in_the_connection_check():
    on = {"state": "enabled", "includeTarget": {"targetType": "group", "id": "all_users"}}
    assert tenant_settings.report_suspicious_activity(PolicyGraph(on)) == ("enabled", "all")
    assert tenant_settings.report_suspicious_activity(PolicyGraph(dict(on, includeTarget={"id": "g-1"}))) == ("enabled", "group")
    for off in ({"state": "default"}, {"state": "disabled"}, {}, None):  # 'Microsoft managed' is off
        assert tenant_settings.report_suspicious_activity(PolicyGraph(off)) == ("off", "")

    ok = setup_check.report_check(PolicyGraph(on))
    assert ok.ok and not ok.required and ok.detail == "switched on for all users"
    assert "for a group" in setup_check.report_check(PolicyGraph(dict(on, includeTarget={"id": "g-1"}))).detail
    off = setup_check.report_check(PolicyGraph({"state": "default"}))
    assert not off.ok and not off.required and "switched off in this organisation" in off.detail
    assert "stays inactive until it is switched on" in off.hint and "Authentication methods > Settings" in off.hint
    assert "'Microsoft managed' means off" in off.hint
    denied = setup_check.report_check(PolicyGraph(error=GraphError(403, "accessDenied", "Request Authorization failed")))
    assert not denied.ok and "not allowed to read the setting" in denied.detail and "Policy.Read.All" in denied.detail
    assert "keeps the check 'MFA prompt reported by the user' active" in denied.hint and "Authentication methods" in denied.hint
    assert setup_check.working([ok, off, denied])  # never in the way of RADAR working


def plugin_ctx(tmp_path, graph):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    return pm.get("signin_threats").plugin, pm.build_context("signin_threats")


def test_rule_is_inactive_while_the_setting_is_off_and_says_so(tmp_path):
    graph = PolicyGraph({"state": "default"})
    plugin, ctx = plugin_ctx(tmp_path, graph)
    plugin.rule_notes = {}
    assert plugin._report_setting(ctx, T0) == "off"
    assert plugin.rule_notes == {"mfa_report": "inactive: 'Report suspicious activity' is off in Entra"}
    assert plugin._report_setting(ctx, T0 + timedelta(hours=2)) == "off" and graph.asked == 1   # asked once a day
    graph.settings = {"state": "enabled", "includeTarget": {"id": "all_users"}}
    assert plugin._report_setting(ctx, T0 + timedelta(hours=25)) == "enabled" and plugin.rule_notes == {}  # on by itself
    graph.settings = {"state": "enabled", "includeTarget": {"id": "g-1"}}
    assert plugin._report_setting(ctx, T0 + timedelta(hours=26), force=True) == "enabled"
    assert plugin.rule_notes == {"mfa_report": "on for a group only"}
    # throttled: what was known stays; not allowed to read: unknown, and the rule stays active
    graph.error = GraphError(429, "TooManyRequests", "slow down")
    assert plugin._report_setting(ctx, T0 + timedelta(hours=60)) == "enabled"
    graph.error = GraphError(403, "accessDenied", "Request Authorization failed")
    assert plugin._report_setting(ctx, T0 + timedelta(hours=90)) == "unknown"
    assert plugin.rule_notes == {"mfa_report": "cannot verify the Entra setting"}


def test_reports_are_fetched_from_the_audit_log_by_their_configured_name(tmp_path, history):
    class AuditGraph:
        def __init__(self):
            self.filters = []

        def get_pages(self, path, params=None, max_pages=None):
            self.filters.append(params["$filter"])
            if "Suspicious activity reported" in params["$filter"] or "Prompt flagged" in params["$filter"]:
                yield [audit(0), audit(1, name="Prompt flagged"), audit(2, result="failure")]

    graph = AuditGraph()
    plugin, ctx = plugin_ctx(tmp_path, graph)
    ctx.now = lambda: T0 + timedelta(minutes=30)
    plugin._ingest_changes(ctx, history, ctx.now(), reports=True)
    got = history.changes(T0 - timedelta(hours=1), T0 + timedelta(hours=1))
    assert [(c.kind, c.user_id) for c in got] == [(REPORT_KIND, "u1")]  # the other name is not configured; failures are not reports
    assert any("activityDisplayName eq 'Suspicious activity reported'" in f for f in graph.filters)
    ctx.settings = dict(ctx.settings, mfa_report={"activities": ["Suspicious activity reported", "Prompt flagged"]})
    plugin._ingest_changes(ctx, history, ctx.now(), reports=True)
    assert len(history.changes(T0 - timedelta(hours=1), T0 + timedelta(hours=1))) == 2
    before = len(graph.filters)
    plugin._ingest_changes(ctx, history, ctx.now(), reports=False)   # setting off in the tenant: not asked for
    assert not any("Suspicious" in f for f in graph.filters[before:])


def test_the_menu_shows_why_a_rule_is_inactive():
    import pytest

    pytest.importorskip("pystray")
    from radar.tray import Tray

    rule = SimpleNamespace(id="mfa_report", name="MFA prompt reported by the user")
    other = SimpleNamespace(id="x", name="Other rule")
    rt = SimpleNamespace(plugin=SimpleNamespace(id="signin_threats", rules=[rule, other],
                                                rule_notes={"mfa_report": "inactive: 'Report suspicious activity' is off in Entra"}))
    app = SimpleNamespace(plugins=SimpleNamespace(is_enabled=lambda pid: True, rule_enabled=lambda pid, rid: True),
                          plugin_status_text=lambda rt: "ok", toggle_plugin=None, scan_now=None, toggle_rule=None)
    texts = [str(item.text) for item in Tray(app)._plugin_items(rt)]
    assert "MFA prompt reported by the user  (inactive: 'Report suspicious activity' is off in Entra)" in texts
    assert "Other rule" in texts


# ------------------------------------------------- the attacker's address
ATTACKER = dict(ip="203.0.113.77", asn=64999, country="NL", city="Amsterdam", os="Linux", browser="Firefox 140.0")


def reported_attack(history):
    baseline(history)
    history.add([make_signin(-60 * 24 * d, user_id="u2", upn="bob@contoso.com", ip="198.51.100.20", asn=812, device_id="lap2")
                 for d in range(1, 8)])
    history.add_changes([AccountChange.from_report(audit(0))])
    history.add([make_signin(-0.3, **USER, **ATTACKER, error_code=500121)])


def test_the_address_of_a_reported_prompt_counts_against_every_sign_in_from_it(history):
    reported_attack(history)
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=3))
    mark = rc.reported_addresses()["203.0.113.77"]
    assert (mark.upn, mark.user_id) == ("alice@contoso.com", "u1")
    # another account, next day, same address: whatever rule looks at it sees the mark
    try_bob = make_signin(60 * 20, user_id="u2", upn="bob@contoso.com", **ATTACKER, error_code=50126)
    history.add([try_bob])
    rc = RuleContext.build([try_bob], history, {}, T0 + timedelta(hours=21))
    a = rc.assessor.assess(try_bob, 10, "test")
    assert any(points == 25 and "alice@contoso.com reported as not theirs" in reason for points, reason in a.as_tuples())
    clean = make_signin(60 * 20, user_id="u2", upn="bob@contoso.com", ip="203.0.113.78", asn=64999, country="NL", error_code=50126)
    assert not any("reported as not theirs" in reason for _, reason in rc.assessor.assess(clean, 10, "test").as_tuples())
    # after mark_days the address is forgotten; with the rule switched off nothing is marked
    assert RuleContext.build([], history, {}, T0 + timedelta(days=8)).reported_addresses() == {}
    assert RuleContext.build([], history, {}, T0 + timedelta(hours=3), enabled_rules=["new_country"]).reported_addresses() == {}


def test_other_accounts_tried_from_the_reported_address_raise_an_alert_of_their_own(history):
    reported_attack(history)
    assert [f.key.split("|")[0] for f in run(history, 180)] == ["mfa-report"]  # nothing else from that address yet
    history.add([make_signin(60 * 20, user_id="u2", upn="bob@contoso.com", **ATTACKER, error_code=50126)])
    by_kind = {f.key.split("|")[0]: f for f in run(history, 60 * 21)}
    tried = by_kind["reported-ip"]
    assert tried.severity == Severity.MEDIUM and tried.score == 45
    assert tried.title == "Address of a reported MFA prompt also used on 1 other account(s): 203.0.113.77"
    assert tried.fields["Accounts"] == "bob@contoso.com" and tried.fields["Reported by"].startswith("alice@contoso.com")
    # the password is right for the next account, and then the attacker is in: high, and it says who
    history.add([make_signin(60 * 20 + 5, user_id="u3", upn="carol@contoso.com", **ATTACKER, error_code=50074),
                 make_signin(60 * 20 + 9, user_id="u3", upn="carol@contoso.com", **ATTACKER)])
    worse = {f.key.split("|")[0]: f for f in run(history, 60 * 21)}["reported-ip"]
    assert worse.key == tried.key and worse.severity == Severity.HIGH and worse.score == 100
    assert worse.title == "Signed in from the address of a reported MFA prompt: carol@contoso.com"
    assert "revoke its sessions" in worse.recommendation and len(worse.evidence) == 3


def test_a_mistaken_report_marks_nothing_and_colleagues_on_their_own_devices_are_left_out(history):
    baseline(history)
    history.add_changes([AccountChange.from_report(audit(0))])
    history.add([make_signin(-0.3, **USER, **HOME, error_code=500121)])  # the user's own computer and network
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=3))
    assert rc.reported_addresses() == {}
    assert [f.key.split("|")[0] for f in rules.mfa_report(rc)] == ["mfa-report"]

    # a real report from a shared network (a hotel): a colleague's known laptop on the same address is no hit
    history.add_changes([AccountChange.from_report(audit(600))])
    history.add([make_signin(599.7, **USER, **ATTACKER, error_code=500121),
                 make_signin(-60 * 24, user_id="u2", upn="bob@contoso.com", ip="198.51.100.20", asn=812, device_id="lap2"),
                 make_signin(640, user_id="u2", upn="bob@contoso.com", device_id="lap2", **ATTACKER)])
    out = rules.mfa_report(RuleContext.build([], history, {}, T0 + timedelta(hours=12)))
    assert "reported-ip" not in {f.key.split("|")[0] for f in out}
