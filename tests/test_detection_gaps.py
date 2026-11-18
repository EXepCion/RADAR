"""Detections that close gaps: prompts judged by where they came from, role activations, a password proven by the
log's own steps, an application's own server, unfamiliar sign-ins, networks that only guess, and tenant changes
nobody watched (trusted networks, sign-in methods, groups that can hold admin roles, domains, reply addresses)."""
import json
import threading
from datetime import timedelta

from conftest import T0, make_signin
from radar import chains
from radar.config import ConfigManager
from radar.plugin_api import Severity
from radar.plugin_manager import PluginManager
from radar.plugins import directory_audit
from radar.plugins.signin_threats import indicators, rules
from radar.plugins.signin_threats.models import ROLE_KIND, AccountChange
from radar.plugins.signin_threats.plugin import SignInThreatsPlugin
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

HOME = dict(asn=812, country="CA", city="Toronto", trust_type="Azure AD joined", compliant=True, managed=True,
            os="Windows10", browser="Edge 140.0")
ELSEWHERE = dict(ip="203.0.113.77", asn=64777, country="CA", city="Montreal", os="Android 14", browser="Chrome Mobile 140.0")


def person(history, i, days=10):
    """An account with ``days`` of ordinary sign-ins from home on its own work laptop."""
    who = dict(user_id=f"u{i}", upn=f"user{i}@contoso.com")
    history.add([make_signin(-60 * 24 * d, **who, ip=f"198.51.100.{10 + i}", device_id=f"lap{i}", **HOME)
                 for d in range(1, days + 1)])
    return who


def context(history, new=(), minutes=120, settings=None):
    history.add(list(new))
    return RuleContext.build(list(new), history, settings or {}, T0 + timedelta(minutes=minutes))


# ------------------------------------------------------------------ MFA prompts not answered
def test_unanswered_prompts_are_judged_by_where_they_came_from(history):
    alice, bob = person(history, 1), person(history, 2)
    own = [make_signin(i, **alice, ip="198.51.100.11", device_id="lap1", error_code=500121, **HOME) for i in range(3)]
    other = [make_signin(i, **bob, error_code=500121, **ELSEWHERE) for i in range(3)]
    out = {f.fields["User"]: f for f in rules.mfa_fatigue(context(history, own + other))}
    mine, theirs = out["user1@contoso.com"], out["user2@contoso.com"]
    assert mine.severity < Severity.LOW and "own surroundings" in mine.summary      # the person not getting through
    assert theirs.severity == Severity.HIGH and "push bombing" in theirs.summary     # somebody who has the password
    assert theirs.score == sum(p for p, _ in theirs.factors) and mine.rule_id == theirs.rule_id == "mfa_fatigue"


def test_a_denied_prompt_counts_and_a_completed_sign_in_takes_away(history):
    bob = person(history, 2)
    rows = [make_signin(i, **bob, error_code=500121, number_match="numberMatchDeny", **ELSEWHERE) for i in range(3)]
    plain = rules.mfa_fatigue(context(history, rows))[0]
    assert any(p == 15 and "DENIED" in r for p, r in plain.factors)
    history.add([make_signin(10, **bob, **ELSEWHERE)])
    done = rules.mfa_fatigue(context(history, rows))[0]
    assert any(p == -15 and "completed from the same address" in r for p, r in done.factors) and done.score < plain.score


# ------------------------------------------------------------------ password proven by the steps of the entry
def test_a_succeeded_password_step_proves_the_password_whatever_the_result(history):
    alice = person(history, 1)
    stopped = make_signin(60, **alice, error_code=50097, failure_reason="Device authentication is required.",
                          auth_methods=["Password"], password_ok=True, **ELSEWHERE)
    assert rules.password_proven(stopped)
    assert not rules.password_proven(make_signin(60, error_code=50097))                              # no step: says nothing
    assert not rules.password_proven(make_signin(60, error_code=50126, password_ok=True))            # a failed password
    assert not rules.password_proven(make_signin(60, error_code=500121, password_ok=True))           # the prompt rule's
    assert rules.password_proven(make_signin(60, error_code=50074))                                  # the result says it
    assert not rules.password_proven(make_signin(60, error_code=50074, auth_methods=["Passkey (device-bound)"]))
    out = rules.password_not_completed(context(history, [stopped]))
    assert len(out) == 1 and out[0].rule_id == "password_not_completed" and "50097" in out[0].fields["Errors"]
    assert out[0].severity >= Severity.LOW
    at_home = make_signin(61, **alice, ip="198.51.100.11", device_id="lap1", error_code=50097, auth_methods=["Password"],
                          password_ok=True, **HOME)
    assert len(rules.password_not_completed(context(history, [at_home]))) == 1                       # still only the first


# ------------------------------------------------------------------ an application's own server
CLOUD = {"scoring": {"extra_asns": {"64600": ["Example Cloud", "cloud"]}, "lookup_asn_names": False}}


def connector(who, minute, **kw):
    return make_signin(minute, **who, ip="203.0.113.200", asn=64600, country="US", city="Ashburn", interactive=False,
                       app="Example Connector", app_id="app-connector", **{"app_owner_tenant": "tenant-of-the-vendor", **kw})


def test_an_application_signing_in_for_several_accounts_from_a_cloud_is_its_own_server(history):
    people = [person(history, i) for i in range(1, 5)]
    first = connector(people[0], 10)
    out = rules.new_country_background(context(history, [first], settings=CLOUD))
    assert len(out) == 1 and out[0].severity >= Severity.LOW          # one account: could be a token in other hands
    history.add([connector(people[1], 20), connector(people[2], 30)])
    assert history.app_network_users("app-connector", 64600, T0 - timedelta(days=1)) == 3
    f = rules.new_country_background(context(history, [connector(people[3], 40)], settings=CLOUD))[0]
    assert f.severity == Severity.INFO and f.score <= 20 and f.score == sum(p for p, _ in f.factors)
    assert any("the application's own server" in r for _, r in f.factors)
    off = dict(CLOUD, new_country_background={"app_server_min_accounts": 0})
    again = person(history, 9)
    assert rules.new_country_background(context(history, [connector(again, 50)], settings=off))[0].severity >= Severity.LOW


def test_microsoft_apps_and_ordinary_networks_are_never_taken_for_a_server(history):
    people = [person(history, i) for i in range(1, 5)]
    history.add([connector(p, 5, app_owner_tenant="f8cdef31-a31e-4b4a-93e4-5f571e91255a") for p in people[:3]])
    assert history.app_network_users("app-connector", 64600, T0 - timedelta(days=1)) == 0     # not even remembered
    f = rules.new_country_background(context(
        history, [connector(people[3], 40, app_owner_tenant="f8cdef31-a31e-4b4a-93e4-5f571e91255a")], settings=CLOUD))[0]
    assert f.severity >= Severity.LOW


# ------------------------------------------------------------------ unfamiliar sign-in
def unfamiliar(history, s, **kw):
    return rules.unfamiliar_signin(context(history, [s], **kw))


def test_a_sign_in_by_hand_from_nothing_the_account_knows(history):
    alice = person(history, 1)
    s = make_signin(60, **alice, auth_methods=["Password", "Mobile app notification"], **ELSEWHERE)
    out = unfamiliar(history, s)
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "unfamiliar_signin" and f.severity >= Severity.LOW and f.fields["User"] == "user1@contoso.com"
    assert f.score == sum(p for p, _ in f.factors) and f.factors[0][0] == 30
    assert chains.stage_of("unfamiliar_signin", f.factors) == 3


def test_what_is_not_an_unfamiliar_sign_in(history):
    alice = person(history, 1)
    fresh = dict(auth_methods=["Password", "Mobile app notification"])
    known_client = dict(ELSEWHERE, os="Windows10", browser="Edge 141.0")
    assert unfamiliar(history, make_signin(60, **alice, **fresh, **known_client)) == []            # their kind of client
    assert unfamiliar(history, make_signin(61, **alice, auth_methods=["Previously satisfied"], **ELSEWHERE)) == []
    assert unfamiliar(history, make_signin(62, **alice, **fresh, **dict(ELSEWHERE, asn=812))) == []  # their network
    assert unfamiliar(history, make_signin(63, **alice, **fresh, device_id="lap1", **ELSEWHERE)) == []
    assert unfamiliar(history, make_signin(64, **alice, **fresh, **dict(ELSEWHERE, country="NL"))) == []  # new_country's
    assert unfamiliar(history, make_signin(65, **alice, **fresh, error_code=50126, **ELSEWHERE)) == []
    newcomer = person(history, 5, days=2)
    assert unfamiliar(history, make_signin(66, **newcomer, **fresh, **ELSEWHERE)) == []            # nothing to compare with
    assert unfamiliar(history, make_signin(67, **person(history, 6, days=2), **fresh, **ELSEWHERE),
                      settings={"unfamiliar_signin": {"min_history_days": 1}}) != []


# ------------------------------------------------------------------ admin role activations
def activation(minute, who, role="Global Administrator", ip=""):
    when = (T0 + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"id": f"PIM_{who['user_id']}_{minute}", "category": "RoleManagement", "result": "success",
            "activityDisplayName": "Add member to role completed (PIM activation)", "activityDateTime": when,
            "loggedByService": "PIM", "initiatedBy": {"user": {"id": who["user_id"], "userPrincipalName": who["upn"]}},
            "targetResources": [{"id": "role-1", "type": "Role", "displayName": role},
                                {"id": who["user_id"], "type": "User", "userPrincipalName": who["upn"]}],
            "additionalDetails": [{"key": "ipaddr", "value": ip}] if ip else []}


def test_a_role_activation_is_read_from_the_audit_entry():
    c = AccountChange.from_audit(activation(0, dict(user_id="u1", upn="user1@contoso.com"), ip="203.0.113.77"))
    assert (c.kind, c.user_id, c.detail, c.actor_ip, c.by_admin) == (ROLE_KIND, "u1", "Global Administrator",
                                                                      "203.0.113.77", False)
    assert "PIM activation" in SignInThreatsPlugin.ROLE_FILTER
    assert {"role_activation", "unfamiliar_signin"} <= {r.id for r in SignInThreatsPlugin.rules}


def test_a_role_activated_at_the_desk_is_a_record_and_from_elsewhere_an_alert(history):
    alice, bob = person(history, 1), person(history, 2)
    history.add([make_signin(50, **alice, ip="198.51.100.11", device_id="lap1", **HOME),
                 make_signin(50, **bob, auth_methods=["Password", "Mobile app notification"], **ELSEWHERE)])
    history.add_changes([AccountChange.from_audit(activation(60, alice)), AccountChange.from_audit(activation(60, bob))])
    rc = context(history)
    out = {f.fields["User"]: f for f in rules.role_activation(rc)}
    desk, away = out["user1@contoso.com"], out["user2@contoso.com"]
    assert desk.signal == "role_activated" and desk.severity == Severity.INFO and desk.score == 15
    assert chains.MIN_WEAK_SCORE <= desk.score < chains.MIN_LINK_SCORE        # a step only inside a chain others make
    assert not away.signal and away.severity == Severity.HIGH and away.key.startswith("roleact-foreign|")
    assert away.score == sum(p for p, _ in away.factors) and away.subjects == ["user2@contoso.com"]
    assert away.evidence[0]["Audit ID"].startswith("PIM_") and any(r.get("Sign-in ID") for r in away.evidence)
    assert chains.stage_of("role_activation", away.factors) == 5
    assert rules.mfa_change(rc) == []                                          # an activation is no change of the account


def test_the_address_of_the_activation_decides_and_no_sign_in_on_record_is_no_alert(history):
    alice, carol = person(history, 1), person(history, 3)
    # alice is at her desk AND her account is in use from elsewhere: the activation came from elsewhere
    history.add([make_signin(50, **alice, ip="198.51.100.11", device_id="lap1", **HOME),
                 make_signin(55, **alice, auth_methods=["Password", "Mobile app notification"], **ELSEWHERE)])
    history.add_changes([AccountChange.from_audit(activation(60, alice, ip="203.0.113.77")),
                         AccountChange.from_audit(activation(60, carol))])
    out = {f.fields["User"]: f for f in rules.role_activation(context(history))}
    assert out["user1@contoso.com"].severity >= Severity.MEDIUM and not out["user1@contoso.com"].signal
    assert out["user3@contoso.com"].signal == "role_activated" and "no sign-in" in out["user3@contoso.com"].summary


# ------------------------------------------------------------------ networks that only guess
def guesses(n, asn=64900, start=0):
    return [make_signin(start + i, user_id=f"u{i + 1}", upn=f"user{i + 1}@contoso.com", ip=f"192.0.2.{50 + i}", asn=asn,
                        country="BR", city="Sao Paulo", error_code=50126) for i in range(n)]


def test_a_network_that_only_guesses_counts_against_what_gets_past_a_password_from_it(history):
    for i in range(1, 6):
        person(history, i)
    history.add(guesses(2))
    rc = context(history)
    assert indicators.apply(rc, []) == [] and history.indicators(rc.now) == []            # two accounts: not yet
    history.add(guesses(3))
    rc = context(history)
    assert indicators.apply(rc, []) == []                                                 # (addresses only are returned)
    marks = history.indicators(rc.now)
    assert [(m.kind, m.value, m.source, m.points) for m in marks] == [("asn", "64900", "guessing_network", indicators.MEDIUM)]
    assert "3 accounts" in marks[0].describe()
    dave = dict(user_id="u4", upn="user4@contoso.com")
    from_it = dict(ip="192.0.2.99", asn=64900, country="BR", city="Sao Paulo")
    got_in = rc.assessor.assess(make_signin(100, **dave, **from_it), 0, "x")
    assert any(p == indicators.MEDIUM and "only guesses passwords" in t for p, t in got_in.as_tuples())
    stopped = rc.assessor.assess(make_signin(100, **dave, **from_it, error_code=50074), 0, "x")
    assert any("only guesses passwords" in t for _, t in stopped.as_tuples())
    guess = rc.assessor.assess(make_signin(100, **dave, **from_it, error_code=50126), 0, "x")
    assert not any("only guesses passwords" in t for _, t in guess.as_tuples())            # the guessing itself: no
    assert rc.hostile(make_signin(100, **dave, **from_it)) is None                         # no "attacker address"


def test_a_network_people_sign_in_from_is_never_a_guessing_network(history):
    for i in range(1, 6):
        person(history, i)
    history.add([make_signin(-60 * 24, user_id="u5", upn="user5@contoso.com", ip="192.0.2.10", asn=64900, country="BR")])
    history.add(guesses(4))
    rc = context(history)
    indicators.apply(rc, [])
    assert history.indicators(rc.now) == []                                               # a carrier a colleague is on
    # ... and a mark from before stops counting the moment somebody else is on the network
    history2_rows = guesses(3, asn=64901)
    history.add(history2_rows)
    rc = context(history)
    indicators.apply(rc, [])
    assert [m.value for m in history.indicators(rc.now)] == ["64901"]
    history.add([make_signin(90, user_id="u5", upn="user5@contoso.com", ip="192.0.2.11", asn=64901, country="BR")])
    rc = context(history)
    a = rc.assessor.assess(make_signin(100, user_id="u4", upn="user4@contoso.com", ip="192.0.2.99", asn=64901), 0, "x")
    assert not any("only guesses passwords" in t for _, t in a.as_tuples())
    assert indicators.derive_networks(context(history, settings={"hostile_indicators": {"network_min_accounts": 0}})) == []


# ------------------------------------------------------------------ tenant changes in the audit log
ROLE_GROUP = "00000000-0000-4000-8000-0000000000a1"


def entry(i, activity, who="admin1@contoso.com", app=False, category="Policy", targets=None, day="2026-11-03"):
    by = {"app": {"displayName": who}} if app else {"user": {"userPrincipalName": who}}
    return {"id": f"e{i}", "activityDateTime": f"{day}T10:{i % 60:02d}:00Z", "activityDisplayName": activity,
            "category": category, "result": "success", "initiatedBy": by, "correlationId": f"c{i}",
            "targetResources": targets or [{"id": f"t{i}", "displayName": f"object {i}", "modifiedProperties": []}]}


def changed(name, new, old="", **target):
    return [{"id": "t", "displayName": "Example App", "type": "Application", **target,
             "modifiedProperties": [{"displayName": name, "oldValue": old, "newValue": new}]}]


def addresses(*urls):
    return json.dumps([{"AddressType": 0, "Address": u, "ReplyAddressClientType": 1} for u in urls])


def member(i, group, who="admin1@contoso.com", app=False, activity="Add member to group"):
    return entry(i, activity, who, app, "GroupManagement", [
        {"id": "u9", "type": "User", "userPrincipalName": "user9@contoso.com", "modifiedProperties": []},
        {"id": group, "type": "Group", "displayName": "", "modifiedProperties": []}])


class Graph:
    def __init__(self, events):
        self.events, self.group_calls = events, 0

    def get_all(self, path, params=None, max_pages=None):
        if path.endswith("/groups"):
            self.group_calls += 1
            assert "isAssignableToRole eq true" in params["$filter"]
            yield {"id": ROLE_GROUP, "displayName": "Tier 0 admins"}
            return
        if "category eq" in params["$filter"]:
            assert "category eq 'ResourceManagement'" in params["$filter"]     # where network connectors are logged
            yield from self.events


def audit_run(tmp_path, events):
    cfg = ConfigManager(tmp_path / "config.json")
    graph = Graph(events)
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    cfg.set("plugins", "directory_audit", "settings", "automation_initiators", value=["Ops Automation"])
    return pm.run("directory_audit"), graph


def test_trusted_networks_and_sign_in_methods_are_watched(tmp_path):
    out, _graph = audit_run(tmp_path, [
        entry(1, "Add named location", targets=changed("NamedLocation", '{"displayName":"x","isTrusted": true}')),
        entry(2, "Update named location", who="admin2@contoso.com",
              targets=changed("NamedLocation", '{"displayName":"x","isTrusted":false}')),
        entry(3, "Authentication Methods Policy Update", category="ApplicationManagement"),
        entry(4, "Authentication Strength Policy Update", who="admin2@contoso.com", category="ApplicationManagement"),
        entry(5, "Update security defaults", who="admin3@contoso.com"),
    ])
    by = {(f.rule_id, f.fields["Initiated by"]): f for f in out}
    trusted = by[("named_locations", "admin1@contoso.com")]
    assert trusted.score == 65 and any(r == directory_audit.TRUSTED_LOCATION_REASON for _, r in trusted.factors)
    assert by[("named_locations", "admin2@contoso.com")].score == 45
    assert by[("auth_methods_policy", "admin1@contoso.com")].score == 50
    assert by[("auth_methods_policy", "admin2@contoso.com")].score == 45
    assert by[("auth_methods_policy", "admin3@contoso.com")].score == 60
    assert all(chains.stage_of(rule) == 5 for rule in ("named_locations", "auth_methods_policy", "privileged_group"))


def test_members_of_groups_that_can_hold_admin_roles(tmp_path):
    out, graph = audit_run(tmp_path, [
        member(1, ROLE_GROUP), member(2, "some-other-group"), member(3, ROLE_GROUP, who="MS-PIM", app=True),
        member(4, ROLE_GROUP, who="admin2@contoso.com", activity="Add owner to group"),
        member(5, ROLE_GROUP, who="Ops Automation", app=True)])
    got = sorted((f.fields["Initiated by"], f.score) for f in out if f.rule_id == "privileged_group")
    assert got == [("Ops Automation", 30), ("admin1@contoso.com", 60), ("admin2@contoso.com", 55)]
    f = next(f for f in out if f.rule_id == "privileged_group" and f.score == 60)
    assert f.title == "Member added to a group that can hold admin roles: user9@contoso.com -> Tier 0 admins"
    assert f.subjects == ["admin1@contoso.com", "user9@contoso.com"] and f.severity == Severity.MEDIUM
    assert graph.group_calls == 1                                              # asked once, then remembered
    quiet, graph = audit_run(tmp_path / "b", [entry(1, "Update named location")])
    assert graph.group_calls == 0                                              # and only when a group changes


def test_rare_changes_of_the_tenant_itself(tmp_path):
    out, _graph = audit_run(tmp_path, [
        entry(1, "Add verified domain", category="DirectoryManagement"),
        entry(2, "Register connector", who="admin2@contoso.com", category="ResourceManagement"),
        entry(3, "Update application", who="admin3@contoso.com", category="ApplicationManagement",
              targets=changed("AppAddress", addresses("https://app.contoso.com/cb", "http://203.0.113.5/cb"),
                              addresses("https://app.contoso.com/cb"))),
        entry(4, "Update application", who="admin3@contoso.com", category="ApplicationManagement",
              targets=changed("PublicClient", "[true]", "[]")),
        entry(5, "Update application", who="Ops Automation", app=True, category="ApplicationManagement",
              targets=changed("AppAddress", addresses("https://new.contoso.com/cb"))),
        entry(6, "Update application", who="admin4@contoso.com", category="ApplicationManagement",
              targets=changed("AppAddress", addresses("https://app.contoso.com/cb"), addresses("https://app.contoso.com/cb"))),
        entry(7, "Update application", who="admin4@contoso.com", category="ApplicationManagement",
              targets=changed("DisplayName", '"New name"')),
        entry(8, "Update service principal", who="admin4@contoso.com", category="ApplicationManagement",
              targets=changed("AppAddress", addresses("https://x.contoso.com/cb"))),
    ])
    by = {f.fields["Initiated by"]: f for f in out if f.rule_id == "tenant_changes"}
    assert set(by) == {"admin1@contoso.com", "admin2@contoso.com", "admin3@contoso.com", "Ops Automation"}
    assert by["admin1@contoso.com"].score == 35 and by["admin2@contoso.com"].score == 35
    app = by["admin3@contoso.com"]                                             # one reminder for the person's week
    assert app.score == 40 and any("http://203.0.113.5/cb" in r and p == 20 for p, r in app.factors)
    assert "Update application" in app.fields["Activities"] and len(app.evidence) == 2
    assert by["Ops Automation"].severity == Severity.INFO and by["Ops Automation"].score == 0
    assert chains.stage_of("tenant_changes") == 4


def test_what_a_reply_address_change_says():
    f = directory_audit.tenant_change_factors
    assert f(entry(1, "Update application", targets=changed("AppAddress", addresses("http://localhost:8400")))) == [
        (20, "Added reply address(es) to an existing application - where its sign-in tokens are sent: http://localhost:8400")]
    wild = f(entry(2, "Update application", targets=changed("AppAddress", addresses("https://*.contoso.com/cb"))))
    assert [p for p, _ in wild] == [20, 20] and "Wildcard" in wild[1][1]
    assert f(entry(3, "Update application", targets=changed("PublicClient", "[true]", "[true]"))) is None
    assert f(entry(4, "Update user")) is None and f(entry(5, "Verify domain"))[0][0] == 35


# ------------------------------------------------------------------ outside organisations, what users may do, deletions
PARTNER_TENANT = "00000000-0000-4000-8000-0000000000b2"
GLOBAL_ADMIN, HELPDESK_ADMIN = "62e90394-69f5-4237-9190-012177145e10", "729827e3-9c14-49f7-bb1b-9608f156bbb8"


def provider(i, tenant, roles, who="admin1@contoso.com"):
    return entry(i, "Adding allowed assignable roles", who, category="DelegatedAdminServiceProviderConstraints", targets=[
        {"id": tenant, "type": "DelegatedAdminServiceProviderConstraints", "modifiedProperties": [   # (as Entra logs it)
            {"displayName": "tenantId", "oldValue": None, "newValue": None},
            {"displayName": "allowedRoleTemplateIds", "oldValue": None, "newValue": json.dumps(roles)}]}])


def test_an_outside_organisation_that_can_be_given_admin_roles(tmp_path):
    out, _graph = audit_run(tmp_path, [
        provider(1, PARTNER_TENANT, [GLOBAL_ADMIN, HELPDESK_ADMIN]),
        provider(2, PARTNER_TENANT, [HELPDESK_ADMIN], who="admin2@contoso.com"),
        provider(3, directory_audit.MS_SUPPORT_TENANT, [directory_audit.SUPPORT_ENGINEER_ROLE], who="admin3@contoso.com"),
        entry(4, "Add partner to company", who="admin4@contoso.com", category="DirectoryManagement"),
    ])
    by = {f.fields["Initiated by"]: f for f in out if f.rule_id == "partner_access"}
    assert set(by) == {"admin1@contoso.com", "admin2@contoso.com", "admin4@contoso.com"}   # (a support case is no partner)
    top = by["admin1@contoso.com"]
    assert top.score == 75 and top.severity == Severity.HIGH
    assert any("Global Administrator" in r and PARTNER_TENANT in r for _, r in top.factors)
    assert by["admin2@contoso.com"].score == 50 and by["admin4@contoso.com"].score == 70
    assert chains.stage_of("partner_access") == 5


def test_the_category_of_service_providers_is_asked_for():
    assert "DelegatedAdminServiceProviderConstraints" in directory_audit.CATEGORIES


def test_what_every_user_may_do_is_a_tenant_change(tmp_path):
    policy = lambda name, new, old="": [{"id": "p", "displayName": "Authorization Policy", "type": "Policy",   # noqa: E731
                                         "modifiedProperties": [{"displayName": name, "oldValue": old, "newValue": new}]}]
    out, _graph = audit_run(tmp_path, [
        entry(1, "Update authorization policy", targets=policy("AllowInvitesFrom", '"everyone"', '"adminsAndGuestInviters"')),
        entry(2, "Update authorization policy", who="admin2@contoso.com",
              targets=policy("PermissionGrantPolicyIdsAssignedToDefaultUserRole",
                             '["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]', "[]")),
    ])
    f = next(f for f in out if f.rule_id == "tenant_changes")
    assert f.fields["Initiated by"] == "admin1@contoso.com" and f.score == 30
    assert any("AllowInvitesFrom" in r for _, r in f.factors)
    assert [x.rule_id for x in out if x.fields.get("Initiated by") == "admin2@contoso.com"] == ["consent_grant"]  # said once


def deleted(i, activity, name, who="admin1@contoso.com", app=False, day="2026-11-03", category="UserManagement"):
    return entry(i, activity, who, app, category, [{"id": f"id-{activity}-{name}", "displayName": name,
                                                    "modifiedProperties": []}], day=day)


def test_many_objects_deleted_by_one_actor_in_a_day(tmp_path):
    events = [deleted(i, "Delete user", f"user{i}") for i in range(5)]                                 # five accounts
    events += [deleted(10 + i, "Delete user", f"user{i}", who="admin2@contoso.com") for i in range(4)]  # four: routine
    events += [deleted(20 + i, "Delete group", f"group{i}", who="admin3@contoso.com", category="GroupManagement")
               for i in range(30)]
    events += [deleted(60 + i, "Hard delete group", f"group{i}", who="admin3@contoso.com", category="GroupManagement")
               for i in range(30)]
    # an application and its enterprise application are one thing deleted, not two
    for i in range(3):
        events += [deleted(100 + 2 * i, "Delete application", f"app{i}", who="admin4@contoso.com", category="ApplicationManagement"),
                   deleted(101 + 2 * i, "Remove service principal", f"app{i}", who="admin4@contoso.com", category="ApplicationManagement")]
    events += [deleted(120 + i, "Remove service principal", f"tool{i}", who="Ops Automation", app=True,
                       category="ApplicationManagement") for i in range(8)]
    events += [deleted(140 + i, "Delete user", f"user{i}", who="admin5@contoso.com", day=f"2026-11-{3 + i:02d}")
               for i in range(6)]                                                                       # one a day
    events += [deleted(150 + i, "Delete group", f"old{i}", who="Microsoft Approval Management", app=True,
                       category="GroupManagement") for i in range(40)]                                  # Microsoft's own
    out, _graph = audit_run(tmp_path, events)
    by = {f.fields["Initiated by"]: f for f in out if f.rule_id == "mass_deletion"}
    assert set(by) == {"admin1@contoso.com", "admin3@contoso.com", "Ops Automation"}
    assert by["admin1@contoso.com"].score == 50 and "5 users" in by["admin1@contoso.com"].title
    wiped = by["admin3@contoso.com"]
    assert wiped.score == 80 and wiped.severity == Severity.HIGH and "30 groups" in wiped.title
    assert any("cannot be restored" in r for _, r in wiped.factors)
    assert by["Ops Automation"].score == 20 and by["Ops Automation"].severity == Severity.INFO
    assert chains.stage_of("mass_deletion") == 5


def test_how_many_deletions_are_many_is_a_setting(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    cfg.set("plugins", "directory_audit", "settings", "mass_deletion", value={"users": 2, "groups": 0, "applications": 5})
    events = [deleted(i, "Delete user", f"user{i}") for i in range(2)]
    events += [deleted(10 + i, "Delete group", f"group{i}", who="admin2@contoso.com", category="GroupManagement") for i in range(50)]
    out, _graph = audit_run(tmp_path, events)
    assert [f.fields["Initiated by"] for f in out if f.rule_id == "mass_deletion"] == ["admin1@contoso.com"]   # (0 = not watched)
