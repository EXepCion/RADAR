"""Connecting the dots: an alert names everybody it is about (the account something was done to, the application
that did it), an odd sign-in followed by a grab for power is a chain, applications have chains of their own, and
what an administrator did from a known attacker address says so."""
from datetime import datetime, timedelta, timezone

from radar import chains, correlation, incidents, paths
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins.signin_threats.history import SignInHistory
from radar.plugins.signin_threats.indicators import Indicator
from radar.store import Store
from test_chains import NOW, USER, chain_for, spread_for, step, store, with_fields
from test_detection_gaps import audit_run, entry

ADMIN, APP = "admin1@contoso.com", "app:backup tool"


def role(i, target, who=ADMIN, app=False, name="Global Administrator", target_type="User", day="2026-11-09"):
    """An admin role assigned, as the audit log has it: the receiver and the role are the targets."""
    receiver = {"id": f"u{i}", "type": target_type, "modifiedProperties": [
        {"displayName": "Role.DisplayName", "oldValue": None, "newValue": f'"{name}"'}]}
    receiver["userPrincipalName" if target_type == "User" else "displayName"] = target
    return entry(i, "Add member to role", who, app, "RoleManagement",
                 [receiver, {"id": "r", "type": "Role", "displayName": name, "modifiedProperties": []}], day=day)


def one(findings, rule):
    found = [f for f in findings if f.rule_id == rule]
    assert len(found) == 1, [f.title for f in findings]
    return found[0]


# ------------------------------------------------------------------ who an alert is about
def test_a_role_assignment_names_the_account_that_got_the_role(tmp_path):
    out, _graph = audit_run(tmp_path, [role(1, "Victim@contoso.com")])
    f = one(out, "role_assignment")
    assert f.subjects == [ADMIN, "victim@contoso.com"] and f.fields["Done to"] == "victim@contoso.com"
    mine, _graph = audit_run(tmp_path / "self", [role(1, ADMIN)])            # to oneself: one account, said once
    f = one(mine, "role_assignment")
    assert f.subjects == [ADMIN] and "Done to" not in f.fields


def test_an_application_that_acts_or_is_acted_on_is_named(tmp_path):
    out, _graph = audit_run(tmp_path, [
        role(1, "victim@contoso.com", who="Deploy Tool", app=True),
        role(2, "Backup Tool", who="admin2@contoso.com", target_type="ServicePrincipal"),
        entry(3, "Add owner to application", who="admin3@contoso.com", category="ApplicationManagement", targets=[
            {"id": "u", "type": "User", "userPrincipalName": "owner@contoso.com", "modifiedProperties": []},
            {"id": "a", "type": "Application", "displayName": "Backup Tool", "modifiedProperties": []}]),
        entry(4, "Delete conditional access policy", who="Deploy Tool", app=True),
    ])
    by = {(f.rule_id, f.fields["Initiated by"]): f for f in out}
    assert by[("role_assignment", "Deploy Tool")].subjects == ["app:deploy tool", "victim@contoso.com"]
    assert by[("role_assignment", "admin2@contoso.com")].subjects == ["admin2@contoso.com", APP]
    assert by[("app_owner_change", "admin3@contoso.com")].subjects == ["admin3@contoso.com", "owner@contoso.com", APP]
    assert by[("conditional_access", "Deploy Tool")].subjects == ["app:deploy tool"]
    # ... and it survives the alert store (a bare name without '@' used to be dropped there)
    ac = AlertCenter(Store(":memory:"))
    stored = ac.ingest("directory_audit", [by[("conditional_access", "Deploy Tool")]])
    assert stored[0].subjects == ["app:deploy tool"]


def test_a_new_address_shared_by_accounts_names_them(history):
    from conftest import make_signin
    from radar.plugins.signin_threats import rules
    from radar.plugins.signin_threats.rules import RuleContext

    new = [make_signin(-10 - i, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip="198.51.100.77", asn=64999)
           for i in range(3)]
    history.add(new)
    rc = RuleContext.build(new, history, {}, max(s.created for s in new) + timedelta(minutes=5))
    f = one(rules.new_shared_ip(rc), "new_shared_ip")
    assert f.subjects == ["user0@contoso.com", "user1@contoso.com", "user2@contoso.com"]


def test_the_account_a_role_was_given_to_has_the_escalation_in_its_chain(tmp_path):
    out, _graph = audit_run(tmp_path, [role(1, USER, day="2026-11-09")])
    given = one(out, "role_assignment")
    ac = store(step("pwok", "password_not_completed", 50, 3), step("abroad", "new_country", 50, 2))
    ac.ingest("directory_audit", [given])
    f, = chain_for(ac)
    assert f.subjects == [USER] and f.fields["Chain"] == "Password known -> Suspicious access -> Escalation"
    # and it is one incident with what was known about that account - although the role change only NAMES the account
    # it was done to (see test_admin_work: five receivers do not become one incident)
    about, named = incidents.links(next(a for a in ac.since(NOW - timedelta(days=30)) if a.rule_id == "role_assignment"))
    assert ("account", USER) in named and ("account", ADMIN) in named and about == []
    together = [i for i in incidents.group(ac.since(NOW - timedelta(days=30)), NOW) if USER in i.accounts]
    assert len(together) == 1 and "role_assignment" in {a.rule_id for a in together[0].alerts}


def test_a_suspected_admin_giving_another_account_a_role_is_an_attack_across_accounts(tmp_path):
    out, _graph = audit_run(tmp_path, [role(1, "bea@contoso.com", who=USER, day="2026-11-08")])
    ac = store(step("pwok", "password_not_completed", 50, 4), step("abroad", "new_country", 60, 3),
               step("later", "new_country", 50, 1, user="bea@contoso.com"))
    ac.ingest("directory_audit", [one(out, "role_assignment")])
    f, = spread_for(ac)
    assert f.subjects == [USER, "bea@contoso.com"]


# ------------------------------------------------------------------ an odd sign-in, then a grab for power
def test_an_odd_sign_in_followed_by_escalation_is_a_chain():
    ac = store(step("odd", "unfamiliar_signin", 45, 2), step("ca", "conditional_access", 70, 1))
    f, = chain_for(ac)
    assert f.fields["Chain"] == "Suspicious access -> Escalation"
    assert f.score == 70 and f.severity == Severity.HIGH                  # (two steps: as high as its strongest one)
    medium, = chain_for(store(step("odd", "new_country", 50, 2), step("del", "mass_deletion", 50, 1)))
    assert medium.score == 60 and medium.severity == Severity.MEDIUM
    # a sign-in that was only Low, or a harmless change, makes nothing of it - and travel + passkey stays quiet
    assert chain_for(store(step("odd", "new_country", 30, 2), step("ca", "conditional_access", 70, 1))) == []
    assert chain_for(store(step("odd", "new_country", 50, 2), step("ca", "tenant_changes", 30, 1))) == []
    assert chain_for(store(step("odd", "new_country", 50, 2), step("mfa", "mfa_change", 50, 1))) == []
    assert chain_for(store(step("ca", "conditional_access", 70, 2), step("odd", "new_country", 50, 1))) == []   # wrong order


def test_cross_tenant_changes_have_their_place_in_a_chain():
    assert chains.stage_of("cross_tenant_access") == 5


# ------------------------------------------------------------------ applications
def app_finding(key, rule, score, days_ago, factors=(), title="", who=""):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    fields = {"App": "Backup Tool", **({"Initiated by": who} if who else {})}
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=title or f"{rule} Backup Tool",
                   occurred_at=NOW - timedelta(days=days_ago), fields=fields, factors=list(factors),
                   subjects=([who] if who else []) + [APP])


ABROAD = [(55, "Signed in from a country it never used (BR); usual: CA")]
FIRST_USE = [(30, "Credential 12345678... used for the first time")]
TRIED = [(55, "80 failed sign-ins with the app's credential this week: invalid client secret (80) - from 3 IP(s) "
              "outside its usual networks")]


def test_what_an_application_sign_in_finding_is_in_a_chain():
    assert chains.stage_of("app_signins", ABROAD) == 5          # using what was planted, from somewhere else
    assert chains.stage_of("app_signins", TRIED) == 1           # somebody trying its secrets
    assert chains.stage_of("app_signins", FIRST_USE) is None    # a rotation looks like this
    assert chains.stage_of("app_signins", [(30, "80 failed sign-ins with the app's credential this week: expired")]) is None


def test_a_secret_added_and_the_application_signing_in_from_abroad_is_a_chain():
    ac = store(app_finding("cred", "app_credentials", 50, 2, who=ADMIN),
               app_finding("cc", "app_signins", 55, 1, ABROAD))
    found = [f for f in chain_for(ac) if f.subjects == [APP]]
    f, = found
    assert f.title.startswith("Possible attack chain: the application backup tool (Persistence -> Escalation)")
    assert f.score == 65 and f.fields["Application"] == "backup tool" and "Account" not in f.fields
    assert "credential" in f.recommendation.lower()
    assert not [x for x in chain_for(ac) if x.subjects == [ADMIN]]            # the admin alone has no chain
    # a new secret that is then simply used is a rotation, not a chain
    ac = store(app_finding("cred", "app_credentials", 50, 2, who=ADMIN), app_finding("key", "app_signins", 30, 1, FIRST_USE))
    assert chain_for(ac) == []


def test_an_admin_under_suspicion_who_plants_a_secret_is_one_story_with_the_application():
    ac = store(step("abroad", "new_country", 55, 3, user=ADMIN),
               app_finding("cred", "app_credentials", 50, 2, who=ADMIN),
               app_finding("cc", "app_signins", 55, 1, ABROAD))
    f, = spread_for(ac)
    assert f.subjects == [ADMIN, APP] and f.fields["Chain"] == "Suspicious access -> Persistence -> Escalation"
    assert f.title.startswith("Attack across 2 accounts / applications: admin1@contoso.com, the application backup tool")
    assert f.severity == Severity.HIGH
    # an admin nobody suspects adding a secret ties nothing together
    calm = store(app_finding("cred", "app_credentials", 50, 2, who=ADMIN), app_finding("cc", "app_signins", 55, 1, ABROAD))
    assert spread_for(calm) == []


# ------------------------------------------------------------------ done from a known attacker address
def from_address(e, ip):
    e["initiatedBy"]["user"]["ipAddress"] = ip
    return e


def test_a_change_made_from_a_known_attacker_address_says_so(tmp_path):
    when = datetime.now(timezone.utc)
    h = SignInHistory(paths.plugin_data_dir("signin_threats") / "signins.db")
    h.add_indicators([Indicator("ip", "203.0.113.9", "session_theft", "a stolen session", 25, "u7", "carl@contoso.com",
                                when - timedelta(hours=3), when + timedelta(days=7))])
    h.close()
    day = f"{when:%Y-%m-%d}"
    out, _graph = audit_run(tmp_path, [
        from_address(entry(1, "Update conditional access policy", day=day), "203.0.113.9"),
        from_address(entry(2, "Update conditional access policy", who="admin2@contoso.com", day=day), "198.51.100.4"),
    ])
    by = {f.fields["Initiated by"]: f for f in out if f.rule_id == "conditional_access"}
    hit, calm = by[ADMIN], by["admin2@contoso.com"]
    assert hit.fields[chains.ATTACKER_ADDRESS_FIELD].startswith("203.0.113.9 - a stolen session")
    assert hit.score == calm.score + 30 and hit.severity == Severity.HIGH
    assert any(p == 30 and "known attacker address" in r.lower() for p, r in hit.factors)
    assert chains.ATTACKER_ADDRESS_FIELD not in calm.fields
    # the field is what ties the admin's change to the account the address was first seen on
    theft = Finding(key="theft", rule_id="session_theft", severity=Severity.HIGH, score=70, title="Session theft",
                    occurred_at=when - timedelta(hours=3), subjects=["carl@contoso.com"],
                    fields={"User": "carl@contoso.com", chains.ATTACKER_ADDRESS_FIELD: "203.0.113.9 - a stolen session"})
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", [theft])
    ac.ingest("directory_audit", [hit])
    groups = incidents.group(ac.since(when - timedelta(days=30)), when + timedelta(days=1))
    assert any({"carl@contoso.com", ADMIN} <= set(i.accounts) for i in groups)


def test_without_a_sign_in_history_nothing_is_looked_up(tmp_path):
    out, _graph = audit_run(tmp_path, [from_address(entry(1, "Update conditional access policy"), "203.0.113.9")])
    assert chains.ATTACKER_ADDRESS_FIELD not in one(out, "conditional_access").fields


# ------------------------------------------------------------------ what a response answers
def test_responses_answer_the_newer_sign_in_alerts_too():
    by = correlation.RESPONSE_SIGNALS
    for rule in ("unfamiliar_signin", "new_shared_ip"):
        assert by["sessions_revoked"].answers(rule, "") and by["password_reset"].answers(rule, "")
        assert by["account_disabled"].answers(rule, "")
    assert by["account_disabled"].answers("attack_tooling", "") and by["account_disabled"].answers("password_spray", "")
    assert not by["sessions_revoked"].answers("attack_tooling", "")           # guessing from outside holds no session
