"""AiTM phishing / session replay and MFA-change rules: attacks score high, everyday changes stay quiet."""
from datetime import timedelta

from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.models import AccountChange
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

MYSIGNINS = "19db86c3-b2b9-44cc-b339-36da233a3be2"
LAPTOP = dict(device_id="lap", device_name="LT-TOR-1", trust_type="Azure AD joined", compliant=True, os="Windows10",
              browser="Edge 140.0")
HOME = dict(asn=812, country="CA", city="Toronto", ip="85.1.1.1")
DO = dict(asn=14061, country="CA", city="Toronto", ip="164.90.1.1")  # DigitalOcean: hosting
USER = dict(user_id="u1", upn="anna@contoso.com")


def baseline(history):
    history.add([make_signin(-60 * 24 * (5 + i), **USER, **HOME, **LAPTOP) for i in range(6)])


def change(minutes, kind="method_added", by_admin=False, detail="User registered security info (Authenticator app)"):
    return AccountChange(id=f"c{minutes}{kind}", created=T0 + timedelta(minutes=minutes), user_id="u1",
                         upn="anna@contoso.com", kind=kind, detail=detail, by_admin=by_admin,
                         actor="helpdesk@contoso.com" if by_admin else "anna@contoso.com", app_id=MYSIGNINS)


def run(history, rule, new=(), changes=(), now_minutes=120, settings=None):
    history.add(list(new))
    history.add_changes(list(changes))
    rc = RuleContext.build(list(new), history, settings or {}, T0 + timedelta(minutes=now_minutes))
    return rule(rc)


# ------------------------------------------------------------------ mfa_change
def test_passkey_added_on_known_laptop_stays_quiet(history):
    baseline(history)
    reg = make_signin(-1, app_id=MYSIGNINS, app="My Signins", **USER, **HOME, **LAPTOP)
    out = run(history, rules.mfa_change, [reg], [change(0, detail="User registered security info (Passkey)")])
    assert len(out) == 1 and out[0].severity == Severity.INFO
    assert "Change made from" in " ".join(r for _, r in out[0].factors)


def test_new_phone_after_registering_it_on_known_laptop_stays_quiet(history):
    baseline(history)
    reg = make_signin(-1, app_id=MYSIGNINS, **USER, **HOME, **LAPTOP)
    phone = make_signin(10, **USER, asn=1234, ip="10.9.9.9", country="CA", city="Toronto", device_id="phone",
                        device_name="iPhone", trust_type="Azure AD registered", os="Ios", browser="Mobile Safari")
    out = run(history, rules.mfa_change, [reg, phone], [change(0)])
    assert out[0].severity == Severity.INFO
    assert "New devices/networks afterwards" in out[0].fields


def test_attacker_registering_own_authenticator_from_datacenter_is_high(history):
    baseline(history)
    reg = make_signin(-1, app_id=MYSIGNINS, **USER, **DO, os="Windows10", browser="Chrome 141.0")
    same_session = make_signin(5, **USER, **DO, os="Windows10", browser="Chrome 141.0")
    out = run(history, rules.mfa_change, [reg, same_session], [change(0)])
    assert out[0].severity == Severity.MEDIUM  # the registration from a datacenter alone (not counted twice)
    assert "Hosting network" in " ".join(r for _, r in out[0].factors)
    other = make_signin(15, **USER, **dict(DO, ip="164.90.1.2"), os="Linux", browser="Firefox 140.0")
    f = run(history, rules.mfa_change, [other], [])[0]
    assert f.severity == Severity.HIGH and f.title.endswith("then new device/network")
    assert f.evidence[0]["Audit ID"] and any(r.get("Sign-in ID") == other.id for r in f.evidence)


def test_social_engineered_help_desk_reset_then_clean_login_from_new_device_is_high(history):
    baseline(history)
    attacker = dict(asn=5555, ip="81.7.7.7", country="CA", city="Montreal", os="MacOs", browser="Safari 18.0")
    reg = make_signin(6, app_id=MYSIGNINS, **USER, **attacker)
    login = make_signin(20, **USER, **attacker, auth_methods=["Password", "Mobile app notification"])
    out = run(history, rules.mfa_change, [reg, login],
              [change(0, "mfa_reset", True, "Admin required re-registration of MFA authentication methods."), change(7)])
    f = out[0]
    assert f.severity >= Severity.MEDIUM and f.fields["Changed by"] == "helpdesk@contoso.com"
    assert f.factors[0][1].startswith("MFA reset")


def test_genuine_help_desk_reset_user_re_registers_on_own_laptop_stays_quiet(history):
    baseline(history)
    reg = make_signin(6, app_id=MYSIGNINS, **USER, **HOME, **LAPTOP)
    out = run(history, rules.mfa_change, [reg],
              [change(0, "mfa_reset", True, "Admin required re-registration of MFA authentication methods."), change(7)])
    assert out[0].severity == Severity.INFO


def test_one_passkey_registration_logged_three_times_is_one_line():
    from radar.plugins.signin_threats.rules import _collapse_changes
    events = [change(0, detail="User registered Passkey"), change(0.1, detail="User registered Fido2 Authentication Method"),
              change(0.5, detail="User registered security info"), change(30, "mfa_reset", True, "Admin reset")]
    lines = _collapse_changes(events)
    assert len(lines) == 2
    assert lines[0].endswith("User registered Passkey / User registered Fido2 Authentication Method")
    assert lines[1].endswith("Admin reset by helpdesk@contoso.com")


def test_guests_are_skipped_by_default(history):
    g = AccountChange(id="g", created=T0, user_id="ug", upn="bob_partner.cz#ext#@contoso.onmicrosoft.com",
                      kind="method_added", detail="x")
    assert run(history, rules.mfa_change, changes=[g]) == []
    assert len(run(history, rules.mfa_change, settings={"mfa_change": {"include_guests": True}})) == 1


# --------------------------------------------------------------- aitm_replay
FRESH = dict(auth_methods=["Password", "Mobile app notification"])


def test_fresh_mfa_through_datacenter_without_device_is_aitm(history):
    baseline(history)
    s = make_signin(0, **USER, **DO, **FRESH, app="OfficeHome", os="Windows10", browser="Chrome 141.0")
    out = run(history, rules.aitm_replay, [s])
    assert len(out) == 1 and out[0].severity == Severity.HIGH and out[0].title.startswith("Possible AiTM")


def test_users_habitual_hosting_exit_is_not_aitm(history):
    history.add([make_signin(-60 * 24 * (4 + i), **USER, **DO, **FRESH) for i in range(5)])
    s = make_signin(0, **USER, **DO, **FRESH)
    assert run(history, rules.aitm_replay, [s]) == []


def test_previously_satisfied_or_registered_device_is_not_aitm(history):
    baseline(history)
    cookie = make_signin(0, **USER, **DO, auth_methods=["Previously satisfied"])
    device = make_signin(1, **USER, **DO, **FRESH, device_id="lap")
    assert run(history, rules.aitm_replay, [cookie, device]) == []


def test_fresh_mfa_session_replayed_from_other_network_same_country(history):
    baseline(history)
    mfa = make_signin(0, **USER, **HOME, **FRESH, session_id="S1", os="Windows10", browser="Chrome 141.0")
    replay = make_signin(12, **USER, asn=5555, ip="81.7.7.7", country="CA", city="Montreal", session_id="S1",
                         interactive=False, auth_methods=["Previously satisfied"], os="Linux", browser="Firefox 140.0")
    out = [f for f in run(history, rules.aitm_replay, [mfa, replay]) if f.key.startswith("replay|")]
    assert len(out) == 1 and out[0].severity >= Severity.MEDIUM
    texts = " ".join(r for _, r in out[0].factors)
    assert "12 min later" in texts and "Different client" in texts


def test_wifi_to_mobile_switch_between_usual_networks_stays_quiet(history):
    baseline(history)
    history.add([make_signin(-60 * 24 * (5 + i), **USER, asn=6730, ip="178.1.1.1", country="CA") for i in range(4)])
    mfa = make_signin(0, **USER, **HOME, **FRESH, session_id="S2", os="Ios", browser="Mobile Safari")
    mobile = make_signin(30, **USER, asn=6730, ip="178.1.1.2", country="CA", session_id="S2", os="Ios",
                         browser="Mobile Safari")
    out = [f for f in run(history, rules.aitm_replay, [mfa, mobile]) if f.key.startswith("replay|")]
    assert len(out) == 1 and out[0].severity == Severity.INFO


def test_cross_country_pair_with_device_is_left_to_session_theft(history):
    baseline(history)
    mfa = make_signin(0, **USER, **HOME, **FRESH, session_id="S3", device_id="x1")
    abroad = make_signin(30, **USER, asn=7777, ip="9.9.9.9", country="US", session_id="S3")
    assert [f for f in run(history, rules.aitm_replay, [mfa, abroad]) if f.key.startswith("replay|")] == []


# ------------------------------------------------------------ audit parsing
def audit(activity, reason, target="u1", initiator="u1", upn="anna@contoso.com", app=None, details=None,
          result="success"):
    init = {"app": app} if app else {"user": {"id": initiator, "userPrincipalName": upn if initiator == target
                                               else "helpdesk@contoso.com", "ipAddress": "4.1.1.1"},
                                      "app": {"appId": MYSIGNINS, "displayName": "My Signins"}}
    return {"id": f"a-{activity}", "activityDateTime": "2026-11-09T12:00:00Z", "activityDisplayName": activity,
            "resultReason": reason, "result": result, "initiatedBy": init,
            "targetResources": [{"id": target, "type": "User", "userPrincipalName": upn}],
            "additionalDetails": [{"key": k, "value": v} for k, v in (details or {}).items()]}


def test_audit_events_are_classified():
    reg = AccountChange.from_audit(audit("User registered security info", "User registered security info"), "Passkey")
    assert (reg.kind, reg.by_admin, reg.detail) == ("method_added", False, "User registered security info (Passkey)")
    reset = AccountChange.from_audit(audit("Admin deleted security info",
                                           "Admin required re-registration of MFA authentication methods.",
                                           initiator="admin1"))
    assert (reset.kind, reset.by_admin, reset.actor) == ("mfa_reset", True, "helpdesk@contoso.com")
    tap = AccountChange.from_audit(audit("Admin registered security info",
                                         "Admin registered temporary access pass method for user", initiator="admin1"))
    assert tap.kind == "tap_issued" and tap.points == 30
    sspr = AccountChange.from_audit(audit("Reset password (self-service)", "Successfully completed reset."))
    assert sspr.kind == "password_reset_self" and sspr.detail == "Reset password (self-service)"
    assert AccountChange.from_audit(audit("Reset user password", "", app={"displayName": "Microsoft password reset "
                                                                                         "service"})) is None
    assert AccountChange.from_audit(audit("User registered security info", "x", result="failure")) is None
    assert AccountChange.from_audit(audit("Get passkey creation options", "ok")) is None
    assert AccountChange.from_json(reg.to_json()) == reg


# ------------------------------------------------------- Microsoft back-end services
OLYMPUS = "bb893c22-978d-4cd4-a6f7-bb6cc0d6e6ce"


def test_olympus_on_another_network_path_is_not_session_theft(history):
    # a phone in one country, the Office policy read via 'Olympus' from the mobile breakout in another:
    # same session, same second, no device id on the Olympus side
    phone = make_signin(0, **USER, asn=3352, ip="192.0.2.152", country="ES", city="Valencia", session_id="S9",
                        device_id="iph", device_name="iPhone", os="Ios", interactive=False)
    olympus = make_signin(0, **USER, asn=39944, ip="192.0.2.186", country="SG", city="Singapore", session_id="S9",
                          app="Olympus", app_id=OLYMPUS, os="Ios", browser="Rich Client 4.83.1.0", interactive=False)
    assert olympus.ms_backend and not phone.ms_backend
    history.add([phone, olympus])
    rc = RuleContext.build([phone, olympus], history, {}, T0 + timedelta(minutes=5))
    assert rules.session_theft(rc) == []


def test_generic_microsoft_backend_signature():
    ms = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    backend = make_signin(0, interactive=False, user_agent="", app_owner_tenant=ms, client_credential="clientAssertion")
    assert backend.ms_backend
    assert not make_signin(0, interactive=False, user_agent="", app_owner_tenant=ms, client_credential="none").ms_backend
    assert not make_signin(0, interactive=False, user_agent="Mozilla/5.0", app_owner_tenant=ms,
                           client_credential="clientAssertion").ms_backend  # browser web app: could be a replay
    assert not make_signin(0, interactive=False, user_agent="", app_owner_tenant="other-tenant",
                           client_credential="clientSecret").ms_backend  # third-party server


def test_real_replay_from_attacker_device_still_detected(history):
    phone = make_signin(0, **USER, asn=3352, ip="192.0.2.152", country="ES", session_id="S10", device_id="iph",
                        os="Ios", interactive=False)
    attacker = make_signin(3, **USER, asn=14061, ip="164.90.1.1", country="NL", session_id="S10", os="Windows10",
                           browser="Chrome 141.0", app="One Outlook Web", interactive=False, user_agent="Mozilla/5.0")
    history.add([phone, attacker])
    rc = RuleContext.build([phone, attacker], history, {}, T0 + timedelta(minutes=10))
    assert len(rules.session_theft(rc)) == 1


# ------------------------------------------- Authenticator device + token binding
def test_mfa_approved_on_a_new_authenticator_device(history):
    baseline(history)
    history.add([make_signin(-60 * 24 * 3, **USER, **HOME, **LAPTOP, mfa_device_id="phone-1", mfa_device_os="Ios")])
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=1))
    usual = make_signin(0, **USER, **HOME, **FRESH, mfa_device_id="phone-1")
    stranger = make_signin(1, **USER, **DO, **FRESH, mfa_device_id="android-x", mfa_device_os="Android")
    texts = lambda s: " ".join(f.text for f in rc.assessor.assess(s, 0, "").factors)  # noqa: E731
    assert "usual Authenticator device" in texts(usual)
    assert "never used before (Android)" in texts(stranger)
    failed = make_signin(2, **USER, **DO, mfa_device_id="phone-1", error_code=500121)
    assert "Authenticator" not in texts(failed)  # a push to the real phone that was NOT approved proves nothing


def test_device_bound_session_is_no_replay(history):
    baseline(history)
    phone = make_signin(0, **USER, asn=3352, ip="192.0.2.152", country="ES", session_id="S11", device_id="iph",
                        os="Ios", interactive=False)
    other = make_signin(3, **USER, asn=14061, ip="164.90.1.1", country="NL", session_id="S11", os="Windows10",
                        browser="Chrome 141.0", interactive=False, user_agent="Mozilla/5.0", token_protection="bound")
    history.add([phone, other])
    f = rules.session_theft(RuleContext.build([phone, other], history, {}, T0 + timedelta(minutes=10)))[0]
    assert any(p == -25 and "device-bound" in r for p, r in f.factors)


def test_graph_fields_for_authenticator_device_and_number_match():
    from radar.plugins.signin_threats.models import SignIn
    s = SignIn.from_graph({
        "id": "x", "createdDateTime": "2026-11-10T08:00:00Z", "status": {"errorCode": 0},
        "authenticationAppDeviceDetails": {"deviceId": "d700c66e", "operatingSystem": "Ios", "clientApp": "Authenticator"},
        "authenticationAppPolicyEvaluationDetails": [{"policyName": "Number Match", "status": "numberMatchDeny"},
                                                     {"policyName": "App Context", "status": "appContextShown"}]})
    assert (s.mfa_device_id, s.mfa_device_os, s.number_match) == ("d700c66e", "Ios", "numberMatchDeny")
