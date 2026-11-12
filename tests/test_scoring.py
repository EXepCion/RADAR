"""Risk scoring / classification and the new detections."""
from datetime import timedelta

from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.models import SignIn
from radar.plugins.signin_threats.rules import RuleContext
from radar.plugins.signin_threats.scoring import (LABEL_TRAVEL, LABEL_UNKNOWN_DEVICE, LABEL_VPN, Assessor,
                                                   severity_for)

from conftest import T0, make_signin

LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD joined", compliant=True,
              incoming_token="primaryRefreshToken", auth_methods=["Windows Hello for Business"],
              auth_requirement="multiFactorAuthentication")
HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812)


def baseline(history, user="u1", n=6, **kw):
    history.add([make_signin(-2000 - i, user_id=user, **{**HOME, **LAPTOP, **kw}) for i in range(n)])


def rc_for(history, new, settings=None, now=None):
    history.add(new)
    return RuleContext.build(new, history, settings or {}, now or T0 + timedelta(hours=2))


def test_severity_thresholds():
    assert severity_for(10) == Severity.INFO
    assert severity_for(30) == Severity.LOW
    assert severity_for(50) == Severity.MEDIUM
    assert severity_for(80) == Severity.HIGH


def test_travel_with_known_managed_device_is_quiet(history):
    baseline(history)
    trip = make_signin(10, country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573, **LAPTOP)
    out = rules.new_country(rc_for(history, [trip]))
    assert len(out) == 1
    assert LABEL_TRAVEL in out[0].title
    assert out[0].severity == Severity.INFO  # logged, no pop-up
    assert any("Known device" in reason for _, reason in out[0].factors)


def test_vpn_switch_on_known_device_is_quiet(history):
    baseline(history)
    at_home = make_signin(5, **HOME, **LAPTOP)
    via_vpn = make_signin(8, country="NL", city="Amsterdam", ip="185.65.134.1", asn=9009, **LAPTOP)
    out = rules.new_country(rc_for(history, [at_home, via_vpn]))
    assert len(out) == 1 and LABEL_VPN in out[0].title
    texts = " ".join(r for _, r in out[0].factors)
    assert "VPN/proxy switch" in texts and "M247" in texts
    assert out[0].severity == Severity.INFO


def test_unknown_device_on_hosting_network_is_high(history):
    baseline(history)
    attacker = make_signin(10, country="NL", city="Amsterdam", ip="167.99.1.1", asn=14061,
                           auth_requirement="singleFactorAuthentication", auth_methods=["Password"], password_ok=True)
    out = rules.new_country(rc_for(history, [attacker]))
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    assert LABEL_VPN in out[0].title  # network is hosting/VPN ...
    texts = " ".join(r for _, r in out[0].factors)
    assert "DigitalOcean" in texts and "No device identity" in texts and "Password only" in texts


def test_unknown_device_residential_is_medium(history):
    baseline(history)
    s = make_signin(10, country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573)
    out = rules.new_country(rc_for(history, [s]))
    assert LABEL_UNKNOWN_DEVICE in out[0].title and out[0].severity == Severity.MEDIUM


def test_trusted_asn_removes_vpn_points(history):
    baseline(history)
    s = make_signin(10, country="NL", city="Amsterdam", ip="185.65.134.1", asn=9009)
    rc = rc_for(history, [s], {"scoring": {"trusted_asns": [9009]}})
    a = Assessor(rc).assess(s, 35, "base")
    assert not any("M247" in f.text for f in a.factors)
    assert any("Corporate network" in f.text for f in a.factors)


def test_risky_signin_keeps_floor_but_ranks_by_context(history):
    baseline(history)
    managed = make_signin(10, risk_during="medium", risk_state="atRisk", **{**HOME, **LAPTOP})
    out = rules.risky_signin(rc_for(history, [managed]))
    assert out[0].severity == Severity.LOW and out[0].score == 30  # floor: Entra flagged it, keep it visible


def test_session_theft_other_country_other_device(history):
    victim = make_signin(0, session_id="S1", **{**HOME, **LAPTOP})
    history.add([victim])
    replay = make_signin(20, session_id="S1", country="US", city="Ashburn", ip="3.3.3.3", asn=16509)
    out = rules.session_theft(rc_for(history, [replay]))
    assert len(out) == 1 and out[0].severity >= Severity.MEDIUM and "token theft" in out[0].title
    # same device in two countries = VPN on the laptop -> not reported
    vpn = make_signin(25, session_id="S2", country="US", city="Ashburn", ip="3.3.3.4", **LAPTOP)
    history.add([make_signin(1, session_id="S2", **{**HOME, **LAPTOP})])
    assert rules.session_theft(rc_for(history, [vpn])) == []


def test_password_not_completed_from_unfamiliar_place(history):
    baseline(history)
    stopped = make_signin(0, country="RU", city="Moscow", ip="203.0.113.66", asn=12389, error_code=50074,
                          failure_reason="Strong Authentication is required.", auth_methods=["Password"], password_ok=True)
    out = rules.password_not_completed(rc_for(history, [stopped], now=T0 + timedelta(minutes=40)))
    assert len(out) == 1 and out[0].severity >= Severity.MEDIUM


def test_password_not_completed_ignored_when_user_finishes_mfa(history):
    baseline(history)
    stopped = make_signin(0, country="RU", city="Moscow", ip="203.0.113.66", error_code=50074, password_ok=True,
                          auth_methods=["Password"])
    done = make_signin(1, country="RU", city="Moscow", ip="203.0.113.66")
    assert rules.password_not_completed(rc_for(history, [stopped, done], now=T0 + timedelta(minutes=40))) == []


def test_password_not_completed_ignored_at_home(history):
    baseline(history)
    stopped = make_signin(0, error_code=50074, password_ok=True, auth_methods=["Password"], **HOME)
    assert rules.password_not_completed(rc_for(history, [stopped], now=T0 + timedelta(minutes=40))) == []


def test_attack_tooling_failures_and_success(history):
    fails = [make_signin(i, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip="45.9.1.1", error_code=50126,
                         user_agent="Go-http-client/1.1") for i in range(4)]
    ok = make_signin(5, user_agent="python-requests/2.31.0")
    noninteractive = make_signin(6, user_id="u7", user_agent="node-fetch/1.0", interactive=False)
    out = rules.attack_tooling(rc_for(history, fails + [ok, noninteractive]))
    keys = sorted(f.key.split("|")[0] for f in out)
    assert keys == ["tool-fail", "tool-ok"]


def test_new_shared_ip(history):
    rows = [make_signin(i, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip="167.99.9.9", asn=14061,
                        country="NL", city="Amsterdam") for i in range(3)]
    out = rules.new_shared_ip(rc_for(history, rows))
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    # an IP known for weeks is not "new"
    history.add([make_signin(-60 * 24 * 5, user_id="u9", ip="198.51.100.200")])
    old = [make_signin(i, user_id=f"v{i}", ip="198.51.100.200") for i in range(3)]
    assert rules.new_shared_ip(rc_for(history, old)) == []


def test_sensitive_app_first_use(history):
    s = make_signin(0, app_id="1b730954-1685-4b74-9bfd-dac224a7b894", app="Azure Active Directory PowerShell",
                    asn=14061, ip="167.99.1.2")
    out = rules.sensitive_app(rc_for(history, [s]))
    assert len(out) == 1 and out[0].severity >= Severity.MEDIUM
    again = make_signin(30, app_id="1b730954-1685-4b74-9bfd-dac224a7b894", asn=14061, ip="167.99.1.2")
    assert rules.sensitive_app(rc_for(history, [again])) == []  # not the first use any more


def test_evidence_rows_carry_hidden_lookup_fields(history):
    s = make_signin(0, auth_protocol="deviceCode", event_type="interactiveUser")
    row = rules.device_code(rc_for(history, [s]))[0].evidence[0]
    assert row["_created"] == s.created.isoformat() and row["_event"] == "interactiveUser"
    assert row["Sign-in ID"] == s.id


def test_model_parses_new_signals():
    s = SignIn.from_graph({
        "id": "x", "createdDateTime": "2026-11-09T10:11:12Z", "autonomousSystemNumber": 14061,
        "userAgent": "python-requests/2.31", "sessionId": "S", "incomingTokenType": "primaryRefreshToken",
        "authenticationRequirement": "multiFactorAuthentication",
        "authenticationDetails": [{"authenticationMethod": "Password", "succeeded": True},
                                  {"authenticationMethod": "Mobile app notification", "succeeded": False}],
        "networkLocationDetails": [{"networkType": "namedNetwork", "networkNames": ["Blocked countries"]}],
        "deviceDetail": {"deviceId": "d", "trustType": "Hybrid Azure AD joined"},
        "status": {"errorCode": 50074},
    })
    assert s.asn == 14061 and s.password_ok and s.auth_methods == ["Password"] and s.prt and s.mfa
    assert s.untrusted_networks == ["Blocked countries"] and not s.trusted_network and s.corp_device
