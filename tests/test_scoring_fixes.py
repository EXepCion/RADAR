"""Regression tests for the issues found in the live dry-run."""
from datetime import timedelta

from radar.plugins.signin_threats import netintel, rules
from radar.plugins.signin_threats.asnames import AsnNameResolver
from radar.plugins.signin_threats.rules import RuleContext
from radar.plugins.signin_threats.scoring import Assessor

from conftest import T0, make_signin
from test_scoring import HOME, LAPTOP, baseline, rc_for


def scanner_smtp(**kw):
    return make_signin(0, upn="scanner@contoso.com", user_id="sc", client_app="Authenticated SMTP",
                       auth_protocol="ropc", user_agent="BAV2ROPC", ip="198.51.100.177", **kw)


def test_legacy_smtp_is_not_reported_as_tool_or_ropc(history):
    rc = rc_for(history, [scanner_smtp()])
    assert rules.attack_tooling(rc) == []
    assert rules.device_code(rc) == []
    assert len(rules.legacy_auth(rc)) == 1  # reported once, by the rule that owns it


def test_ropc_from_modern_client_still_reported(history):
    s = make_signin(0, client_app="Mobile Apps and Desktop clients", auth_protocol="ropc")
    out = rules.device_code(rc_for(history, [s]))
    assert len(out) == 1 and out[0].title.startswith("ROPC")


def test_anonymous_ip_not_double_counted_with_vpn_network(history):
    s = make_signin(0, asn=9009, risk_events=["anonymizedIPAddress"])
    a = Assessor(rc_for(history, [s])).assess(s, 50, "base")
    risk = next(f for f in a.factors if f.text.startswith("Entra ID Protection detections"))
    assert risk.points == 0 and "already counted" in risk.text
    assert any(f.points == 20 and "M247" in f.text for f in a.factors)


def test_session_plausible_travel_is_low_and_judges_device_less_side(history):
    # phone with device id in SG, 5 h later the same session without device id in HK: a trip, not theft
    sg = make_signin(0, session_id="S", country="SG", city="Singapore", ip="192.0.2.138", lat=1.35, lon=103.8,
                     device_id="phone", device_name="iPhone 16 Pro")
    history.add([make_signin(-3000 - i, device_id="phone", country="SG", city="Singapore") for i in range(3)])
    history.add([sg])
    hk = make_signin(300, session_id="S", country="HK", city="Central", ip="192.0.2.103", lat=22.28, lon=114.16)
    out = rules.session_theft(rc_for(history, [hk]))
    assert len(out) == 1
    assert out[0].fields["Judged side"].startswith("Central")
    assert any("plausible" in reason for _, reason in out[0].factors)
    assert out[0].severity <= 1  # Info/Low


def test_session_simultaneous_use_far_apart_is_high(history):
    baseline(history)
    laptop = make_signin(0, session_id="S", **{**HOME, **LAPTOP})
    history.add([laptop])
    replay = make_signin(3, session_id="S", country="US", city="Ashburn", ip="3.3.3.3", asn=14061,
                         lat=39.0, lon=-77.5)
    out = rules.session_theft(rc_for(history, [replay]))
    assert len(out) == 1 and out[0].severity == 3
    assert any("simultaneous use" in reason for _, reason in out[0].factors)


def test_session_same_phone_via_vpn_interleaved_is_low(history):
    # a phone app with device id; a second later an app on the same phone without device id through a VPN elsewhere
    phone = make_signin(0, session_id="S", country="AE", city="Dubai", ip="2001:8f8::1", lat=25.2, lon=55.3,
                        device_id="iphone", device_name="iPhone 14", os="Ios 27.2.0", asn=8966)
    history.add([phone])
    vpn = make_signin(0.02, session_id="S", country="IT", city="Milano", ip="198.51.100.198", lat=45.46, lon=9.19,
                      os="Ios", asn=212238)
    out = rules.session_theft(rc_for(history, [vpn]))
    assert len(out) == 1 and out[0].severity <= 1
    texts = " ".join(r for _, r in out[0].factors)
    assert "Same platform on both sides (iOS)" in texts and "interleaved" in texts and "simultaneous" not in texts


def test_session_replay_from_other_platform_is_high(history):
    phone = make_signin(0, session_id="S", device_id="iphone", os="Ios 27.2.0", **HOME)
    history.add([phone])
    replay = make_signin(4, session_id="S", country="US", city="Ashburn", ip="3.3.3.3", asn=14061, lat=39.0,
                         lon=-77.5, os="Windows10")
    out = rules.session_theft(rc_for(history, [replay]))
    assert out[0].severity == 3
    texts = " ".join(r for _, r in out[0].factors)
    assert "Different platforms (Windows vs iOS)" in texts and "simultaneous use" in texts


def test_os_family():
    assert rules.os_family("Ios 27.2.0") == "iOS" and rules.os_family("Windows10") == "Windows"
    assert rules.os_family("MacOs") == "macOS" and rules.os_family("") == ""


def test_trusted_ips_with_office_names(history):
    offices = {"198.51.100.177": "UK office", "198.51.100.0/24": "Lab"}
    s = make_signin(0, ip="198.51.100.177", country="GB", city="London")
    rc = rc_for(history, [s], {"trusted_ips": offices})
    assert rc.trusted(s) and rc.trusted_label(s) == "UK office"
    a = Assessor(rc).assess(s, 35, "base")
    assert any(f.text == "Corporate network: UK office" for f in a.factors)
    assert rules.IpMatcher(offices).label("198.51.100.7") == "Lab"
    assert rules.IpMatcher(["10.0.0.0/8"]).label("10.1.2.3") == ""  # plain list still works
    assert rules.IpMatcher(offices).label("8.8.8.8") is None


def test_pin_to_any_office_ip(history):
    settings = {"trusted_ips": {"198.51.100.177": "UK office", "203.0.113.166": "CA office"},
                "pinned_accounts": {"accounts": {"scanner@contoso.com": ["trusted_ips"]}}}
    at_uk = scanner_smtp()
    elsewhere = make_signin(5, upn="scanner@contoso.com", user_id="sc", client_app="Authenticated SMTP",
                            ip="203.0.113.50", country="NL", city="Amsterdam")
    rc = rc_for(history, [at_uk, elsewhere], settings)
    out = rules.pinned_accounts(rc)
    assert len(out) == 1 and "203.0.113.50" in out[0].summary
    assert "198.51.100.177 (UK office)" in out[0].fields["Allowed IPs"]
    assert rules.legacy_auth(rc) == []  # the office SMTP sign-in is expected, the other one is the pinned alarm


def test_name_based_network_classification(history):
    assert netintel.classify_asn_name("Liteserver The Infrastructure Group B.V.") == "hosting"
    assert netintel.classify_asn_name("EMERALD-ONION - Emerald Onion") == "vpn"
    assert netintel.classify_asn_name("ROGERS-COMMUNICATIONS Rogers Communications Canada Inc.") is None
    s = make_signin(0, asn=60404)
    history.add([s])
    rc = RuleContext.build([s], history, {}, T0, asn_resolver=lambda asn: "Liteserver The Infrastructure Group B.V.")
    net = Assessor(rc).network(s)
    assert net == ("Liteserver The Infrastructure Group B.V.", "hosting")


class FakeState(dict):
    def set(self, key, value):
        self[key] = value


class FakeResp:
    ok = True

    def __init__(self, holder):
        self.holder = holder

    def json(self):
        return {"data": {"holder": self.holder}}


def test_asn_resolver_caches_and_respects_budget(monkeypatch):
    state = FakeState()
    r = AsnNameResolver(state, budget=1)
    calls = []
    monkeypatch.setattr(r._session, "get", lambda url, params, timeout: calls.append(params) or FakeResp("X Hosting"))
    assert r(64500) == "X Hosting"
    assert r(64500) == "X Hosting"  # cached, no second request
    assert r(64501) is None  # budget exhausted
    assert len(calls) == 1
    r.save()
    assert state["asn_names"]["64500"]["n"] == "X Hosting"
    assert AsnNameResolver(state, enabled=False)(64500) == "X Hosting"  # served from persisted cache


def test_disabled_resolver_makes_no_requests(monkeypatch):
    r = AsnNameResolver(FakeState(), enabled=False)
    monkeypatch.setattr(r._session, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))
    assert r(64500) is None
