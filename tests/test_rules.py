from datetime import timedelta

from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

SETTINGS = {
    "password_spray": {"window_minutes": 60, "min_distinct_users": 5},
    "brute_force": {"window_minutes": 60, "min_failures": 10},
    "mfa_fatigue": {"window_minutes": 60, "min_denials": 3},
    "impossible_travel": {"min_distance_km": 500, "max_speed_kmh": 900, "lookback_hours": 24},
    "new_country": {"min_baseline_signins": 5},
}


def ctx(history, signins, settings=None, new=None):
    history.add(signins)
    return RuleContext.build(new if new is not None else signins, history, settings or SETTINGS, T0 + timedelta(hours=2))


def test_password_spray_detected(history):
    rows = [make_signin(i, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip="203.0.113.9", error_code=50126)
            for i in range(6)]
    out = rules.password_spray(ctx(history, rows))
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH and "203.0.113.9" in out[0].title
    assert out[0].fields["Targeted accounts"] == "6"


def test_password_spray_below_threshold_and_spread_out(history):
    rows = [make_signin(i * 30, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip="203.0.113.9", error_code=50126)
            for i in range(6)]  # 6 users but only 3 within any 60 min window
    assert rules.password_spray(ctx(history, rows)) == []


def test_password_spray_ignores_busy_corporate_ip(history):
    fails = [make_signin(i, user_id=f"u{i}", ip="198.51.100.1", error_code=50126) for i in range(6)]
    ok = [make_signin(i, user_id=f"u{i}", ip="198.51.100.1") for i in range(20)]
    assert rules.password_spray(ctx(history, fails + ok)) == []


def test_ignore_ips_cidr(history):
    rows = [make_signin(i, user_id=f"u{i}", ip="203.0.113.9", error_code=50126) for i in range(6)]
    settings = dict(SETTINGS, ignore_ips=["203.0.113.0/24"])
    assert rules.password_spray(ctx(history, rows, settings)) == []


def test_brute_force_and_success_escalation(history):
    fails = [make_signin(i, ip="203.0.113.50", error_code=50126) for i in range(10)]
    success = make_signin(15, ip="203.0.113.50")
    out = rules.brute_force(ctx(history, fails + [success]))
    by_key = {f.key.split("|")[0]: f for f in out}
    assert by_key["brute"].severity == Severity.MEDIUM
    assert by_key["brute-success"].severity == Severity.HIGH


def test_brute_force_success_from_other_ip_is_not_escalated(history):
    fails = [make_signin(i, ip="203.0.113.50", error_code=50126) for i in range(10)]
    success = make_signin(15, ip="198.51.100.10")
    keys = [f.key.split("|")[0] for f in rules.brute_force(ctx(history, fails + [success]))]
    assert keys == ["brute"]


def test_mfa_fatigue_and_fraud(history):
    denials = [make_signin(i, error_code=500121, additional_details="MFA denied; user declined the authentication")
               for i in range(3)]
    fraud = make_signin(5, user_id="u9", upn="bob@contoso.com", error_code=500121,
                        additional_details="MFA denied; Phone App Reported Fraud")
    out = rules.mfa_fatigue(ctx(history, denials + [fraud]))
    titles = sorted(f.title for f in out)
    assert any("fraud reported by bob" in t for t in titles)
    assert any("Repeated MFA denials for alice" in t for t in titles)


def test_impossible_travel(history):
    toronto = make_signin(0, ip="198.51.100.10", lat=43.65, lon=-79.38, country="CA", device_id="d1")
    singapore = make_signin(30, ip="203.0.113.7", lat=1.35, lon=103.82, country="SG", city="Singapore", device_id="d2")
    history.add([toronto])
    out = rules.impossible_travel(ctx(history, [singapore]))
    assert len(out) == 1 and "Impossible travel" in out[0].title
    assert out[0].severity == Severity.MEDIUM


def test_impossible_travel_same_device_ignored(history):
    toronto = make_signin(0, ip="198.51.100.10", lat=43.65, lon=-79.38, device_id="d1")
    singapore = make_signin(30, ip="203.0.113.7", lat=1.35, lon=103.82, country="SG", device_id="d1")
    history.add([toronto])
    assert rules.impossible_travel(ctx(history, [singapore])) == []


def test_impossible_travel_plausible_speed(history):
    toronto = make_signin(0, ip="198.51.100.10", lat=43.65, lon=-79.38)
    new_york = make_signin(300, ip="203.0.113.7", lat=40.71, lon=-74.01, country="US")  # 550 km in 5 h
    history.add([toronto])
    assert rules.impossible_travel(ctx(history, [new_york])) == []


def test_impossible_travel_skips_trusted_coarse_and_same_country(history):
    toronto = make_signin(0, ip="198.51.100.10", lat=43.65, lon=-79.38)
    history.add([toronto])
    trusted = make_signin(30, ip="203.0.113.7", lat=1.35, lon=103.82, country="SG", trusted_network=True)
    coarse = make_signin(31, ip="203.0.113.8", lat=1.35, lon=103.82, country="SG", city="")
    by_ip = make_signin(32, ip="192.0.2.44", lat=1.35, lon=103.82, country="SG")
    assert rules.impossible_travel(ctx(history, [trusted])) == []
    assert rules.impossible_travel(ctx(history, [coarse])) == []
    assert rules.impossible_travel(ctx(history, [by_ip], dict(SETTINGS, trusted_ips=["192.0.2.0/24"]))) == []


def test_impossible_travel_same_country_ignored(history):
    history.add([make_signin(0, ip="198.51.100.10", lat=43.65, lon=-79.38)])
    ottawa = make_signin(5, ip="192.0.2.99", lat=45.42, lon=-75.7, country="CA", city="Ottawa")
    settings = dict(SETTINGS, impossible_travel={"min_distance_km": 100})
    assert rules.impossible_travel(ctx(history, [ottawa], settings)) == []
    settings = dict(SETTINGS, impossible_travel={"min_distance_km": 100, "ignore_same_country": False})
    assert len(rules.impossible_travel(RuleContext.build([ottawa], history, settings, T0))) == 1


def test_new_country_needs_baseline(history):
    baseline = [make_signin(-1000 - i) for i in range(5)]
    history.add(baseline)
    brazil = make_signin(10, country="BR", city="Sao Paulo", ip="203.0.113.77")
    out = rules.new_country(ctx(history, [brazil]))
    assert len(out) == 1 and "(BR)" in out[0].title
    assert "unknown device" in out[0].title and out[0].severity >= Severity.LOW

    # new user without baseline: no finding
    newbie = make_signin(10, user_id="u2", country="BR")
    assert rules.new_country(ctx(history, [newbie])) == []


def test_new_country_allow_list(history):
    s = make_signin(0, country="RU")
    settings = dict(SETTINGS, new_country={"allowed_countries": ["CA", "DE"]})
    out = rules.new_country(ctx(history, [s], settings))
    assert len(out) == 1 and out[0].severity == Severity.MEDIUM


def test_new_country_ignores_non_interactive_by_default(history):
    history.add([make_signin(-1000 - i) for i in range(5)])
    s = make_signin(10, country="BR", interactive=False)
    assert rules.new_country(ctx(history, [s])) == []


def test_legacy_auth(history):
    s = make_signin(0, client_app="IMAP4")
    failed = make_signin(1, client_app="IMAP4", error_code=50126)
    modern = make_signin(2, client_app="Mobile Apps and Desktop clients")
    unknown = make_signin(3, user_id="u2", client_app="Unknown")
    out = rules.legacy_auth(ctx(history, [s, failed, modern, unknown]))
    assert len(out) == 1 and "IMAP4" in out[0].title
    allowed = dict(SETTINGS, legacy_auth={"allowed_users": ["ALICE@contoso.com"]})
    assert rules.legacy_auth(ctx(history, [make_signin(4, client_app="Authenticated SMTP")], allowed)) == []


PINNED = dict(SETTINGS, pinned_accounts={"accounts": {"Scanner@contoso.com": ["198.51.100.10"]}})


def test_pinned_account_from_pinned_ip_is_quiet_including_legacy(history):
    smtp = make_signin(0, upn="scanner@contoso.com", user_id="sc", client_app="Authenticated SMTP", ip="198.51.100.10")
    rc = ctx(history, [smtp], PINNED)
    assert rules.pinned_accounts(rc) == []
    assert rules.legacy_auth(rc) == []


def test_pinned_account_from_other_ip_alarms_once_without_duplicate_legacy_alert(history):
    smtp = make_signin(0, upn="scanner@contoso.com", user_id="sc", client_app="Authenticated SMTP",
                       ip="198.51.100.177", city="London", country="GB")
    browser = make_signin(5, upn="scanner@contoso.com", user_id="sc", client_app="Browser", ip="198.51.100.177")
    failed = make_signin(6, upn="scanner@contoso.com", user_id="sc", ip="203.0.113.1", error_code=50126)
    rc = ctx(history, [smtp, browser, failed], PINNED)
    out = rules.pinned_accounts(rc)
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    assert "198.51.100.177" in out[0].summary and "198.51.100.10" in out[0].summary
    assert len(out[0].evidence) == 2
    assert rules.legacy_auth(rc) == []  # reported by pinned_accounts instead


def test_pinned_legacy_falls_back_to_legacy_alert_when_pin_rule_disabled(history):
    smtp = make_signin(0, upn="scanner@contoso.com", user_id="sc", client_app="Authenticated SMTP", ip="198.51.100.177")
    history.add([smtp])
    rc = RuleContext.build([smtp], history, PINNED, T0, enabled_rules={"legacy_auth"})
    assert len(rules.legacy_auth(rc)) == 1


def test_device_code(history):
    s = make_signin(0, auth_protocol="deviceCode", transfer_method="deviceCodeFlow")
    out = rules.device_code(ctx(history, [s]))
    assert len(out) == 1 and out[0].severity == Severity.MEDIUM
    allowed = dict(SETTINGS, device_code={"allowed_users": ["alice@*"]})
    assert rules.device_code(ctx(history, [make_signin(1, auth_protocol="deviceCode")], allowed)) == []


def test_device_code_session_refresh_is_not_flagged(history):
    refresh = make_signin(0, upn="meetingroom-a@contoso.com", interactive=False, auth_protocol="none",
                          transfer_method="deviceCodeFlow")
    assert rules.device_code(ctx(history, [refresh])) == []


def test_ignore_users_wildcards(history):
    rows = [make_signin(i, user_id=f"u{i}", upn=f"meetingroom-{i}@contoso.com", auth_protocol="deviceCode")
            for i in range(3)]
    assert rules.device_code(ctx(history, rows, dict(SETTINGS, ignore_users=["meetingroom-*@contoso.com"]))) == []


def test_risky_signin_grouped_per_user_day(history):
    a = make_signin(0, risk_during="high", risk_state="atRisk", risk_events=["anonymizedIPAddress"])
    b = make_signin(5, risk_during="medium", risk_state="atRisk")
    c = make_signin(6, user_id="u2", risk_during="low", risk_state="atRisk")
    d = make_signin(7, user_id="u3", risk_during="high", risk_state="dismissed")
    out = rules.risky_signin(ctx(history, [a, b, c, d]))
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH and "anonymizedIPAddress" in out[0].summary
    assert len(out[0].evidence) == 2


def test_sliding_window_distinct():
    rows = [make_signin(i * 10, user_id=f"u{i % 3}") for i in range(10)]
    n, window_rows = rules._max_in_window(rows, timedelta(minutes=60), key=lambda s: s.user_id)
    assert n == 3 and len(window_rows) == 7


def test_background_activity_from_a_new_country_is_a_low_alert(history):
    """new_country only sees sign-ins by hand. A device active from a new country in the background only (a phone
    travelling - or a token in use elsewhere) gets its own alert: at least Low, once per account and country."""
    history.add([make_signin(-1000 - i) for i in range(5)])
    phone = dict(interactive=False, country="LK", city="", ip="203.0.113.80", asn=18001, device_id="ph1", device_name="iPhone 16",
                 os="Ios", trust_type="Azure AD registered", app="Microsoft Teams")
    rows = [make_signin(10 + i, **phone) for i in range(3)]
    out = rules.new_country_background(ctx(history, rows))
    assert len(out) == 1
    f = out[0]
    assert f.title.startswith("Background activity from new country (LK): ") and f.severity >= Severity.LOW
    assert f.key == "country-bg|u1|LK" and f.fields["Device"] == "iPhone 16" and f.fields["Usual countries"] == "CA"
    assert "3 background sign-in(s)" in f.summary and "without a sign-in by hand" in f.summary
    assert rules.new_country(ctx(history, rows)) == []                      # not the by-hand rule's business
    # nothing for: the usual country, an account without history, a sign-in by hand from there (new_country's alert)
    assert rules.new_country_background(ctx(history, [make_signin(20, interactive=False, device_id="ph1")])) == []
    assert rules.new_country_background(ctx(history, [make_signin(20, user_id="u2", **phone)])) == []
    hand = make_signin(30, country="LK", city="Colombo", ip="203.0.113.81")
    assert rules.new_country_background(ctx(history, [hand, make_signin(31, **phone)])) == []
    assert any(r.meta.id == "new_country_background" for r in rules.RULES)
