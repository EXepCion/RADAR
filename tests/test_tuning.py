"""Tunings from looking at real alert lists: what is one event is one alert, what is the person's own device on
their own network is logged only, what is risky stays risky inside the office."""
import sqlite3
from datetime import datetime, timedelta, timezone

from radar.plugin_api import Finding, Severity
from radar.plugins.signin_threats import netintel, rules
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
from radar.plugins.signin_threats.apps import AppSignIn, AppStore, app_findings
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

PHONE = dict(device_id="ph1", device_name="Phone of Alice", os="iOS", browser="Mobile Safari", asn=64500)


def test_background_activity_abroad_on_the_own_phone_and_network_is_only_logged(history):
    usual = [make_signin(-60 * 24 * d, **PHONE) for d in range(2, 9)]             # a week at home, roaming contract
    history.add(usual)
    roaming = [make_signin(m, interactive=False, country="JP", city="Tokyo", ip="203.0.113.40", **PHONE) for m in (0, 5)]
    history.add(roaming)
    f = rules.new_country_background(RuleContext.build(roaming, history, {}, T0 + timedelta(hours=1)))[0]
    assert f.severity == Severity.INFO and f.score < 25
    assert any("own device on a network they use anyway" in text for _p, text in f.factors)


def test_background_activity_abroad_on_an_unknown_device_stays_an_alert(history):
    history.add([make_signin(-60 * 24 * d, **PHONE) for d in range(2, 9)])
    foreign = [make_signin(m, interactive=False, country="JP", city="Tokyo", ip="203.0.113.40", asn=64999,
                           os="Windows10", browser="Edge 18") for m in (0, 5)]
    history.add(foreign)
    f = rules.new_country_background(RuleContext.build(foreign, history, {}, T0 + timedelta(hours=1)))[0]
    assert f.severity >= Severity.LOW and f.score >= 25


def test_networks_that_hide_where_someone_is_are_known_by_name():
    assert netintel.classify_asn_name("PV-HOSTED Proton AG") == "vpn"
    assert netintel.classify_asn_name("EXAMPLE-HOSTED Example Hosted Services") == "hosting"
    assert netintel.classify_asn_name("Example Telecom Broadband") is None


def test_password_only_flow_of_an_admin_without_mfa_stays_high_inside_the_office(history):
    def score(account):
        s = make_signin(0, user_id="u9", upn="svc-admin@contoso.com", auth_protocol="ropc", trusted_network=True,
                        client_app="Mobile Apps and Desktop clients")
        history.add([s])
        rc = RuleContext.build([s], history, {}, T0 + timedelta(hours=1), accounts=AccountDirectory({"u9": account}))
        return rules.device_code(rc)[0]

    plain = score(AccountInfo(user_id="u9", upn="svc-admin@contoso.com", roles=["Global Administrator"]))
    exposed = score(AccountInfo(user_id="u9", upn="svc-admin@contoso.com", roles=["Global Administrator"],
                                mfa_excluded=["MFA_Exempt group"]))
    assert exposed.severity == Severity.HIGH and exposed.score >= 80 > plain.score
    texts = [text for _p, text in exposed.factors]
    assert exposed.factors[0] == (65, "ROPC sign-in: the password alone, MFA cannot be asked for in this flow")
    assert sum("ROPC" in t or "Password only" in t for t in texts) == 1      # said once, counted once
    assert (-10, "Corporate network: trusted network - counts for little here: an admin account without MFA whose "
                 "password sits in a script") in [(p, t.replace(t.split(": ")[1].split(" - ")[0], "trusted network"))
                                                   for p, t in exposed.factors if t.startswith("Corporate network")]
    assert (-30, True) in [(p, t.startswith("Corporate network")) for p, t in plain.factors]


def _finding(key, rule, score, sign_in, location, **fields):
    return Finding(key=key, rule_id=rule, severity=Severity.MEDIUM, score=score, title=f"{rule}: anna@contoso.com",
                   fields={"User": "anna@contoso.com", "Risk score": f"{score}/100  (likely VPN / proxy)", **fields},
                   factors=[(score, "First sign-in from NL (usually DE, CH)" if rule == "new_country" else "rated high risk")],
                   evidence=[{"Sign-in ID": sign_in, "Location": location}])


def test_a_risky_sign_in_from_a_new_country_is_one_alert():
    risky = _finding("risky|u|d", "risky_signin", 60, "s1", "Amsterdam, NL")
    country = _finding("country|u|NL", "new_country", 50, "s1", "Amsterdam, NL", Country="NL")
    other = _finding("country|u|JP", "new_country", 50, "s2", "Tokyo, JP", Country="JP")   # another sign-in: stays
    out = rules.fold_same_signin([country, other, risky])
    assert [f.key for f in out] == ["country|u|JP", "risky|u|d"]
    assert risky.score == 70 and risky.severity == Severity.HIGH and risky.supersedes == ["country|u|NL"]
    assert risky.factors[-1] == (10, "First sign-in from NL (usually DE, CH) - the same sign-in")
    assert risky.fields["Risk score"] == "70/100  (likely VPN / proxy)" and "usually DE, CH" in risky.fields["New country"]
    assert rules.fold_same_signin([country]) == [country]                                    # nothing to fold into
    cloud = _finding("risky|u|d", "risky_signin", 60, "s1", "Amsterdam, NL")
    cloud.factors.append((10, "Cloud network: Example Cloud (AS64500)"))
    rules.fold_same_signin([_finding("country|u|NL", "new_country", 50, "s1", "Amsterdam, NL", Country="NL"), cloud])
    assert cloud.score == 60 and cloud.factors[-1][0] == 0 and "not counted" in cloud.factors[-1][1]   # named only


def test_a_rating_that_is_held_up_says_so_and_a_registering_device_is_not_blamed_for_having_no_identity(history):
    home = dict(asn=64500, ip="198.51.100.10")
    history.add([make_signin(-60 * 24 * d + m, device_id="pc1", device_name="PC of Alice", **home)
                 for d in range(1, 9) for m in (0, 30)])                            # a known device, a habitual network
    code = make_signin(0, auth_protocol="deviceCode", device_id="pc1", device_name="PC of Alice", trusted_network=True, **home)
    reg = make_signin(5, resource_id=netintel.DEVICE_REGISTRATION_RESOURCE, resource="Device Registration Service",
                      os="MacOs", **home)
    history.add([code, reg])
    rc = RuleContext.build([code, reg], history, {}, T0 + timedelta(hours=1))
    f = rules.device_code(rc)[0]
    assert f.score == 30 and sum(p for p, _t in f.factors) < 30                   # the reasons add up to less ...
    assert f.factors[-1][0] == 0 and f.factors[-1][1].startswith("Rated at least Low (30): with a phished code")   # ... and it says why
    r = rules.sensitive_app(rc)[0]
    assert not any("No device identity" in text for _p, text in r.factors)
    assert r.severity == Severity.INFO                                              # from home, a new device: logged only


def test_the_detection_behind_a_risk_rating_is_not_counted_twice(history):
    s = make_signin(0, risk_during="high", risk_state="atRisk", risk_events=["unfamiliarFeatures"])
    t = make_signin(1, user_id="u2", upn="ben@contoso.com", risk_during="high", risk_state="atRisk",
                    risk_events=["unfamiliarFeatures", "attackerInTheMiddle"])
    history.add([s, t])
    out = {f.fields["User"]: f for f in rules.risky_signin(RuleContext.build([s, t], history, {}, T0 + timedelta(hours=1)))}
    plain = next((p, text) for p, text in out["alice@contoso.com"].factors if text.startswith("Entra ID Protection detections"))
    aitm = next((p, text) for p, text in out["ben@contoso.com"].factors if text.startswith("Entra ID Protection detections"))
    assert plain == (0, "Entra ID Protection detections: unfamiliarFeatures (what the rating is made of: not counted again)")
    assert aitm[0] == 35                                                            # a specific detection still counts


def test_a_credential_that_keeps_failing_is_one_alert_until_it_stops_or_fails_differently():
    now = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)   # a Tuesday
    store = AppStore(sqlite3.connect(":memory:"))

    def week(start, code=7000215, n=60):
        rows = [AppSignIn(id=f"{start:%j}-{code}-{i}", created=start + timedelta(minutes=i), app="Branch VPN", app_id="a",
                          sp_id="vpn", ip="192.0.2.181", country="", error_code=code, key_id="",
                          failure_reason="Invalid client secret provided.") for i in range(n)]
        return app_findings(store, rows, start + timedelta(hours=2))[0]

    first, second = week(now), week(now + timedelta(days=7))
    assert first.key == second.key and first.fields["Kind"].startswith("Operational")   # dismissed once, it stays so
    assert first.supersedes == ["appfail|vpn|2026-W45"]                                 # (the weekly alert of before)
    assert week(now + timedelta(days=14), code=7000222).key != first.key                # it fails differently now
    assert week(now + timedelta(days=35)).key != first.key                              # it stopped, and began again
