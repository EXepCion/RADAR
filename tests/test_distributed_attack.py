"""An IP-rotating password attack in which every attempt is blocked, and the user's own activity next to it."""
from datetime import timedelta

from radar.plugin_api import Severity
from radar.plugins.signin_threats import netintel, rules
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

HOME = dict(country="SG", city="Singapore", ip="203.116.1.1", asn=55430, device_id="mac", device_name="SG-MB-00103",
            trust_type="Workplace", compliant=True)
TOOL_UAS = ["Mozilla/5.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Go-http-client/1.1", ""]


def campaign(user="u1", upn="priya@contoso.com", n=20, start_minutes=-60 * 60, **kw):
    """One failed attempt per IP from rotating residential proxies, like the real attack."""
    return [make_signin(start_minutes + i * 150, user_id=user, upn=upn, ip=f"45.{i}.{i}.{i}", asn=20000 + i,
                        country=["US", "GB", "LU", "FR"][i % 4], city="X", error_code=50053,
                        failure_reason="The account is locked", app="Azure Active Directory PowerShell",
                        user_agent=TOOL_UAS[i % 4], risk_during="medium" if i % 5 == 0 else "", **kw)
            for i in range(n)]


def setup(history, extra=()):
    home = [make_signin(-60 * 24 * 5 - i, user_id="u1", upn="priya@contoso.com", **HOME) for i in range(5)]
    history.add(home)
    rows = campaign() + list(extra)
    history.add(rows)
    return RuleContext.build(rows, history, {}, T0 + timedelta(hours=2))


def test_blocked_rotating_attack_is_medium_with_explanation(history):
    out = rules.distributed_attack(setup(history))
    assert len(out) == 1
    f = out[0]
    assert f.severity == Severity.MEDIUM and f.score == 50
    assert "from rotating IPs" in f.title
    texts = " ".join(r for _, r in f.factors)
    assert "20 failed passwords from 20 IPs" in texts
    assert "Entra ID Protection flagged 4" in texts
    assert "Attack-tool fingerprints" in texts and "Every attempt failed at the password" in texts
    assert f.key.startswith("dpa|u1|")


def test_risky_failed_attempts_are_not_risky_signins(history):
    rc = setup(history)
    assert rules.risky_signin(rc) == []


def test_attempt_past_the_password_escalates_to_high(history):
    past = make_signin(-30, user_id="u1", upn="priya@contoso.com", ip="45.99.99.99", asn=29999, country="US",
                       city="X", error_code=50074, failure_reason="Strong Authentication is required.")
    out = rules.distributed_attack(setup(history, [past]))
    assert out[0].severity == Severity.HIGH and "got past the password" in out[0].title


def test_users_own_mfa_prompt_during_attack_is_not_the_attacker(history):
    # an MFA prompt on the user's own computer: Entra logs the 50074 first without UPN/ASN/location, from
    # another IPv6 address of a /64 the account already uses
    history.add([make_signin(-60 * 24 * 6, user_id="u1", upn="priya@contoso.com", ip="2001:db8:2004:767:aaaa::1",
                             asn=55430, country="SG", device_id="mac")])
    prompt = make_signin(-20, user_id="u1", upn="", ip="2001:db8:2004:767:1de9:e8ce:d60d:8169", asn=None, country="",
                         city="", lat=None, lon=None, error_code=50074, app="Microsoft Office",
                         failure_reason="Strong Authentication is required.")
    out = rules.distributed_attack(setup(history, [prompt]))
    f = out[0]
    assert f.severity == Severity.MEDIUM and "rotating IPs" in f.title and "got past" not in f.summary.lower()
    assert "Microsoft Office from 2001:db8:2004:767:1de9:e8ce:d60d:8169" in f.fields["Not counted"]
    assert all(r["Sign-in ID"] != prompt.id for r in f.evidence)


def test_prompt_followed_by_completed_sign_in_from_same_new_ip_is_the_user(history):
    hotel = dict(user_id="u1", upn="priya@contoso.com", ip="81.2.3.4", city="X")
    prompt = make_signin(-30, error_code=50074, asn=None, country="", **hotel)  # preliminary record, no network yet
    done = make_signin(-28, device_id="mac", asn=12345, country="SG", **hotel)  # MFA completed right after, the user's device
    out = rules.distributed_attack(setup(history, [prompt, done]))
    assert out[0].severity == Severity.MEDIUM and "Not counted" in out[0].fields


def test_success_from_unfamiliar_network_escalates_to_high(history):
    breach = make_signin(-20, user_id="u1", upn="priya@contoso.com", ip="45.98.98.98", asn=29998, country="US",
                         city="X")
    out = rules.distributed_attack(setup(history, [breach]))
    assert out[0].severity == Severity.HIGH and "possible break-in" in out[0].title


def test_own_devices_signing_in_during_attack_do_not_escalate(history):
    mine = make_signin(-10, user_id="u1", upn="priya@contoso.com", **HOME)
    out = rules.distributed_attack(setup(history, [mine]))
    assert out[0].severity == Severity.MEDIUM


def test_own_phone_on_new_mobile_network_does_not_escalate(history):
    # a registered phone signing in non-interactively over a mobile network it has not used before
    phone = make_signin(-15, user_id="u1", upn="priya@contoso.com", ip="111.65.1.1", asn=45143, country="SG",
                        city="Singapore", device_id="samsung", device_name="Galaxy S24", trust_type="Workplace",
                        interactive=False)
    out = rules.distributed_attack(setup(history, [phone]))
    assert out[0].severity == Severity.MEDIUM and "rotating IPs" in out[0].title


def test_profile_remembers_non_interactive_devices_and_networks(history):
    phone = make_signin(-60 * 24 * 3, user_id="u9", ip="111.65.1.1", asn=45143, device_id="samsung", interactive=False)
    history.add([phone])
    history.purge(T0 - timedelta(days=30), T0)  # non-interactive rows gone (3 h retention) ...
    assert history.query(user_id="u9") == []
    later = T0 + timedelta(hours=1)
    assert history.user_devices("u9", later) == {"samsung"}  # ... but the profile still knows them
    assert history.user_asns("u9", later) == {45143}
    assert history.asn_user_count(45143, later) == 1


def test_older_history_is_upgraded_in_place_with_backfilled_profile(tmp_path):
    from radar.plugins.signin_threats.history import SignInHistory

    path = tmp_path / "signins.db"
    h = SignInHistory(path)
    h.add([make_signin(0, user_id="u5", asn=3758, device_id="mac")])
    h._conn.executescript("DROP TABLE profile; UPDATE meta SET value='3' WHERE key='schema';")
    h._conn.commit()
    h.close()
    h = SignInHistory(path)  # what the installed v2 database will go through
    assert not h.was_reset and h.count() == 1
    later = T0 + timedelta(hours=1)
    assert h.user_devices("u5", later) == {"mac"} and h.user_asns("u5", later) == {3758}
    h.close()


def test_user_mistyping_at_home_is_not_an_attack(history):
    history.add([make_signin(-60 * 24 * 5 - i, user_id="u2", **HOME) for i in range(3)])
    typos = [make_signin(-i, user_id="u2", error_code=50126, **HOME) for i in range(12)]
    history.add(typos)
    assert rules.distributed_attack(RuleContext.build(typos, history, {}, T0 + timedelta(hours=2))) == []


def test_campaign_scope_lists_other_targets(history):
    other = campaign(user="u3", upn="omar@contoso.com", n=10)
    out = rules.distributed_attack(setup(history, other))
    by_user = {f.fields["Account"]: f for f in out}
    assert by_user["priya@contoso.com"].fields["Same campaign also targets"] == "omar@contoso.com"
    assert by_user["omar@contoso.com"].fields["Same campaign also targets"] == "priya@contoso.com"  # never itself


def test_preliminary_record_is_replaced_by_completed_one_but_not_new(history):
    prelim = make_signin(0, id="p1", upn="", user_name="", asn=None, country="", city="", lat=None, lon=None,
                         error_code=50074)
    assert history.add([prelim]) == [prelim]
    assert [s.id for s in history.incomplete(T0 - timedelta(hours=1))] == ["p1"]
    final = make_signin(-0.2, id="p1", upn="priya@contoso.com", user_name="Priya", asn=55430, country="SG",
                        error_code=50074, auth_requirement="multiFactorAuthentication")
    assert history.add([final]) == [] and history.enriched == 1
    stored = history.get("p1")
    assert (stored.upn, stored.asn, stored.country, stored.created) == ("priya@contoso.com", 55430, "SG", final.created)
    assert history.query(user_id="u1", codes=[50074])[0].asn == 55430  # indexed columns updated too
    assert history.incomplete(T0 - timedelta(hours=1)) == []
    assert history.add([prelim]) == [] and history.get("p1").asn == 55430  # never downgraded


def test_result_column_is_short():
    from radar.plugins.signin_threats.models import SignIn  # noqa: F401
    locked = make_signin(error_code=50053, failure_reason="The account is locked, you've tried to sign in too many times "
                         "with an incorrect user ID or password.", additional_details="This error can be returned for two "
                         "reasons - the sign in could have come from a malicious IP address, or ... " * 3)
    assert locked.result == ("Failure 50053: The account is locked, you've tried to sign in too many times with an "
                             "incorrect user ID or password.")
    denied = make_signin(error_code=500121, failure_reason="Authentication failed during strong authentication request.",
                         additional_details="MFA denied; user declined the authentication")
    assert denied.result.endswith("request. (MFA denied; user declined the authentication)")
    noisy = make_signin(error_code=50203, failure_reason="User has not registered the authenticator app.",
                        additional_details="MFA completed in Azure AD")
    assert noisy.result == "Failure 50203: User has not registered the authenticator app."


def test_tool_user_agents_from_the_campaign():
    rx = netintel.compile_user_agents(None)
    for ua in ("Mozilla/5.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "<RndUA>",
               "Python/3.11 aiohttp/3.13.5", "Go-http-client/1.1"):
        assert rx.search(ua), ua
    for ua in ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
               "Windows-AzureAD-Authentication-Provider/1.0", "MSAL 1.1.0 (iPhone; OS 27_2_0 like Mac OS X)"):
        assert not rx.search(ua), ua


# --------------------------------------------- preliminary results / MFA abort while travelling
def test_preliminary_result_is_replaced_by_final_one(history):
    prelim = make_signin(0, id="r1", user_id="u4", upn="dana@contoso.com", ip="192.0.2.171", asn=3352,
                         country="ES", error_code=50097, auth_methods=["Previously satisfied"])
    history.add([prelim])
    # the final record lists fewer passed steps than the preliminary one - it must still win
    final = make_signin(1 / 60, id="r1", user_id="u4", upn="dana@contoso.com", ip="192.0.2.171", asn=3352,
                        country="ES", error_code=50074)
    assert history.add([final]) == [] and history.enriched == 1
    assert history.get("r1").error_code == 50074
    assert history.query(user_id="u4", codes=[50074])  # indexed column updated too
    weaker = make_signin(0, id="r1", user_id="u4", upn="", asn=None, country="", error_code=50097)
    history.add([weaker])
    assert history.get("r1").error_code == 50074  # a less complete copy never overwrites


def test_mfa_abort_on_a_network_of_the_own_phone_is_not_password_known(history):
    home = dict(user_id="u4", upn="dana@contoso.com", ip="203.0.113.166", asn=577, country="CA", device_id="lap")
    history.add([make_signin(-60 * 24 * 20 - i, **home) for i in range(5)])
    # the registered phone on the same Wi-Fi for days (background sign-ins)
    history.add([make_signin(-60 * 24 * d, user_id="u4", upn="dana@contoso.com", ip="192.0.2.171", asn=3352,
                             country="ES", device_id="samsung", interactive=False) for d in (5, 4, 3, 2)])
    abort = make_signin(-60, user_id="u4", upn="dana@contoso.com", ip="192.0.2.171", asn=3352, country="ES",
                        error_code=50074, os="Android", browser="Chrome Mobile 157.0", app="Approvals_Prod")
    history.add([abort])
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=2))
    assert rules.password_not_completed(rc) == []  # network + country the phone uses: skipped
    # same IP but a network the profile does not know as a whole: the own-IP factor keeps it below Medium
    stranger = make_signin(-50, user_id="u4", upn="dana@contoso.com", ip="192.0.2.171", asn=99999, country="ES",
                           error_code=50074)
    history.add([stranger])
    out = rules.password_not_completed(RuleContext.build([], history, {}, T0 + timedelta(hours=2)))
    assert all(f.score < 45 for f in out) and any("own devices sign in" in r for f in out for _, r in f.factors)


def test_ip_used_by_own_phone_only_after_the_attempt_counts_too(history):
    # the phone's Wi-Fi may enter the profile only minutes after the attempt
    history.add([make_signin(-60 * 24 * 20 - i, user_id="u5", upn="ann@contoso.com", ip="203.0.113.166", asn=577,
                             country="CA", device_id="lap") for i in range(5)])
    # that morning the phone was already seen on the same provider from another address (no country yet)
    history.add([make_signin(-150, user_id="u5", upn="ann@contoso.com", ip="2a0c:5a80::1", asn=3352, country="",
                             device_id="samsung", interactive=False)])
    abort = make_signin(-60, user_id="u5", upn="ann@contoso.com", ip="192.0.2.171", asn=3352, country="ES",
                        error_code=50074, os="Android", browser="Chrome Mobile 157.0")
    phone_later = make_signin(10, user_id="u5", upn="ann@contoso.com", ip="192.0.2.171", asn=3352, country="ES",
                              device_id="samsung", interactive=False)  # 70 min later (not "completed right after")
    history.add([abort, phone_later])
    out = rules.password_not_completed(RuleContext.build([], history, {}, T0 + timedelta(hours=2)))
    assert out and all(f.score < 25 for f in out)  # logged as Info, no reminder


def test_attack_that_locks_the_person_out_is_high(history):
    """Smart Lockout refuses the attacker's addresses (counted as attempts). When the person's own device is
    refused as locked too, the alert goes up a level - which brings a dismissed one back."""
    own = make_signin(30, user_id="u1", upn="priya@contoso.com", error_code=50053, failure_reason="The account is locked", **HOME)
    f = rules.distributed_attack(setup(history, extra=[own]))[0]
    assert f.severity == Severity.HIGH and "locked the person out" in f.title
    assert any("locked out too: 1 sign-in" in r for _, r in f.factors)
    assert "locked for them as well" in f.summary
