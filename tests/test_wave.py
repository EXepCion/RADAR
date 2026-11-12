"""A wave: several accounts, each with one odd sign-in, all from the same new network or client."""
from datetime import timedelta

from conftest import T0, make_signin
from radar import chains
from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.rules import RuleContext

PROXY = dict(asn=64777, country="NL", city="Amsterdam", os="Windows10", browser="Chrome 140.0")


def people(history, n):
    """n accounts with a week of ordinary sign-ins from home, each on its own laptop."""
    for i in range(n):
        history.add([make_signin(-60 * 24 * d, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip=f"198.51.100.{10 + i}",
                                 asn=812, device_id=f"lap{i}", user_agent="Mozilla/5.0 Edge/140") for d in range(1, 8)])


def victim(i, minute, **kw):
    return make_signin(minute, user_id=f"u{i}", upn=f"user{i}@contoso.com", ip=f"203.0.113.{100 + i}",
                       **{"user_agent": "Mozilla/5.0 Chrome/140", **PROXY, **kw})


def wave(history, minutes=120, settings=None):
    return rules.signin_wave(RuleContext.build([], history, settings or {}, T0 + timedelta(minutes=minutes)))


def test_four_accounts_from_one_network_nobody_used_before_are_a_wave(history):
    people(history, 6)
    history.add([victim(i, 10 * i) for i in range(3)])
    assert wave(history) == []                                   # three: below the default
    history.add([victim(3, 40)])
    out = wave(history)
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "signin_wave" and f.severity == Severity.HIGH and f.score == 45 + 10 + 15
    assert f.title.startswith("Wave of unusual sign-ins: 4 accounts from the network") and "AS64777" in f.title
    assert f.subjects == [f"user{i}@contoso.com" for i in range(4)] and len(f.evidence) == 4
    assert chains.stage_of("signin_wave", f.factors) == 3
    history.add([victim(4, 50), victim(5, 55)])
    assert wave(history)[0].score == 45 + 10 + 10 + 15 and wave(history)[0].key == f.key   # grows, stays one alert
    assert wave(history, minutes=60 * 9) == []                   # outside the window
    assert len(wave(history, settings={"signin_wave": {"min_accounts": 7}})) == 0


def test_what_is_not_a_wave(history):
    people(history, 6)
    # a team at a conference: same new network, but everybody on the own known laptop
    history.add([victim(i, 10 * i, device_id=f"lap{i}") for i in range(5)])
    assert wave(history) == []
    # wrong passwords only (that is a spray, not a wave of access)
    history.add([victim(i, 30 + i, asn=64888, error_code=50126) for i in range(5)])
    assert wave(history) == []
    # an ordinary provider that people in the tenant already use, e.g. a mobile carrier
    history.add([make_signin(-60 * 24 * 3, user_id="x1", upn="x1@contoso.com", ip="203.0.113.200", asn=64999)])
    history.add([victim(i, 60 + i, asn=64999, user_agent="Mozilla/5.0 Edge/140") for i in range(5)])
    assert wave(history) == []


def test_one_new_client_on_many_accounts_is_a_wave_even_across_networks(history):
    people(history, 5)
    history.add([make_signin(-60 * 24 * 3, user_id=f"y{i}", upn=f"y{i}@contoso.com", ip=f"203.0.113.{150 + i}", asn=64100 + i)
                 for i in range(5)])                               # the networks themselves are known in the tenant
    history.add([victim(i, 10 * i, asn=64100 + i, error_code=50074, user_agent="python-requests/2.31") for i in range(4)])
    out = wave(history)
    assert len(out) == 1 and "client 'python-requests/2.31'" in out[0].title
    assert out[0].fields["Completed sign-ins"] == "0" and any("Attack-tool fingerprint" in r for _, r in out[0].factors)
    assert out[0].severity == Severity.MEDIUM                      # stopped at MFA: nobody got in
