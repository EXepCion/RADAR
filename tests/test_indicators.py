"""Attacker addresses: one finding's proof raises everything else that touches the same address."""
from datetime import timedelta

from conftest import T0, make_signin
from radar import chains
from radar.plugin_api import Finding, Severity
from radar.plugins.signin_threats import indicators, rules
from radar.plugins.signin_threats.indicators import Indicator
from radar.plugins.signin_threats.models import AccountChange
from radar.plugins.signin_threats.rules import RuleContext
from test_mfa_report import HOME, USER, audit, baseline

ATTACKER = dict(ip="203.0.113.77", asn=64999, country="NL", city="Amsterdam", os="Linux", browser="Firefox 140.0")
BOB = dict(user_id="u2", upn="bob@contoso.com")
CAROL = dict(user_id="u3", upn="carol@contoso.com")


def scan(history, minutes, settings=None, **kw):
    """One run as the plugin does it: the report rule, then what its findings prove, then the reuse rule."""
    rc = RuleContext.build([], history, settings or {}, T0 + timedelta(minutes=minutes), **kw)
    findings = rules.mfa_report(rc)
    marked = indicators.apply(rc, findings)
    return rc, findings, marked


def reported_attack(history):
    baseline(history)
    history.add([make_signin(-60 * 24 * d, **BOB, ip="198.51.100.20", asn=812, device_id="lap2") for d in range(1, 8)])
    history.add_changes([AccountChange.from_report(audit(0))])
    history.add([make_signin(-0.3, **USER, **ATTACKER, error_code=500121)])


def test_a_proven_address_is_remembered_and_counts_against_other_accounts(history):
    reported_attack(history)
    rc, findings, marked = scan(history, 180)
    assert [(m.kind, m.value, m.source, m.points, m.upn) for m in marked] == [
        ("ip", "203.0.113.77", "mfa_report", indicators.HIGH, "alice@contoso.com")]
    assert Indicator.from_json(marked[0].to_json()) == marked[0]
    # the alert the address came from names it - and is not raised by its own indicator
    report = findings[0]
    assert report.fields[indicators.FIELD].startswith("203.0.113.77 - a sign-in whose MFA prompt the user reported")
    assert indicators.addresses_in(report.fields) == ["203.0.113.77"]
    again = scan(history, 190)[1][0]
    assert again.score == report.score and not any("Known attacker address" in r for _, r in again.factors)

    # another account, next day, same address: whatever rule assesses it sees the proof
    try_bob = make_signin(60 * 20, **BOB, **ATTACKER, error_code=50126)
    history.add([try_bob])
    rc = RuleContext.build([try_bob], history, {}, T0 + timedelta(hours=21))
    a = rc.assessor.assess(try_bob, 10, "test")
    assert any(p == 25 and r.startswith("Known attacker address: used in a sign-in whose MFA prompt") and "alice@contoso.com" in r
               for p, r in a.as_tuples())
    clean = make_signin(60 * 20, **BOB, ip="203.0.113.78", asn=64999, country="NL", error_code=50126)
    assert not any("Known attacker address" in r for _, r in rc.assessor.assess(clean, 10, "test").as_tuples())
    # the reporter's own later sign-ins from it count too (the attacker getting in after all) - earlier ones do not
    later = make_signin(60 * 22, **USER, **ATTACKER)
    assert rc.hostile(later) is not None and rc.hostile(make_signin(-5, **USER, **ATTACKER)) is None
    # forgotten after the configured days; switched off: nothing is used
    assert RuleContext.build([], history, {}, T0 + timedelta(days=8)).hostile_index() == {}
    assert RuleContext.build([], history, {"hostile_indicators": {"enabled": False}}, T0 + timedelta(hours=21)).hostile(try_bob) is None


def test_other_accounts_on_a_proven_address_raise_an_alert_that_grows(history):
    reported_attack(history)
    assert [f.rule_id for f in scan(history, 180)[1]] == ["mfa_report"]  # nothing else from that address yet
    history.add([make_signin(60 * 20, **BOB, **ATTACKER, error_code=50126)])
    reuse = {f.rule_id: f for f in scan(history, 60 * 21)[1]}["hostile_reuse"]
    assert reuse.severity == Severity.MEDIUM and reuse.score == 45
    assert reuse.title == "Known attacker address also used on 1 other account(s): 203.0.113.77"
    assert reuse.fields["Accounts"] == "bob@contoso.com" and "alice@contoso.com" in reuse.fields["Known from"]
    assert reuse.subjects == ["bob@contoso.com"] and chains.stage_of("hostile_reuse", reuse.factors) == 1
    # the password is right for the next account, and then the attacker is in: high, and it says who
    history.add([make_signin(60 * 20 + 5, **CAROL, **ATTACKER, error_code=50074),
                 make_signin(60 * 20 + 9, **CAROL, **ATTACKER)])
    worse = {f.rule_id: f for f in scan(history, 60 * 21)[1]}["hostile_reuse"]
    assert worse.key == reuse.key and worse.severity == Severity.HIGH and worse.score == 100
    assert worse.title == "Signed in from a known attacker address: carol@contoso.com"
    assert "revoke its sessions" in worse.recommendation and len(worse.evidence) == 3
    assert worse.subjects == ["bob@contoso.com", "carol@contoso.com"] and chains.stage_of("hostile_reuse", worse.factors) == 3


def test_what_does_not_mark_an_address(history):
    baseline(history)
    # 1) a report of the user's own prompt (own computer, own network)
    history.add_changes([AccountChange.from_report(audit(0))])
    history.add([make_signin(-0.3, **USER, **HOME, error_code=500121)])
    assert scan(history, 180)[2] == []
    # 2) a low finding, a rule that proves nothing, a row from the account's own surroundings, a wrong-password row
    own = make_signin(5, **USER, **HOME)
    foreign_fail = make_signin(6, **USER, **ATTACKER, error_code=50126)
    history.add([own, foreign_fail])
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=1))

    def finding(rule, score, rows, key="k|1", title="t", factors=()):
        return Finding(key=key, rule_id=rule, severity=Severity.MEDIUM, score=score, title=title,
                       evidence=[s.evidence() for s in rows], factors=list(factors))

    foreign_ok = make_signin(7, **USER, **ATTACKER)
    history.add([foreign_ok])
    assert indicators.derive(rc, [finding("session_theft", 30, [foreign_ok])]) == []          # below Medium
    assert indicators.derive(rc, [finding("new_country", 80, [foreign_ok])]) == []            # not a proving rule
    assert indicators.derive(rc, [finding("session_theft", 80, [own, foreign_fail])]) == []   # own place / wrong password
    assert indicators.derive(rc, [finding("distributed_attack", 80, [foreign_ok])]) == []     # guessing that got nowhere
    got = indicators.derive(rc, [finding("distributed_attack", 80, [foreign_ok], factors=[(30, "Attacker got past the password 1 time(s)")])])
    assert [(m.value, m.source) for m in got] == [("203.0.113.77", "distributed_attack")]
    spray = indicators.derive(rc, [finding("password_spray", 75, [foreign_fail])])            # attack traffic: weaker
    assert [(m.value, m.points) for m in spray] == [("203.0.113.77", indicators.MEDIUM)]
    trusted = RuleContext.build([], history, {"trusted_ips": ["203.0.113.77"]}, T0 + timedelta(hours=1))
    assert indicators.derive(trusted, [finding("session_theft", 80, [foreign_ok])]) == []     # an office address

    # 3) an address several people regularly sign in from (a hotel, a carrier gateway)
    for n in range(3):
        history.add([make_signin(-60 * 24 * 6, user_id=f"c{n}", upn=f"c{n}@contoso.com", ip="203.0.113.99", asn=64000)])
    hotel = make_signin(8, **USER, ip="203.0.113.99", asn=64000, country="NL")
    history.add([hotel])
    assert indicators.derive(rc, [finding("session_theft", 80, [hotel])]) == []


def test_colleagues_on_their_own_devices_are_no_hits_and_only_proven_access_makes_the_alert(history):
    reported_attack(history)
    history.add([make_signin(640, **BOB, device_id="lap2", **ATTACKER)])   # Bob's known laptop on the same network
    rc, findings, _ = scan(history, 700)
    assert "hostile_reuse" not in {f.rule_id for f in findings}
    assert not any("Known attacker address" in r for _, r in rc.assessor.assess(history.query(ip="203.0.113.77")[-1], 10, "t").as_tuples())
    # an address only known from attack traffic (a spray) raises assessments, but no reuse alert of its own
    history.add_indicators([Indicator("ip", "203.0.113.50", "password_spray", "a password spray", indicators.MEDIUM, "", "",
                                      T0, T0 + timedelta(days=7))])
    history.add([make_signin(710, **CAROL, ip="203.0.113.50", asn=64001, country="NL", error_code=50126)])
    rc, findings, _ = scan(history, 720)
    assert "hostile_reuse" not in {f.rule_id for f in findings}
    hit = rc.hostile(history.query(ip="203.0.113.50")[-1])
    assert hit.points == indicators.MEDIUM and hit.source == "password_spray"
