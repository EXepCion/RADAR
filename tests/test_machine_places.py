"""A machine's place is not the person's place (machines.py), a device-code sign-in is one event judged by the
device_code rule, and a long-lived session is reported per day."""
from datetime import datetime, time, timedelta

from conftest import T0, make_signin

from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.history import SignInHistory
from radar.plugins.signin_threats.rules import RuleContext
from radar.plugins.signin_threats.scoring import Assessor

CLOUD = 64501  # a documentation AS number, declared a cloud network in the settings below
SETTINGS = {"scoring": {"extra_asns": {str(CLOUD): ["Example Cloud", "cloud"]}},
            "new_country": {"min_baseline_signins": 5},
            "impossible_travel": {"min_distance_km": 500, "max_speed_kmh": 900, "lookback_hours": 24}}
HOME = dict(ip="198.51.100.10", asn=64496, country="CA", city="Toronto", lat=43.65, lon=-79.38)
LAPTOP = dict(device_id="0c1e7a52-5d0b-4b8e-9a51-3f0d2c1b0a01", device_name="LT-ALICE", os="Windows10",
              trust_type="Azure AD joined", compliant=True, managed=True, incoming_token="primaryRefreshToken")
DUBLIN = dict(country="IE", city="Dublin", lat=53.35, lon=-6.26)
VM = dict(device_id="5b2d9c4e-7f1a-4e3b-8c6d-2a1f0e9d8c02", device_name="vm-build-01", os="Windows10",
          trust_type="Azure AD joined", managed=True, ip="203.0.113.40", asn=CLOUD, **DUBLIN)
DAY = 60 * 24


def build(history, new, settings=None, now=None):
    return RuleContext.build(new, history, settings or SETTINGS, now or T0 + timedelta(minutes=10))


def at_home(history, user="u1", days=7, **kw):
    """The account's own laptop at home, by hand, once a day for a week."""
    history.add([make_signin(-DAY * d, user_id=user, **{**HOME, **LAPTOP, **kw}) for d in range(1, days + 1)])


# ------------------------------------------------------------------ machines in a cloud data centre
def test_a_device_whose_sign_ins_all_come_from_a_cloud_lives_there(history):
    history.add([make_signin(-3 * DAY + 10 * i, interactive=False, **VM) for i in range(25)])
    now = make_signin(0, **VM)
    history.add([now])
    rc = build(history, [now])
    assert rc.machine(now) == "a machine in a cloud data centre" and rc.on_virtual_host(now)
    # the same machine from an ordinary network: that is no data centre - judged as usual
    assert rc.machine(make_signin(1, **{**VM, "ip": "192.0.2.15", "asn": 64497})) == ""


def test_a_laptop_mostly_behind_a_cloud_gateway_is_no_machine_in_the_cloud(history):
    laptop = dict(LAPTOP, device_id="9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a503")
    history.add([make_signin(-3 * DAY + 10 * i, interactive=False, **{**laptop, "ip": "203.0.113.41", "asn": CLOUD})
                 for i in range(16)]
                + [make_signin(-2 * DAY + 10 * i, interactive=False, **{**laptop, **HOME}) for i in range(4)])
    s = make_signin(0, **{**laptop, "ip": "203.0.113.41", "asn": CLOUD})
    assert build(history, [s]).machine(s) == ""  # 80 % from the gateway's cloud: a person's laptop


def test_a_cloud_machine_needs_enough_sign_ins_and_time_there(history):
    few = dict(VM, device_id="1a2b3c4d-0000-4e3b-8c6d-2a1f0e9d8c04")
    fresh = dict(VM, device_id="1a2b3c4d-1111-4e3b-8c6d-2a1f0e9d8c05")
    history.add([make_signin(-3 * DAY + 10 * i, interactive=False, **few) for i in range(10)]
                + [make_signin(-120 + 2 * i, interactive=False, **fresh) for i in range(40)])
    rc = build(history, [])
    assert rc.machine(make_signin(0, **few)) == ""    # ten sign-ins prove nothing yet
    assert rc.machine(make_signin(0, **fresh)) == ""  # turned up two hours ago: a stranger's as likely as not


# ------------------------------------------------------------------ machines reached by remote desktop
SERVER = dict(device_id="7d6c5b4a-3928-4170-8f9e-ad0c1b2a3906", device_name="SRV-APP-01", os="Windows Server",
              trust_type="Azure AD joined", managed=True, ip="192.0.2.80", asn=64510, country="US", city="Chicago",
              lat=41.88, lon=-87.63)
RD_CLIENT = dict(resource_id="a4a365df-50f1-4397-bc59-1a1564b8bb9c", resource="Microsoft Remote Desktop",
                 app="Remote desktop client")


def test_a_machine_reached_by_remote_desktop_is_not_where_the_person_is(history):
    at_home(history)
    client = make_signin(0, **{**HOME, **LAPTOP, **RD_CLIENT})
    target = make_signin(0.5, **SERVER)                        # starts signing in half a minute later
    later = make_signin(90, interactive=False, **SERVER)       # ... and goes on for hours
    history.add([client, target, later])
    rc = build(history, [target, later], now=T0 + timedelta(minutes=100))
    assert rc.machine(target) == rc.machine(later) == "a machine reached by remote desktop"
    assert rules.impossible_travel(rc) == [] and rules.new_country(rc) == []


def test_a_remote_desktop_token_marks_the_machine_it_was_used_on(history):
    s = make_signin(0, incoming_token="remoteDesktopToken", **{k: v for k, v in SERVER.items() if k != "incoming_token"})
    history.add([s])
    assert build(history, [s]).machine(s) == "a machine reached by remote desktop"


def test_what_starts_near_a_remote_desktop_connection_is_not_always_its_target(history):
    client = make_signin(0, **{**HOME, **LAPTOP, **RD_CLIENT})
    phone = make_signin(0.3, device_id="3c2b1a09-8f7e-4d6c-b5a4-938271605f07", device_name="iPhone", os="Ios 27.1",
                        ip="192.0.2.81", asn=64511, country="US")                              # a phone is no target
    slow = make_signin(10, **dict(SERVER, device_id="4d3c2b1a-0f9e-4d8c-a7b6-c5d4e3f2a108"))  # too long after
    beside = make_signin(1, **dict(SERVER, device_id="5e4d3c2b-1a0f-4e9d-b8c7-d6e5f4a3b209", ip=HOME["ip"]))  # same address
    history.add([client, phone, slow, beside])
    rc = build(history, [phone, slow, beside], now=T0 + timedelta(minutes=20))
    assert [rc.machine(s) for s in (phone, slow, beside)] == ["", "", ""]


# ------------------------------------------------------------------ what the account learns (countries, networks)
JOINED = dict(os="Windows10", trust_type="Azure AD joined", compliant=True, managed=True)


CONFIGURED = {**SETTINGS, "virtual_desktops": [{"match": "IE-CTX-*", "label": "Citrix"}]}


def on_the_desktop(history):
    """The account works on a virtual desktop in a Dublin data centre now and then (it lives at home in Canada)."""
    at_home(history)
    history.add([make_signin(-DAY * d + 30, ip="203.0.113.60", asn=64502, device_id="2f1e0d9c-8b7a-4695-a4b3-c2d1e0f9a810",
                             device_name="IE-CTX-01", **DUBLIN, **JOINED) for d in range(1, 4)])


def test_a_country_known_only_through_a_virtual_desktop_is_not_the_accounts(history):
    on_the_desktop(history)
    trip = make_signin(0, ip="192.0.2.99", asn=64503, **DUBLIN)        # the person in Dublin, on a borrowed browser
    history.add([trip])
    plain, listed = build(history, [trip]), build(history, [trip], CONFIGURED)
    assert "IE" in plain.countries("u1", trip.created, True) and "IE" not in listed.countries("u1", trip.created, True)
    assert "IE" in plain.profile_countries("u1", trip.created) and "IE" not in listed.profile_countries("u1", trip.created)
    assert listed.countries("u1", trip.created, True)["CA"] == 7       # (the person's own countries stay)
    assert rules.new_country(plain) == [] and [f.fields["Country"] for f in rules.new_country(listed)] == ["IE"]


def test_background_activity_learns_no_country_from_a_virtual_desktop(history):
    on_the_desktop(history)
    phone = make_signin(0, interactive=False, ip="192.0.2.98", asn=64503, os="Ios 27.1",
                        device_id="6f5e4d3c-2b1a-4f0e-9d8c-7b6a5f4e3d11", **DUBLIN)
    history.add([phone])
    assert rules.new_country_background(build(history, [phone])) == []
    assert [f.fields["Country"] for f in rules.new_country_background(build(history, [phone], CONFIGURED))] == ["IE"]


def vm_days(history, user="u1", days=10, device=VM):
    """The account's cloud machine, every day for ``days`` days: a machine that lives in the data centre."""
    history.add([make_signin(-DAY * d + 5 * i, user_id=user, interactive=False, **device)
                 for d in range(1, days + 1) for i in range(4)])


def credits(rc, s):
    return [f.text for f in Assessor(rc).assess(s, 0, "").factors if f.points < 0 and "network" in f.text.lower()]


def test_a_cloud_network_is_not_made_the_accounts_own_by_its_machine(history):
    at_home(history)
    vm_days(history)
    stranger = make_signin(0, ip="203.0.113.77", asn=CLOUD, **DUBLIN)       # somebody on that cloud, no device
    history.add([stranger])
    assert credits(build(history, [stranger]), stranger) == []
    # what the account does on that network without the machine still counts - and only that is counted
    history.add([make_signin(-DAY * d, ip="203.0.113.78", asn=CLOUD, **DUBLIN) for d in range(1, 5)])
    found = credits(build(history, [stranger]), stranger)  # (four before, and this one; not the machine's forty)
    assert len(found) == 1 and found[0].startswith("Habitual network of the user") and ": 5 sign-ins since" in found[0]


def test_colleagues_on_the_same_cloud_machine_do_not_make_its_network_familiar(history):
    at_home(history)
    for user in ("u2", "u3", "u4"):
        vm_days(history, user=user, days=5)
    stranger = make_signin(0, ip="203.0.113.77", asn=CLOUD, **DUBLIN)
    history.add([stranger])
    assert not any("colleagues" in text for text in credits(build(history, [stranger]), stranger))
    for user in ("u2", "u3", "u4"):  # their own use of that cloud (no machine) is the network being theirs
        history.add([make_signin(-DAY, user_id=user, ip="203.0.113.79", asn=CLOUD, **DUBLIN)])
    assert any("also used by 3 colleagues" in text for text in credits(build(history, [stranger]), stranger))


# ------------------------------------------------------------------ device code: one event, judged by device_code
APP = "6d1f3a5e-9b2c-4d7e-8f01-23456789ab12"  # an invented command-line tool
CLIENT = dict(app_id=APP, app="Example CLI", ip="203.0.113.50", asn=CLOUD, country="NL", city="Amsterdam",
              lat=52.37, lon=4.9)


def device_code_case(history):
    """The account approves a device code on its laptop at home; a machine in a cloud asked for it and uses the
    tokens it was given - in the session of the laptop's browser."""
    at_home(history)
    laptop = [make_signin(m, interactive=False, session_id="S", **{**HOME, **LAPTOP}) for m in (-10, -2, 3)]
    code = make_signin(0, auth_protocol="deviceCode", transfer_method="deviceCodeFlow", session_id="S2",
                       **{**LAPTOP, **CLIENT})
    tokens = [make_signin(0.1 + i / 60, interactive=False, transfer_method="deviceCodeFlow", session_id="S",
                          os="Linux", browser="Python Requests", **CLIENT) for i in range(3)]
    history.add(laptop + [code] + tokens)
    return laptop, code, tokens


def test_the_tokens_of_a_device_code_sign_in_are_no_stolen_session(history):
    laptop, code, tokens = device_code_case(history)
    assert rules.session_theft(build(history, tokens)) == []
    assert rules.session_theft(build(history, laptop)) == []         # neither side
    # the same kind of token used from somewhere the code was never asked from: that is a stolen one
    away = make_signin(1, interactive=False, transfer_method="deviceCodeFlow", session_id="S", os="Linux",
                       **{**CLIENT, "ip": "192.0.2.200", "asn": 64505, "country": "US", "city": "Ashburn",
                          "lat": 39.0, "lon": -77.5})
    history.add([away])
    assert len(rules.session_theft(build(history, [away]))) == 1


def test_a_device_code_sign_in_is_no_position_of_the_person(history):
    _laptop, code, tokens = device_code_case(history)
    rc = build(history, [code] + tokens)
    assert rc.machine(code) == rc.machine(tokens[0]) == "the machine that asked for a device code"
    assert rules.new_country(rc) == [] and rules.impossible_travel(rc) == [] and rules.new_country_background(rc) == []
    assert [f.rule_id for f in rules.device_code(rc)] == ["device_code"]      # judged once, by the device-code rule


def test_a_device_code_token_is_no_replay_in_the_same_country(history):
    at_home(history)
    mfa = make_signin(-10, session_id="S", auth_methods=["Password", "Mobile app notification"],
                      auth_requirement="multiFactorAuthentication", **{**HOME, **LAPTOP})
    here = dict(CLIENT, country="CA", city="Toronto", lat=43.65, lon=-79.38)
    code = make_signin(0, auth_protocol="deviceCode", transfer_method="deviceCodeFlow", session_id="S2", **{**LAPTOP, **here})
    token = make_signin(1, interactive=False, transfer_method="deviceCodeFlow", session_id="S", os="Linux", **here)
    history.add([mfa, code, token])
    assert rules.aitm_replay(build(history, [token])) == []


def approval(history, active):
    at_home(history)
    history.add(active)
    code = make_signin(0, auth_protocol="deviceCode", transfer_method="deviceCodeFlow", session_id="S2",
                       auth_methods=["Previously satisfied"], **{**LAPTOP, **CLIENT})
    history.add([code])
    return rules.device_code(build(history, [code]))[0]


def test_the_approving_device_vouches_nothing_for_the_machine_that_asked(history):
    f = approval(history, [make_signin(m, interactive=False, **{**HOME, **LAPTOP}) for m in (-12, 4)])
    texts = [text for _p, text in f.factors]
    assert not any(t.startswith(("Known device", "Company-managed", "Device-bound SSO token")) for t in texts)
    points, why = next((p, t) for p, t in f.factors if t.startswith("Approved on LT-ALICE"))
    assert points > 0 and "Toronto, CA" in why and "not counted" in why

    quiet = approval(SignInHistory(":memory:"), [])                     # no sign of the laptop elsewhere: as before
    assert any(t.startswith("Known device") for _p, t in quiet.factors) and f.score > quiet.score
    same_net = approval(SignInHistory(":memory:"), [make_signin(m, interactive=False, **{**LAPTOP, **CLIENT, "ip": "203.0.113.51"})
                                                    for m in (-12, 4)])  # the laptop itself on that network
    assert any(t.startswith("Known device") for _p, t in same_net.factors)


ATTACKER_NETS = {"unknown": 64509, "cloud": 64506, "hosting": 64507}   # networks nobody in the tenant uses
PHISH_SETTINGS = {**SETTINGS, "scoring": {"extra_asns": {str(CLOUD): ["Example Cloud", "cloud"],
                                                          "64506": ["Example Cloud Two", "cloud"],
                                                          "64507": ["Example Hosting", "hosting"]}}}
AUTHENTICATOR = "8a7b6c5d-4e3f-4a2b-9c1d-0e9f8a7b6c12"


def phished(history, asn, privileged=False):
    """Device-code phishing: the victim, at home on their own laptop, approves a code (with their usual Authenticator)
    that the attacker's machine asked for from somewhere else; the attacker uses the tokens there - and later moves
    them on to another address."""
    at_home(history, mfa_device_id=AUTHENTICATOR)
    history.add([make_signin(m, interactive=False, session_id="S", **{**HOME, **LAPTOP}) for m in (-15, 6)])
    attacker = dict(app_id=APP, app="Example CLI", ip="203.0.113.66", asn=asn, country="NL", city="Amsterdam",
                    lat=52.37, lon=4.9)
    code = make_signin(0, auth_protocol="deviceCode", transfer_method="deviceCodeFlow", session_id="P",
                       mfa_device_id=AUTHENTICATOR, auth_methods=["Mobile app notification"], **{**LAPTOP, **attacker})
    there = make_signin(0.2, interactive=False, transfer_method="deviceCodeFlow", session_id="S", os="Linux", **attacker)
    moved = make_signin(20, interactive=False, transfer_method="deviceCodeFlow", session_id="S", os="Linux",
                        **{**attacker, "ip": "192.0.2.201", "asn": 64505, "country": "US", "city": "Ashburn",
                           "lat": 39.0, "lon": -77.5})
    history.add([code, there, moved])
    accounts = None
    if privileged:
        from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
        accounts = AccountDirectory({"u1": AccountInfo(user_id="u1", upn="alice@contoso.com", roles=["Global Administrator"])})
    rc = RuleContext.build([code, there, moved], history, PHISH_SETTINGS, T0 + timedelta(minutes=30), accounts=accounts)
    return rc, code, there, moved


def test_a_phished_device_code_comes_out_high_from_the_device_code_rule(history):
    from radar.plugin_api import Severity

    for privileged in (False, True):
        for kind, asn in ATTACKER_NETS.items():
            h = SignInHistory(":memory:")
            rc, code, there, moved = phished(h, asn, privileged)
            f = rules.device_code(rc)[0]
            assert f.severity == Severity.HIGH, (kind, privileged, f.score, f.factors)
            assert any(p > 0 and t.startswith("Approved on LT-ALICE") for p, t in f.factors), kind  # the phish's sign
            assert not any("Authenticator" in t or t.startswith("Known device") for _p, t in f.factors), kind
            # the tokens used where the code was asked for: that sign-in continuing, judged above - not a second alert
            assert rc.machine(there) == "the machine that asked for a device code"
            # moved on to yet another address: a stolen token, caught as such
            assert rc.machine(moved) == ""
            stolen = [x for x in rules.session_theft(rc) if x.fields["Second"].startswith("Ashburn")]
            assert len(stolen) == 1 and stolen[0].severity == Severity.HIGH, (kind, privileged, stolen)
            h.close()


# ------------------------------------------------------------------ a long-lived session: an alert per day
def test_a_long_lived_session_is_reported_per_day_and_a_pair_has_one_day(history):
    at_home(history)
    local = T0.astimezone()
    midnight = datetime.combine(local.date() + timedelta(days=1), time(0), tzinfo=local.tzinfo)
    m = (midnight - T0).total_seconds() / 60
    away = dict(ip="192.0.2.200", asn=64505, country="US", city="Ashburn", lat=39.0, lon=-77.5)
    before = make_signin(m - 2, session_id="S", **{**HOME, **LAPTOP})
    after = make_signin(m + 2, session_id="S", **away)               # the same session abroad, four minutes on
    history.add([before, after])
    day = rules._day(before.created)
    first = rules.session_theft(build(history, [before], now=midnight + timedelta(minutes=10)))
    second = rules.session_theft(build(history, [after], now=midnight + timedelta(minutes=10)))
    assert [f.key for f in first] == [f.key for f in second] == [f"session|u1|S|{day}"]
    # the next day the session is used from abroad again: a finding of that day, the first one stays as it was
    again = [make_signin(m + DAY, session_id="S", **{**HOME, **LAPTOP}), make_signin(m + DAY + 1, session_id="S", **away)]
    history.add(again)
    later = rules.session_theft(build(history, again[1:], now=midnight + timedelta(days=1, minutes=10)))
    assert [f.key for f in later] == [f"session|u1|S|{rules._day(again[0].created)}"] != [f.key for f in first]


def test_an_account_the_device_code_rule_does_not_judge_is_still_watched_by_the_other_rules(history):
    """The other rules pass a device-code event over only because the device_code rule judges it. Where that rule
    stays silent - the account is on its allowed list, or the rule is switched off - nothing may be passed over:
    a phished code for such an account would otherwise raise nothing at all."""
    _laptop, code, tokens = device_code_case(history)
    allowed = {**SETTINGS, "device_code": {"allowed_users": [code.upn]}}
    rc = build(history, [code] + tokens, settings=allowed)
    assert rules.device_code(rc) == [] and rc.machine(code) == rc.machine(tokens[0]) == "" and not rc.device_code_flow(tokens[0])
    assert len(rules.session_theft(build(history, tokens, settings=allowed))) == 1
    off = RuleContext.build(tokens, history, SETTINGS, T0 + timedelta(minutes=10),
                            enabled_rules=[r.meta.id for r in rules.RULES if r.meta.id != "device_code"])
    assert not off.device_code_flow(tokens[0]) and len(rules.session_theft(off)) == 1
    assert rules.session_theft(build(history, tokens)) == []      # (judged by the device_code rule: passed over)
