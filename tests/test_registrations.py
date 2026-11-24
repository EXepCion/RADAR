"""A sign-in to the device registration service says that something was done there, not what. The audit log does:
which device was registered - or that it was no registration at all (a Windows Hello key on a device that exists).
And: a device judged to have travelled is watched - when it turns up at home while it is still abroad, that is said."""
from datetime import timedelta

from radar import linkify
from radar.plugin_api import Severity
from radar.plugins.signin_threats import netintel, registrations, rules
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812, lat=43.65, lon=-79.38)
ABROAD = dict(country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573, lat=-23.55, lon=-46.63)
CLOUD = dict(country="NL", city="Amsterdam", ip="167.99.1.1", asn=14061, os="Windows10", browser="Edge 18.26100")
LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD registered")
PHONE = dict(device_id="dev-phone", device_name="iPhone", trust_type="Azure AD registered", os="Ios", browser="Mobile Safari")
DEVICE_ID = "11111111-2222-4333-8444-555555555555"


def entry(minutes, activity="Register device", user="u1", name="WS-00001", correlation="c-other", device_id=DEVICE_ID):
    return {"id": f"a{minutes}{activity[:3]}", "activityDisplayName": activity, "result": "success", "correlationId": correlation,
            "activityDateTime": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "initiatedBy": {"user": {"id": user}},
            "targetResources": [{"type": "Device" if activity == "Register device" else "User", "displayName": name + "\x00\x00"}],
            "additionalDetails": [{"key": "Device Id", "value": device_id}] if activity == "Register device" else []}


def drs(minutes=0, **kw):
    return make_signin(minutes, **{**CLOUD, "resource_id": netintel.DEVICE_REGISTRATION_RESOURCE, "correlation_id": "c1",
                                   "app": "Microsoft Authentication Broker", **kw})


# ------------------------------------------------------------------------------ what the audit log says
def test_the_audit_entry_of_the_account_around_that_time_says_what_it_was():
    s = drs()
    m = registrations.match(s, [entry(0.2)])
    assert (m.kind, m.device, m.device_id) == (registrations.REGISTERED, "WS-00001", DEVICE_ID)   # (name cleaned)
    assert registrations.match(s, [entry(0.2, "Add Windows Hello for Business credential")]).kind == registrations.HELLO
    assert registrations.match(s, [entry(0.2, user="u2")]) is None           # somebody else's
    assert registrations.match(s, [entry(9)]) is None                         # another time
    # a registration counts before a Hello key of the same minutes; the entry of the same operation before a nearer one
    both = [entry(0.1, "Add Windows Hello for Business credential"), entry(2, name="WS-2")]
    assert registrations.match(s, both).device == "WS-2"
    same_operation = [entry(0.1, name="NEAR"), entry(3, name="MINE", correlation="c1")]
    assert registrations.match(s, same_operation).device == "MINE"


def baseline(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])


def test_the_alert_names_the_device_the_audit_log_says_was_registered(history):
    baseline(history)
    s = drs()
    history.add([s])
    rc = RuleContext.build([s], history, {}, T0 + timedelta(minutes=5))
    rc.registrations = {s.id: registrations.match(s, [entry(0.2)])}
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert f.fields["Device"] == "WS-00001" and f.fields[linkify.DEVICE_ID_FIELD] == DEVICE_ID
    assert "registered WS-00001" in f.summary


def test_a_windows_hello_key_on_a_device_that_exists_is_no_device_registration(history):
    baseline(history)
    s = drs(**{**HOME, **LAPTOP, "app": "Microsoft Device Registration Client"})
    history.add([s])
    rc = RuleContext.build([s], history, {}, T0 + timedelta(minutes=5))
    rc.registrations = {s.id: registrations.match(s, [entry(0.2, "Add Windows Hello for Business credential")])}
    assert [f for f in rules.sensitive_app(rc) if "Device registration" in f.title] == []


def test_without_an_audit_entry_the_alert_is_as_before(history):
    baseline(history)
    s = drs()
    history.add([s])
    rc = RuleContext.build([s], history, {}, T0 + timedelta(minutes=5))
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert "Device" not in f.fields


# ------------------------------------------------------------ the audit entry may arrive a scan later
def settle(history, new, state, minutes, entries=()):
    history.add(new)
    return registrations.settle(new, history, state, T0 + timedelta(minutes=minutes), lambda _since: list(entries))


def test_a_sign_in_waits_for_the_audit_entry_and_is_judged_with_its_device(history):
    baseline(history)
    s = drs()
    out = settle(history, [s], {}, 3)                       # nothing in the audit log yet: it waits, unjudged
    assert out.matches == {} and out.hold == {s.id} and out.release == [] and s.id in out.state
    out = settle(history, [], out.state, 13, [entry(0.2)])  # there it is
    assert [x.id for x in out.release] == [s.id] and out.matches[s.id].device == "WS-00001" and out.state == {}
    assert out.hold == set()
    rc = RuleContext.build(out.release, history, {}, T0 + timedelta(minutes=13))
    rc.registrations = out.matches
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert f.fields["Device"] == "WS-00001" and f.key.startswith("sensitive|u1|Device registration|")   # the same alert


def test_what_is_matched_at_once_or_never_does_not_wait(history):
    baseline(history)
    s = drs()
    out = settle(history, [s], {}, 3, [entry(0.2)])
    assert out.matches[s.id].kind == registrations.REGISTERED and out.state == {} and out.hold == set()
    late = drs(1)
    out = settle(history, [late], {}, 3)
    assert out.hold == {late.id}
    out = settle(history, [], out.state, 40)                # half an hour and more: judged without the audit log's word
    assert out.state == {} and [x.id for x in out.release] == [late.id] and out.matches == {}
    assert settle(history, [], out.state, 50).release == []
    assert settle(history, [make_signin(0, **HOME)], {}, 3).state == {}   # not a sign-in to the registration service


def test_when_the_audit_log_cannot_be_read_the_alert_stands_as_it_is(history):
    baseline(history)
    s = drs()
    history.add([s])

    def broken(_since):
        raise RuntimeError("no")

    out = registrations.settle([s], history, {}, T0 + timedelta(minutes=3), broken)
    assert out.matches == {} and s.id in out.state


# ------------------------------------------------- a device that "travelled" and is at home after all
def travelled(history):
    history.add([make_signin(-60 * 24 * 20 - i * 30, **HOME, **PHONE, interactive=bool(i % 2)) for i in range(12)])
    history.add([make_signin(-60 * 14, **HOME, **PHONE, interactive=False)])
    abroad = [make_signin(m, **ABROAD, **PHONE, interactive=False) for m in (0, 1, 2)]
    history.add(abroad)
    first = rules.new_country_background(RuleContext.build(abroad, history, {}, T0 + timedelta(minutes=10)))
    assert len(first) == 1 and first[0].severity == Severity.INFO      # judged to have travelled: logged
    return first[0]


def test_a_device_that_travelled_and_turns_up_at_home_at_once_is_raised_after_all(history):
    logged = travelled(history)
    more_abroad = make_signin(170, **ABROAD, **PHONE, interactive=False)
    at_home = make_signin(200, **HOME, **PHONE, interactive=False)      # half an hour after its last sign-in abroad
    history.add([more_abroad, at_home])
    out = rules.new_country_background(RuleContext.build([at_home], history, {}, T0 + timedelta(minutes=210)))
    assert len(out) == 1 and out[0].key == logged.key and out[0].severity == Severity.LOW
    assert any("at home again" in t and "Sao Paulo" in t for _p, t in out[0].factors)
    assert out[0].fields["Country"] == "BR"


def test_coming_home_by_plane_raises_nothing(history):
    travelled(history)
    back = make_signin(60 * 16, **HOME, **PHONE, interactive=False)     # sixteen hours later
    history.add([back])
    assert rules.new_country_background(RuleContext.build([back], history, {}, T0 + timedelta(hours=16, minutes=5))) == []


def test_other_devices_of_the_person_at_home_raise_nothing(history):
    travelled(history)
    laptop = make_signin(30, **HOME, **LAPTOP, interactive=False)       # the laptop stayed at home
    history.add([laptop])
    assert rules.new_country_background(RuleContext.build([laptop], history, {}, T0 + timedelta(minutes=40))) == []
