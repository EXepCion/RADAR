"""What an audit of all detection rules found: a sign-in lost when Entra lists its id twice, prompt bombing that
did not mark its address, travel alerts for a device that simply moved, and a removed device that answered nothing."""
from datetime import datetime, timedelta, timezone

from radar import chains, correlation, linkify
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins.directory_audit import DirectoryAuditPlugin
from radar.plugins.signin_threats import indicators, rules
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

from conftest import T0, make_signin

HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812, lat=43.65, lon=-79.38)
ABROAD = dict(country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573, lat=-23.55, lon=-46.63)
CLOUD = dict(country="NL", city="Amsterdam", ip="167.99.1.1", asn=14061, lat=52.37, lon=4.89)
PHONE = dict(device_id="dev-phone", device_name="iPhone", trust_type="Azure AD registered", os="Ios", browser="Mobile Safari")
DEVICE_ID = "11111111-2222-4333-8444-555555555555"


# -------------------------------------------- 1. one id, two sign-ins: by hand and in the background
def twins():
    by_hand = make_signin(0, id="X1", **CLOUD, interactive=True, auth_methods=["Password", "Mobile app notification"])
    background = make_signin(-0.3, id="X1", **CLOUD, interactive=False, error_code=50132)
    return by_hand, background


def test_a_background_record_with_the_same_id_does_not_replace_the_sign_in_by_hand(history):
    by_hand, background = twins()
    assert [s.interactive for s in history.add([by_hand])] == [True]
    assert [(s.interactive, s.error_code) for s in history.add([background])] == [(False, 50132)]   # a sign-in of its own
    both = history.query(T0 - timedelta(hours=1), T0 + timedelta(hours=1), user_id="u1")
    assert sorted((s.interactive, s.error_code) for s in both) == [(False, 50132), (True, 0)]
    assert history.get("X1", interactive=True).success and history.get("X1", interactive=False).error_code == 50132
    assert history.add([by_hand, background]) == []                              # read again: nothing new
    # the background copy goes after hours, the sign-in by hand stays its 30 days
    history.purge(T0 - timedelta(days=30), T0 + timedelta(hours=1))
    left = history.query(T0 - timedelta(hours=1), T0 + timedelta(hours=1), user_id="u1")
    assert [(s.interactive, s.success) for s in left] == [(True, True)]
    assert history.get("X1").success


def test_the_sign_in_by_hand_is_new_also_when_its_background_twin_came_first(history):
    by_hand, background = twins()
    history.add([background])
    assert [s.interactive for s in history.add([by_hand])] == [True]                 # it is judged, not taken for known
    assert history.get("X1", interactive=True).success
    assert history.add([by_hand]) == [] and history.add([background]) == []


def test_two_copies_of_one_sign_in_are_still_one(history):
    """(what was there before: a preliminary record is completed, not doubled)"""
    preliminary = make_signin(0, id="P1", ip="198.51.100.10", country="", upn="")
    complete = make_signin(0, id="P1", **HOME)
    history.add([preliminary])
    assert history.add([complete]) == [] and history.enriched == 1
    assert history.get("P1").country == "CA"
    assert len(history.query(T0 - timedelta(hours=1), T0 + timedelta(hours=1))) == 1


def test_the_attackers_address_is_remembered_although_the_id_has_a_twin(history):
    history.add([make_signin(-3000 - i, **HOME, **PHONE) for i in range(6)])
    by_hand, background = twins()
    history.add([background])
    history.add([by_hand])
    rc = RuleContext.build([by_hand], history, {}, T0 + timedelta(minutes=5))
    finding = Finding(key="aitm|u1|d", rule_id="aitm_replay", severity=Severity.HIGH, score=70, title="x",
                      evidence=[{"Sign-in ID": "X1", "IP address": by_hand.ip, "_event": "interactiveUser", "Result": "Success"}])
    assert [(i.value, i.source) for i in indicators.derive(rc, [finding])] == [(by_hand.ip, "aitm_replay")]


# ----------------------------------------- 2. whoever causes MFA prompts knows the password
def test_the_address_behind_mfa_prompt_bombing_is_remembered(history):
    history.add([make_signin(-3000 - i, **HOME, **PHONE) for i in range(6)])
    prompts = [make_signin(m, id=f"F{m}", **CLOUD, error_code=rules.MFA_DENIED_CODE) for m in (0, 1, 2)]
    history.add(prompts)
    rc = RuleContext.build(prompts, history, {}, T0 + timedelta(minutes=5))
    finding = Finding(key="fatigue|u1", rule_id="mfa_fatigue", severity=Severity.HIGH, score=75, title="x",
                      evidence=[{"Sign-in ID": s.id, "IP address": s.ip, "_event": "interactiveUser"} for s in prompts])
    marked = indicators.derive(rc, [finding])
    assert [(i.value, i.source, i.points) for i in marked] == [(CLOUD["ip"], "mfa_fatigue", indicators.MEDIUM)]
    # the user's own prompts at home mark nothing
    own = [make_signin(m, id=f"H{m}", **HOME, **PHONE, error_code=rules.MFA_DENIED_CODE) for m in (3, 4)]
    history.add(own)
    home = Finding(key="fatigue|u1|h", rule_id="mfa_fatigue", severity=Severity.HIGH, score=75, title="x",
                   evidence=[{"Sign-in ID": s.id, "IP address": s.ip} for s in own])
    assert indicators.derive(rc, [home]) == []


# --------------------------- 3. a known device that simply moved: logged; one in two places at once: an alert
def background_abroad(history, last_home_minutes):
    history.add([make_signin(-60 * 24 * 20 - i * 30, **HOME, **PHONE, interactive=bool(i % 2)) for i in range(12)])
    history.add([make_signin(last_home_minutes, **HOME, **PHONE, interactive=False)])
    abroad = [make_signin(m, **ABROAD, **PHONE, interactive=False) for m in (0, 1, 2)]
    history.add(abroad)
    return rules.new_country_background(RuleContext.build(abroad, history, {}, T0 + timedelta(minutes=10)))


def test_a_known_device_that_travelled_is_logged_only(history):
    out = background_abroad(history, last_home_minutes=-60 * 14)      # last seen at home 14 h ago: a flight away
    assert len(out) == 1 and out[0].severity == Severity.INFO
    assert any("nowhere else at the same time" in t for _p, t in out[0].factors)


def test_a_known_device_in_two_countries_at_once_stays_an_alert(history):
    out = background_abroad(history, last_home_minutes=-30)           # at home half an hour before: no flight is that fast
    assert len(out) == 1 and out[0].severity == Severity.LOW
    assert any("in one place" in t and "Toronto" in t for _p, t in out[0].factors)


def test_and_so_does_one_that_is_active_at_home_afterwards(history):
    out = background_abroad(history, last_home_minutes=4)             # ... and at home again while it is "abroad"
    assert len(out) == 1 and out[0].severity == Severity.LOW


def test_a_device_nobody_knows_abroad_is_judged_as_before(history):
    history.add([make_signin(-60 * 24 * 20 - i * 30, **HOME, **PHONE, interactive=bool(i % 2)) for i in range(12)])
    abroad = [make_signin(0, **ABROAD, device_id="dev-x", device_name="X", interactive=False)]
    history.add(abroad)
    out = rules.new_country_background(RuleContext.build(abroad, history, {}, T0 + timedelta(minutes=10)))
    assert len(out) == 1 and out[0].severity >= Severity.LOW


# ------------------------------------------------ 4. removing the device answers its registration
NOW = datetime.now(timezone.utc)


def registration_alert(device_id=DEVICE_ID, hours_ago=5.0):
    return Finding(key=f"sensitive|u1|Device registration|{device_id}", rule_id="sensitive_app", severity=Severity.MEDIUM,
                   score=60, title="Device registration: anna@contoso.com", occurred_at=NOW - timedelta(hours=hours_ago),
                   fields={"User": "anna@contoso.com", "Device": "WS-1", linkify.DEVICE_ID_FIELD: device_id},
                   subjects=["anna@contoso.com"], factors=[(60, "Registered a device")])


def removal(device_id=DEVICE_ID, hours_ago=1.0, activity="Delete device", key="DeviceId"):
    return {"id": f"del-{device_id}-{activity}", "activityDisplayName": activity, "result": "success",
            "activityDateTime": (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z"),
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
            "targetResources": [{"type": "Device", "displayName": "WS-1", "id": "object-id"}],
            "additionalDetails": [{"key": key, "value": device_id}]}


def test_the_audit_watch_records_a_device_that_was_removed():
    for activity, key in (("Delete device", "DeviceId"), ("Unregister device", "Device Id")):
        f = DirectoryAuditPlugin._device_removed_signal(removal(activity=activity, key=key))
        assert f.signal == "device_removed" and f.fields[linkify.DEVICE_ID_FIELD] == DEVICE_ID
        assert f.fields["Device"] == "WS-1" and f.fields["Initiated by"] == "admin@contoso.com"
    no_id = removal()
    no_id["additionalDetails"] = []
    assert DirectoryAuditPlugin._device_removed_signal(no_id) is None           # which device? nothing to tie it to
    assert "device_removed" in chains.NOT_LINKS and "device_removed" in correlation.RESPONSE_SIGNALS


def test_removing_the_device_lowers_the_alert_about_its_registration():
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", [registration_alert(), registration_alert("99999999-2222-4333-8444-555555555555")], now=NOW)
    ac.ingest("directory_audit", [DirectoryAuditPlugin._device_removed_signal(removal())], now=NOW)
    mine, other = sorted(ac.since(NOW - timedelta(days=1)), key=lambda a: a.score)[:2]
    mine = next(a for a in ac.since(NOW - timedelta(days=1)) if a.fields.get(linkify.DEVICE_ID_FIELD) == DEVICE_ID and not a.signal)
    other = next(a for a in ac.since(NOW - timedelta(days=1)) if a.fields.get(linkify.DEVICE_ID_FIELD, "").startswith("9999"))
    assert mine.score == 45 and "Device removed" in mine.fields["Response"] and "admin@contoso.com" in mine.fields["Response"]
    assert other.score == 60 and "Response" not in other.fields              # another device: not answered by it


def test_a_removal_before_the_registration_answers_nothing():
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("directory_audit", [DirectoryAuditPlugin._device_removed_signal(removal(hours_ago=9))], now=NOW)
    ac.ingest("signin_threats", [registration_alert(hours_ago=5)], now=NOW)
    alert = next(a for a in ac.since(NOW - timedelta(days=1)) if not a.signal)
    assert alert.score == 60 and "Response" not in alert.fields
