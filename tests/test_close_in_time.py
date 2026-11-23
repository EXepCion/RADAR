"""What happens seconds apart must not vouch for itself: a device registered a moment ago is not the user's known
device, a network first used a minute ago is not a usual one. And the alert about a registration names the device."""
from datetime import datetime, timedelta, timezone

from radar import chains, linkify
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins.directory_audit import DirectoryAuditPlugin
from radar.plugins.signin_threats import netintel, rules
from radar.plugins.signin_threats.models import AccountChange
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

from conftest import T0, make_signin

LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD joined", compliant=True,
              incoming_token="primaryRefreshToken", auth_requirement="multiFactorAuthentication",
              os="MacOs", browser="Chrome 140.0")
HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812)
CLOUD = dict(country="NL", city="Amsterdam", ip="167.99.1.1", asn=14061, os="Windows10", browser="Edge 18.26100")  # hosting
NEW_PC = dict(device_id="dev-new", device_name="WS-00001", trust_type="Azure AD registered",
              incoming_token="primaryRefreshToken", auth_requirement="multiFactorAuthentication")


def texts(rc, s, **kw):
    return " | ".join(f.text for f in rc.assessor.assess(s, 50, "base", **kw).factors)


def points(rc, s, word):
    return [f.points for f in rc.assessor.assess(s, 50, "base").factors if word in f.text]


def story(history, later_minutes=1.0):
    """The account's own month, then: a sign-in through a datacenter registers a device, and that device signs in."""
    history.add([make_signin(-2000 - i, **HOME, **LAPTOP) for i in range(6)])
    register = make_signin(0, **CLOUD, resource_id=netintel.DEVICE_REGISTRATION_RESOURCE, correlation_id="corr-1",
                           session_id="sess-1", auth_methods=["Password", "Mobile app notification"])
    first_use = make_signin(later_minutes, **CLOUD, **NEW_PC, correlation_id="corr-1", session_id="sess-1")
    history.add([register, first_use])
    rc = RuleContext.build([register, first_use], history, {}, T0 + timedelta(minutes=later_minutes + 5))
    return rc, register, first_use


# ------------------------------------------------------- familiar needs to have been there for a while
def test_a_device_registered_a_moment_ago_is_not_the_users_known_device(history):
    rc, _register, first_use = story(history)
    assert "Device not seen before for this user" in texts(rc, first_use)  # its very first sign-in
    again = make_signin(2, **CLOUD, **NEW_PC)
    said = texts(rc, again)
    assert "Known device of the user" not in said
    assert "Device first used by this account 1 min before" in said and "Azure AD registered" in said
    assert points(rc, again, "Device first used") == [5]
    # the token of a device nobody knows vouches for nothing
    assert "Primary Refresh Token" not in said
    # ... and the network it was registered from a minute ago is not a usual one
    assert "usual network" not in said and "never seen in the tenant" in said


def test_the_same_device_is_known_once_it_has_been_in_use_for_half_a_day(history):
    """... when it is also seen where the user is (see test_review_fixes: age alone is not enough)."""
    rc, _register, _first = story(history)
    history.add([make_signin(30, **HOME, **NEW_PC, interactive=False)])     # the new computer on the user's own network
    rc = RuleContext.build([], history, {}, T0 + timedelta(hours=14))
    next_day = make_signin(60 * 13, **CLOUD, **NEW_PC)
    said = texts(rc, next_day)
    assert "Known device of the user (WS-00001)" in said and "Primary Refresh Token" in said
    assert "User's usual network" in said
    still_new = make_signin(60 * 11 + 1, **CLOUD, **NEW_PC)
    assert "Device first used by this account 11 h before" in texts(rc, still_new)


def test_a_device_never_seen_and_the_long_known_one_are_judged_as_before(history):
    rc, _register, _first = story(history)
    assert "Device not seen before for this user" in texts(rc, make_signin(3, **HOME, device_id="dev-x", device_name="X"))
    own = texts(rc, make_signin(3, **HOME, **LAPTOP))
    assert "Known device of the user (LAPTOP-1)" in own and "Primary Refresh Token" in own


def test_how_long_it_takes_is_a_setting(history):
    history.add([make_signin(-2000 - i, **HOME, **LAPTOP) for i in range(6)])
    first = make_signin(0, **CLOUD, **NEW_PC)
    history.add([first, make_signin(5, **HOME, **NEW_PC, interactive=False)])
    rc = RuleContext.build([], history, {"scoring": {"familiar_after_hours": 1}}, T0 + timedelta(hours=3))
    assert "Known device of the user" in texts(rc, make_signin(120, **CLOUD, **NEW_PC))


def test_an_authenticator_that_approved_for_the_first_time_a_minute_ago_is_not_the_usual_one(history):
    history.add([make_signin(-2000 - i, **HOME, **LAPTOP, mfa_device_id="phone-1") for i in range(3)])
    first = make_signin(0, **CLOUD, mfa_device_id="phone-x", mfa_device_os="Android")
    history.add([first])
    rc = RuleContext.build([], history, {}, T0 + timedelta(minutes=10))
    again = make_signin(1, **CLOUD, mfa_device_id="phone-x", mfa_device_os="Android")
    said = texts(rc, again)
    assert "usual Authenticator device" not in said and "Authenticator device this user never used before" in said
    assert "usual Authenticator device" in texts(rc, make_signin(2, **HOME, mfa_device_id="phone-1"))


def test_the_real_story_is_rated_high_not_low(history):
    """Entra rates a sign-in medium risk; it comes from a device registered half a minute earlier through a
    datacenter. That device, network and token took 40 points off - now they do not."""
    rc, _register, first_use = story(history, later_minutes=0.5)
    first_use.risk_during = first_use.risk_aggregated = "medium"
    first_use.risk_state = "atRisk"
    out = rules.risky_signin(rc)
    assert len(out) == 1 and out[0].severity == Severity.HIGH, out[0].factors


def test_a_new_network_is_the_users_own_at_once_when_their_known_device_uses_it(history):
    """On the road: the phone the account has had for weeks is on the hotel's Wi-Fi - that network is the user's."""
    history.add([make_signin(-2000 - i, **HOME, **LAPTOP) for i in range(6)])
    hotel = dict(country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573)
    history.add([make_signin(-5, **hotel, **LAPTOP, interactive=False)])
    rc = RuleContext.build([], history, {}, T0 + timedelta(minutes=10))
    assert "User's usual network" in texts(rc, make_signin(0, **hotel))
    # the same network without the known device on it: nobody vouches for it
    other = dict(country="BR", city="Sao Paulo", ip="203.0.113.77", asn=64500)
    history.add([make_signin(-5, **other, device_id="dev-other", device_name="OTHER")])
    assert "usual network" not in texts(rc, make_signin(1, **other))


# -------------------------------------------------------------- the registration names its device
def test_the_sign_in_that_registers_a_device_names_the_device(history):
    rc, _register, _first = story(history)
    out = [f for f in rules.sensitive_app(rc) if "Device registration" in f.title]
    assert len(out) == 1
    f = out[0]
    assert f.fields["Device"] == "WS-00001" and f.fields[linkify.DEVICE_ID_FIELD] == "dev-new"
    assert "Device ID" not in f.fields  # said once: the name is shown, the id only makes its link exact
    assert "registered WS-00001" in f.summary


def test_without_a_sign_in_of_the_new_device_the_alert_says_nothing_about_it(history):
    history.add([make_signin(-2000 - i, **HOME, **LAPTOP) for i in range(6)])
    register = make_signin(0, **CLOUD, resource_id=netintel.DEVICE_REGISTRATION_RESOURCE, correlation_id="corr-1")
    own = make_signin(1, **HOME, **LAPTOP)  # the user's own computer keeps working: not the new device
    history.add([register, own])
    rc = RuleContext.build([register, own], history, {}, T0 + timedelta(minutes=5))
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert "Device" not in f.fields and linkify.DEVICE_ID_FIELD not in f.fields


DEVICE_ID = "11111111-2222-4333-8444-555555555555"


def register_audit(name="WS-00001", object_id=None):
    return {"id": "Device Registration Service_x_1", "category": "Device", "correlationId": "corr-1",
            "result": "success", "resultReason": "(blank)", "activityDisplayName": "Register device",
            "activityDateTime": "2026-11-18T09:07:15Z", "loggedByService": "Device Registration Service",
            "initiatedBy": {"app": None, "user": {"id": "u1", "userPrincipalName": "Anna@contoso.com",
                                                  "ipAddress": "203.0.113.9"}},
            "targetResources": [{"id": object_id, "displayName": name, "type": "Device", "modifiedProperties": []}],
            "additionalDetails": [{"key": "Device Trust Type", "value": "Azure AD register"},
                                  {"key": "Device OS", "value": "Windows"}, {"key": "Device Id", "value": DEVICE_ID}]}


def test_the_audit_side_says_which_device_and_from_where():
    f = DirectoryAuditPlugin._device_signal(register_audit())
    assert f.fields["Device"] == "WS-00001" and f.fields[linkify.DEVICE_ID_FIELD] == DEVICE_ID
    assert "Device ID" not in f.fields
    assert f.fields["Kind"] == "Azure AD register, Windows" and f.fields["Registered from"] == "203.0.113.9"
    assert f.subjects == ["anna@contoso.com"]
    # the name is the link, and it is looked up by exactly this id - not by a name several devices can share
    found = linkify.find_entities(f.fields["Device"], "Device", f.fields)
    assert [(e.kind, e.value, e.ref) for e in found] == [("device", "WS-00001", DEVICE_ID)]
    assert linkify.find_entities("WS-00001", "Device")[0].ref == ""  # without an id: by its name, as before
    assert linkify.find_entities("anna@contoso.com", "User", f.fields)[0].ref == ""  # only the device


def test_the_id_behind_the_device_is_not_shown_a_second_time():
    from radar.ui import details

    f = DirectoryAuditPlugin._device_signal(register_audit())
    assert linkify.DEVICE_ID_FIELD not in dict(details.shown_fields(f.fields))
    assert dict(details.shown_fields(f.fields))["Device"] == "WS-00001"
    assert DEVICE_ID not in " ".join(f"{k}: {v}" for k, v in details.shown_fields(f.fields))


def test_a_device_name_padded_by_the_log_is_cleaned():
    f = DirectoryAuditPlugin._device_signal(register_audit(name="CA-LNX-0001" + "\u0000" * 40))
    assert f.fields["Device"] == "CA-LNX-0001" and "\u0000" not in f.title + f.summary + str(f.evidence)


def test_a_registration_without_details_still_works():
    audit = register_audit()
    audit["additionalDetails"] = []
    audit["initiatedBy"]["user"].pop("ipAddress")
    f = DirectoryAuditPlugin._device_signal(audit)
    assert f.fields == {"User": "anna@contoso.com", "Device": "WS-00001"}


# ------------------------------------------------------------------------------- the chain
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
USER = "anna@contoso.com"


def step(key, rule, score, hours_ago, signal=""):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule} {USER}", signal=signal,
                   occurred_at=NOW - timedelta(hours=hours_ago), fields={"User": USER}, subjects=[USER])


def chain_for(*findings):
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", list(findings))
    return chains.chain_findings(ac.since(NOW - timedelta(days=30)), NOW)


def test_a_sign_in_rated_high_followed_by_a_way_to_stay_is_a_chain():
    out = chain_for(step("aitm", "aitm_replay", 70, 3), step("dev", "device_registration", 30, 2.9, "device_registered"))
    assert len(out) == 1 and out[0].fields["Chain"] == "Suspicious access -> Persistence"
    assert out[0].severity == Severity.HIGH


def test_travel_followed_by_a_new_device_or_method_stays_quiet():
    assert chain_for(step("nc", "new_country", 50, 3), step("dev", "device_registration", 30, 2, "device_registered")) == []
    assert chain_for(step("nc", "new_country", 69, 3), step("mfa", "mfa_change", 30, 2)) == []
    # a step judged harmless on its own does not complete it either
    assert chain_for(step("aitm", "aitm_replay", 70, 3), step("mfa", "mfa_change", 10, 2)) == []
    # and the way to stay has to come afterwards
    assert chain_for(step("dev", "device_registration", 30, 30, "device_registered"), step("aitm", "aitm_replay", 70, 3)) == []


def test_an_older_weaker_sign_in_does_not_take_the_place_of_the_one_that_matters():
    """Nine days ago the account travelled (Medium, dismissed). Today: a sign-in rated High, then a device. The
    chain is today's - the old trip could come before the device too, but it is not what happened."""
    out = chain_for(step("trip", "new_country", 50, 9 * 24), step("aitm", "aitm_replay", 70, 3),
                    step("travel", "impossible_travel", 80, 3), step("reg", "sensitive_app", 60, 2.9))
    assert len(out) == 1 and out[0].severity == Severity.HIGH
    assert [r["Step"].split()[0] for r in out[0].evidence] == ["impossible_travel", "sensitive_app"]


# ------------------------------------------------------------------ a reason the log leaves blank
def test_a_blank_reason_in_the_log_is_not_shown_as_the_change():
    audit = {"id": "Device Registration Service_x_2", "result": "success", "resultReason": "(blank)",
             "activityDisplayName": "Add passwordless phone sign-in credential",
             "activityDateTime": "2026-11-13T19:25:05Z",
             "initiatedBy": {"user": {"id": "u1", "userPrincipalName": "anna@contoso.com"}},
             "targetResources": [{"type": "User", "id": "u1", "userPrincipalName": "anna@contoso.com"}]}
    change = AccountChange.from_audit(audit)
    assert change.detail == "Add passwordless phone sign-in credential"
