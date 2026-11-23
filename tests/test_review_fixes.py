"""What a review of the enrolment, familiarity and device changes found missing - each as a test."""
from datetime import datetime, timedelta, timezone

from radar import chains, linkify
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins import directory_audit
from radar.plugins.signin_threats import enrolment, netintel, rules
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

from conftest import T0, make_signin

HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812, lat=43.65, lon=-79.38)
LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD registered", os="MacOs",
              browser="Chrome 140.0")
SERVICE = dict(country="NL", city="Amsterdam", ip="203.0.113.96", asn=8075, lat=52.37, lon=4.89)
CLOUD = dict(country="NL", city="Amsterdam", ip="167.99.1.1", asn=14061, os="Windows10", browser="Edge 18.26100")
DEVICE_ID = "11111111-2222-4333-8444-555555555555"
CORPORATE = {"deviceId": DEVICE_ID, "displayName": "iPad Pro", "isManaged": True, "enrollmentType": "AppleDEP"}


def registration(minutes):
    return {"activityDisplayName": "Register device",
            "activityDateTime": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "initiatedBy": {"user": {"id": "u1"}}, "additionalDetails": [{"key": "Device Id", "value": DEVICE_ID}]}


def proven_enrolment(history, more=()):
    """The account's own weeks, then a corporate enrolment through the service's address - proven."""
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    service = make_signin(0, **SERVICE, resource_id=netintel.ENROLMENT_RESOURCE, auth_requirement="singleFactorAuthentication")
    new = [service, *more]
    history.add(new)
    out = enrolment.settle(new, history, {}, T0 + timedelta(minutes=12), lambda _s: [registration(5)], lambda _i: CORPORATE)
    assert len(out.records) == 1
    return out, service


def raised(history, new, minutes, out):
    rc = RuleContext.build(new, history, {}, T0 + timedelta(minutes=minutes), excluded=out.excluded)
    return [(f.rule_id, f.score) for rd in rules.RULES for f in rd.evaluate(rc) if f.rule_id != "device_enrolment"]


# ---------------------------------------------------- 1. a proven enrolment teaches the profile nothing
def test_what_the_enrolment_service_did_is_not_learned_as_the_users_habit(history):
    out, service = proven_enrolment(history)
    assert "NL" not in history.user_profile("u1", "country", T0 + timedelta(days=1))
    assert 8075 not in history.user_asns("u1", T0 + timedelta(days=1))
    assert service.ip not in history.user_profile("u1", "ip", T0 + timedelta(days=1))
    assert history.user_asns("u1", T0 + timedelta(days=1)) == {812}          # what the user did is still known
    # thirteen hours later a stranger signs in from that cloud network and country: as new as it ever was
    stranger = make_signin(60 * 13, country="NL", city="Amsterdam", ip="203.0.113.200", asn=8075, lat=52.37, lon=4.89,
                           auth_methods=["Password"], password_ok=True, auth_requirement="singleFactorAuthentication")
    history.add([stranger])
    found = dict(raised(history, [stranger], 60 * 13 + 5, out))
    assert found.get("new_country", 0) >= 70, found


def test_a_network_the_user_also_uses_themselves_stays_known(history):
    """Only what came from the enrolment alone is forgotten: an Autopilot computer unpacked at home."""
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    at_home = make_signin(0, **HOME, resource_id=netintel.ENROLMENT_RESOURCE)
    history.add([at_home])
    out = enrolment.settle([at_home], history, {}, T0 + timedelta(minutes=12), lambda _s: [registration(5)],
                           lambda _i: {**CORPORATE, "physicalIds": ["[ZTDID]:x"], "enrollmentType": "AzureDomainJoined"})
    assert len(out.records) == 1
    assert history.user_asns("u1", T0 + timedelta(days=1)) == {812}
    assert "CA" in history.user_profile("u1", "country", T0 + timedelta(days=1))


def test_a_sign_in_that_only_waits_is_not_forgotten(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    service = make_signin(0, **SERVICE, resource_id=netintel.ENROLMENT_RESOURCE)
    history.add([service])
    out = enrolment.settle([service], history, {}, T0 + timedelta(minutes=5), lambda _s: [], lambda _i: None)
    assert out.records == [] and 8075 in history.user_asns("u1", T0 + timedelta(days=1))


# ------------------------------------------------- 5. ... and is no end of a journey for the next sign-in
def test_the_users_next_sign_in_is_not_measured_against_the_enrolment_services(history):
    own = make_signin(10, **HOME, device_id="dev-other", device_name="PHONE")
    out, _service = proven_enrolment(history, more=[own])
    assert "impossible_travel" not in dict(raised(history, [s for s in out.new], 12, out))


# ----------------------------------------------- 2. a device nobody vouches for does not become known by age
def story(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    born = make_signin(0, **CLOUD, device_id="dev-new", device_name="WS-00001", trust_type="Azure AD registered")
    history.add([born])
    return RuleContext.build([], history, {}, T0 + timedelta(days=3))


def said(rc, s):
    return " | ".join(f.text for f in rc.assessor.assess(s, 50, "base").factors)


def test_a_device_only_ever_seen_on_a_network_of_its_own_stays_a_stranger(history):
    """Registered through a datacenter and used from there: three days later it is three days old, not the user's."""
    rc = story(history)
    later = make_signin(60 * 24 * 2, **CLOUD, device_id="dev-new", device_name="WS-00001", trust_type="Azure AD registered",
                        incoming_token="primaryRefreshToken")
    text = said(rc, later)
    assert "Known device of the user" not in text and "Primary Refresh Token" not in text
    assert "only on networks the account does not otherwise use" in text
    assert "usual network" not in text       # ... and it cannot vouch for its network either


def test_after_weeks_of_use_it_is_the_users_all_the_same(history):
    """A phone that only ever uses mobile data: nothing vouches for it, and it is no stranger for ever."""
    story(history)
    rc = RuleContext.build([], history, {}, T0 + timedelta(days=16))
    assert "nothing vouches for it" in said(rc, make_signin(60 * 24 * 13, **CLOUD, device_id="dev-new", device_name="WS-00001"))
    assert "Known device of the user (WS-00001)" in said(rc, make_signin(60 * 24 * 15, **CLOUD, device_id="dev-new", device_name="WS-00001"))
    rc = RuleContext.build([], history, {"scoring": {"unvouched_after_days": 3}}, T0 + timedelta(days=16))
    assert "Known device of the user" in said(rc, make_signin(60 * 24 * 4, **CLOUD, device_id="dev-new", device_name="WS-00001"))


def test_once_it_shows_up_where_the_user_is_it_is_theirs(history):
    rc = story(history)
    history.add([make_signin(60 * 20, **HOME, device_id="dev-new", device_name="WS-00001", interactive=False)])
    later = make_signin(60 * 24 * 2, **CLOUD, device_id="dev-new", device_name="WS-00001")
    assert "Known device of the user (WS-00001)" in said(rc, later)


def test_another_device_of_the_user_on_the_same_network_vouches_too(history):
    """The new phone on the hotel's Wi-Fi the laptop is on."""
    rc = story(history)
    history.add([make_signin(60 * 20, **{**CLOUD, **LAPTOP}, interactive=False)])
    later = make_signin(60 * 24 * 2, **CLOUD, device_id="dev-new", device_name="WS-00001")
    assert "Known device of the user (WS-00001)" in said(rc, later)


def test_the_first_devices_of_a_new_account_need_nobody_to_vouch(history):
    """A new colleague: device and network appear together - there is nothing older to compare with."""
    first = make_signin(0, **HOME, device_id="dev-first", device_name="LT-1")
    history.add([first])
    rc = RuleContext.build([], history, {}, T0 + timedelta(days=3))
    assert "Known device of the user (LT-1)" in said(rc, make_signin(60 * 24 * 2, **HOME, device_id="dev-first", device_name="LT-1"))


# --------------------------------------------------- 3. a proven enrolment is no step of an attack
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
USER = "anna@contoso.com"


def step(key, rule, score, hours_ago, signal="", **fields):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule} {USER}", signal=signal,
                   occurred_at=NOW - timedelta(hours=hours_ago), fields={"User": USER, **fields}, subjects=[USER])


def chain_for(*findings):
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("x", list(findings))
    return chains.chain_findings(ac.since(NOW - timedelta(days=30)), NOW)


def test_the_registration_of_a_device_whose_enrolment_is_proven_is_no_step():
    device = {linkify.DEVICE_ID_FIELD: DEVICE_ID}
    guessing, policy = step("g", "distributed_attack", 50, 30), step("c", "conditional_access", 55, 4)
    registered = step("d", "device_registration", 30, 5, "device_registered", **device)
    proven = step("e", "device_enrolment", 0, 5, **device)
    said = lambda *steps: [f.fields["Chain"] for f in chain_for(*steps)]  # noqa: E731
    assert said(guessing, registered, policy) == ["Targeted -> Persistence -> Escalation"]   # not proven: a step
    # proven: the guessing and the policy change are still a story - the device is no part of it
    assert said(guessing, registered, policy, proven) == ["Targeted -> Escalation"]
    assert said(guessing, registered, proven) == []
    # another device registered in the same days is still a step
    other = step("d2", "device_registration", 30, 6, "device_registered", **{linkify.DEVICE_ID_FIELD: "99999999-2222-4333-8444-555555555555"})
    assert said(guessing, registered, other, policy, proven) == ["Targeted -> Persistence -> Escalation"]


# -------------------------------------- 4. a device registered from a known attacker address says so
def test_a_registration_made_from_a_known_attacker_address_names_it():
    audit = {"id": "x1", "activityDisplayName": "Register device", "activityDateTime": "2026-11-18T09:07:15Z",
             "correlationId": "c", "initiatedBy": {"user": {"id": "u1", "userPrincipalName": "anna@contoso.com",
                                                            "ipAddress": "203.0.113.9"}},
             "targetResources": [{"type": "Device", "displayName": "WS-1"}],
             "additionalDetails": [{"key": "Device Id", "value": DEVICE_ID}]}
    f = directory_audit.DirectoryAuditPlugin._device_signal(audit)
    directory_audit.mark_attacker_addresses([f], {}, {"203.0.113.9": "guessed passwords"})
    assert f.fields[chains.ATTACKER_ADDRESS_FIELD] == "203.0.113.9 - guessed passwords"
    clean = directory_audit.DirectoryAuditPlugin._device_signal(audit)
    directory_audit.mark_attacker_addresses([clean], {}, {"198.51.100.1": "x"})
    assert chains.ATTACKER_ADDRESS_FIELD not in clean.fields


# --------------------------------------------------------------- 6. one waiting time for one idea
def test_a_browser_first_used_two_hours_ago_is_not_the_users_known_client_yet(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    history.add([make_signin(0, **CLOUD)])
    rc = RuleContext.build([], history, {}, T0 + timedelta(days=1))
    assert "Known client of the user" not in said(rc, make_signin(120, **CLOUD))
    assert "Known client of the user (Windows, Edge)" in said(rc, make_signin(60 * 13, **CLOUD))
    assert "Known client of the user (macOS, Chrome)" in said(rc, make_signin(120, **HOME, os="MacOs", browser="Chrome 141.0"))
