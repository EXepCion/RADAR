"""A corporate device enrolment signs in from the enrolment service's address in a cloud, not from the device. That
it is one cannot be seen from the sign-in - anybody can rent an address there - but from what came out of it: a
managed device from the organisation's automated enrolment, registered by the account right afterwards."""
from datetime import timedelta

from radar.plugins.signin_threats import enrolment, netintel, rules
from radar.plugins.signin_threats.rules import RuleContext

from conftest import T0, make_signin

HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812)
LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD joined", compliant=True)
SERVICE = dict(country="NL", city="Amsterdam", ip="203.0.113.96", asn=8075)  # the service's address, in a cloud
DEVICE_ID = "11111111-2222-4333-8444-555555555555"
ANNA = dict(user_id="u1", upn="anna@contoso.com")
BEN = dict(user_id="u2", upn="ben@contoso.com")


def enrol(minutes, who=ANNA, **kw):
    return make_signin(minutes, **{**who, **SERVICE, "resource_id": netintel.ENROLMENT_RESOURCE,
                                   "app": "Microsoft Intune Company Portal", "resource": "Microsoft Intune Enrollment",
                                   "auth_requirement": "singleFactorAuthentication", **kw})


def registration(minutes, who=ANNA, device_id=DEVICE_ID, name="iPad Pro"):
    return {"activityDisplayName": "Register device", "result": "success",
            "activityDateTime": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "initiatedBy": {"user": {"id": who["user_id"], "userPrincipalName": who["upn"]}},
            "targetResources": [{"type": "Device", "displayName": name}],
            "additionalDetails": [{"key": "Device Id", "value": device_id}]}


CORPORATE = {"deviceId": DEVICE_ID, "displayName": "iPad Pro", "isManaged": True, "deviceOwnership": "Company",
             "enrollmentType": "AppleACMEDEPUDASetupAsstLegacy", "enrollmentProfileName": "Corporate iPad"}
REGISTERED_ONLY = {"deviceId": DEVICE_ID, "displayName": "WS-1", "isManaged": None, "enrollmentType": None}
OWN_DEVICE = {"deviceId": DEVICE_ID, "displayName": "MacBook", "isManaged": True, "deviceOwnership": "Company",
              "enrollmentType": "AppleACMEBasicBYOD"}


AUTOPILOT = {"deviceId": DEVICE_ID, "displayName": "LT-TOR-0042", "isManaged": True, "deviceOwnership": "Company",
             "enrollmentType": "AzureDomainJoined", "enrollmentProfileName": "Corporate laptops",
             "physicalIds": ["[HWID]:h:1", "[ZTDID]:99999999-2222-4333-8444-555555555555", "[OrderId]:Sales"]}
JOINED_BY_HAND = {**AUTOPILOT, "physicalIds": ["[HWID]:h:1", "[GID]:g:1"], "enrollmentProfileName": None}


def baseline(history):
    history.add([make_signin(-3000 - i, **who, **HOME, **LAPTOP) for who in (ANNA, BEN) for i in range(6)])


def settle(history, new, state, minutes, audits=(), device=None, fail=False):
    history.add(new)

    def registrations(_since):
        if fail:
            raise RuntimeError("audit log not readable")
        return list(audits)

    def lookup(device_id):  # one device for every id, or {device id: device}
        return device.get(device_id) if isinstance(device, dict) and "isManaged" not in device else device

    return enrolment.settle(new, history, state, T0 + timedelta(minutes=minutes), registrations, lookup,
                            enrolment.CORPORATE_TYPES)


def findings(history, outcome, minutes):
    rc = RuleContext.build(outcome.new, history, {}, T0 + timedelta(minutes=minutes), excluded=outcome.excluded)
    out = []
    for rd in rules.RULES:
        out.extend(rd.evaluate(rc))
    return [f for f in out if f.rule_id != "device_enrolment"]


# ----------------------------------------------------------------------------------- what counts
def test_what_proves_an_enrolment():
    assert "Corporate iPad" in enrolment.proves(CORPORATE, enrolment.CORPORATE_TYPES)
    assert not enrolment.proves(REGISTERED_ONLY, enrolment.CORPORATE_TYPES)   # registered, managed by nobody
    assert not enrolment.proves(OWN_DEVICE, enrolment.CORPORATE_TYPES)        # a user enrolling a device of their own
    assert not enrolment.proves({**CORPORATE, "isManaged": False}, enrolment.CORPORATE_TYPES)
    assert not enrolment.proves(None, enrolment.CORPORATE_TYPES)
    assert enrolment.proves(OWN_DEVICE, ["byod"])  # (which kinds count is a setting)


def test_a_windows_computer_the_organisation_registered_for_autopilot_proves_it_too():
    """Its hardware was registered by the organisation (or its supplier) beforehand: the directory marks that."""
    said = enrolment.proves(AUTOPILOT, enrolment.CORPORATE_TYPES)
    assert "Windows Autopilot" in said and "Corporate laptops" in said
    assert not enrolment.proves(JOINED_BY_HAND, enrolment.CORPORATE_TYPES)   # joined by a user: anybody's computer
    assert not enrolment.proves({**AUTOPILOT, "isManaged": None}, enrolment.CORPORATE_TYPES)  # registered, not enrolled
    assert not enrolment.proves(AUTOPILOT, ["DEP"])                          # (switched off by the setting)
    assert "physicalIds" in enrolment.DEVICE_SELECT


def test_an_autopilot_enrolment_from_a_place_the_account_never_was_is_a_record(history):
    baseline(history)
    abroad = dict(country="BR", city="Sao Paulo", ip="203.0.113.5", asn=28573)
    first = enrol(0, **abroad, app="Microsoft Authentication Broker", os="Windows10", browser="Edge 18.26100")
    out = settle(history, [first], {}, 12, [registration(3, name="LT-TOR-0042")], AUTOPILOT)
    assert out.new == [] and len(out.records) == 1 and "Windows Autopilot" in out.records[0].fields["Enrolment"]
    assert findings(history, out, 12) == []


def test_only_sign_ins_to_the_enrolment_service_without_a_device_are_candidates():
    assert enrolment.is_candidate(enrol(0))
    assert not enrolment.is_candidate(enrol(0, device_id="d"))
    assert not enrolment.is_candidate(enrol(0, error_code=50126))
    assert not enrolment.is_candidate(make_signin(0, **ANNA, **SERVICE))  # the same address, something else


# ------------------------------------------------------------------------------- proven: a record
def test_a_proven_enrolment_is_a_record_and_its_sign_ins_are_not_judged(history):
    baseline(history)
    service = enrol(0)
    password = make_signin(-0.5, **ANNA, **SERVICE, interactive=False, auth_methods=["Password"], password_ok=True)
    wrong = make_signin(-1, **ANNA, **SERVICE, interactive=False, error_code=50126)
    out = settle(history, [wrong, password, service], {}, 12, [registration(10)], CORPORATE)
    assert out.new == [] and out.excluded == {service.id, password.id, wrong.id}
    assert findings(history, out, 12) == []
    assert len(out.records) == 1
    f = out.records[0]
    assert f.rule_id == "device_enrolment" and f.score == 0 and f.subjects == ["anna@contoso.com"]
    assert f.fields["Device"] == "iPad Pro" and f.fields["_Device ID"] == DEVICE_ID
    assert "AppleACMEDEPUDASetupAsstLegacy" in f.fields["Enrolment"] and "Corporate iPad" in f.fields["Enrolment"]
    assert len(f.evidence) == 3
    # ... and stay out of what later scans look back on
    later = settle(history, [], out.state, 60)
    assert service.id in later.excluded and later.records == []


def test_without_it_the_same_sign_in_is_an_alert(history):
    """(what the proof is for: this is what the rules make of the sign-in on its own)"""
    baseline(history)
    service = enrol(0)
    history.add([service])
    rc = RuleContext.build([service], history, {}, T0 + timedelta(minutes=5))
    assert [f.rule_id for f in rules.new_country(rc)] == ["new_country"]


def test_two_accounts_enrolling_through_the_same_address_do_not_make_it_an_attackers(history):
    baseline(history)
    a, b = enrol(0), enrol(3, BEN)
    audits = [registration(5), registration(8, BEN, device_id="22222222-2222-4333-8444-555555555555")]
    out = settle(history, [a, b], {}, 12, audits, CORPORATE)
    assert out.new == [] and len(out.records) == 2
    assert findings(history, out, 12) == []


def test_of_two_devices_enrolled_in_a_row_the_record_names_the_one_registered_next(history):
    baseline(history)
    laptop_id = "22222222-2222-4333-8444-555555555555"
    audits = [registration(13, device_id=laptop_id, name="LT-TOR-0042"), registration(4)]  # (newest first, as read)
    out = settle(history, [enrol(0)], {}, 20, audits, {DEVICE_ID: CORPORATE, laptop_id: {**AUTOPILOT, "deviceId": laptop_id}})
    assert [f.fields["Device"] for f in out.records] == ["iPad Pro"]


# -------------------------------------------------------------------------- not proven: judged
def test_until_the_device_is_there_the_sign_in_waits_then_it_is_judged_like_any_other(history):
    baseline(history)
    service = enrol(0)
    out = settle(history, [service], {}, 5)                       # nothing registered yet
    assert out.new == [] and service.id in out.excluded and out.records == []
    assert findings(history, out, 5) == []
    out = settle(history, [], out.state, 20, [registration(10)], REGISTERED_ONLY)  # a device, but nobody's
    assert out.new == []
    out = settle(history, [], out.state, 35, [registration(10)], REGISTERED_ONLY)  # half an hour: no proof came
    assert [s.id for s in out.new] == [service.id] and service.id not in out.excluded
    assert "new_country" in [f.rule_id for f in findings(history, out, 35)]
    assert settle(history, [], out.state, 45).new == []           # judged once


def test_the_proof_may_arrive_a_scan_later(history):
    baseline(history)
    service = enrol(0)
    out = settle(history, [service], {}, 5)
    out = settle(history, [], out.state, 15, [registration(10)], CORPORATE)
    assert out.new == [] and len(out.records) == 1 and service.id in out.excluded


def test_a_registration_by_somebody_else_or_long_before_proves_nothing(history):
    baseline(history)
    service = enrol(0)
    out = settle(history, [service], {}, 40, [registration(10, BEN), registration(-60)], CORPORATE)
    assert [s.id for s in out.new] == [service.id] and out.records == []


def test_when_the_directory_cannot_be_asked_nothing_is_excused(history):
    baseline(history)
    service = enrol(0)
    out = settle(history, [service], {}, 5, fail=True)
    assert out.new == []                                          # waits ...
    out = settle(history, [], out.state, 35, fail=True)
    assert [s.id for s in out.new] == [service.id]                # ... and is judged


def test_the_address_itself_is_no_excuse(history):
    """Somebody else on the same address, not enrolling anything: judged as ever."""
    baseline(history)
    service = enrol(0)
    other = make_signin(2, **BEN, **SERVICE, auth_methods=["Password"], password_ok=True,
                        auth_requirement="singleFactorAuthentication")
    out = settle(history, [service, other], {}, 12, [registration(10)], CORPORATE)
    assert [s.id for s in out.new] == [other.id]
    assert "new_country" in [f.rule_id for f in findings(history, out, 12)]


def test_what_is_remembered_is_forgotten_with_the_history(history):
    baseline(history)
    out = settle(history, [enrol(0)], {}, 12, [registration(10)], CORPORATE)
    assert out.state["explained"]
    assert settle(history, [], out.state, 60 * 24 * 40).state["explained"] == {}
