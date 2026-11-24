"""An administrator doing their work is not an attack across accounts. What puts an account under suspicion is
evidence that somebody else may be in it - not what it does with its rights. And a role alert says which role, on
what, for whom."""
import threading
from datetime import datetime, timedelta, timezone

from radar import chains, incidents, linkify
from radar.alerts import AlertCenter
from radar.config import ConfigManager
from radar.plugin_api import Finding, Severity
from radar.plugin_manager import PluginManager
from radar.plugins import directory_audit as da
from radar.plugins.signin_threats import enrolment, netintel, registrations, rules
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

from conftest import T0, make_signin

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
ADMIN, ANNA, BEN = "admin@contoso.com", "anna@contoso.com", "ben@contoso.com"
DEVICE_ID = "11111111-2222-4333-8444-555555555555"


def sev(score):
    return Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO


def signin_alert(key, rule, score, hours_ago, user, **fields):
    return Finding(key=key, rule_id=rule, severity=sev(score), score=score, title=f"{rule}: {user}",
                   occurred_at=NOW - timedelta(hours=hours_ago), fields={"User": user, **fields}, subjects=[user])


def admin_change(key, rule, score, hours_ago, to=(), who=ADMIN):
    return Finding(key=key, rule_id=rule, severity=sev(score), score=score, title=f"{rule}: {who}",
                   occurred_at=NOW - timedelta(hours=hours_ago),
                   fields={"Initiated by": who, **({"Done to": ", ".join(to)} if to else {})}, subjects=[who, *to])


def center(*findings, dismiss=()):
    ac = AlertCenter(Store(":memory:"))
    for f in sorted(findings, key=lambda f: f.occurred_at):
        ac.ingest("x", [f], now=f.occurred_at + timedelta(minutes=5))
    ac.dismiss([a.id for a in ac.since(NOW - timedelta(days=30)) if a.key in dismiss])
    return ac


def spread(ac):
    return chains.spread_findings(ac.since(NOW - timedelta(days=30)), NOW)


# --------------------------------------------- A: an admin's own changes are no suspicion against the admin
def test_an_admin_who_assigns_roles_two_days_running_is_not_under_suspicion():
    """Yesterday a role assignment (Medium - it is one), today another, for Anna. Anna has a week-old device code
    sign-in and a policy change. None of that makes the admin's account somebody else's."""
    ac = center(admin_change("r1", "role_assignment", 45, 26), admin_change("r2", "role_assignment", 45, 2, to=[ANNA]),
                signin_alert("dc", "device_code", 50, 30, ANNA), admin_change("ca", "conditional_access", 55, 20, who=ANNA),
                signin_alert("reg", "sensitive_app", 45, 28, ADMIN))
    assert spread(ac) == []
    assert chains.connected_accounts(ac.since(NOW - timedelta(days=30)),
                                     chains.links_by_subject(ac.since(NOW - timedelta(days=30)), NOW)) == []


def test_an_admin_whose_sign_in_is_suspicious_and_who_then_acts_on_somebody_is(tmp_path):
    ac = center(signin_alert("nc", "new_country", 60, 5, ADMIN), admin_change("r", "role_assignment", 55, 3, to=[ANNA]),
                signin_alert("odd", "new_country", 50, 1, ANNA))
    out = spread(ac)
    assert len(out) == 1 and out[0].subjects == [ADMIN, ANNA]


# ------------------------------------- B: what ties two accounts covers what follows it, not what was before
def test_what_the_other_account_did_a_week_before_it_was_acted_on_is_no_part_of_the_story():
    old = [signin_alert("old1", "new_country", 50, 24 * 8, ANNA), admin_change("old2", "conditional_access", 55, 24 * 8 - 2, who=ANNA)]
    ac = center(*old, signin_alert("nc", "new_country", 60, 5, ADMIN), admin_change("r", "role_assignment", 55, 3, to=[ANNA]))
    for f in spread(ac):
        assert not {"old1", "old2"} & {row["_key"] for row in f.evidence}, f.evidence
    # ... what Anna's account does afterwards is
    ac = center(*old, signin_alert("nc", "new_country", 60, 5, ADMIN), admin_change("r", "mfa_exclusion_change", 55, 3, to=[ANNA]),
                admin_change("after", "conditional_access", 55, 1, who=ANNA))
    out = spread(ac)
    assert len(out) == 1 and "after" in {row["_key"] for row in out[0].evidence}
    assert not {"old1", "old2"} & {row["_key"] for row in out[0].evidence}


# ------------------------------------------- D: an admin change does not make its receivers one incident
def grouped(ac):
    return incidents.group(ac.since(NOW - timedelta(days=30)), NOW)


def test_a_role_change_for_five_people_does_not_pull_their_old_travel_alerts_into_one_incident():
    people = [f"p{i}@contoso.com" for i in range(5)]
    travel = [signin_alert(f"t{i}", "new_country_background", 25, 24 * 2 + i, p) for i, p in enumerate(people)]
    ac = center(*travel, admin_change("r", "role_assignment", 45, 2, to=people), dismiss=[f"t{i}" for i in range(5)])
    assert grouped(ac) == []                                    # one reminder about a role change: no incident
    about, named = incidents.links(next(a for a in ac.since(NOW - timedelta(days=30)) if a.rule_id == "role_assignment"))
    assert ("account", people[0]) in named and ("account", people[0]) not in about


def test_it_does_join_what_is_open_or_serious_about_a_receiver():
    ac = center(signin_alert("pw", "password_not_completed", 50, 6, ANNA), admin_change("r", "role_assignment", 55, 2, to=[ANNA]))
    found = grouped(ac)
    assert len(found) == 1 and found[0].own == 2                # somebody knows Anna's password, then she gets a role
    ac = center(signin_alert("low", "new_country_background", 25, 6, ANNA), admin_change("r", "role_assignment", 55, 2, to=[ANNA]))
    assert len(grouped(ac)) == 1                                # still open: it is looked at together
    ac = center(signin_alert("low", "new_country_background", 25, 6, ANNA), admin_change("r", "role_assignment", 55, 2, to=[ANNA]),
                dismiss=["low"])
    assert grouped(ac) == []                                    # looked at, Low, dismissed: not reopened by a role


# ---------------------------------- C: a registered device that is the organisation's own is no way to stay in
HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812)
LAPTOP = dict(device_id="dev-laptop", device_name="LAPTOP-1", trust_type="Azure AD registered")
CORPORATE = {"deviceId": DEVICE_ID, "displayName": "LT-TOR-0042", "isManaged": True, "deviceOwnership": "Company",
             "enrollmentType": "AzureDomainJoined", "enrollmentProfileName": "Corporate laptops", "physicalIds": ["[ZTDID]:x"]}


def entry(minutes, activity="Register device", name="LT-TOR-0042"):
    return {"id": f"a{minutes}", "activityDisplayName": activity, "result": "success", "correlationId": "c",
            "activityDateTime": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "initiatedBy": {"user": {"id": "u1"}}, "targetResources": [{"type": "Device", "displayName": name}],
            "additionalDetails": [{"key": "Device Id", "value": DEVICE_ID}]}


def drs(minutes=0):
    return make_signin(minutes, **HOME, resource_id=netintel.DEVICE_REGISTRATION_RESOURCE, app="Microsoft Authentication Broker",
                       os="Windows10", browser="Edge 18.26100")


def settle(history, new, state, minutes, entries=(), device=None):
    history.add(new)
    return registrations.settle(new, history, state, T0 + timedelta(minutes=minutes), lambda _s: list(entries),
                                (lambda _id: device), enrolment.CORPORATE_TYPES)


def test_a_registration_waits_until_the_directory_says_whose_device_it_is(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    s = drs()
    out = settle(history, [s], {}, 3, [entry(0.2)], {**CORPORATE, "isManaged": None})     # registered, not managed yet
    assert out.hold == {s.id} and out.release == [] and out.matches == {} and s.id in out.state
    out = settle(history, [], out.state, 12, [entry(0.2)], CORPORATE)                      # now it is
    assert out.hold == set() and [x.id for x in out.release] == [s.id] and out.state == {}
    assert "Windows Autopilot" in out.matches[s.id].proof and out.matches[s.id].device == "LT-TOR-0042"
    rc = RuleContext.build(out.release, history, {}, T0 + timedelta(minutes=12))
    rc.registrations = out.matches
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert f.severity == Severity.INFO and "Windows Autopilot" in f.fields["Enrolment"]
    assert any(p < 0 and "organisation's own" in t for p, t in f.factors)


def test_after_half_an_hour_without_proof_it_is_judged_as_it_is(history):
    history.add([make_signin(-3000 - i, **HOME, **LAPTOP) for i in range(6)])
    s = drs()
    unmanaged = {"deviceId": DEVICE_ID, "displayName": "WS-1", "isManaged": None}
    out = settle(history, [s], {}, 3, [entry(0.2, name="WS-1")], unmanaged)
    assert out.hold == {s.id}
    out = settle(history, [], out.state, 35, [entry(0.2, name="WS-1")], unmanaged)
    assert [x.id for x in out.release] == [s.id] and out.matches[s.id].proof == "" and out.matches[s.id].device == "WS-1"
    rc = RuleContext.build(out.release, history, {}, T0 + timedelta(minutes=35))
    rc.registrations = out.matches
    f = next(f for f in rules.sensitive_app(rc) if "Device registration" in f.title)
    assert f.fields["Device"] == "WS-1" and "Enrolment" not in f.fields and f.score >= 25
    assert settle(history, [], out.state, 45).release == []                                # judged once


def test_a_windows_hello_key_is_settled_at_once(history):
    s = drs()
    out = settle(history, [s], {}, 3, [entry(0.2, "Add Windows Hello for Business credential")])
    assert out.hold == set() and out.matches[s.id].kind == registrations.HELLO and out.state == {}


def test_the_audit_watchs_record_of_a_proven_device_is_no_step_either():
    device = {linkify.DEVICE_ID_FIELD: DEVICE_ID}
    guessing = signin_alert("g", "distributed_attack", 50, 30, ANNA)
    registered = Finding(key="d", rule_id="device_registration", severity=Severity.LOW, score=30, title="x", signal="device_registered",
                         occurred_at=NOW - timedelta(hours=5), fields={"User": ANNA, **device}, subjects=[ANNA])
    policy = admin_change("c", "conditional_access", 55, 4, who=ANNA)
    proven = signin_alert("s", "sensitive_app", 5, 5, ANNA, Enrolment="Windows Autopilot, profile Corporate laptops", **device)
    chain = lambda *f: [x.fields["Chain"] for x in chains.chain_findings(center(*f).since(NOW - timedelta(days=30)), NOW)]  # noqa: E731
    assert chain(guessing, registered, policy) == ["Targeted -> Persistence -> Escalation"]
    assert chain(guessing, registered, policy, proven) == ["Targeted -> Escalation"]


# ------------------------------------------------------------- E: a role alert says which role, on what
def pim(i, kind, user, upn, role="Owner", scope="Contoso Production", scope_type="Subscription", who=ADMIN, minutes=0,
        category="ResourceManagement"):
    return {"id": f"p{i}{kind}", "activityDateTime": (NOW - timedelta(minutes=30 - minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "activityDisplayName": f"Add eligible member to role in PIM {kind} (timebound)", "category": category,
            "result": "success", "loggedByService": "PIM", "correlationId": f"c{i}",
            "initiatedBy": {"user": {"userPrincipalName": who, "id": "admin-id"}},
            "targetResources": [{"type": "Role", "displayName": role, "modifiedProperties": []},
                                {"type": scope_type, "displayName": scope}, {"type": scope_type, "displayName": scope},
                                {"type": "User", "id": user, "displayName": "x", "userPrincipalName": upn},
                                {"type": "Request", "displayName": "r"}, {"type": "Other", "displayName": "o"}],
            "additionalDetails": [{"key": "RoleAssignmentRequestId", "value": f"req-{i}"}]}


def test_the_role_and_what_it_is_on_are_read_from_a_pim_entry():
    a = pim(1, "completed", "u2", ANNA)
    assert da._role(a) == "Owner" and da._scope(a) == ("Azure subscription", "Contoso Production")
    score, factors = da.score_audit("role_assignment", a, [])
    assert score == 60 and any(p == 15 and "Owner" in t and "Contoso Production" in t for p, t in factors)
    reader = pim(2, "completed", "u2", ANNA, role="Reader")
    assert da.score_audit("role_assignment", reader, [])[0] == 45                  # a role that cannot hand out access
    directory = pim(3, "completed", "u2", ANNA, role="Global Administrator", scope="Contoso", scope_type="Directory",
                    category="RoleManagement")
    assert da._scope(directory) is None and da.score_audit("role_assignment", directory, [])[0] == 70   # a top directory role


class Graph:
    def __init__(self, events):
        self.events = events

    def get_all(self, path, params=None, max_pages=None):
        yield from self.events

    def get(self, path, params=None):
        raise RuntimeError(path)


def run_audit(tmp_path, events):
    pm = PluginManager(ConfigManager(tmp_path / "config.json"), Store(":memory:"), graph_factory=lambda: Graph(events),
                       user_dir=tmp_path / "x", stop_event=threading.Event())
    pm.discover()
    return pm.run("directory_audit")


def test_the_alert_names_role_and_scope_counts_each_assignment_once_and_says_who_gave_it_to_themselves(tmp_path):
    events = [pim(1, k, "u2", ANNA) for k in ("requested", "completed")] + [pim(2, k, "u3", BEN, scope="Contoso Test") for k in ("requested", "completed")]
    f = next(f for f in run_audit(tmp_path, events) if f.rule_id == "role_assignment")
    assert f.fields["Roles"] == "Owner on Contoso Production (Azure subscription), Owner on Contoso Test (Azure subscription)"
    assert "made 2 role assignment(s)" in f.summary and "4 change" not in f.summary
    assert f.fields["Done to"] == f"{ANNA}, {BEN}" and f.score == 60
    own = [pim(3, k, "admin-id", ADMIN) for k in ("requested", "completed")]
    g = next(f for f in run_audit(tmp_path / "b", own) if f.rule_id == "role_assignment")
    assert g.score == 65 and any("their own account" in t for _p, t in g.factors)
    assert "their own account" in g.summary
