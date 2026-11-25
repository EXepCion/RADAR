"""Search: one field that finds accounts, devices, IP addresses, applications, sign-ins and alerts in what RADAR has
stored - and the page about one account: who it is, what is open, its habits, what stands out, and a timeline."""
import re
from datetime import datetime, timedelta
from types import SimpleNamespace

from radar import geo, search, timefmt
from radar.plugin_api import Severity
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
from radar.plugins.signin_threats.history import SignInHistory
from radar.plugins.signin_threats.models import AccountChange

from conftest import T0, make_signin

NOW = T0 + timedelta(hours=2)
HOME = dict(country="CA", city="Toronto", ip="198.51.100.10", asn=812)
AWAY = dict(country="BR", city="Sao Paulo", ip="203.0.113.5", asn=64500, lat=-23.55, lon=-46.63)
LAPTOP = dict(device_id="11111111-2222-4333-8444-555555555555", device_name="ALICE-LAPTOP", trust_type="Azure AD joined",
              compliant=True, managed=True, os="Windows10")
DEVICE_SIGNIN = dict(incoming_token="primaryRefreshToken", auth_requirement="multiFactorAuthentication", token_protection="bound",
                     auth_methods=["Previously satisfied"], ca_status="success")
NAMES = {"812": {"n": "Example Telecom"}, "64500": {"n": "Example Hosting"}}


def directory():
    return AccountDirectory({a.user_id: a for a in (
        AccountInfo("u1", "alice@contoso.com", "Alice Example", last_signin="2025-01-01T00:00:00Z", mfa_methods=["Authenticator app"],
                    mfa_registered=True, pwd_changed="2024-09-12T08:00:00Z", created="2022-03-03T08:00:00Z", licenses=["SPE_E3"]),
        AccountInfo("u2", "adm-alice@contoso.com", "Alice Example (admin)", roles=["Global Administrator"]),
        AccountInfo("u3", "bob@contoso.com", "Bob Example", enabled=False),
    )})


def alert(alert_id, title, subject="alice@contoso.com", status="active", severity=Severity.MEDIUM, minutes=0, score=55, **fields):
    return SimpleNamespace(id=alert_id, title=title, summary=title + ".", subjects=[subject], fields=fields, severity=severity,
                           status=status, occurred_at=T0 + timedelta(minutes=minutes), last_seen=T0 + timedelta(minutes=minutes),
                           score=score, rule_id="new_country", plugin_id="signin_threats")


def usual(history, days=10):
    """Ten working days at home on the laptop, then - today - a guessed password and a sign-in from far away."""
    rows = []
    for d in range(days, 0, -1):
        rows += [make_signin(-d * 1440 + i * 5, **HOME, **LAPTOP, **DEVICE_SIGNIN, interactive=bool(i == 0), app="Office 365" if i < 3 else "Teams")
                 for i in range(5)]
    today = [make_signin(-30, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="home-today")]
    today += [make_signin(1 + i / 10, **AWAY, error_code=50126, failure_reason="Invalid username or password", id=f"guess{i}") for i in range(5)]
    today += [make_signin(3, **AWAY, id="away-ok", auth_requirement="multiFactorAuthentication", ca_status="success", token_protection="unbound",
                          auth_methods=["Password", "Mobile app notification"], risk_during="medium", session_id="sess-1",
                          correlation_id="99999999-aaaa-4bbb-8ccc-dddddddddddd", browser="Chrome 131", user_agent="Mozilla/5.0 Chrome/131")]
    today += [make_signin(5, **AWAY, id="blocked", app="Exchange Online", error_code=53003, ca_status="failure", failure_reason="Access has been blocked by Conditional Access policies")]
    history.add(rows + today)
    return history


# ------------------------------------------------------------------------------------------------ the field
def test_a_name_finds_the_account_its_devices_sign_ins_and_alerts(history):
    usual(history)
    alerts = [alert(1, "Sign-in from a new country: alice@contoso.com from Brazil"), alert(2, "Something about Bob", subject="bob@contoso.com")]
    r = search.search("alice", history, directory(), alerts, NOW)
    accounts = r.hits["account"]
    assert [h.title for h in accounts] == ["Alice Example", "Alice Example (admin)"]
    assert accounts[0].key == "u1" and "alice@contoso.com" in accounts[0].line and accounts[0].note == "1 open alert"
    assert accounts[1].note == "Global Administrator"
    assert [h.title for h in r.hits["device"]] == ["ALICE-LAPTOP"] and r.hits["device"][0].key == LAPTOP["device_id"]
    assert [h.key for h in r.hits["alert"]] == [1]
    assert r.counts["signin"] == history.count() and len(r.hits["signin"]) == 5          # the newest five, and how many there are
    assert r.hits["signin"][0].key == "blocked"
    assert r.total == 2 + 1 + 1 + history.count()


def test_what_is_typed_decides_what_is_looked_for(history):
    usual(history)
    d = directory()
    by_address = search.search("203.0.113", history, d, [], NOW)
    assert [h.title for h in by_address.hits["address"]] == ["203.0.113.5"] and "Sao Paulo" in by_address.hits["address"][0].line
    assert by_address.hits["account"] == [] and by_address.counts["signin"] == 7
    by_id = search.search("away-ok", history, d, [], NOW)
    assert [h.key for h in by_id.hits["signin"]] == ["away-ok"] and by_id.counts["signin"] == 1
    by_correlation = search.search("99999999-AAAA-4bbb-8ccc-dddddddddddd", history, d, [], NOW)       # any letter case
    assert [h.key for h in by_correlation.hits["signin"]] == ["away-ok"]
    by_device_id = search.search(LAPTOP["device_id"], history, d, [], NOW)
    assert [h.title for h in by_device_id.hits["device"]] == ["ALICE-LAPTOP"]
    by_app = search.search("exchange", history, d, [], NOW)
    assert [h.title for h in by_app.hits["application"]] == ["Exchange Online"] and by_app.counts["signin"] == 1
    assert search.search("teams", history, d, [], NOW).hits["application"][0].line.startswith("1 account")


def test_too_little_or_nothing_typed_finds_nothing_and_strange_input_breaks_nothing(history):
    usual(history)
    for text in ("", " ", "a", "%", "_", "'; drop table signins --", "\x00"):
        r = search.search(text, history, directory(), [], NOW)
        assert r.total == 0 or text == "%", text
    assert search.search("100%", history, directory(), [], NOW).total == 0     # a percent sign is a percent sign
    assert history.count() > 0


def test_several_words_must_all_occur(history):
    usual(history)
    d = directory()
    assert [h.key for h in search.search("alice admin", history, d, [], NOW).hits["account"]] == ["u2"]
    assert search.search("alice nobody", history, d, [], NOW).hits["account"] == []


# ------------------------------------------------------------------------------------------- one account
def view(history, alerts=(), incidents=()):
    return search.account_view("u1", history, directory(), list(alerts), list(incidents), NOW, NAMES)


def test_the_head_says_who_the_account_is(history):
    v = view(usual(history))
    assert (v.title, v.upn, v.enabled) == ("Alice Example", "alice@contoso.com", True)
    facts = dict((f.label, f.value) for f in v.facts)
    assert facts["Roles"] == "None" and facts["MFA methods"] == "Authenticator app"
    assert facts["Risk in Entra"] == "medium on a sign-in today" and facts["Password changed"] == "12.09.2024"
    assert re.search(timefmt.ZONE + "$", facts["Last sign-in"])                      # every time names its zone
    assert [f.label for f in v.facts if f.warn] == ["Risk in Entra"]
    assert [f.label for f in v.facts[:4]] == ["Risk in Entra", "MFA approved from", "Roles", "Last sign-in"]


def test_right_now_holds_what_is_open_and_nothing_else(history):
    usual(history)
    alerts = [alert(1, "Sign-in from a new country: Brazil", minutes=3), alert(2, "Old thing", status="dismissed", minutes=-9000),
              alert(3, "Somebody else", subject="bob@contoso.com")]
    v = view(history, alerts)
    assert [a.id for a in v.open_alerts] == [1] and v.earlier_alerts == 1 and v.risk == 55
    quiet = view(history, [alerts[1]])
    assert quiet.open_alerts == [] and quiet.risk is None


def test_habits_are_the_account_in_thirty_days_with_what_is_new(history):
    v = view(usual(history))
    kinds = {k.label: k.entries for k in v.habits}
    assert [(e.name, e.count, e.new) for e in kinds["Countries"]] == [(geo.country_name("CA"), 51, False), (geo.country_name("BR"), 1, True)]
    assert kinds["Countries"][1].ref == ("country", "BR")                    # (the name is shown, the code is what opens the page)
    assert [(e.name, e.new) for e in kinds["Networks"]] == [("Example Telecom", False), ("Example Hosting", True)]
    assert kinds["Networks"][0].ref == ("network", "812")
    assert [(e.name, e.ref) for e in kinds["Devices"]] == [("ALICE-LAPTOP", ("device", LAPTOP["device_id"]))]
    assert [(e.name, e.count) for e in kinds["Applications"]] == [("Office 365", 32), ("Teams", 20)]
    assert [k.label for k in v.habits] == ["Countries", "Networks", "Devices", "Applications", "How it signs in", "With what"]
    how = dict((e.name, e.count) for e in kinds["How it signs in"])
    assert how == {"Known device": 51, "MFA": 1, "Failed": 6}


def test_worth_a_look_counts_what_stands_out_and_can_name_the_sign_ins(history):
    v = view(usual(history))
    worth = {w.label: w for w in v.worth}
    assert worth["Entra saw risk on a sign-in"].count == 1 and worth["Entra saw risk on a sign-in"].ids == ["away-ok"]
    assert worth["Blocked by a policy"].ids == ["blocked"] and "Exchange Online" in worth["Blocked by a policy"].detail
    assert worth["Token not bound to a device"].count == 1
    assert "Password only, no MFA" not in worth and "Device code sign-in" not in worth          # nothing of it: no line
    # the timeline can show what an entry counts - also where a line stands for many sign-ins
    picked = [ln for ln in v.timeline if search.covers(ln, worth["Blocked by a policy"])]
    assert [ln.ref for ln in picked] == [("signin", "blocked")]
    history.add([make_signin(-2880 + 7, **HOME, **LAPTOP, **DEVICE_SIGNIN, interactive=False, risk_during="low", id="risky-in-a-run")])
    again = view(history)
    risk = next(w for w in again.worth if w.label == "Entra saw risk on a sign-in")
    assert risk.count == 2 and sorted(ln.count for ln in again.timeline if search.covers(ln, risk)) == [1, 6]
    assert view(history.__class__(":memory:")).worth == []


def test_the_timeline_is_everything_in_order_newest_first(history):
    usual(history)
    history.add_changes([AccountChange("c1", T0 + timedelta(minutes=6), "u1", "alice@contoso.com", "method_added",
                                       "User registered security info (Passkey)", "alice@contoso.com", False, "203.0.113.5")])
    v = view(history, [alert(1, "Sign-in from a new country: Brazil", minutes=3)])
    top = v.timeline[:5]
    assert [(ln.kind, ln.what) for ln in top] == [
        ("Change", "User registered security info (Passkey)"),
        ("Failed", "Exchange Online"),
        ("Alert", "Sign-in from a new country: Brazil"),
        ("Sign-in", "Office 365 · MFA by Mobile app notification"),
        ("Failed", "Office 365 · wrong password, 5 times in 1 minute")]
    assert top[1].marks == ["blocked by policy"] and top[3].marks == ["Entra risk: medium"]
    assert (top[3].place, top[3].ip, top[3].device) == ("Sao Paulo, BR", "203.0.113.5", "") and top[3].ref == ("signin", "away-ok")
    assert top[0].ip == "203.0.113.5" and top[2].ref == ("alert", 1) and top[4].count == 5
    assert all(a.when >= b.when for a, b in zip(v.timeline, v.timeline[1:]))
    # a day at home is one line that says how many sign-ins it stands for
    day = next(ln for ln in v.timeline if ln.count == 5 and ln.kind == "Sign-in")
    assert "5 sign-ins until" in day.what and day.device == "ALICE-LAPTOP" and day.ref[0] == "signin"
    assert v.counts == {"Sign-in": 52, "Failed": 6, "Change": 1, "Alert": 1}


def test_guessing_from_many_addresses_is_one_line_and_being_asked_for_mfa_is_no_failure(history):
    usual(history)
    spray = [make_signin(30 + i / 4, country="NL", city="Amsterdam", ip=f"203.0.113.{100 + i}", asn=64500, error_code=50053,
                         failure_reason="The account is locked", id=f"spray{i}") for i in range(40)]
    asked = [make_signin(60, **HOME, **LAPTOP, error_code=50074, failure_reason="Strong Authentication is required.", id="asked"),
             make_signin(61, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="asked-and-in")]      # (asked, answered, signed in: the usual)
    history.add(spray + asked)
    v = view(history)
    line = next(ln for ln in v.timeline if ln.kind == "Failed")
    assert (line.kind, line.count, line.ip) == ("Failed", 40, "") and line.what == "Office 365 · locked out, 40 times in 10 minutes from 40 addresses"
    assert v.counts["Failed"] == 46 and not any(ln.ref == ("signin", "asked") for ln in v.timeline)
    assert len([ln for ln in v.timeline if ln.kind == "Failed"]) == 3
    # attempts spread over the day are still one line: it says over how long
    slow = [make_signin(-4320 + i * 120, country="NL", city="Amsterdam", ip="203.0.113.200", asn=64500, error_code=50053, id=f"slow{i}") for i in range(4)]
    history.add(slow)
    spread = [ln.what for ln in view(history).timeline if ln.count == 4]
    assert spread == ["Office 365 · locked out, 4 times over 6 hours"]


def test_a_sign_in_that_stopped_at_the_mfa_prompt_is_shown_unless_one_that_worked_followed(history):
    """Being asked for MFA is a step of an ordinary sign-in - but with a stolen password it is where the thief stops:
    the first step passed, the prompt was never answered, and nothing follows. That must not be invisible."""
    usual(history)
    asked = dict(error_code=50074, failure_reason="Strong Authentication is required.")
    history.add([make_signin(60, **HOME, **LAPTOP, **asked, id="asked"),
                 make_signin(61, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="asked-and-in"),
                 make_signin(70, **AWAY, **asked, id="stopped1"),
                 make_signin(71, **AWAY, error_code=50076, failure_reason="MFA is required because of the location.", id="stopped2"),
                 make_signin(80, country="NL", city="Amsterdam", ip="203.0.113.77", asn=64500, error_code=50079,
                             failure_reason="The user is required to enrol for MFA.", id="enrol")])
    v = view(history)
    stopped = [ln for ln in v.timeline if "MFA" in ln.what and ln.kind == "Failed"]
    assert [(ln.what, ln.ip, ln.count) for ln in stopped] == [
        ("Office 365 · MFA has to be set up first, stopped there", "203.0.113.77", 1),
        ("Office 365 · stopped at the MFA prompt, 2 times in 1 minute", AWAY["ip"], 2)]
    assert stopped[1].ids == {"stopped1", "stopped2"} and not any("asked" in ln.ids for ln in v.timeline)
    assert v.counts["Failed"] == 6 + 3
    worth = {w.label: (w.count, sorted(w.ids)) for w in v.worth}
    assert worth["Stopped at the MFA prompt, nothing followed"] == (3, ["enrol", "stopped1", "stopped2"])
    # ... on the page about the address it came from, where it stands under what the address is seen with
    address = search.thing_view("address", AWAY["ip"], history, directory(), [], [], NOW, NAMES)
    assert any(ln.what == "Office 365 · stopped at the MFA prompt, 2 times in 1 minute" for ln in address.timeline)
    assert ("Stopped at MFA", 2) in [(e.name, e.count) for k in address.habits if k.label == "Results" for e in k.entries]
    assert any(w.label == "Stopped at the MFA prompt, nothing followed" and w.count == 2 for w in address.worth)
    # ... and in the list of sign-ins a search finds
    found = [ln.what for ln in search.signin_list("alice", history, directory(), NOW)]
    assert "Office 365 · stopped at the MFA prompt, 2 times in 1 minute" in found
    assert len([w for w in found if "MFA prompt" in w or "set up first" in w]) == 2
    # a success from somewhere else does not vouch for it: the owner working at home is not the one at the prompt
    history.add([make_signin(72, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="owner-at-home")])
    assert any("stopped at the MFA prompt, 2 times" in ln.what for ln in view(history).timeline)


def test_a_line_unfolds_into_how_with_what_and_which_session(history):
    v = view(usual(history))
    line = next(ln for ln in v.timeline if ln.ref == ("signin", "away-ok"))
    detail = dict(search.unfold(history, line))
    assert detail["How"] == "Password, then Mobile app notification · all policies passed"
    assert detail["With"] == "Chrome 131 · Browser · the token is not bound to a device"
    assert "session sess-1" in detail["Session"] and "99999999-aaaa" in detail["Session"]
    # a line that stands for a day of background sign-ins opens too, although its sign-ins are no longer stored one by one
    day = next(ln for ln in v.timeline if ln.count == 5 and ln.kind == "Sign-in")
    history.conn.execute("DELETE FROM signins WHERE id=?", (day.ref[1],))
    assert dict(search.unfold(history, day))["With"].endswith("the token is bound to the device")


ZURICH = dict(country="CH", city="Zurich", ip="203.0.113.70", asn=64501, lat=47.37, lon=8.54)
DALLAS = dict(country="US", city="Dallas", asn=64502, lat=32.78, lon=-96.80)
PHONE = dict(os="iOS 18.1", browser="Mobile Safari 18.1")


def travels(history):
    """The usual days at home - and Alice's trip, with her laptop and her phone (an iPhone that is not registered):
    three days ago both in Dallas for some hours; an hour ago the laptop in Zurich for some minutes, and the phone there
    too."""
    usual(history)
    day = 1440
    history.add([make_signin(-3 * day + 300, **DALLAS, ip="2001:db8:a:b::10", **LAPTOP, **DEVICE_SIGNIN, id="dallas-laptop-1"),
                 make_signin(-3 * day + 310, **DALLAS, ip="2001:db8:a:b::20", **PHONE, id="dallas-phone-1"),
                 make_signin(-3 * day + 480, **DALLAS, ip="2001:db8:a:b::10", **LAPTOP, **DEVICE_SIGNIN, id="dallas-laptop-2"),
                 make_signin(-3 * day + 485, **DALLAS, ip="2001:db8:a:b::21", **PHONE, id="dallas-phone-2"),
                 make_signin(-60, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="before-zurich"),
                 make_signin(-46, **ZURICH, **LAPTOP, **DEVICE_SIGNIN, id="zurich-1"),
                 make_signin(-44, **ZURICH, **LAPTOP, **DEVICE_SIGNIN, id="zurich-2"),
                 make_signin(-40, **ZURICH, **PHONE, id="phone-zurich"),
                 make_signin(-20, **HOME, **LAPTOP, **DEVICE_SIGNIN, id="after-zurich")])
    return history


def moves(*signins, settings=None):
    """The movement of an account that made these sign-ins (and nothing else)."""
    h = SignInHistory(":memory:")
    h.add(list(signins))
    try:
        return search.account_view("u1", h, directory(), [], [], NOW, NAMES, settings=settings).movement
    finally:
        h.close()


def test_movement_is_a_lane_for_every_device_with_its_stays_at_places(history):
    """Where the account's devices were in the last days: every device - the managed laptop, the phone nobody manages,
    the sign-ins that name no device - each as its stays at one place in the order of time. A silence of more than
    four hours ends a stay."""
    m = view(travels(history)).movement
    assert [(lane.name, lane.kind) for lane in m.lanes] == [
        ("ALICE-LAPTOP", "work computer, managed"), ("Phone", "iOS, not managed"), ("No device", "the sign-ins name none")]
    laptop, phone, nothing = m.lanes
    assert laptop.key == LAPTOP["device_id"] and phone.key == "os:iOS" and nothing.key == ""
    label = {p.key: p.label for p in m.places}
    where = [label[r.place] for r in laptop.runs]
    assert where[-3:] == ["Toronto, CA", "Zurich, CH", "Toronto, CA"] and where.count("Dallas, US") == 1   # (three days ago: one stay of three hours)
    dallas = next(r for r in laptop.runs if label[r.place] == "Dallas, US")
    assert dallas.end - dallas.begin == timedelta(hours=3) and where[where.index("Dallas, US") - 1] == "Toronto, CA"
    days = [r for r in laptop.runs if label[r.place] == "Toronto, CA"]
    assert len(days) >= 6 and all(r.begin <= r.end for r in laptop.runs)                     # every day at home a stay of its own
    assert all(a.end <= b.begin for a, b in zip(laptop.runs, laptop.runs[1:]))              # in the order of time
    zurich = laptop.runs[-2]
    assert (zurich.end - zurich.begin, zurich.network) == (timedelta(minutes=2), "AS64501")
    assert [(label[r.place], r.network) for r in nothing.runs] == [("Sao Paulo, BR", "Example Hosting")]
    assert [label[r.place] for r in phone.runs] == ["Dallas, US", "Zurich, CH"]
    # the places: the one the devices spent most time at first (the colours are given in that order) - here the six hours
    # of laptop and phone in Dallas, before twenty minutes a day at home
    assert [p.label for p in m.places] == ["Dallas, US", "Toronto, CA", "Zurich, CH", "Sao Paulo, BR"]
    assert [p.short for p in m.places] == ["Dallas", "Toronto", "Zurich", "Sao Paulo"]
    assert m.since.astimezone().time() == datetime.min.time() and (m.now - m.since) < timedelta(days=7) and m.now == NOW
    assert all(r.begin >= m.since for lane in m.lanes for r in lane.runs)                   # (nothing older than the card reaches)


def test_movement_needs_two_places_and_leaves_out_what_is_no_device_of_the_account():
    at_home = [make_signin(-30 - i * 60, **HOME, **LAPTOP, **DEVICE_SIGNIN) for i in range(5)]
    assert moves(*at_home) is None                                                           # one place all week: no movement
    # a service acting for the account is no device of it - wherever its servers are
    service = make_signin(-25, **AWAY, client_credential="clientAssertion", app="Some service")
    assert moves(*at_home, service) is None
    # ... and a phone nobody manages is a device like any other
    phone = make_signin(-25, **ZURICH, **PHONE)
    m = moves(*at_home, phone)
    assert [lane.name for lane in m.lanes] == ["ALICE-LAPTOP", "Phone"] and [p.label for p in m.places] == ["Toronto, CA", "Zurich, CH"]
    # an office is named as the office
    m = moves(*at_home, make_signin(-25, **ZURICH, **LAPTOP, **DEVICE_SIGNIN),
              settings={"offices": [{"name": "Zurich office", "city": "Zurich", "country": "CH", "ips": [ZURICH["ip"]]}]})
    office = next(p for p in m.places if p.key.startswith("office:"))
    assert (office.label, office.short) == ("Zurich office", "Zurich office") and m.lanes[0].runs[-1].network == "office network"
    # a stay goes on through a silence of up to four hours, and ends with a longer one
    m = moves(make_signin(-600, **HOME, **LAPTOP), make_signin(-400, **HOME, **LAPTOP), make_signin(-100, **HOME, **LAPTOP), phone)
    assert [(r.begin, r.end) for r in m.lanes[0].runs] == [(T0 - timedelta(minutes=600), T0 - timedelta(minutes=400)),
                                                            (T0 - timedelta(minutes=100), T0 - timedelta(minutes=100))]


def test_sign_ins_per_day_the_level_of_the_risk_and_where_an_alert_points(history):
    usual(history)
    a = alert(1, "Sign-in from a new country: Brazil", minutes=3, Country="BR", Device="iPhone", **{"IP address": "203.0.113.5 (Example Hosting)"})
    v = view(history, [a])
    assert len(v.per_day) == search.DAYS and v.per_day[-1] == 2 and v.per_day[-2] == 5 and sum(v.per_day) == 52
    assert (v.risk, v.risk_level) == (55, "Medium")
    line = next(ln for ln in v.timeline if ln.kind == "Alert")
    assert (line.place, line.ip, line.device) == ("BR", "203.0.113.5", "iPhone")


def test_the_list_of_sign_ins_a_search_found(history):
    usual(history)
    lines = search.signin_list("alice", history, directory(), NOW)
    assert [(ln.kind, ln.what, ln.account) for ln in lines[:3]] == [
        ("Failed", "Exchange Online", "Alice Example"),
        ("Sign-in", "Office 365 · MFA by Mobile app notification", "Alice Example"),
        ("Failed", "Office 365 · wrong password, 5 times in 1 minute", "Alice Example")]
    assert lines[0].marks == ["blocked by policy"] and lines[1].ref == ("signin", "away-ok") and len(lines) == 54
    assert [ln.ref for ln in search.signin_list("away-ok", history, directory(), NOW)] == [("signin", "away-ok")]
    assert search.signin_list("a", history, directory(), NOW) == []


def test_an_account_radar_has_never_seen_is_still_a_page(history):
    v = search.account_view("nobody", history, directory(), [], [], NOW, NAMES)
    assert v.title == "nobody" and v.facts == [] and v.timeline == [] and v.habits == [] and v.worth == []
