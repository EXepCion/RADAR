"""The pages about a device, an IP address, a network, a country and an application: built like the account's page -
what it is, what is open, what it is seen with, what stands out, and a timeline that says whose each sign-in is."""
from datetime import timedelta

from radar import geo, search

from conftest import T0, make_signin
from test_search import AWAY, HOME, LAPTOP, NAMES, NOW, alert, directory, usual


def crowd(history):
    """The usual data, and Bob being guessed at from the same far-away address - without success."""
    usual(history)
    history.add([make_signin(2 + i / 10, user_id="u3", upn="bob@contoso.com", **AWAY, error_code=50126, id=f"bob{i}") for i in range(3)])
    return history


def thing(history, kind, key, alerts=()):
    return search.thing_view(kind, key, history, directory(), list(alerts), [], NOW, NAMES)


def kinds(view):
    return {k.label: [(e.name, e.count, e.new) for e in k.entries] for k in view.habits}


def test_an_address_says_who_came_from_it_and_what_came_of_it(history):
    v = thing(crowd(history), "address", "203.0.113.5", [alert(1, "Sign-in from a new country: Brazil", minutes=3, **{"IP address": "203.0.113.5"})])
    assert (v.kind, v.title, v.habits_title) == ("address", "203.0.113.5", "Seen with")
    assert v.upn == "Sao Paulo, BR · Example Hosting" and ("First seen today", True) in v.tags
    facts = dict((f.label, f.value) for f in v.facts)
    assert facts["Accounts"] == "2" and facts["Sign-ins"] == "10 · 9 failed" and facts["Network"] == "Example Hosting"
    seen = kinds(v)
    assert seen["Accounts"] == [("Alice Example", 1, False)] and list(seen) == ["Accounts", "Applications", "Results"]
    assert seen["Results"] == [("Success", 1, False), ("Wrong password", 8, False), ("Blocked by a policy", 1, False)]
    worth = {w.label: w for w in v.worth}
    assert worth["Wrong password, then a success"].ids == ["away-ok"] and "Alice Example" in worth["Wrong password, then a success"].detail
    assert worth["Only failed sign-ins for an account"].detail == "1 account" and worth["Only failed sign-ins for an account"].count == 3
    assert worth["Sign-ins without a device"].count == 1 and "Entra saw risk on a sign-in" in worth
    assert [a.id for a in v.open_alerts] == [1] and v.risk == 55
    # the timeline: newest first, every sign-in with its account; guessing at two accounts on one day is one line
    assert [(ln.kind, ln.account) for ln in v.timeline[:3]] == [("Failed", "Alice Example"), ("Alert", ""), ("Sign-in", "Alice Example")]
    guessing = next(ln for ln in v.timeline if ln.count == 8)
    assert guessing.what == "Office 365 · wrong password, 8 times in 2 minutes against 2 accounts" and guessing.account == ""
    assert v.counts == {"Sign-in": 1, "Failed": 9, "Alert": 1}


def test_a_device_says_whose_it_is_and_where_it_is_used(history):
    v = thing(crowd(history), "device", LAPTOP["device_id"])
    assert v.title == "ALICE-LAPTOP" and v.upn == "Windows10 · Azure AD joined"
    assert v.tags == [("Compliant", False), ("Managed", False)] and v.open_alerts == [] and v.risk is None
    seen = kinds(v)
    assert seen["Accounts"] == [("Alice Example", 51, False)] and seen["Networks"] == [("Example Telecom", 51, False)]
    assert seen["Applications"][0][0] == "Office 365" and v.habits[0].entries[0].ref == ("account", "u1")
    assert dict((f.label, f.value) for f in v.facts)["Device ID"] == LAPTOP["device_id"] and v.worth == []
    day = next(ln for ln in v.timeline if ln.count == 5)
    assert day.account == "Alice Example" and day.user_id == "u1" and "5 sign-ins until" in day.what


def test_a_network_a_country_and_an_application(history):
    crowd(history)
    net = thing(history, "network", "64500")
    assert net.title == "Example Hosting" and net.upn == "AS64500 · BR" and kinds(net)["Addresses"] == [("203.0.113.5", 1, False)]
    assert dict((f.label, f.value) for f in net.facts)["Addresses"] == "1"
    country = thing(history, "country", "BR")
    assert country.title == geo.country_name("BR") and country.key == "BR" and country.upn == "Sao Paulo"
    assert kinds(country)["Networks"] == [("Example Hosting", 1, False)]
    assert country.open_alerts == []                               # (a country's code is in too many texts to tell alerts by it)
    app = thing(history, "application", "Exchange Online")
    assert app.title == "Exchange Online" and app.counts["Failed"] == 1 and [w.label for w in app.worth] == ["Blocked by a policy"]
    # an application a device uses in the background: who uses it and how often comes from the accounts' profiles
    teams = thing(history, "application", "Teams")
    assert teams.counts == {"Sign-in": 20, "Failed": 0, "Alert": 0} and kinds(teams)["Accounts"] == [("Alice Example", 20, False)]
    assert kinds(teams)["Countries"] == [(geo.country_name("CA"), 20, False)] and dict((f.label, f.value) for f in teams.facts)["Accounts"] == "1"
    assert ("People sign in to it", False) in teams.tags
    # what kind of network it is, is said where RADAR knows it
    history.add([make_signin(9, user_id="u3", upn="bob@contoso.com", country="NL", city="Amsterdam", ip="198.51.100.200", asn=14061, error_code=50126, id="do1")])
    assert ("Hosting provider", True) in thing(history, "network", "14061").tags and ("Hosting provider", True) in thing(history, "address", "198.51.100.200").tags
    assert thing(history, "network", "64500").tags == [("First seen today", True)]


def test_an_alert_belongs_to_a_page_only_when_it_names_the_thing_as_a_whole(history):
    """A network's number, a short address or a short name can occur inside something else - a longer address, a
    score, an id. Such an alert is somebody else's: it must not stand under "Right now" or set the page's risk."""
    crowd(history)
    strangers = [alert(1, "Sign-in from 1203.0.113.50 is not this address", **{"IP address": "203.0.113.55"}),
                 alert(2, "Risk score 64500 and id 9-64500-1"), alert(3, "Network AS645001 looks odd"),
                 alert(4, "About x203.0.113.5y"), alert(5, "Somebody on ALICE-LAPTOP-2"), alert(6, "Exchange Online Protection changed")]
    assert thing(history, "address", "203.0.113.5", strangers).open_alerts == []
    assert thing(history, "network", "64500", strangers).open_alerts == []
    assert thing(history, "device", LAPTOP["device_id"], strangers).open_alerts == []
    own = [alert(7, "Sign-in from 203.0.113.5."), alert(8, "Guessing", **{"IP addresses": "198.51.100.1, 203.0.113.5"}),
           alert(9, "Hosting network Example Hosting (AS64500)"), alert(10, "New device", Device="ALICE-LAPTOP", **{"_Device ID": LAPTOP["device_id"]}),
           alert(11, "Consent for Exchange Online", subject="app:exchange online")]
    assert [a.id for a in thing(history, "address", "203.0.113.5", own + strangers).open_alerts] == [7, 8]
    # (an alert about one of the network's addresses is about the network too)
    assert sorted(a.id for a in thing(history, "network", "64500", own + strangers).open_alerts) == [7, 8, 9]
    assert [a.id for a in thing(history, "device", LAPTOP["device_id"], own + strangers).open_alerts] == [10]
    assert [a.id for a in thing(history, "application", "Exchange Online", own + strangers).open_alerts] == [11]
    assert search.names_it(own[0], "") is False and search.names_it(own[0], "5") is False        # too short to mean anything


def test_something_radar_has_never_seen_is_an_empty_page_and_strange_keys_break_nothing(history):
    usual(history)
    for kind, key in (("device", "no-such-device"), ("address", "192.0.2.1"), ("network", "not-a-number"), ("country", "'; --"), ("application", "%")):
        v = thing(history, kind, key)
        assert v.timeline == [] and v.facts == [] and v.habits == [] and v.title, (kind, key)
    assert history.count() > 0
