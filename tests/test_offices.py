"""Offices: the structure, the old labelled trusted IPs it replaces, validation, and what the rules trust."""
from datetime import timedelta

import tkinter as tk

import pytest
from conftest import T0, make_signin

from radar.mapview import data
from radar.plugins.signin_threats import offices
from radar.plugins.signin_threats.offices import Office
from radar.plugins.signin_threats.rules import RuleContext

OLD = {"trusted_ips": {"203.0.113.5": "CA office (HQ Toronto)", "203.0.113.6": "CA office (HQ Toronto)",
                       "198.51.100.9": "UK office (London)", "192.0.2.1": "SG office", "192.0.2.200": ""}}


def test_old_labels_are_understood_as_offices():
    assert offices.parse_label("CA office (HQ Toronto)") == ("CA office", "Toronto", True)
    assert offices.parse_label("UK office (London)") == ("UK office", "London", False)
    assert offices.parse_label("SG office") == ("SG office", "", False)
    found = {o.name: o for o in offices.load(OLD)}
    assert set(found) == {"CA office", "UK office", "SG office"}  # the unlabelled trusted IP is no office
    assert found["CA office"].hq and found["CA office"].city == "Toronto" and len(found["CA office"].ips) == 2
    assert not offices.configured(OLD)
    assert offices.trusted_map(OLD) == OLD["trusted_ips"]  # nothing changes for the rules until the offices are saved


def test_saving_moves_office_addresses_out_of_trusted_ips_and_the_rules_still_trust_them(history):
    edited = offices.load(OLD)
    next(o for o in edited if o.name == "UK office").country = "GB"
    saved = offices.save_into(OLD, edited)
    assert saved["trusted_ips"] == {"192.0.2.200": ""}  # other trusted addresses stay
    assert offices.configured(saved) and [o["name"] for o in saved["offices"]] == ["CA office", "UK office", "SG office"]
    assert offices.trusted_map(saved)["203.0.113.6"] == "CA office" and "192.0.2.200" in offices.trusted_map(saved)
    rc = RuleContext.build([], history, saved, T0)
    office = make_signin(ip="203.0.113.6")
    assert rc.trusted(office) and rc.trusted_label(office) == "CA office"
    assert rc.trusted(make_signin(ip="192.0.2.200")) and not rc.trusted(make_signin(ip="192.0.2.77"))
    again = offices.load(saved)
    assert [(o.name, o.city, o.country, o.hq) for o in again][:2] == [("CA office", "Toronto", "", True), ("UK office", "London", "GB", False)]
    removed = offices.save_into(saved, [o for o in again if o.name != "SG office"])
    assert "192.0.2.1" not in offices.trusted_map(removed)  # a removed office is no longer trusted


def test_validation_names_what_to_fix():
    ok = [Office("CA office", "Toronto", "CA", True, ["203.0.113.5", "2001:db8:12::/48"]), Office("UK office", ips=["198.51.100.0/28"])]
    assert offices.validate(ok) == []
    bad = offices.validate([
        Office("CA office", hq=True, ips=["203.0.113.5", "not-an-ip", "10.0.0.5", "8.0.0.0/8"]),
        Office("ca office", hq=True, ips=["203.0.113.5"], lat=43.7),
        Office("", ips=["192.0.2.1"]), Office("Empty")])
    text = " | ".join(bad)
    for expected in ("'not-an-ip' is not an IP", "private address", "very large range", "Two offices are called", "both CA office and ca office",
                     "both latitude and longitude", "needs a name", "Empty: add at least one IP", "Only one office can be the headquarters"):
        assert expected in text, expected


def test_map_uses_the_configured_position_and_fills_a_missing_city_from_the_signins(history):
    settings = {"offices": [{"name": "UK office", "ips": ["198.51.100.9"]},
                            {"name": "US office", "city": "Chicago", "country": "US", "ips": ["192.0.2.1"], "lat": 41.9, "lon": -87.7}]}
    history.add([
        make_signin(10, user_id="u1", ip="198.51.100.9", city="London", country="GB", lat=51.51, lon=-0.13),
        make_signin(20, user_id="u2", ip="192.0.2.1", city="Chicago", country="US", lat=41.88, lon=-87.63),
    ])
    places = {p["label"]: p for p in data.build_snapshot(history, settings, None, T0 + timedelta(hours=1))["places"]}
    assert (places["UK office"]["city"], places["UK office"]["country"], places["UK office"]["lat"]) == ("London", "GB", 51.51)
    assert (places["US office"]["city"], places["US office"]["lat"], places["US office"]["lon"]) == ("Chicago", 41.9, -87.7)
    assert not places["UK office"]["hq"]


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    yield r
    r.destroy()


def test_offices_window_edits_validates_and_saves(root):
    from radar.ui import theme
    from radar.ui.offices import OfficesWindow

    theme.init(root)
    saved = []
    win = OfficesWindow(root, None, offices.load(OLD), lambda items: saved.append(items))
    root.update()
    assert [win.tree.set(i, "Office") for i in win.tree.get_children()] == ["CA office", "UK office", "SG office"]
    assert win.tree.set("0", "HQ") == "HQ" and win.vars["city"].get() == "Toronto"  # the first office is selected
    win.tree.selection_set("1")
    root.update()
    win.vars["country"].set("gb")
    win.hq.set(True)
    win._edited()
    assert win.offices[1].country == "GB" and win.offices[1].hq and not win.offices[0].hq  # one headquarters
    assert win.tree.set("0", "HQ") == "" and win.tree.set("1", "HQ") == "HQ"
    win.ips.insert("end", "\nnot-an-ip")
    win._edited()
    win.save()
    assert not saved and "not-an-ip" in win.status.cget("text") and win.exists()  # nothing is saved with a mistake in it
    win.ips.delete("1.0", "end")
    win.ips.insert("1.0", "198.51.100.9\n198.51.100.0/28")
    win._edited()
    win.show_suggestions([{"ip": "192.0.2.44", "users": 17, "city": "Madrid", "country": "ES", "network": ""}])
    win.suggest.selection_set("0")
    win._use_suggestion(new=True)
    assert win.offices[-1].name == "Madrid office" and win.offices[-1].ips == ["192.0.2.44"]
    assert not win.suggest.get_children()
    win.save()
    assert len(saved) == 1 and not win.exists()
    names = {o.name: o for o in saved[0]}
    assert names["UK office"].ips == ["198.51.100.9", "198.51.100.0/28"] and names["Madrid office"].country == "ES"


def test_offices_window_first_time_starts_empty_with_a_hint(root):
    from radar.ui import theme
    from radar.ui.offices import OfficesWindow

    theme.init(root)
    win = OfficesWindow(root, None, [], lambda items: None, first_time=True)
    root.update()
    assert "No office yet" in win.status.cget("text") and str(win.entries["name"].cget("state")) == "disabled"
    win.add()
    assert win.offices and str(win.entries["name"].cget("state")) == "normal"
    win.top.destroy()
