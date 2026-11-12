"""Virtual desktops / shared hosts: matching, detection from the sign-ins, effect on map and location rules, window."""
import tkinter as tk
from datetime import timedelta

import pytest
from conftest import T0, make_signin

from radar.mapview import data
from radar.plugins.signin_threats import hosts, presence, rules
from radar.plugins.signin_threats.rules import RuleContext

OFFICES = [{"name": "Toronto office", "city": "Toronto", "country": "CA", "hq": True, "ips": ["203.0.113.5"]}]
JOINED = dict(os="Windows10", trust_type="Azure AD joined", compliant=True, managed=True)
CITRIX = dict(ip="203.0.113.5", asn=812, device_id="cx1", device_name="TOR-CTX-01", **JOINED)
AZURE_ASN = next(asn for asn, (name, category) in __import__(
    "radar.plugins.signin_threats.netintel", fromlist=["KNOWN_ASNS"]).KNOWN_ASNS.items() if category == "cloud")


def test_matcher_by_name_pattern_and_ip_range():
    m = hosts.HostMatcher([{"match": "tor-ctx-*", "label": "Citrix"}, {"match": "20.50.10.0/28", "label": "AVD"},
                           {"match": "cloud-vm-01", "label": ""}])
    assert m.label(make_signin(device_name="TOR-CTX-01")) == "Citrix"  # any case
    assert m.label(make_signin(device_name="", ip="20.50.10.7")) == "AVD"
    assert m.label(make_signin(device_name="CLOUD-VM-01")) == "virtual desktop"
    assert make_signin(device_name="LT-TOR-00101", ip="198.51.100.1") not in m
    assert not hosts.HostMatcher([]) and bool(m)
    assert hosts.load({"virtual_desktops": ["TOR-CTX-*", {"match": " US-CX-* ", "label": "Citrix"}, {"match": ""}]}) == [
        {"match": "TOR-CTX-*", "label": ""}, {"match": "US-CX-*", "label": "Citrix"}]


def test_validation():
    assert hosts.validate([{"match": "TOR-CTX-*"}, {"match": "20.50.10.0/28"}, {"match": "cloud-vm-01"}]) == []
    text = " | ".join(hosts.validate([{"match": "*"}, {"match": "CX"}, {"match": "20.50.10.999"}, {"match": "tor-ctx-*"},
                                      {"match": "TOR-CTX-*"}, {"match": ""}]))
    for expected in ("'*' would match almost every device", "'CX' would match", "looks like an IP address", "listed twice",
                     "needs a device name"):
        assert expected in text, expected


def signins():
    out = []
    for i, user in enumerate(["u1", "u2", "u3", "u4"]):  # four people on the Citrix host at the same time
        out.append(make_signin(i, user_id=user, upn=f"{user}@contoso.com", **CITRIX))
    for i, user in enumerate(["u1", "u2", "u3"]):  # a shop-floor PC: three people, but one after the other
        out.append(make_signin(i * 300, user_id=user, ip="203.0.113.5", device_id="pc1", device_name="LT-PC-0200", **JOINED))
    out.append(make_signin(5, user_id="u5", ip="192.0.2.9", asn=AZURE_ASN, city="Dublin", country="IE", device_id="vm1",
                           device_name="cloud-vm-01", **JOINED))  # a managed machine in Azure
    out.append(make_signin(6, user_id="u1", device_id="nb1", device_name="LT-TOR-00101", **JOINED))  # an ordinary laptop
    for user in ("u1", "u2", "u3"):  # phones share model names: never a host
        out.append(make_signin(7, user_id=user, device_id=f"p{user}", device_name="iPhone", os="Ios"))
    return out


def suggest(settings):
    return hosts.suggest(signins(), settings, lambda s: "Toronto office" if s.ip == "203.0.113.5" else None,
                         lambda s: presence.device_class(s) == presence.SERVICE)


def test_suggestions_find_session_hosts_and_cloud_machines_but_not_shared_pcs_or_phones():
    found = {c["name"]: c for c in suggest({})}
    assert set(found) == {"TOR-CTX-01", "cloud-vm-01"}
    cx = found["TOR-CTX-01"]
    assert (cx["users"], cx["together"], cx["where"], cx["label"]) == (4, 4, "Toronto office", "Citrix")
    assert cx["why"] == "4 accounts, up to 4 at the same time"
    assert found["cloud-vm-01"]["why"] == "a managed machine that signs in from a cloud data centre"
    assert found["cloud-vm-01"]["label"].endswith("virtual machine")
    # once configured (here by pattern) it is not proposed again
    assert [c["name"] for c in suggest({"virtual_desktops": [{"match": "tor-ctx-*"}]})] == ["cloud-vm-01"]


def test_map_does_not_place_people_by_a_virtual_desktop(history):
    """Remote people on the Citrix host in the office are not 'in the office'."""
    home = dict(ip="198.51.100.80", asn=6830, city="Lyon", country="FR", lat=45.76, lon=4.84)
    history.add([
        make_signin(10, user_id="u1", user_name="Rosa", device_id="nb1", device_name="FR-NB-1", **dict(JOINED, **home)),
        make_signin(20, user_id="u1", user_name="Rosa", interactive=False, **CITRIX),  # her session on the Citrix host
        make_signin(25, user_id="u2", user_name="Omar", interactive=False, **CITRIX),  # only the Citrix session is seen
    ])
    now = T0 + timedelta(minutes=40)
    plain = data.build_snapshot(history, {"offices": OFFICES}, None, now)
    # not configured: Omar, seen only on the Citrix host, looks like he is in the office. (Rosa is placed at home
    # anyway - her laptop is the computer she signed in to by hand, the host session only runs in the background.)
    assert {p["name"]: p["place"] for p in plain["people"]} == {"Rosa": "city:Lyon|FR", "Omar": "office:Toronto office"}
    assert plain["host_suggestions"] == 0  # (two accounts are not enough to propose it)

    snap = data.build_snapshot(history, {"offices": OFFICES, "virtual_desktops": [{"match": "TOR-CTX-*", "label": "Citrix"}]}, None, now)
    rosa = snap["people"][0]
    assert rosa["place"] == "city:Lyon|FR" and rosa["also"] == ["Working on Citrix TOR-CTX-01 (in Toronto office)"]
    omar = snap["unlocated"][0]
    assert omar["name"] == "Omar" and omar["precision"] == "virtual" and "Only seen on Citrix TOR-CTX-01" in omar["how"]
    assert snap["stats"]["in_office"] == 0 and snap["stats"]["unlocated"] == 1
    detail = data.person_detail(history, {"offices": OFFICES, "virtual_desktops": [{"match": "TOR-CTX-*", "label": "Citrix"}]}, None, now, "u1")
    assert [(d["name"], d["class"]) for d in detail["devices"]] == [("FR-NB-1", "work computer"), ("TOR-CTX-01", "virtual desktop")]
    assert [h["label"] for h in detail["hops"]] == ["Lyon, FR"]  # the host is no stop on the trail


def test_location_rules_ignore_virtual_desktops_in_a_data_centre(history):
    """A session on a virtual machine in Azure Dublin, minutes after a sign-in at home, is not travel / a new country."""
    home = dict(ip="198.51.100.80", asn=6830, city="Toronto", country="CA", lat=43.65, lon=-79.38)
    base = [make_signin(-60 * 24 * d, user_id="u1", **home) for d in range(1, 8)]
    vm = make_signin(30, user_id="u1", ip="192.0.2.9", asn=AZURE_ASN, city="Dublin", country="IE", lat=53.35, lon=-6.26,
                     device_id="vm1", device_name="cloud-vm-01", **JOINED)
    last = make_signin(20, user_id="u1", **home)
    history.add(base + [last, vm])
    settings = {"impossible_travel": {"ignore_same_device": True}}

    def run(extra):
        rc = RuleContext.build([vm], history, {**settings, **extra}, T0 + timedelta(minutes=31))
        return [f.rule_id for f in rules.impossible_travel(rc) + rules.new_country(rc)]

    assert run({}) == ["impossible_travel", "new_country"]
    assert run({"virtual_desktops": [{"match": "cloud-vm-*", "label": "Azure virtual machine"}]}) == []


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    yield r
    r.destroy()


def test_hosts_window_takes_suggestions_validates_and_saves(root):
    from radar.ui import theme
    from radar.ui.hosts import HostsWindow

    theme.init(root)
    saved = []
    win = HostsWindow(root, None, [{"match": "US-CX-*", "label": "Citrix"}], lambda entries: saved.append(entries))
    win.show_suggestions(suggest({}) + [{"name": "us-cx-*", "users": 3, "together": 2, "where": "", "label": "", "why": ""}])
    root.update()
    assert [win.suggest.set(i, "Machine") for i in win.suggest.get_children()] == ["TOR-CTX-01", "cloud-vm-01"]  # not the listed one
    win.suggest.selection_set("0")
    win._add_selected()
    assert win.entries[-1] == {"match": "TOR-CTX-01", "label": "Citrix"} and len(win.suggest.get_children()) == 1
    assert win.vars["match"].get() == "TOR-CTX-01"  # the new entry is selected: it can be turned into a pattern
    win.vars["match"].set("CX")
    win.save()
    assert not saved and "would match almost every device" in win.status.cget("text") and win.exists()
    win.vars["match"].set("TOR-CTX-*")
    win._add_all()
    win.save()
    assert saved == [[{"match": "US-CX-*", "label": "Citrix"}, {"match": "TOR-CTX-*", "label": "Citrix"},
                      {"match": "cloud-vm-01", "label": win.entries[-1]["label"]}]] and not win.exists()
    assert hosts.save_into({"x": 1}, saved[0])["virtual_desktops"][1] == {"match": "TOR-CTX-*", "label": "Citrix"}
