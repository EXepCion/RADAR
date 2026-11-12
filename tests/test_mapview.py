"""Live map: what it shows (data), how it is served (local, secret path), and that the tray app never loads it."""
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer

from conftest import T0, make_signin

from radar.mapview import data
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo

SETTINGS = {"offices": [{"name": "Toronto office", "city": "Toronto", "country": "CA", "hq": True, "ips": ["203.0.113.5"]}]}
NOW = T0 + timedelta(hours=2)


LAPTOP = dict(device_id="d1", device_name="LT-YYZ-1", os="Windows10", trust_type="Azure AD joined", compliant=True, managed=True)
OFFICE = dict(ip="203.0.113.5", asn=812, **LAPTOP)


def fill(history):
    history.add([
        make_signin(5, user_id="u1", upn="alice@contoso.com", user_name="Alice", **OFFICE),  # earlier: not in the feed twice
        # two people in the office, two in the same city elsewhere, one behind a preliminary record without place
        make_signin(10, user_id="u1", upn="alice@contoso.com", user_name="Alice", **OFFICE),
        make_signin(20, user_id="u2", upn="bob@contoso.com", user_name="Bob", **OFFICE),
        make_signin(30, user_id="u3", upn="carol@contoso.com", user_name="Carol", ip="198.51.100.30", asn=6830,
                    city="Munich", country="DE", lat=48.14, lon=11.58, **dict(LAPTOP, device_id="d3", device_name="LT-MUC-3")),
        make_signin(40, user_id="u4", upn="dave@contoso.com", user_name="Dave", ip="198.51.100.31", asn=6830,
                    city="Munich", country="DE", lat=48.14, lon=11.58, os="Windows10", browser="Firefox 140"),  # no device identity
        make_signin(50, user_id="u5", upn="erin@contoso.com", user_name="Erin", ip="198.51.100.32", lat=None, lon=None,
                    city="", country="", **dict(LAPTOP, device_id="d5")),
        # password attempts on Carol from a network she never used, and one that got past the password
        make_signin(100, user_id="u3", upn="carol@contoso.com", ip="192.0.2.50", asn=64500, error_code=50126,
                    city="Hanoi", country="VN", lat=21.03, lon=105.85),
        make_signin(101, user_id="u3", upn="carol@contoso.com", ip="192.0.2.51", asn=64500, error_code=50126,
                    city="Hanoi", country="VN", lat=21.03, lon=105.85),
        make_signin(102, user_id="u3", upn="carol@contoso.com", ip="192.0.2.52", asn=64500, error_code=500121,
                    password_ok=True, city="Hanoi", country="VN", lat=21.03, lon=105.85),
        # Alice mistyping her password in the office is not an attack
        make_signin(105, user_id="u1", upn="alice@contoso.com", error_code=50126, **OFFICE),
    ])


def test_snapshot_groups_people_by_office_and_city_and_draws_attacks(history):
    fill(history)
    accounts = AccountDirectory({"u3": AccountInfo(user_id="u3", upn="carol@contoso.com", display_name="Carol C.",
                                                   mfa_registered=False)}, NOW)
    snap = data.build_snapshot(history, SETTINGS, accounts, NOW)
    places = {p["key"]: p for p in snap["places"]}
    assert places["office:Toronto office"]["count"] == 2 and places["office:Toronto office"]["kind"] == "office"
    hq = places["office:Toronto office"]
    assert (hq["label"], hq["city"], hq["country"], hq["hq"], hq["ips"]) == ("Toronto office", "Toronto", "CA", True, 1)
    assert [a["users"] for a in snap["attacks"]] == [["u3"], ["u3"]] and snap["offices_configured"]
    assert places["city:Munich|DE"]["count"] == 2 and places["city:Munich|DE"]["lat"] == 48.14
    people = {p["id"]: p for p in snap["people"]}
    assert set(people) == {"u1", "u2", "u3", "u4"}
    assert [p["id"] for p in snap["unlocated"]] == ["u5"]  # Erin has no place: counted, but not on the map
    assert people["u1"]["how"] == "Work computer LT-YYZ-1 on the office network (Toronto office)"
    assert people["u1"]["precision"] == "office" and not people["u1"]["unusual"] and not people["u1"]["flagged"]
    assert people["u3"]["name"] == "Carol C." and people["u3"]["tags"][:2] == ["under attack", "no MFA"]
    assert people["u3"]["precision"] == "city" and people["u3"]["unusual"]
    # Dave's browser did not identify a device: shown in the city, but flagged
    assert people["u4"]["precision"] == "city_unconfirmed" and people["u4"]["flagged"] and "unmanaged device" in people["u4"]["tags"]
    assert people["u4"]["how"].startswith("Unidentified device (Windows10 / Firefox 140)") and not people["u4"]["unusual"]
    blocked = [a for a in snap["attacks"] if not a["breach"]]
    breach = [a for a in snap["attacks"] if a["breach"]]
    assert len(blocked) == 1 and blocked[0]["count"] == 2 and blocked[0]["ip_count"] == 2
    assert blocked[0]["to"] == "city:Munich|DE" and blocked[0]["source"] == "Hanoi, VN"
    assert len(breach) == 1 and breach[0]["count"] == 1
    assert snap["stats"] == {"people": 5, "in_office": 2, "guessed": 0, "unlocated": 1, "rooms": 0, "attempts": 3, "breaches": 1,
                             "accounts_attacked": 1}
    kinds = [e["kind"] for e in snap["events"]]
    assert kinds.count("attack") == 2 and kinds.count("breach") == 1 and kinds.count("signin") == 4
    assert snap["events"] == sorted(snap["events"], key=lambda e: e["ts"], reverse=True)
    assert snap["absent_targets"] == []  # Carol is signed in: the arrows end on her own dot
    json.dumps(snap)  # everything is plain data for the page


def test_attack_on_an_account_that_is_not_signed_in_points_to_where_it_was_last_seen(history):
    history.add([
        make_signin(-60 * 24 * 3, user_id="u9", upn="info@contoso.com", ip="203.0.113.5", asn=812),
        make_signin(110, user_id="u9", upn="info@contoso.com", ip="192.0.2.60", asn=64501, error_code=50053,
                    city="Lagos", country="NG", lat=6.52, lon=3.38),
    ])
    snap = data.build_snapshot(history, SETTINGS, None, NOW)
    assert snap["people"] == []
    assert [a["to"] for a in snap["attacks"]] == ["office:Toronto office"]
    # the attacked account is not signed in: it gets a marker of its own for the arrow to end on
    ghost = snap["absent_targets"][0]
    assert (ghost["upn"], ghost["place"], ghost["attempts"], ghost["absent"]) == ("info@contoso.com", "office:Toronto office", 1, True)
    assert ghost["tags"][0] == "under attack" and ghost["id"] == snap["attacks"][0]["users"][0]
    assert [p["key"] for p in snap["places"]] == ["office:Toronto office"]


def test_position_follows_the_best_evidence_not_the_latest_signin(history):
    """A day like the user's: laptop and phone in the office, services acting on his behalf from elsewhere, the
    phone on mobile data - and in the evening the laptop signs in from home."""
    phone = dict(device_id="p1", device_name="Pixel", os="Android", trust_type="Azure AD registered", compliant=True, managed=True)
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    history.add([
        make_signin(-60 * 24 * 2, user_id="u1", user_name="Sam", **dict(LAPTOP, **home)),  # the laptop was at home before
        make_signin(60, user_id="u1", user_name="Sam", **OFFICE),
        make_signin(70, user_id="u1", user_name="Sam", interactive=False, ip="198.51.100.200", asn=812, city="Toronto", country="CA",
                    lat=43.65, lon=-79.38, client_credential="clientAssertion", app="Microsoft Teams Services", **LAPTOP),
        make_signin(80, user_id="u1", user_name="Sam", interactive=False, ip="192.0.2.150", asn=812, city="Montreal", country="CA",
                    lat=45.50, lon=-73.57, **phone),  # phone on mobile data, 10 minutes after the office sign-in
    ])
    now = T0 + timedelta(minutes=90)
    sam = data.build_snapshot(history, SETTINGS, None, now)["people"][0]
    assert sam["place"] == "office:Toronto office" and sam["precision"] == "office"  # neither Teams' address nor the phone
    assert sam["also"] == ["Managed phone or tablet Pixel on a network of its own (mobile data or foreign Wi-Fi)"]

    # the laptop has been silent for more than an hour, the phone is still active: the person has left the office
    history.add([make_signin(150, user_id="u1", user_name="Sam", interactive=False, ip="192.0.2.151", asn=812, city="Montreal",
                             country="CA", lat=45.50, lon=-73.57, **phone)])
    snap = data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=155))
    sam = snap["people"][0]
    # only the phone is seen now, on mobile data ("Montreal" is the carrier's gateway): the best guess is the place where
    # his laptop usually is outside the office - not the gateway, and not a vague country marker
    assert sam["place"] == "city:Mississauga|CA" and sam["precision"] == "guess"
    assert sam["guess"] == "the place where the work computer is most often outside the office"
    assert [(p["kind"], p["label"], p["count"]) for p in snap["places"]] == [
        ("office", "Toronto office", 0), ("city", "Mississauga, CA", 1)] and snap["stats"]["guessed"] == 1

    # at home the laptop signs in 50 minutes after its last office sign-in: a device is where it is now
    history.add([make_signin(210, user_id="u1", user_name="Sam", **dict(LAPTOP, **home)),
                 make_signin(160, user_id="u1", user_name="Sam", **OFFICE)])
    sam = data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=215))["people"][0]
    assert sam["place"] == "city:Mississauga|CA" and sam["precision"] == "city"
    assert sam["how"] == "Work computer LT-YYZ-1 on a normal internet connection"

    # the phone on the Wi-Fi the laptop uses at home is at home too (fair evidence), not "somewhere in CA"
    history.add([make_signin(260, user_id="u1", user_name="Sam", interactive=False, **dict(phone, **dict(home, ip="198.51.100.81")))])
    history.add([make_signin(400, user_id="u1", user_name="Sam", interactive=False, **dict(phone, **dict(home, ip="198.51.100.82")))])
    snap = data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=405))
    sam = snap["people"][0]
    assert sam["place"] == "city:Mississauga|CA" and sam["device"] == "managed mobile" and sam["precision"] == "city"
    assert snap["stats"]["guessed"] == 0


def test_vpn_hides_the_place_and_falls_back_to_the_last_located_signin(history):
    from radar.plugins.signin_threats import netintel

    vpn_asn = next(asn for asn, (_name, category) in netintel.KNOWN_ASNS.items() if category == "vpn")
    history.add([
        make_signin(10, user_id="u1", user_name="Vera", ip="198.51.100.30", asn=6830, city="Munich", country="DE", lat=48.14,
                    lon=11.58, **LAPTOP),
        make_signin(100, user_id="u1", user_name="Vera", ip="192.0.2.99", asn=vpn_asn, city="Amsterdam", country="NL", lat=52.37,
                    lon=4.9, **LAPTOP),
        make_signin(100, user_id="u2", user_name="Walt", ip="192.0.2.98", asn=vpn_asn, city="Amsterdam", country="NL", lat=52.37,
                    lon=4.9, **dict(LAPTOP, device_id="d2")),
    ])
    snap = data.build_snapshot(history, SETTINGS, None, NOW)
    vera = snap["people"][0]
    assert vera["place"] == "city:Munich|DE" and vera["precision"] == "hidden" and vera["fallback"] and vera["unusual"]
    assert "place unknown" in vera["how"] and "VPN / proxy" in vera["tags"]
    # Walt was never seen on a normal network: he is put at the exit of the VPN he comes through, and it says so
    walt = [p for p in snap["people"] if p["name"] == "Walt"][0]
    assert walt["place"] == "city:Amsterdam|NL" and walt["precision"] == "guess" and walt["exit"] and snap["unlocated"] == []
    assert walt["guess"].startswith("at the exit of the network this account signs in through: ") and "192.0.2.98" in walt["guess"]
    assert "(vpn)" in walt["guess"] and "The person may be somewhere else" in walt["guess"]
    # Walt was in the Munich area yesterday: he is shown there as a best guess, with how long ago that was
    history.add([make_signin(-60 * 20, user_id="u2", user_name="Walt", ip="198.51.100.31", asn=6830, city="Munich", country="DE",
                             lat=48.14, lon=11.58, **dict(LAPTOP, device_id="d2"))])
    snap = data.build_snapshot(history, SETTINGS, None, NOW)
    walt = [p for p in snap["people"] if p["name"] == "Walt"][0]
    assert walt["place"] == "city:Munich|DE" and walt["precision"] == "guess" and snap["unlocated"] == [] and not walt.get("exit")
    assert walt["located"].startswith("2026-11-08T16:00") and walt["seen"] > walt["located"]
    assert walt["guess"] == "where this person was last located; now only behind a cloud network or VPN"
    assert all(p["key"] != "city:Amsterdam|NL" for p in snap["places"])  # with a real place on record the exit is not used


def test_person_detail_lists_devices_and_movement_and_flags_impossible_travel(history):
    history.add([
        make_signin(-600, user_id="u1", **OFFICE),
        make_signin(-500, user_id="u1", **OFFICE),
        make_signin(-300, user_id="u1", ip="198.51.100.40", asn=6830, city="New York", country="US", lat=40.71, lon=-74.01, **LAPTOP),
        make_signin(-290, user_id="u1", ip="198.51.100.44", asn=6830, city="Boston", country="US", lat=42.36, lon=-71.06,
                    os="Ios", browser="Safari", device_id="p9", device_name="iPhone"),  # unmanaged phone: no stop on the trail
        make_signin(-280, user_id="u1", ip="198.51.100.41", asn=64510, city="Lagos", country="NG", lat=6.52, lon=3.38,
                    **dict(LAPTOP, device_id="d7", device_name="LT-NEW")),  # 5000 km in 20 minutes
    ])
    detail = data.person_detail(history, SETTINGS, None, NOW, "u1")
    assert [h["label"] for h in detail["hops"]] == ["Toronto office", "New York, US", "Lagos, NG"]  # repeats are one stop
    assert [h["bad"] for h in detail["hops"]] == [False, False, True]
    assert [h["tz"] for h in detail["hops"]] == ["America/Toronto", "America/New_York", "Africa/Lagos"]  # each stop in its own time
    assert detail["hops"][2]["km"] > 4000 and detail["hops"][0]["how"].endswith("on the office network (Toronto office)")
    assert [(d["name"], d["class"]) for d in detail["devices"]] == [
        ("LT-NEW", "work computer"), ("LT-YYZ-1", "work computer"), ("iPhone", "unmanaged device")]
    json.dumps(detail)


def _serve(source):
    from radar.mapview.__main__ import make_handler

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(source, "secret-token", [0.0]))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url, host=None):
    request = urllib.request.Request(url, headers={"Host": host} if host else {})
    try:
        with urllib.request.urlopen(request, timeout=5) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_map_server_serves_only_below_its_secret_path_on_loopback(tmp_path, history):
    from radar.mapview.__main__ import MapData

    class Source(MapData):
        def snapshot(self, attack_hours=24, offline=False):
            return {"people": [], "marker": "snapshot", "attacks": attack_hours, "offline": offline}

        def person(self, user_id):
            return {"id": user_id}

    server, base = _serve(Source(data_dir=tmp_path, config_path=tmp_path / "config.json", db_path=tmp_path / "x.db"))
    try:
        status, body, headers = _get(f"{base}/secret-token/data")
        assert status == 200 and json.loads(body)["marker"] == "snapshot" and headers["Cache-Control"] == "no-store"
        assert json.loads(_get(f"{base}/secret-token/person?id=u%201")[1]) == {"id": "u 1"}
        assert json.loads(_get(f"{base}/secret-token/data?attacks=72")[1])["attacks"] == 72
        assert json.loads(_get(f"{base}/secret-token/data?attacks=24&offline=1")[1])["offline"] is True
        assert json.loads(_get(f"{base}/secret-token/data")[1])["offline"] is False
        page = _get(f"{base}/secret-token/")
        assert page[0] == 200 and b"Live sign-in map" in page[1] and b"http://" not in page[1].replace(b"http://www.w3.org", b"")
        assert _get(f"{base}/secret-token/static/world.js")[0] == 200  # the map ships with the app: nothing from the internet
        assert _get(f"{base}/secret-token/static/echarts.min.js")[0] == 200
        for url in (f"{base}/data", f"{base}/", f"{base}/wrong-token/data", f"{base}/secret-token/static/../__main__.py",
                    f"{base}/secret-token/static/..%2f__main__.py", f"{base}/secret-token/unknown",
                    f"{base}/secret-token/static/index.html", f"{base}/secret-token/static/C:%5CWindows%5Cwin.json",
                    f"{base}/secret-token/static/C:/Windows/win.json", f"{base}/secret-token/static/%5C%5Chost%5Cshare%5Cx.js"):
            assert _get(url)[0] == 404, url
        assert _get(f"{base}/secret-token/data", host="evil.example")[0] == 404  # no DNS-rebinding from a web page
    finally:
        server.shutdown()


def test_map_data_reads_the_apps_files_without_a_history(tmp_path):
    from radar.mapview.__main__ import MapData

    snap = MapData(data_dir=tmp_path, config_path=tmp_path / "config.json", db_path=tmp_path / "x.db").snapshot()
    assert snap["empty"] and snap["people"] == [] and snap["ui"] == {"dark": False, "animations": True}


def test_the_tray_app_never_loads_the_map():
    """The map is a process of its own: importing the app (and its tray) must not import any of it."""
    code = ("import sys; import radar.app, radar.tray, radar.scheduler; "
            "print(sorted(m for m in sys.modules if m.startswith('radar.mapview')))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"
    from radar.app import App

    command = App.map_command()
    assert command[1:] == ["-m", "radar.mapview"] and "python" in command[0].lower()


def test_open_map_makes_the_scheduler_read_signins_more_often():
    from radar.scheduler import Scheduler

    runs = []

    class Plugins:
        def ordered(self):
            return [type("RT", (), {"plugin": type("P", (), {"id": "signin_threats"})()})()]

        def is_enabled(self, pid):
            return True

        def interval_seconds(self, pid):
            return 600

    class App:
        ATTACK_PLUGIN = "signin_threats"
        MAP_SCAN_SECONDS = 120
        stop_event = threading.Event()
        paused = False
        plugins = Plugins()
        cfg = type("Cfg", (), {"get": staticmethod(lambda *a, default=None: 0)})()
        open = False

        def on_tick(self):
            pass

        def map_open(self):
            return self.open

        def run_plugin(self, pid):
            runs.append(pid)
            return True

    app = App()
    s = Scheduler(app)
    s._tick()
    assert len(runs) == 1  # the normal first scan
    s._tick()
    assert len(runs) == 1  # next one in 10 minutes
    app.open = True
    s._tick()
    assert len(runs) == 1  # map open, but the last scan is younger than two minutes
    s._last_run["signin_threats"] -= 121
    s._tick()
    assert len(runs) == 2  # two minutes later: scanned again although the interval is 10 minutes
    app.open = False
    s._last_run["signin_threats"] -= 121
    s._tick()
    assert len(runs) == 2  # map closed: back to the normal interval


def test_a_distant_city_minutes_after_the_office_is_a_cloud_service_not_a_trip(history):
    """Office presence is certain; a geolocated 'city' 9000 km away two minutes later is a relay / SaaS address."""
    office = OFFICE
    history.add([
        make_signin(-100, user_id="u1", **office),
        make_signin(-95, user_id="u1", ip="198.51.100.77", asn=64520, city="San Francisco", country="US", lat=37.77, lon=-122.42, **LAPTOP),
        make_signin(-30, user_id="u1", **office),
        make_signin(-28, user_id="u1", ip="198.51.100.78", asn=64520, city="San Francisco", country="US", lat=37.77, lon=-122.42, **LAPTOP),
        make_signin(-5, user_id="u1", **office),
    ])
    detail = data.person_detail(history, SETTINGS, None, NOW, "u1")
    assert [h["label"] for h in detail["hops"]] == ["Toronto office"] and not detail["hops"][0]["bad"]
    assert detail["ignored_places"] == 2


def test_phone_only_guesses(history):
    """Where a phone-only person is put: laptop seen at home an hour ago -> there; abroad -> the phone's own city."""
    phone = dict(device_id="p1", device_name="Pixel", os="Android", trust_type="Azure AD registered", compliant=True, managed=True)
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    history.add([
        make_signin(0, user_id="u1", user_name="Sam", **dict(LAPTOP, **home)),   # laptop at home, then the lid is closed
        make_signin(90, user_id="u1", user_name="Sam", interactive=False, ip="192.0.2.150", asn=812, city="Montreal", country="CA",
                    lat=45.50, lon=-73.57, **phone),
        # Tina has no computer on record and is abroad with her phone
        make_signin(95, user_id="u2", user_name="Tina", interactive=False, ip="192.0.2.170", asn=6830, city="Lisbon", country="PT",
                    lat=38.72, lon=-9.14, **dict(phone, device_id="p2")),
    ])
    people = {p["name"]: p for p in data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=100))["people"]}
    assert people["Sam"]["place"] == "city:Mississauga|CA" and people["Sam"]["precision"] == "guess"
    assert people["Sam"]["guess"].startswith("where the work computer was last seen (")
    assert people["Tina"]["place"] == "city:Lisbon|PT" and people["Tina"]["guess"] == "where the phone's network is located"


def test_meeting_rooms_are_listed_with_their_office_but_are_not_people(history):
    """A room is what Entra licenses as one (Teams Rooms licence) - not what its name or device looks like."""
    room_device = dict(ip="203.0.113.5", asn=812, device_id="r1", device_name="AnyVendorBar-7", os="Android", app="Microsoft Teams")
    history.add([
        make_signin(10, user_id="u1", upn="alice@contoso.com", user_name="Alice", **OFFICE),
        make_signin(11, user_id="r1", upn="boardroom@contoso.com", user_name="Boardroom 5th floor", interactive=False, **room_device),
        make_signin(12, user_id="r2", upn="foyer@contoso.com", user_name="Foyer", interactive=False,
                    **dict(room_device, device_id="r2", app="Microsoft Teams Rooms")),  # no licence on record, but the room app
        make_signin(13, user_id="r3", upn="lab-display@contoso.com", user_name="Lab Display", interactive=False,
                    **dict(OFFICE, device_id="k3", device_name="LT-PC-0300")),  # only the setting says it is a room
        make_signin(14, user_id="u2", upn="meeting.roomer@contoso.com", user_name="Meeting Roomer", **dict(OFFICE, device_id="d9")),
    ])
    accounts = AccountDirectory({
        "r1": AccountInfo(user_id="r1", upn="boardroom@contoso.com", display_name="Boardroom 5th floor", licenses=["Microsoft_Teams_Rooms_Basic"]),
        "u1": AccountInfo(user_id="u1", upn="alice@contoso.com", display_name="Alice", licenses=["SPB"]),
    }, NOW)
    assert accounts.get("r1").room and not accounts.get("u1").room
    snap = data.build_snapshot(history, dict(SETTINGS, room_accounts=["lab-display@*"]), accounts, T0 + timedelta(minutes=30))
    assert [p["name"] for p in snap["people"]] == ["Alice", "Meeting Roomer"]  # a person with 'meeting room' in the name stays a person
    assert [r["name"] for r in snap["rooms"]] == ["Boardroom 5th floor", "Foyer", "Lab Display"]
    office = snap["places"][0]
    assert (office["count"], office["rooms"]) == (2, 3)
    assert snap["stats"]["people"] == 2 and snap["stats"]["in_office"] == 2 and snap["stats"]["rooms"] == 3
    without = data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=30))
    assert [r["name"] for r in without["rooms"]] == ["Foyer"]  # without licence data and setting only the room app tells


def test_office_is_placed_by_its_configured_city_when_entra_locates_the_address_elsewhere(history):
    """The Brazilian office: Entra locates its address in Rio de Janeiro, the office is in Sao Paulo (350 km away)."""
    settings = {"offices": [{"name": "BR office", "city": "São Paulo", "country": "BR", "ips": ["203.0.113.5"]},
                            {"name": "AR office", "city": "Buenos Aires", "country": "AR", "ips": ["203.0.113.9"]}]}
    rio = dict(city="Rio de Janeiro", country="BR", lat=-22.91, lon=-43.17)
    history.add([
        make_signin(10, user_id="u1", user_name="Ana", **dict(OFFICE, **rio)),
        make_signin(-600, user_id="u2", user_name="Luis", ip="198.51.100.70", asn=28573, city="Sao Paulo", country="BR", lat=-23.55,
                    lon=-46.63, **dict(LAPTOP, device_id="d2")),  # somebody once signed in from Sao Paulo: that is where it is
        make_signin(20, user_id="u3", user_name="Rui", **dict(OFFICE, ip="203.0.113.9", device_id="d3", city="Cordoba", country="AR",
                                                             lat=-31.42, lon=-64.18)),
    ])
    places = {p["label"]: p for p in data.build_snapshot(history, settings, None, T0 + timedelta(minutes=30))["places"]}
    es = places["BR office"]
    assert (es["lat"], es["lon"], es["position"]) == (-23.55, -46.63, "city")
    assert "Entra locates this office's address in Rio de Janeiro, BR" in es["position_note"] and "km away" in es["position_note"]
    pt = places["AR office"]  # nobody ever signed in from Buenos Aires: the offline index of towns knows where it is
    assert (round(pt["lat"], 1), round(pt["lon"], 1), pt["position"]) == (-34.6, -58.4, "city")


def test_every_configured_office_is_on_the_map_also_with_nobody_in_it(history):
    settings = {"offices": [
        {"name": "CA office", "city": "Toronto", "country": "CA", "ips": ["203.0.113.5"]},
        {"name": "UK office", "city": "Birmingham", "country": "UK", "ips": ["203.0.113.6"]},       # nobody in today
        {"name": "JP office", "city": "Osaka", "country": "JP", "ips": ["203.0.113.7"], "lat": 34.69, "lon": 135.5},
        {"name": "New office", "city": "Atlantis", "country": "XX", "ips": ["203.0.113.8"]},     # never seen, city unknown
    ]}
    history.add([
        make_signin(10, user_id="u1", user_name="Alice", **OFFICE),
        # the UK office was used last week; Entra locates its address in Coventry, somebody else signed in from Birmingham
        make_signin(-60 * 24 * 6, user_id="u2", ip="203.0.113.6", asn=2856, city="Coventry", country="GB", lat=52.41, lon=-1.51,
                    **dict(LAPTOP, device_id="d2")),
        make_signin(-60 * 24 * 5, user_id="u3", ip="198.51.100.90", asn=2856, city="Birmingham", country="GB", lat=52.48, lon=-1.9,
                    **dict(LAPTOP, device_id="d3")),
    ])
    snap = data.build_snapshot(history, settings, None, T0 + timedelta(minutes=30))
    places = {p["label"]: p for p in snap["places"]}
    assert set(places) == {"CA office", "UK office", "JP office"}
    assert places["CA office"]["count"] == 1 and places["UK office"]["count"] == 0 and places["JP office"]["count"] == 0
    assert (places["UK office"]["lat"], places["UK office"]["position"]) == (52.48, "city")  # Birmingham, although 'UK' is written
    # also without anybody ever having signed in from Birmingham: the town index places it ('UK' is understood as GB)
    alone = data.build_snapshot(SignInHistoryEmpty(), {"offices": [settings["offices"][1]]}, None, T0)["places"][0]
    assert (round(alone["lat"], 2), round(alone["lon"], 2), alone["position"], alone["count"]) == (52.48, -1.9, "city", 0)
    assert (places["JP office"]["lat"], places["JP office"]["lon"], places["JP office"]["position"]) == (34.69, 135.5, "set by hand")
    assert snap["unplaced_offices"] == ["New office"] and snap["stats"]["in_office"] == 1


def SignInHistoryEmpty():
    from radar.plugins.signin_threats.history import SignInHistory

    return SignInHistory(":memory:")


def test_town_index():
    from radar.mapview import cities

    assert [round(x, 1) for x in cities.locate("São Paulo", "BR")] == [-23.5, -46.6]
    assert [round(x, 1) for x in cities.locate("birmingham", "uk")] == [52.5, -1.9]  # the English one, not Birmingham in the US
    assert cities.locate("Birmingham", "US") != cities.locate("Birmingham", "GB")
    assert cities.locate("Atlantis", "XX") is None and cities.locate("") is None
    assert cities.timezone("Singapore", "SG") == "Asia/Singapore" and cities.timezone("Birmingham", "UK") == "Europe/London"
    # a place the index does not know by name: the nearest town of the country decides (the US has several zones)
    assert cities.timezone("Nowhereville", "US", 40.7, -74.0) == "America/New_York"
    assert cities.timezone("Nowhereville", "US", 34.0, -118.2) == "America/Los_Angeles"
    assert cities.timezone("Nowhereville", "JP") == "Asia/Tokyo" and cities.timezone("", "") == ""


def test_map_click_is_handed_to_the_tray_app_as_a_validated_request(tmp_path):
    from radar.mapview.__main__ import REQUESTS, MapData

    source = MapData(data_dir=tmp_path, config_path=tmp_path / "config.json", db_path=tmp_path / "x.db")
    server, base = _serve(source)
    try:
        ok = json.loads(_get(f"{base}/secret-token/open?kind=user&value=00000000-0000-4000-8000-000000000010&action=user_signins")[1])
        assert ok == {"ok": True}
        files = list((tmp_path / REQUESTS).glob("*.json"))
        assert len(files) == 1 and json.loads(files[0].read_text(encoding="utf-8")) == {
            "kind": "user", "value": "00000000-0000-4000-8000-000000000010", "action": "user_signins"}
        # only users and devices, only their own actions, nothing odd in the value
        for query in ("kind=user&value=x&action=url", "kind=ip&value=1.2.3.4&action=abuseipdb", "kind=device&value=d1&action=user",
                      "kind=user&value=&action=user", "kind=user&value=" + "a" * 300 + "&action=user", "kind=user&value=a%0Ab&action=user"):
            assert json.loads(_get(f"{base}/secret-token/open?{query}")[1]) == {"ok": False}, query
        assert len(list((tmp_path / REQUESTS).glob("*"))) == 1
        assert _get(f"{base}/open?kind=user&value=x&action=user")[0] == 404  # not without the secret path
    finally:
        server.shutdown()


def test_tray_app_takes_map_requests_only_while_a_map_is_open(tmp_path, monkeypatch):
    from radar import paths
    from radar.app import App

    monkeypatch.setattr(paths, "plugin_data_dir", lambda plugin_id: tmp_path)
    folder = tmp_path / App.MAP_REQUESTS
    folder.mkdir()
    (folder / "1.json").write_text(json.dumps({"kind": "device", "value": "d1", "action": "device"}), encoding="utf-8")
    (folder / "2.json").write_text(json.dumps({"kind": "url", "value": "https://evil.example", "action": "url"}), encoding="utf-8")
    (folder / "3.json").write_text("not json", encoding="utf-8")
    opened = []

    class Fake:
        ATTACK_PLUGIN, MAP_REQUESTS, MAP_HEARTBEAT = App.ATTACK_PLUGIN, App.MAP_REQUESTS, App.MAP_HEARTBEAT
        tray = None
        open = False

        def map_open(self):
            return self.open

        def entity_action(self, entity, action, status=None):
            opened.append((entity.kind, entity.value, action))

    app = Fake()
    App.take_map_requests(app)
    assert not opened and len(list(folder.iterdir())) == 3  # no map open: nothing is read
    app.open = True
    App.take_map_requests(app)
    assert opened == [("device", "d1", "device")]  # the valid one is opened, the others are dropped
    assert list(folder.iterdir()) == []


def test_movement_separates_stays_by_silence(history):
    """Office yesterday, laptop off overnight, office today, home in the evening: three stays with the silences between."""
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    day = 24 * 60
    office_times = [-day + 0, -day + 120, -day + 300, -day + 509,   # yesterday 09:08 - 17:37
                    1, 200, 400, 582]                                  # today 09:09 - 18:51
    history.add([make_signin(m, user_id="u1", **OFFICE) for m in office_times] +
                [make_signin(m, user_id="u1", **dict(LAPTOP, **home)) for m in (632, 700, 733)])  # today 19:41 - 21:22
    detail = data.person_detail(history, SETTINGS, None, T0 + timedelta(minutes=740), "u1")
    hops = detail["hops"]
    assert [(h["label"], h["signins"]) for h in hops] == [("Toronto office", 4), ("Toronto office", 4), ("Mississauga, CA", 3)]
    assert hops[0]["until"] < hops[1]["when"] and hops[1]["same_place"] and not hops[2]["same_place"]
    assert hops[1]["idle_minutes"] == day + 1 - 509 and hops[2]["idle_minutes"] == 50  # 15 h overnight; 50 min on the way home
    assert not any(h["bad"] for h in hops)


def test_activity_record_keeps_the_end_of_a_stay_after_the_background_signins_are_purged(history):
    """One interactive sign-in in the morning, then only background sign-ins until 17:00. The app keeps those for
    three hours - the activity record still knows the laptop was in the office until 17:00."""
    morning = make_signin(0, user_id="u1", user_name="Ida", **OFFICE)
    background = [make_signin(m, user_id="u1", user_name="Ida", interactive=False, **OFFICE) for m in range(60, 301, 60)]
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    evening = [make_signin(m, user_id="u1", user_name="Ida", interactive=False, **dict(LAPTOP, **home)) for m in (360, 420)]
    history.add([morning] + background + evening)
    later = T0 + timedelta(hours=30)
    history.purge(later - timedelta(days=30), later - timedelta(hours=3))  # as the app does after every scan
    assert history.count() == 1  # only the interactive sign-in is left ...
    runs = history.activity(T0 - timedelta(hours=1), later)
    assert [(s.device_name, s.ip, round((b - a).total_seconds() / 60), n) for s, a, b, n in runs] == [
        ("LT-YYZ-1", "203.0.113.5", 300, 6), ("LT-YYZ-1", "198.51.100.80", 60, 2)]  # ... but the runs are known
    hops = data.person_detail(history, SETTINGS, None, later, "u1")["hops"]
    assert [(h["label"], h["when"][11:16], h["until"][11:16]) for h in hops] == [
        ("Toronto office", "12:00", "17:00"), ("Mississauga, CA", "18:00", "19:00")]
    # the record is purged with the retention time, and a service acting for the user never enters it
    history.add([make_signin(2000, user_id="u1", client_credential="clientAssertion", **OFFICE)])
    assert len(history.activity(T0, T0 + timedelta(days=3))) == 2
    history.purge(later + timedelta(days=40), later + timedelta(days=40))
    assert history.activity(T0 - timedelta(days=1), later + timedelta(days=50)) == []


def test_activity_record_is_built_once_from_the_stored_signins(tmp_path):
    """An existing installation: the record starts from the sign-ins that are in the history at that moment."""
    from radar.plugins.signin_threats.history import SignInHistory

    path = tmp_path / "signins.db"
    h = SignInHistory(path)
    h.add([make_signin(m, user_id="u1", **OFFICE) for m in (0, 30, 60)])
    h.conn.execute("DELETE FROM activity")
    h.conn.execute("DELETE FROM meta WHERE key='activity'")  # as written by a version before the activity record
    h.conn.commit()
    h.close()
    h = SignInHistory(path)
    assert [(round((b - a).total_seconds() / 60), n) for _s, a, b, n in h.activity(T0 - timedelta(hours=1), T0 + timedelta(hours=2))] == [(60, 3)]
    h.close()
    h = SignInHistory(path)  # opened again: not built a second time
    assert len(h.activity(T0 - timedelta(hours=1), T0 + timedelta(hours=2))) == 1
    h.close()


def test_people_active_three_to_four_hours_ago_are_still_on_the_map(history):
    """The map shows the last 4 hours, background sign-ins are kept for 3: the activity record closes the gap."""
    history.add([make_signin(-200, user_id="u1", user_name="Noa", interactive=False, **OFFICE)])
    now = T0 + timedelta(minutes=10)
    history.purge(now - timedelta(days=30), now - timedelta(hours=3))
    assert history.count() == 0
    snap = data.build_snapshot(history, SETTINGS, None, now)
    assert [p["name"] for p in snap["people"]] == ["Noa"] and snap["people"][0]["place"] == "office:Toronto office"


def test_activity_record_keeps_every_run_of_a_batch(history):
    """Several days arrive in one go (first import, or the app was off): each day's run keeps its own begin and end."""
    day = 24 * 60
    history.add([make_signin(d * day + m, user_id="u1", **OFFICE) for d in range(3) for m in (0, 60, 120, 480)])
    runs = history.activity(T0 - timedelta(hours=1), T0 + timedelta(days=4))
    assert [(round((b - a).total_seconds() / 60), n) for _s, a, b, n in runs] == [(120, 3), (0, 1)] * 3  # 6 h pause after noon


def test_two_addresses_of_one_device_are_cross_checked_against_the_office_the_person_goes_to(history):
    """Laptop at home near Sao Paulo: its IPv4 address is located at the provider's hub in Rio de Janeiro, its IPv6 address
    (seen by a cloud service acting for the user) in Guarulhos. The person goes to the Sao Paulo office: Guarulhos
    is right. Without an office to go by, the map falls back to what it did before."""
    settings = {"offices": [{"name": "BR office", "city": "São Paulo", "country": "BR", "ips": ["203.0.113.5"]}]}
    v4 = dict(ip="198.51.100.204", asn=57269, city="Rio de Janeiro", country="BR", lat=-22.91, lon=-43.17)
    v6 = dict(ip="2001:db8:9a03::7", asn=57269, city="Guarulhos", country="BR", lat=-23.46, lon=-46.53)
    laptop = dict(LAPTOP, device_id="es1", device_name="LT-SAO-4")
    history.add([
        make_signin(-60 * 24 * 3, user_id="u1", user_name="Uma", **dict(laptop, ip="203.0.113.5", asn=3352)),  # in the office 3 days ago
        make_signin(10, user_id="u1", user_name="Uma", **dict(laptop, **v4)),
        make_signin(20, user_id="u1", user_name="Uma", interactive=False, client_credential="clientAssertion", app="Olympus",
                    **dict(laptop, **v6)),
        # Kim has the same two addresses but was never in an office: nothing to decide by
        make_signin(10, user_id="u2", user_name="Kim", **dict(laptop, device_id="es2", **v4)),
        make_signin(20, user_id="u2", user_name="Kim", interactive=False, client_credential="clientAssertion", app="Olympus",
                    **dict(laptop, device_id="es2", **v6)),
    ])
    now = T0 + timedelta(minutes=40)
    people = {p["name"]: p for p in data.build_snapshot(history, settings, None, now)["people"]}
    assert people["Uma"]["place"] == "city:Guarulhos|BR"
    assert "Entra places 198.51.100.204 in Rio de Janeiro" in people["Uma"]["corrected"] and "km away" in people["Uma"]["corrected"]
    assert people["Kim"]["place"] == "city:Rio de Janeiro|BR" and people["Kim"]["corrected"] == ""  # as before
    hops = data.person_detail(history, settings, None, now, "u1")["hops"]
    assert [h["label"] for h in hops] == ["BR office", "Guarulhos, BR"]  # the trail uses the corrected place too

    # two addresses that are both within commuting distance of the office: nothing is changed
    history.add([make_signin(50, user_id="u3", user_name="Leo", **dict(laptop, device_id="es3", ip="203.0.113.5", asn=3352)),
                 make_signin(200, user_id="u3", user_name="Leo", **dict(laptop, device_id="es3", ip="198.51.100.9", asn=28573, city="Santo Andre",
                                                                      country="BR", lat=-23.66, lon=-46.53)),
                 make_signin(205, user_id="u3", user_name="Leo", interactive=False, **dict(laptop, device_id="es3", ip="2001:db8:5::1",
                                                                                     asn=28573, city="Osasco", country="BR", lat=-23.53, lon=-46.79))])
    leo = [p for p in data.build_snapshot(history, settings, None, T0 + timedelta(minutes=210))["people"] if p["name"] == "Leo"][0]
    assert leo["corrected"] == "" and leo["place"] in ("city:Santo Andre|BR", "city:Osasco|BR")


def test_trail_ignores_a_machine_that_only_runs_in_the_background(history):
    """Laptop in use at home while a Mac left on in the office keeps syncing: the trail does not jump between them."""
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    mac = dict(ip="203.0.113.5", asn=812, os="MacOs")  # no device identity, never signed in to by hand
    history.add([make_signin(0, user_id="u1", **dict(LAPTOP, **home))] +
                [make_signin(m, user_id="u1", interactive=False, **dict(LAPTOP, **home)) for m in (20, 60, 100)] +
                [make_signin(m, user_id="u1", interactive=False, **mac) for m in (10, 50, 90)])
    hops = data.person_detail(history, SETTINGS, None, T0 + timedelta(minutes=120), "u1")["hops"]
    assert [h["label"] for h in hops] == ["Mississauga, CA"]


def test_map_server_lives_as_long_as_a_page_uses_it():
    """Not as long as the browser process it started: with a map window already open, the browser hands the new
    window over and the started process ends within half a second - the server must stay for the page."""
    from radar.mapview.__main__ import IDLE_EXIT_SECONDS, START_GRACE_SECONDS, keep_serving

    assert keep_serving(False, 1, None)                       # browser process gone at once, page not there yet: wait
    assert not keep_serving(False, START_GRACE_SECONDS + 1, None)   # nobody ever asked: give up
    assert keep_serving(False, 300, 20)                       # the page is asking: serve, whatever the process does
    assert not keep_serving(False, 900, IDLE_EXIT_SECONDS + 1)      # the page went silent and no window process: closed
    assert keep_serving(True, 900, IDLE_EXIT_SECONDS + 1)     # silent but our window process runs: minimised, asleep
    assert not keep_serving(True, 9000, 16 * 60)              # ... not forever
    assert keep_serving(True, 9000, None)                     # our window runs and has not loaded yet


def test_accounts_not_signed_in_and_guests_are_marked_for_the_switches(history):
    """'Not signed in' (off by default): known accounts that are not active now, each where it was last located.
    'Guests' (off by default): guest accounts carry a mark so that the page can leave them out."""
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    day = 24 * 60
    history.add([
        make_signin(10, user_id="u1", user_name="Alice", **OFFICE),                                   # signed in now
        make_signin(20, user_id="g1", upn="ext.partner@fabrikam.com", user_name="Pat Partner", user_type="Guest",
                    ip="198.51.100.90", asn=6830, city="Lyon", country="FR", lat=45.76, lon=4.84),      # a guest, signed in now
        make_signin(-2 * day, user_id="u2", user_name="Bea", **dict(OFFICE, device_id="d2")),            # in the office 2 days ago
        make_signin(-2 * day + 300, user_id="u2", user_name="Bea", interactive=False, **dict(LAPTOP, device_id="d2", **home)),
        make_signin(-5 * day, user_id="u3", user_name="Cy", **dict(OFFICE, device_id="d3")),             # disabled meanwhile
        make_signin(-3 * day, user_id="g2", upn="old.guest@fabrikam.com", user_name="Old Guest", user_type="Guest",
                    ip="198.51.100.91", asn=6830, city="Lyon", country="FR", lat=45.76, lon=4.84),
        make_signin(-4 * day, user_id="r1", upn="room@contoso.com", user_name="Room", app="Microsoft Teams Rooms", **dict(OFFICE, device_id="r1")),
    ])
    accounts = AccountDirectory({
        "u1": AccountInfo(user_id="u1", upn="alice@contoso.com", display_name="Alice"),
        "u2": AccountInfo(user_id="u2", upn="bea@contoso.com", display_name="Bea"),
        "u3": AccountInfo(user_id="u3", upn="cy@contoso.com", display_name="Cy", enabled=False),
        "g1": AccountInfo(user_id="g1", upn="ext.partner_fabrikam.com#EXT#@contoso.onmicrosoft.com", display_name="Pat Partner", user_type="Guest"),
        "g2": AccountInfo(user_id="g2", upn="old.guest_fabrikam.com#EXT#@contoso.onmicrosoft.com", display_name="Old Guest", user_type="Guest"),
        "r1": AccountInfo(user_id="r1", upn="room@contoso.com", display_name="Room"),
    }, NOW)
    now = T0 + timedelta(minutes=30)
    plain = data.build_snapshot(history, SETTINGS, accounts, now)
    assert plain["offline"] == []  # not asked for: nothing is computed
    assert {p["name"]: p["guest"] for p in plain["people"]} == {"Alice": False, "Pat Partner": True}
    snap = data.build_snapshot(history, SETTINGS, accounts, now, include_offline=True)
    off = {p["name"]: p for p in snap["offline"]}
    assert set(off) == {"Bea", "Old Guest"}  # not Alice (signed in), not Cy (disabled), not the room
    assert off["Bea"]["place"] == "city:Mississauga|CA" and off["Bea"]["offline"] and off["Bea"]["absent"]  # her latest place
    assert off["Bea"]["how"].startswith("Not signed in - last seen here: Work computer LT-YYZ-1")
    assert off["Old Guest"]["guest"] and not off["Bea"]["guest"]
    assert {p["key"] for p in snap["places"]} >= {"city:Mississauga|CA", "city:Lyon|FR", "office:Toronto office"}
    assert snap["stats"]["people"] == plain["stats"]["people"]  # the counts of who is signed in do not change
    # the rest of the directory is counted, so that the figures add up: nobody here is without a place ...
    assert snap["unplaced"] == {"silent": 0, "silent_guests": 0, "active": 0, "active_guests": 0}
    assert plain["unplaced"] == snap["unplaced"]  # (not worked out without the switch)
    # ... until the directory knows accounts that never signed in
    accounts.accounts["u9"] = AccountInfo(user_id="u9", upn="never@contoso.com", display_name="Never")
    accounts.accounts["g9"] = AccountInfo(user_id="g9", upn="x_fabrikam.com#EXT#@contoso.onmicrosoft.com", display_name="X", user_type="Guest")
    accounts.accounts["u8"] = AccountInfo(user_id="u8", upn="gone@contoso.com", display_name="Gone", enabled=False)
    snap = data.build_snapshot(history, SETTINGS, accounts, now, include_offline=True)
    assert snap["unplaced"] == {"silent": 1, "silent_guests": 1, "active": 0, "active_guests": 0}


def test_feed_has_an_entry_for_people_who_turn_up_without_signing_in_by_hand(history):
    """A device coming online in the background puts its person on the map; the feed says so once - not for people
    who signed in by hand (that sign-in is the entry), not for people who were there already before the feed's time."""
    home = dict(ip="198.51.100.80", asn=812, city="Mississauga", country="CA", lat=43.59, lon=-79.64)
    abroad = dict(ip="203.0.113.150", asn=18001, city="Colombo", country="LK", lat=6.93, lon=79.85)
    day = 24 * 60
    history.add([
        make_signin(10, user_id="u1", user_name="Alice", **OFFICE),                                              # by hand
        make_signin(-2 * day, user_id="u2", upn="bea@contoso.com", user_name="Bea", **dict(OFFICE, device_id="d2")),
        make_signin(15, user_id="u2", upn="bea@contoso.com", user_name="Bea", interactive=False, **dict(LAPTOP, device_id="d2", **home)),
        make_signin(25, user_id="u2", upn="bea@contoso.com", user_name="Bea", interactive=False, **dict(LAPTOP, device_id="d2", **home)),
        make_signin(-3 * day, user_id="u3", upn="cy@contoso.com", user_name="Cy", **dict(OFFICE, device_id="d3")),
        make_signin(20, user_id="u3", upn="cy@contoso.com", user_name="Cy", interactive=False, **dict(LAPTOP, device_id="d3", **abroad)),
        make_signin(-300, user_id="u4", upn="dan@contoso.com", user_name="Dan", interactive=False, **dict(LAPTOP, device_id="d4", **home)),
        make_signin(18, user_id="u4", upn="dan@contoso.com", user_name="Dan", interactive=False, **dict(LAPTOP, device_id="d4", **home)),
    ])
    snap = data.build_snapshot(history, SETTINGS, None, T0 + timedelta(minutes=30))
    assert {p["name"] for p in snap["people"]} == {"Alice", "Bea", "Cy", "Dan"}
    feed = {e["who"]: e for e in snap["events"]}
    assert feed["Alice"]["kind"] == "signin"
    assert feed["Bea"]["kind"] == "seen" and feed["Bea"]["place"] == "city:Mississauga|CA" and not feed["Bea"]["new_country"]
    assert feed["Bea"]["ts"].startswith((T0 + timedelta(minutes=15)).isoformat()[:16])  # when she was first seen there
    assert feed["Bea"]["device"] == "LT-YYZ-1" and feed["Bea"]["sid"]
    assert feed["Cy"]["kind"] == "seen" and feed["Cy"]["new_country"] == "LK"  # never seen in that country before
    assert "Dan" not in feed  # at home already before the feed's time: nothing new
    assert len(snap["events"]) == 3


def test_map_page_has_radars_icon(tmp_path):
    """The map opens in an Edge app window, which takes the page's icon: RADAR's, not a blank page."""
    import pathlib

    from radar import mapview
    from radar.mapview.__main__ import MapData

    src = MapData(data_dir=tmp_path, config_path=tmp_path / "config.json", db_path=tmp_path / "radar.db")
    png = src.icon("32")
    assert png[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) and src.icon("32") is png  # a PNG, drawn once
    assert src.icon("nonsense")[:4] == png[:4] and len(src.icon("256")) > len(png)
    page = (pathlib.Path(mapview.__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    assert 'rel="icon"' in page and 'href="icon.png?size=32"' in page
