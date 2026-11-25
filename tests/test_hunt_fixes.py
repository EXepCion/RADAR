"""What a hunt for bugs found - each as a test that failed before it was fixed."""
import json
import re
import sqlite3
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace

import pytest
import requests

from conftest import T0, make_signin
from radar import linkify, quiet, search
from radar.alerts import ACTIVE, DISMISSED, SYSTEM_PLUGIN, AlertCenter
from radar.config import ConfigManager
from radar.graph import GraphClient, GraphError, _retry_after
from radar.plugin_api import Finding, Severity
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import SignInThreatsPlugin
from radar.plugins.signin_threats.accounts import AccountDirectory
from radar.plugins.signin_threats.history import SignInHistory
from radar.plugins.signin_threats.models import parse_time
from radar.store import Store
from radar.ui import theme
from test_main_window import app  # noqa: F401  (a real App on an empty data folder)
from test_ui import root  # noqa: F401  (the Tk fixture)

PLUGIN = "signin_threats"
CLIENT = "11111111-2222-4333-8444-555555555555"
OFFICES = [{"name": "Toronto office", "ips": ["198.51.100.10"]}]


def run_like_the_app(fn, *args, name=""):
    """What App._background does with a worker - here and now: whatever it raises is caught and logged."""
    try:
        fn(*args)
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------- Graph's sign-in log behind the real client
class Resp:
    def __init__(self, body, status=200, headers=None):
        self.status_code, self._body, self.headers, self.url, self.text = status, body, headers or {}, "", ""

    def json(self):
        return self._body


class Signins:
    """Microsoft Graph's sign-in log as the real GraphClient sees it: what a filter asks for, newest first, ``size`` to
    a page, with a link to the next page while there is more. Anything else Graph is asked has nothing."""

    def __init__(self, rows, size=2):
        self.rows, self.size, self._asked = rows, size, {}

    def get(self, url, params=None, **_kw):
        if "auditLogs/signIns" not in url:
            return Resp({"value": []})
        if params is not None:   # a question (a next link carries the question it belongs to)
            flt = params.get("$filter", "")
            kind = re.search(r"t eq '(\w+)'", flt)
            start = re.search(r"createdDateTime ge (\S+)", flt)
            end = re.search(r"createdDateTime le (\S+)", flt)
            hits = sorted((r for r in self.rows
                           if (kind is None or kind.group(1) in r["signInEventTypes"])
                           and (start is None or parse_time(r["createdDateTime"]) >= parse_time(start.group(1)))
                           and (end is None or parse_time(r["createdDateTime"]) <= parse_time(end.group(1)))),
                          key=lambda r: r["createdDateTime"], reverse=True)
            token, n = str(len(self._asked)), 0
            self._asked[token] = hits
        else:
            token, page = re.search(r"q=(\d+)&page=(\d+)", url).groups()
            n = int(page)
        hits = self._asked[token]
        body = {"value": hits[n * self.size:(n + 1) * self.size]}
        if (n + 1) * self.size < len(hits):
            body["@odata.nextLink"] = f"https://graph.microsoft.com/beta/auditLogs/signIns?q={token}&page={n + 1}"
        return Resp(body)


def graph_for(server=None):
    class Auth:
        def get_token(self, force_refresh=False):
            return "token"

    client = GraphClient(Auth(), threading.Event())
    if server is not None:
        client._session.get = server.get
    client._sleep = lambda seconds: None
    return client


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def by_hand(i, when):
    return {"id": f"int{i}", "createdDateTime": stamp(when), "userId": "u1", "userPrincipalName": "alice@contoso.com",
            "ipAddress": "198.51.100.10", "status": {"errorCode": 0}, "isInteractive": True, "appDisplayName": "Office 365",
            "location": {"countryOrRegion": "CA", "city": "Toronto"}, "clientAppUsed": "Browser",
            "signInEventTypes": ["interactiveUser"]}


def by_app(i, when):
    return {"id": f"sp{i}", "createdDateTime": stamp(when), "appDisplayName": "Contoso Backup",
            "appId": "22222222-3333-4444-8555-666666666666", "servicePrincipalId": "33333333-4444-4555-8666-777777777777",
            "ipAddress": "203.0.113.10", "location": {"countryOrRegion": "CA"}, "status": {"errorCode": 0},
            "servicePrincipalCredentialKeyId": "44444444-5555-4666-8777-888888888888", "clientCredentialType": "clientSecret",
            "resourceDisplayName": "Microsoft Graph", "signInEventTypes": ["servicePrincipal"]}


def scanner(tmp_path, server, **settings):
    """RADAR's sign-in plugin as the app runs it, reading from ``server``."""
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: graph_for(server), user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    for name, value in settings.items():
        cfg.set("plugins", PLUGIN, "settings", name, value=value)

    def scan():
        ctx = pm.build_context(PLUGIN)
        SignInThreatsPlugin().run(ctx)
        return ctx

    return pm, scan


def stored(ctx):
    h = SignInHistory(ctx.data_dir / "signins.db")
    try:
        return {s.id for s in h.query()}, h.pending()[0]
    finally:
        h.close()


# ======================================================== 1. the live map never repairs the settings file
def test_the_live_map_never_repairs_or_rewrites_the_settings_file(tmp_path):
    from radar.mapview.__main__ import MapData

    path = tmp_path / "config.json"
    tray = ConfigManager(path)
    pm = PluginManager(tray, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    tray.set("auth", "client_id", value=CLIENT)
    tray.set("plugins", PLUGIN, "settings", "offices", value=OFFICES)
    source = MapData(data_dir=tmp_path / "data", config_path=path, db_path=tmp_path / "radar.db")
    assert source.settings()["offices"] == OFFICES
    time.sleep(0.05)
    broken = path.read_text(encoding="utf-8").replace('"paused": false,', '"paused": false')   # a comma lost in Notepad
    path.write_text(broken, encoding="utf-8")
    assert tray.reload_if_changed() is False                     # the tray app keeps what it had
    assert source.settings()["offices"] == OFFICES                # ... and so does the open map
    source.snapshot()
    assert path.read_text(encoding="utf-8") == broken             # nothing moved away, nothing written
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("config")) == ["config.json"]
    later = MapData(data_dir=tmp_path / "data", config_path=path, db_path=tmp_path / "radar.db")
    assert later.settings() == {} and later.snapshot()["ui"] == {"dark": False, "animations": True}
    assert path.read_text(encoding="utf-8") == broken             # a map started now does not repair it either
    time.sleep(0.05)
    assert tray.reload_if_changed() is False
    assert tray.get("auth", "client_id") == CLIENT and tray.get("plugins", PLUGIN, "settings", "offices") == OFFICES
    assert pm.is_enabled(PLUGIN)


def test_a_settings_file_without_its_plugins_section_does_not_switch_scanning_off(tmp_path, caplog):
    path = tmp_path / "config.json"
    cfg = ConfigManager(path)
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    cfg.set("plugins", PLUGIN, "interval_minutes", value=5)
    assert pm.is_enabled(PLUGIN)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["plugins"]                                           # the section deleted by hand
    time.sleep(0.05)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    assert cfg.reload_if_changed() is True
    assert pm.is_enabled(PLUGIN) and pm.rule_enabled(PLUGIN, "brute_force")   # the defaults are back: it scans on
    assert cfg.get("plugins", PLUGIN, "settings", "max_pages_per_run") == 400
    assert PLUGIN in json.loads(path.read_text(encoding="utf-8"))["plugins"]   # ... and in the file
    assert f"'{PLUGIN}'" in caplog.text                          # (the log says what was put back)


# ======================================================== 2. what the page limit leaves unread is read afterwards
def test_sign_ins_the_page_limit_left_unread_are_read_by_the_next_scan(tmp_path):
    now = datetime.now(timezone.utc)
    server = Signins([by_hand(i, now - timedelta(minutes=m)) for i, m in enumerate((10, 20, 60, 70, 150, 170), start=1)])
    pm, scan = scanner(tmp_path, server, event_types=["interactiveUser"], max_pages_per_run=2)
    pm.build_context(PLUGIN).state.set("checkpoint:interactiveUser", (now - timedelta(hours=3)).isoformat())
    ctx = scan()
    assert stored(ctx)[0] == {"int1", "int2", "int3", "int4"}     # two pages: the newest
    (start, end), = ctx.state.get("backlog:interactiveUser")       # what lies before them is owed
    assert abs(parse_time(end) - (now - timedelta(minutes=70))) < timedelta(minutes=1)
    assert parse_time(start) <= now - timedelta(hours=3, minutes=59)
    ctx = scan()
    ids, waiting = stored(ctx)
    assert ids == {f"int{i}" for i in range(1, 7)} and waiting == []   # read - and judged like any other
    assert not ctx.state.get("backlog:interactiveUser")


def test_app_sign_ins_the_page_limit_left_unread_are_read_by_the_next_scan(tmp_path):
    now = datetime.now(timezone.utc)
    server = Signins([by_app(i, now - timedelta(minutes=5 * i)) for i in range(203)], size=1)
    pm, scan = scanner(tmp_path, server, event_types=["interactiveUser"])

    def judged(ctx):
        conn = sqlite3.connect(ctx.data_dir / "signins.db")
        try:
            return {r[0] for r in conn.execute("SELECT id FROM app_ids")}
        finally:
            conn.close()

    ctx = scan()
    assert len(judged(ctx)) == 200 and ctx.state.get("backlog:servicePrincipal")   # 200 pages; the oldest three owed
    ctx = scan()
    assert judged(ctx) == {f"sp{i}" for i in range(203)} and not ctx.state.get("backlog:servicePrincipal")


def test_a_baseline_the_page_limit_cut_short_is_completed_by_the_next_scan(tmp_path):
    from radar import paths

    now = datetime.now(timezone.utc)
    server = Signins([by_hand(i, now - timedelta(days=d)) for i, d in enumerate((3, 4, 5, 6, 7, 8), start=1)])
    pm, scan = scanner(tmp_path, server, event_types=["interactiveUser"], max_pages_per_run=2)
    pm.build_context(PLUGIN).state.set("checkpoint:interactiveUser", (now - timedelta(minutes=5)).isoformat())
    h = SignInHistory(paths.plugin_data_dir(PLUGIN) / "signins.db")
    h.add([make_signin(0, id="recent", created=now - timedelta(days=2))])   # what was read so far: two days
    h.close()
    ctx = scan()
    assert stored(ctx)[0] == {"recent", "int1", "int2", "int3", "int4"}
    ctx = scan()
    assert stored(ctx)[0] == {"recent"} | {f"int{i}" for i in range(1, 7)}


# ======================================================== 3. the live map tells the true age of its data
def test_the_live_map_reads_without_writing_and_tells_the_time_of_the_last_scan(tmp_path):
    from radar.mapview.__main__ import CACHE_SECONDS, MapData

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    h = SignInHistory(data_dir / "signins.db")
    h.add([make_signin(0), make_signin(1, user_id="u2", upn="bob@contoso.com")])
    h.close()
    scanned = datetime(2026, 11, 20, 11, 50, tzinfo=timezone.utc)
    store = Store(tmp_path / "radar.db")
    store.kv_set(f"plugin:{PLUGIN}", "data_as_of", scanned.isoformat())
    before = (data_dir / "signins.db").read_bytes()
    source = MapData(data_dir=data_dir, config_path=tmp_path / "config.json", db_path=tmp_path / "radar.db")
    try:
        first = source.snapshot(24)
        assert source.as_of() == scanned and first["as_of"] == scanned.isoformat()
        assert (data_dir / "signins.db").read_bytes() == before            # not a byte written by the map
        wal = data_dir / "signins.db-wal"
        assert not wal.exists() or wal.stat().st_size == 0
        # a while later, no scan in between: what was worked out holds
        key = (24, False)
        made, stamp_, result = source._cache[key]
        source._cache[key] = (made - CACHE_SECONDS - 1, stamp_, result)
        assert source.snapshot(24) is first
        # the tray app finished a scan: worked out anew, with that scan's time
        store.kv_set(f"plugin:{PLUGIN}", "data_as_of", (scanned + timedelta(minutes=10)).isoformat())
        made, stamp_, result = source._cache[key]
        source._cache[key] = (made - CACHE_SECONDS - 1, stamp_, result)
        again = source.snapshot(24)
        assert again is not first and again["as_of"] == (scanned + timedelta(minutes=10)).isoformat()
    finally:
        store.close()


# ======================================================== 4. the account page never waits for a scan
def test_reading_the_history_on_the_window_thread_does_not_wait_for_a_scan(app, monkeypatch):  # noqa: F811
    from radar import paths

    path = paths.plugin_data_dir(PLUGIN) / "signins.db"
    h = SignInHistory(path)
    h.add([make_signin(0, id="held", session_id="sess-1"), make_signin(1, session_id="sess-1")])
    h.close()
    holding, release = threading.Event(), threading.Event()

    def scan_writing():   # a scan in the middle of a write (a big page of sign-ins, a purge ...)
        scan = SignInHistory(path)
        scan.conn.execute("BEGIN IMMEDIATE")
        scan.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('x', 'y')")
        holding.set()
        release.wait(3)
        scan.conn.commit()
        scan.close()

    writer = threading.Thread(target=scan_writing)
    writer.start()
    holding.wait()
    opened, closed = [], []
    real_open, real_close = app.search_history, SignInHistory.close
    monkeypatch.setattr(app, "search_history", lambda: opened.append(real_open()) or opened[-1])
    monkeypatch.setattr(SignInHistory, "close", lambda self: (closed.append(self), real_close(self)))
    try:
        t0 = time.monotonic()
        line = search.Line(when=T0, kind="Sign-in", what="Office 365", ref=("signin", "held"))
        detail = dict(app.unfold(line))
        assert time.monotonic() - t0 < 1.5
        assert detail["Session"].startswith("2 sign-ins in this session")
        assert opened and all(x in closed for x in opened)        # and what was opened is let go of
    finally:
        release.set()
        writer.join()


def test_a_row_that_cannot_be_unfolded_leaves_the_row_and_the_page_as_they_were(root, history):  # noqa: F811
    from radar.ui.account import AccountPage
    from test_search import usual
    from test_search_pages import FakeApp

    class Unreadable(FakeApp):
        def search_history(self):
            raise sqlite3.OperationalError("database is locked")

        def unfold(self, line):
            raise sqlite3.OperationalError("database is locked")

    usual(history)
    host = tk.Toplevel(root)
    host.geometry("1196x780")
    p = AccountPage(root, Unreadable(history), host, "u1", on_back=lambda: None, on_search=lambda t: None, background=False)
    p.top.pack(fill="both", expand=True)
    p.load(wait=True)
    root.update()
    try:
        line = next(ln for ln in p.visible_lines() if ln.ref == ("signin", "away-ok"))
        before = p.written()
        p._fold(line)
        root.update()
        assert line.ref not in p.unfolded and p.written() == before and all(r.detail is None for r in p.rows)
        p.filters.choose("Failed")
        p.filters.choose("all")                                   # the timeline drawn anew: whole
        root.update()
        assert p.rows and all(r.detail is None for r in p.rows) and "How\t" not in p.written()
        assert any(r.line.ref == ("signin", "away-ok") for r in p.rows)
    finally:
        host.destroy()


# ======================================================== 5. no network during a scan: "no connection"
def test_no_network_during_a_scan_says_no_connection_and_not_failed(app):  # noqa: F811
    graph = graph_for()

    def unreachable(*_a, **_k):
        raise requests.exceptions.ConnectionError("Failed to resolve 'graph.microsoft.com' (getaddrinfo failed)")

    graph._session.get = unreachable
    with pytest.raises(GraphError) as raised:
        graph.get("/beta/auditLogs/signIns", {"$top": "1"})

    def scan(plugin_id, defer=False):
        raise raised.value

    app.plugins.run = scan
    assert app.run_plugin(PLUGIN) is False
    assert app.offline and "no connection" in app.tray_state()[1] and "failed" not in app.tray_state()[1]

    def refused(plugin_id, defer=False):
        raise GraphError(500, "InternalServerError", "something went wrong")

    app.plugins.run = refused                                     # Graph answered - with an error: that is a failure
    assert app.run_plugin(PLUGIN) is False
    assert not app.offline and "failed" in app.tray_state()[1]


# ======================================================== 6. the user's decision always wins
def new_country(severity=Severity.MEDIUM, score=55, **more):
    return Finding(key="k", title="Sign-in from a new country: alice@contoso.com", severity=severity, rule_id="new_country",
                   occurred_at=T0, fields={"User": "alice@contoso.com"}, score=score, **more)


def test_a_dismissal_while_a_scan_stores_its_findings_is_not_undone(monkeypatch):
    from radar import alerts as alerts_mod

    center = AlertCenter(Store(":memory:"))
    center.ingest(PLUGIN, [new_country()], now=T0)
    alert = center.active()[0]
    real = alerts_mod.correlation.subjects_from

    def meanwhile(fields, explicit=None):   # the user presses Dismiss while the scan is between reading and writing
        if center.get(alert.id).status == ACTIVE:
            center.dismiss([alert.id])
        return real(fields, explicit)

    monkeypatch.setattr(alerts_mod.correlation, "subjects_from", meanwhile)
    popped = center.ingest(PLUGIN, [new_country()], now=T0 + timedelta(minutes=10))
    assert center.get(alert.id).status == DISMISSED and popped == []
    center.reactivate([alert.id])
    popped = center.ingest(PLUGIN, [new_country(Severity.HIGH, 80)], now=T0 + timedelta(minutes=20))   # even when worse
    after = center.get(alert.id)
    assert after.status == DISMISSED and after.severity == Severity.HIGH and popped == []
    monkeypatch.setattr(alerts_mod.correlation, "subjects_from", real)
    # (a finding worse than what was dismissed before it was read still brings it back: no decision is overruled)
    other = Finding(key="k2", title="Password spray: bob@contoso.com", severity=Severity.LOW, rule_id="password_spray",
                    occurred_at=T0, fields={"User": "bob@contoso.com"}, score=30)
    center.ingest(PLUGIN, [other], now=T0)
    second = next(a for a in center.active() if a.key == "k2")
    center.dismiss([second.id])
    other.severity, other.score = Severity.HIGH, 80
    popped = center.ingest(PLUGIN, [other], now=T0 + timedelta(minutes=40))
    assert center.get(second.id).status == ACTIVE and [a.id for a in popped] == [second.id]


def test_a_dismissal_while_an_alert_is_judged_anew_is_not_undone(monkeypatch):
    from radar import alerts as alerts_mod

    center = AlertCenter(Store(":memory:"))
    center.ingest(PLUGIN, [new_country(evidence=[{"Time": "1", "_created": T0.isoformat(), "Sign-in ID": "a"}])], now=T0)
    alert = center.active()[0]
    real = alerts_mod._merge_evidence

    def meanwhile(old, new, drop=frozenset()):
        center.dismiss([alert.id])
        return real(old, new, drop)

    monkeypatch.setattr(alerts_mod, "_merge_evidence", meanwhile)
    assert center.replace_assessment(new_country(Severity.LOW, 30, evidence=[
        {"Time": "1", "_created": T0.isoformat(), "Sign-in ID": "a"}]))
    after = center.get(alert.id)
    assert after.status == DISMISSED and after.score == 30          # judged anew - and still dismissed


# ======================================================== 7. named fonts, not copies of them
def test_the_reminder_header_and_the_field_names_are_measured_in_the_fonts_they_are_drawn_in(root):  # noqa: F811
    from radar.ui.reminder import SUMMARY_LINES, ReminderWindow
    from radar.ui.richtext import RichText
    from test_ui import FakeApp as ReminderApp

    text = "Impossible travel: alice@contoso.com (likely VPN / proxy)"
    names = ["User", "Sign-in ID", "Impossible travel", "Usual countries"]
    before = theme._scale
    try:
        for scale in (1.0, 1.25, 1.5, 1.75):
            theme.set_scale(root, scale)
            win = ReminderWindow(root, ReminderApp())
            box = tk.Toplevel(root)
            rich = RichText(box)
            try:
                for used, name in ((win._f_title, theme.FONT_BOLD), (win._f_body, theme.FONT),
                                   (win._f_caption, theme.FONT_CAPTION), (rich._bold, theme.FONT_BOLD)):
                    named = tkfont.nametofont(name, root=root)
                    assert (used.measure(text), used.metrics("linespace")) == (
                        named.measure(text), named.metrics("linespace")), (scale, name)
            finally:
                win.top.destroy()
                box.destroy()
        for scale in (1.0, 1.5):                                  # ... and what is laid out with them fits
            theme.set_scale(root, scale)
            reminding = ReminderApp()
            reminding.alerts.ingest("p", [Finding(key="long", title="A very long title " * 8, severity=Severity.HIGH,
                                                  summary=" ".join(["Session of alice@contoso.com was used elsewhere."] * 12))])
            win = ReminderWindow(root, reminding)
            win.show()
            root.update()
            box = tk.Toplevel(root)
            rich = RichText(box)
            try:
                bottom = win.h_summary.winfo_y() + win.h_summary.winfo_reqheight()
                assert bottom <= win.header.winfo_height() and win.h_summary.cget("text").count("\n") == SUMMARY_LINES - 1
                bold = tkfont.nametofont(theme.FONT_BOLD, root=root)
                width = rich.set_key_width(names)
                assert all(bold.measure(f"{n}:") < width for n in names), scale
            finally:
                win.top.destroy()
                box.destroy()
    finally:
        theme.set_scale(root, before)


# ======================================================== 8. one rule that keeps failing holds nothing back
def test_a_rule_that_keeps_failing_no_longer_holds_the_scan_back(tmp_path, monkeypatch):
    from radar.plugins.signin_threats import plugin as plugin_mod

    original = list(plugin_mod.RULES)
    broken = next(r for r in original if r.meta.id == "brute_force")

    def boom(rc):
        raise RuntimeError("example failure")

    monkeypatch.setattr(plugin_mod, "RULES", [SimpleNamespace(meta=broken.meta, evaluate=boom) if r is broken else r
                                              for r in original])
    now = datetime.now(timezone.utc)
    server = Signins([by_hand(i, now - timedelta(minutes=m)) for i, m in enumerate((5, 15, 25), start=1)])
    pm, scan = scanner(tmp_path, server, event_types=["interactiveUser"])
    start = (now - timedelta(hours=1)).isoformat()
    pm.build_context(PLUGIN).state.set("checkpoint:interactiveUser", start)
    for _ in range(2):
        ctx = scan()
        assert ctx.incomplete and not ctx.failing and ctx.state.get("checkpoint:interactiveUser") == start
    ctx = scan()                                                  # the third time in a row: judged without it
    assert not ctx.incomplete and len(ctx.failing) == 1 and broken.meta.name in ctx.failing[0]
    assert ctx.state.get("checkpoint:interactiveUser") != start and stored(ctx)[1] == []
    monkeypatch.setattr(plugin_mod, "RULES", original)
    ctx = scan()                                                  # it works again
    assert not ctx.incomplete and not ctx.failing


def test_the_user_is_told_once_which_check_keeps_failing(app):  # noqa: F811
    shown = []
    app.ui_call = lambda fn, *args: fn(*args)
    app.reminders = SimpleNamespace(visible=False, show=lambda attention=False: shown.append(attention), refresh=lambda: None)
    ctx = app.plugins.build_context(PLUGIN)
    ctx.failing.append("'Brute force' (RuntimeError: example failure)")
    app.plugins.run = lambda plugin_id, defer=False: []
    for _ in range(3):
        app.plugins._contexts[PLUGIN] = ctx
        assert app.run_plugin(PLUGIN) is True
    told = [a for a in app.alerts.active() if a.is_system]
    assert len(told) == 1 and "Brute force" in told[0].summary and shown == [True]   # once, not with every scan
    assert app.last_error is None                                 # (the scans themselves work: nothing "failed")
    ctx.failing.clear()
    app.plugins._contexts[PLUGIN] = ctx
    assert app.run_plugin(PLUGIN) is True
    assert not [a for a in app.alerts.active() if a.is_system]     # it works again: the reminder goes


# ======================================================== 9. a lookup always ends
def test_a_looked_up_object_without_a_name_still_ends_the_lookup(app):  # noqa: F811
    device = {"kind": "device", "id": "44444444-5555-4666-8777-888888888888",
              "deviceId": "55555555-6666-4777-8888-999999999999", "name": None}
    assert linkify.portal_url("device", device).endswith("/deviceId/55555555-6666-4777-8888-999999999999")
    said, opened = [], []
    app.ui_call = lambda fn, *args: fn(*args)
    app._background = run_like_the_app
    app.open_link = opened.append
    for info, action in ((device, "device"), ({"id": "x"}, "find_id")):
        said.clear()
        app._resolver = SimpleNamespace(resolve=lambda kind, value, info=info: info)
        app.entity_action(linkify.Entity("device", "LT-0042", 0, 7), action, status=lambda text, error=False: said.append(text))
        assert said[0].startswith("Looking up") and len(said) == 2, said   # it said how it ended
    assert len(opened) == 1 and said[-1].startswith("Could not look up")


# ======================================================== 10. every worker reports back
def test_the_windows_hear_back_when_their_refresh_fails(app, monkeypatch):  # noqa: F811
    from radar import setup_check

    app.ui_call = lambda fn, *args: fn(*args)
    app._background = run_like_the_app
    app.refresh_threat_data = lambda: 1 / 0
    told = []
    app.tray = SimpleNamespace(notify=told.append, refresh=lambda: None)
    # the ongoing attacks
    attacks = []
    page = SimpleNamespace(hours=72.0, show_error=lambda message: attacks.append(("error", message)),
                           show=lambda *a, **k: attacks.append(("show",)))
    app.load_attacks(page, 72.0, refresh=True)
    assert attacks and attacks[-1][0] == "error"

    # the MFA exposure report: its refresh ends, with the reason
    class Age:
        busy, error = False, ""

        def set(self, as_of=None, busy=False, error="", keep_time=False):
            self.busy, self.error = busy, error

    report = SimpleNamespace(age=Age(), report=None, exists=lambda: True)
    app.refresh_exposure_report(report)
    assert report.age.busy is False and report.age.error

    # opening the report: whatever goes wrong is said
    app.threat_data_as_of = lambda: 1 / 0
    app.show_exposure_report()
    assert told and "report" in told[-1].lower()

    # the connection check ends, whatever happens on the way
    finished = []
    monkeypatch.setattr(setup_check, "sign_in", lambda auth, kind: 1 / 0)
    check = SimpleNamespace(step_done=lambda c: None, finished=finished.append, exists=lambda: True)
    app.run_setup_check(check)
    assert finished and not setup_check.working(finished[0])


# ======================================================== 11. an odd Retry-After
def test_an_odd_retry_after_is_waited_out_as_if_none_was_given():
    assert _retry_after(Resp({}, 429, {"Retry-After": "soon"}), 2) == 4.0
    assert _retry_after(Resp({}, 429, {"Retry-After": "Wed, 99 Foo 2026 25:61:00 GMT"}), 1) == 2.0
    later = datetime.now(timezone.utc) + timedelta(seconds=30)
    for zone in ("-0000", "+0000", "GMT"):                      # -0000: UTC, said without saying it
        header = format_datetime(later.replace(microsecond=0)).replace("+0000", zone)
        assert 20 <= _retry_after(Resp({}, 429, {"Retry-After": header}), 1) <= 31, header
    waits, answers = [], [Resp({}, 429, {"Retry-After": "soon"}), Resp({"value": [1]})]
    graph = graph_for()
    graph._session.get = lambda *a, **k: answers.pop(0)
    graph._sleep = waits.append
    assert graph.get("/v1.0/users") == {"value": [1]} and waits == [2.0]


# ======================================================== 12. the status survives scans starting and ending
def test_the_status_is_read_while_scans_start_and_end_and_the_tick_goes_on(app, root, monkeypatch):  # noqa: F811
    win = app._open_main()
    for _ in range(5):
        root.update()
    real_get = app.plugins.get
    app._running.update({PLUGIN, "directory_audit"})

    def get(plugin_id):   # a scan ends while the names of the running ones are read
        app._running.discard("directory_audit" if plugin_id == PLUGIN else PLUGIN)
        return real_get(plugin_id)

    monkeypatch.setattr(app.plugins, "get", get)
    assert win.status_now()[1] == "Scanning"
    app._running.update({PLUGIN, "directory_audit"})
    assert app.status_line().startswith("Status: scanning")
    app._running.clear()
    monkeypatch.setattr(app.plugins, "get", real_get)
    scheduled = []
    monkeypatch.setattr(win.top, "after", lambda ms, fn=None, *a: scheduled.append(fn))
    monkeypatch.setattr(win, "status_now", lambda: 1 / 0)
    win._tick()                                                   # one status that cannot be read ...
    assert scheduled == [win._tick]                               # ... and the next one is still coming


# ======================================================== 13. accounts saved while somebody reads them
def test_the_accounts_are_saved_while_a_window_or_the_map_reads_them(tmp_path):
    path = tmp_path / "accounts.json"
    AccountDirectory(synced_at=T0).save(path)
    reader = open(path, "rb")                                     # (Windows: a file open elsewhere cannot be replaced)
    threading.Timer(0.3, reader.close).start()
    AccountDirectory(synced_at=T0 + timedelta(hours=12)).save(path)
    assert AccountDirectory.load(path).synced_at == T0 + timedelta(hours=12)


def test_a_fresh_account_sync_is_used_even_when_it_cannot_be_saved(tmp_path, monkeypatch):
    from radar.plugins.signin_threats import plugin as plugin_mod

    fresh = AccountDirectory(synced_at=datetime.now(timezone.utc))

    def cannot(self, path):
        raise PermissionError(13, "The process cannot access the file because it is being used by another process")

    monkeypatch.setattr(plugin_mod, "sync_directory", lambda graph, now, groups: fresh)
    monkeypatch.setattr(AccountDirectory, "save", cannot)
    pm = PluginManager(ConfigManager(tmp_path / "config.json"), Store(":memory:"), graph_factory=lambda: None,
                       user_dir=tmp_path / "none", stop_event=threading.Event())
    pm.discover()
    plugin = SignInThreatsPlugin()
    plugin._account_sync_error = ""
    assert plugin._accounts(pm.build_context(PLUGIN), datetime.now(timezone.utc)) is fresh


# ======================================================== RADAR's own notices are "core", not "system"
def test_radars_own_notices_are_never_part_of_an_incident_nor_switched_off():
    center = AlertCenter(Store(":memory:"))
    now = datetime.now(timezone.utc)
    center.ingest(PLUGIN, [Finding(key=f"a{i}", title=f"Alert {i}: alice@contoso.com", severity=Severity.MEDIUM, score=50,
                                   rule_id="new_country", occurred_at=now - timedelta(days=i), fields={"User": "alice@contoso.com"})
                           for i in (1, 2)])
    center.ingest(SYSTEM_PLUGIN, [Finding(key=f"{SYSTEM_PLUGIN}:h{i}", title="RADAR needs attention", severity=Severity.MEDIUM,
                                          rule_id="health", occurred_at=now, fields={"User": "alice@contoso.com"}) for i in (1, 2)])
    from radar import incidents

    found = incidents.group(center.since(now - timedelta(days=31)), now)
    assert len(found) == 1 and not any(a.rule_id == "health" for a in found[0].alerts)
    notice = SimpleNamespace(plugin_id=SYSTEM_PLUGIN, rule_id="health", subjects=["alice@contoso.com"], signal="")
    assert quiet.choices(notice) == []
