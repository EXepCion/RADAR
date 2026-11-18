"""Keeping RADAR whole over time: the background sign-ins of the hours the PC was off are read afterwards, a lost
connection is waited out, the history gives back the room of what it purged, and a build says what it is."""
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

import pytest
import requests

from conftest import T0, make_signin
from radar.config import ConfigManager
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import SignInThreatsPlugin
from radar.plugins.signin_threats.history import SignInHistory
from radar.plugins.signin_threats.models import parse_time
from radar.store import Store
from test_main_window import app  # noqa: F401  (a real App on an empty data folder)
from test_ui import root  # noqa: F401

BACKLOG = "backlog:nonInteractiveUser"


# ------------------------------------------------------------------ the hours the PC was off
class Log:
    """A sign-in log that answers by the time range asked for, newest first, in pages of two."""

    def __init__(self, rows):
        self.rows, self.asked = rows, []

    def get_pages(self, path, params=None, max_pages=None):
        flt = params["$filter"]
        if "nonInteractiveUser" not in flt:
            return
        start = parse_time(re.search(r"createdDateTime ge (\S+)", flt).group(1))
        end = re.search(r"createdDateTime le (\S+)", flt)
        end = parse_time(end.group(1)) if end else None
        self.asked.append((start, end, max_pages))
        hits = sorted((r for r in self.rows if start <= parse_time(r["createdDateTime"]) and
                       (end is None or parse_time(r["createdDateTime"]) <= end)),
                      key=lambda r: r["createdDateTime"], reverse=True)
        for n, i in enumerate(range(0, len(hits), 2)):
            if max_pages and n >= max_pages:
                return
            yield hits[i:i + 2]


def background(i, hours_ago, now):
    return {"id": f"bg{i}", "createdDateTime": (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
            "userId": "u1", "userPrincipalName": "alice@contoso.com", "ipAddress": f"203.0.113.{i}",
            "status": {"errorCode": 0}, "location": {"countryOrRegion": "CA"}, "clientAppUsed": "Mobile Apps and Desktop clients",
            "isInteractive": False, "deviceDetail": {"deviceId": f"dev{i}"}}


def tenant(tmp_path, off_for_hours, **settings):
    """A RADAR whose last scan was ``off_for_hours`` ago, and the background sign-ins of a day and a half."""
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    for name, value in settings.items():
        cfg.set("plugins", "signin_threats", "settings", name, value=value)
    now = datetime.now(timezone.utc)
    log = Log([background(i, h, now) for i, h in enumerate((0.5, 5, 8, 12, 19, 30), start=1)])

    def scan():
        ctx = pm.build_context("signin_threats")
        ctx.graph = log
        SignInThreatsPlugin().run(ctx)
        return ctx

    first = pm.build_context("signin_threats")
    for event in ("interactiveUser", "nonInteractiveUser"):
        first.state.set(f"checkpoint:{event}", (now - timedelta(hours=off_for_hours)).isoformat())
    return scan, log, now


def devices(ctx):
    h = SignInHistory(ctx.data_dir / "signins.db")
    try:
        return h.user_devices("u1", datetime.now(timezone.utc) + timedelta(minutes=1))
    finally:
        h.close()


def test_the_first_scan_after_a_night_is_quick_and_the_night_is_read_in_the_scans_after_it(tmp_path):
    scan, log, now = tenant(tmp_path, off_for_hours=20)
    ctx = scan()
    assert devices(ctx) == {"dev1", "dev2"}                       # the last six hours: at once
    (start, end), = ctx.state.get(BACKLOG)                        # the hours before: owed
    assert abs(parse_time(start) - (now - timedelta(hours=20, minutes=20))) < timedelta(minutes=2)
    assert abs(parse_time(end) - (now - timedelta(hours=6))) < timedelta(minutes=2)
    ctx = scan()
    assert devices(ctx) == {"dev1", "dev2", "dev3", "dev4", "dev5"}   # (30 hours ago was read before the PC went off)
    assert not ctx.state.get(BACKLOG)
    asked = len(log.asked)
    scan()
    assert len(log.asked) == asked + 1                            # nothing owed any more: only the usual question


def test_a_long_absence_is_read_in_portions_newest_first(tmp_path):
    scan, log, now = tenant(tmp_path, off_for_hours=20, backlog_pages_per_run=1)
    scan()
    ctx = scan()
    assert devices(ctx) == {"dev1", "dev2", "dev3", "dev4"}       # one page of two: the newest of what is owed
    (start, end), = ctx.state.get(BACKLOG)
    assert abs(parse_time(end) - (now - timedelta(hours=12))) < timedelta(minutes=2)   # from there on next time
    ctx = scan()
    assert devices(ctx) == {"dev1", "dev2", "dev3", "dev4", "dev5"}
    ctx = scan()
    assert not ctx.state.get(BACKLOG)


def test_how_far_back_is_read_has_a_limit_and_can_be_switched_off(tmp_path):
    scan, _log, now = tenant(tmp_path / "a", off_for_hours=24 * 20, non_interactive_backlog_days=2)
    (start, _end), = scan().state.get(BACKLOG)
    assert abs(parse_time(start) - (now - timedelta(days=2))) < timedelta(minutes=2)
    scan, _log, now = tenant(tmp_path / "b", off_for_hours=20, non_interactive_backlog_days=0)
    ctx = scan()
    assert not ctx.state.get(BACKLOG) and devices(ctx) == {"dev1", "dev2"}
    assert devices(scan()) == {"dev1", "dev2"}


def test_what_is_read_afterwards_is_judged_like_any_sign_in(tmp_path):
    scan, log, now = tenant(tmp_path, off_for_hours=20)
    night = background(9, 10, now)
    night.update(userId="u7", userPrincipalName="svc@contoso.com", clientAppUsed="IMAP4", isInteractive=False)
    log.rows.append(night)
    scan()
    cfg_ctx = scan()
    h = SignInHistory(cfg_ctx.data_dir / "signins.db")
    try:
        assert "imap4" in h.user_profile("u7", "proto", datetime.now(timezone.utc) + timedelta(minutes=1))
    finally:
        h.close()


# ------------------------------------------------------------------ no connection
def test_a_lost_connection_is_waited_out_and_not_called_a_crash(app, caplog):  # noqa: F811
    def no_network(plugin_id):
        raise requests.exceptions.ConnectionError("HTTPSConnectionPool(host='login.microsoftonline.com', port=443)")

    app.plugins.run = no_network
    with caplog.at_level(logging.INFO):
        assert app.run_plugin("signin_threats") is False
    assert app.offline and app.last_error == "no connection to Microsoft - trying again"
    assert app.status_line() == "Status: no connection to Microsoft - trying again"
    assert "no connection" in app.tray_state()[1] and "failed" not in app.tray_state()[1]
    assert "crashed" not in caplog.text and not any(r.exc_info for r in caplog.records)
    assert "HTTPSConnectionPool" not in app.last_error

    def wrapped(plugin_id):
        try:
            raise requests.exceptions.ReadTimeout("read timed out")
        except requests.exceptions.ReadTimeout as exc:
            raise RuntimeError("token request failed") from exc

    app.plugins.run = wrapped
    assert app.run_plugin("signin_threats") is False and app.offline
    app.plugins.run = lambda plugin_id: []
    assert app.run_plugin("signin_threats") is True and not app.offline and app.last_error is None


def test_a_real_fault_is_still_a_crash(app, caplog):  # noqa: F811
    def broken(plugin_id):
        raise ValueError("boom")

    app.plugins.run = broken
    assert app.run_plugin("signin_threats") is False
    assert not app.offline and "ValueError: boom" in app.last_error and "crashed" in caplog.text


# ------------------------------------------------------------------ the room of what was purged
def test_the_history_gives_back_the_room_of_what_it_purged(tmp_path):
    path = tmp_path / "signins.db"
    h = SignInHistory(path)
    try:
        h.add([make_signin(i / 10, interactive=False, user_agent="x" * 1500) for i in range(2500)])
        assert h.compact() == 0                                   # nothing is free yet
        h.purge(T0 + timedelta(days=1), T0 + timedelta(days=1))
        free = h.free_bytes()
        assert free > 2_000_000
        assert h.compact(min_free_bytes=10 ** 9) == 0             # not worth it below the threshold
        assert h.compact(min_free_bytes=1_000_000, min_free_ratio=0.2) >= free * 0.9
        assert h.free_bytes() < 100_000 and h.count() == 0
        h.add([make_signin(1)])
        assert h.count() == 1                                     # and it works on as before
    finally:
        h.close()
    assert path.stat().st_size < 1_000_000


def test_compacting_is_tried_once_a_week(tmp_path):
    calls = []

    class History:
        def compact(self):
            calls.append(1)
            return 5_000_000

    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    ctx = pm.build_context("signin_threats")
    plugin, now = SignInThreatsPlugin(), datetime.now(timezone.utc)
    plugin._compact(ctx, History(), now)
    plugin._compact(ctx, History(), now + timedelta(days=3))
    assert calls == [1]
    plugin._compact(ctx, History(), now + timedelta(days=8))
    assert calls == [1, 1]


# ------------------------------------------------------------------ what build this is
def test_a_build_that_is_not_the_release_says_so():
    from radar import __version__, buildinfo

    assert buildinfo.mark(__version__, tag=f"v{__version__}", commit="abc1234", changed=False) == ""    # the release
    assert buildinfo.mark(__version__, tag="", commit="abc1234", changed=False) == "dev.abc1234"
    assert buildinfo.mark(__version__, tag=f"v{__version__}", commit="abc1234", changed=True) == "dev.abc1234+changes"
    assert buildinfo.mark(__version__, tag="v0.0.1", commit="abc1234", changed=False) == "dev.abc1234"
    assert buildinfo.mark(__version__, tag="", commit="", changed=False) == ""            # no git: nothing is claimed
    assert buildinfo.full_version(__version__, "") == __version__
    assert buildinfo.full_version(__version__, "dev.abc1234") == f"{__version__} (dev.abc1234)"


@pytest.mark.parametrize("name", ["__version__"])
def test_the_version_number_itself_stays_what_the_release_is_checked_against(name):
    import radar

    assert re.fullmatch(r"\d+\.\d+\.\d+", getattr(radar, name))     # (the tag check and the update check use it)


def test_the_release_notes_hold_this_version_only_and_the_changelog_all_of_them():
    """What GitHub shows for a release is that version's part; it does not grow with every release."""
    from pathlib import Path

    import radar

    root = Path(__file__).resolve().parents[1]
    notes = (root / "packaging" / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    assert re.findall(r"\*\*New in ([\d.]+)\*\*", notes) == [radar.__version__]
    assert "**Files**" in notes and "CHANGELOG.md" in notes
    log = re.findall(r"\*\*New in ([\d.]+)\*\*", (root / "CHANGELOG.md").read_text(encoding="utf-8"))
    assert log[0] == radar.__version__ and len(log) == len(set(log)) > 1
    assert log == sorted(log, key=lambda v: tuple(map(int, v.split("."))), reverse=True)

