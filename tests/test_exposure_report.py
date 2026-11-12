"""MFA exposure report on demand (tray), independent of the weekly reminder rule - and the age of its data."""
import threading
from datetime import datetime, timedelta, timezone

from radar.config import ConfigManager
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import SignInThreatsPlugin
from radar.plugins.signin_threats import plugin as plugin_module
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
from radar.store import Store


def context(tmp_path, accounts, synced_ago_hours=1.0, scanned_ago_minutes=None):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    pm.set_rule_enabled("signin_threats", "mfa_exposure_report", False)  # weekly reminder off
    ctx = pm.build_context("signin_threats")
    now = ctx.now()
    AccountDirectory(accounts, now - timedelta(hours=synced_ago_hours)).save(ctx.data_dir / "accounts.json")
    if scanned_ago_minutes is not None:
        ctx.state.set(plugin_module.DATA_AS_OF, (now - timedelta(minutes=scanned_ago_minutes)).isoformat())
    return ctx


def test_report_on_demand_even_with_weekly_reminder_off(tmp_path):
    ctx = context(tmp_path, {
        "u1": AccountInfo(user_id="u1", upn="scanner@contoso.com", mfa_excluded=["MFA_Exempt group"],
                          pwd_changed="2020-01-01T00:00:00Z"),
        "u2": AccountInfo(user_id="u2", upn="anna@contoso.com"),
    }, scanned_ago_minutes=4)
    p = SignInThreatsPlugin()
    assert "mfa_exposure_report" not in ctx.enabled_rules
    f = p.exposure_report(ctx)
    assert f.key == "mfaexposure|on-demand" and f.fields["Excluded from MFA"] == "1"
    assert f.evidence[0]["Account"] == "scanner@contoso.com" and "password" in f.evidence[0]["Flags"]
    assert next(iter(f.fields)) == "Data as of" and f.fields["Data as of"] != "unknown"


def test_report_is_built_from_local_data_without_the_network(tmp_path, monkeypatch):
    """The window opens at once: building the report never waits for Entra, however old the copy is."""
    def sync(*_a, **_k):
        raise AssertionError("the report must not read Entra itself")

    monkeypatch.setattr(plugin_module, "sync_directory", sync)
    ctx = context(tmp_path, {"u2": AccountInfo(user_id="u2", upn="scanner@contoso.com", mfa_excluded=["group"])},
                  synced_ago_hours=30)
    assert SignInThreatsPlugin().exposure_report(ctx) is not None
    empty = context(tmp_path / "b", {"u2": AccountInfo(user_id="u2", upn="anna@contoso.com")})
    assert SignInThreatsPlugin().exposure_report(empty) is None  # nobody without MFA


def test_data_age_is_the_oldest_part(tmp_path):
    """Sign-ins are read every few minutes, accounts every 12 h: the data is only as current as its oldest part."""
    p = SignInThreatsPlugin()
    ctx = context(tmp_path, {}, synced_ago_hours=5, scanned_ago_minutes=3)
    age = ctx.now() - p.data_as_of(ctx)
    assert timedelta(hours=4, minutes=59) < age < timedelta(hours=5, minutes=1)
    ctx = context(tmp_path / "b", {}, synced_ago_hours=0.01, scanned_ago_minutes=20)
    assert timedelta(minutes=19) < ctx.now() - p.data_as_of(ctx) < timedelta(minutes=21)
    assert p.data_as_of(context(tmp_path / "c", {}, synced_ago_hours=1)) is None  # no complete scan yet


def test_full_refresh_reads_the_accounts_again_and_gives_all_data_the_same_age(tmp_path, monkeypatch):
    """Refresh button: the next scan re-reads the accounts although they are younger than account_sync_hours - an
    account disabled an hour ago is no longer reported as enabled."""
    russia = dict(user_id="u1", upn="info-east@contoso.com", mfa_registered=False)
    scanner = AccountInfo(user_id="u2", upn="scanner@contoso.com", mfa_excluded=["MFA_Exempt group"])
    ctx = context(tmp_path, {"u1": AccountInfo(**russia), "u2": scanner}, synced_ago_hours=1, scanned_ago_minutes=5)
    calls = []

    def sync(graph, now, groups):  # Entra now: the account has been disabled
        calls.append(now)
        return AccountDirectory({"u1": AccountInfo(**russia, enabled=False), "u2": scanner}, now)

    monkeypatch.setattr(plugin_module, "sync_directory", sync)
    p = SignInThreatsPlugin()
    assert len(p.exposure_report(ctx).evidence) == 2
    now = ctx.now()
    p._accounts(ctx, now)  # an ordinary scan: one hour old is young enough
    assert not calls
    p.request_full_refresh()
    full, p._full_refresh = p._full_refresh, False  # what run() does at the start of the scan
    p._accounts(ctx, now, max_age=timedelta(0) if full else None)
    ctx.state.set(plugin_module.DATA_AS_OF, now.isoformat())
    assert calls == [now]
    assert [r["Account"] for r in p.exposure_report(ctx).evidence] == ["scanner@contoso.com"]
    assert p.data_as_of(ctx) == now and p.refresh_error() == ""


def test_failed_account_refresh_is_reported_and_the_age_stays_old(tmp_path, monkeypatch):
    def sync(graph, now, groups):
        raise RuntimeError("429 Too Many Requests")

    monkeypatch.setattr(plugin_module, "sync_directory", sync)
    ctx = context(tmp_path, {"u2": AccountInfo(user_id="u2", upn="scanner@contoso.com", mfa_excluded=["group"])},
                  synced_ago_hours=3, scanned_ago_minutes=0)
    p = SignInThreatsPlugin()
    p._account_sync_error = ""
    p._accounts(ctx, ctx.now(), max_age=timedelta(0))
    assert "429" in p.refresh_error()
    assert ctx.now() - p.data_as_of(ctx) > timedelta(hours=2, minutes=59)  # never shown younger than it is


def test_scheduler_reports_the_end_of_a_requested_scan():
    from radar.scheduler import Scheduler

    runs, results = [], []

    class Plugins:
        def ordered(self):
            return [type("RT", (), {"plugin": type("P", (), {"id": "signin_threats"})()})()]

        def is_enabled(self, pid):
            return True

        def interval_seconds(self, pid):
            return 600

    class App:
        stop_event = threading.Event()
        paused = True  # a requested scan runs even while paused
        plugins = Plugins()
        cfg = type("Cfg", (), {"get": staticmethod(lambda *a, default=None: default)})()

        def on_tick(self):
            pass

        def run_plugin(self, pid):
            runs.append(pid)
            return len(runs) == 1

    s = Scheduler(App())
    s.trigger("signin_threats", done=results.append)
    s.trigger("signin_threats", done=results.append)  # two windows asking at once: one scan, both are told
    s._tick()
    assert runs == ["signin_threats"] and results == [True, True]
    s._tick()
    assert runs == ["signin_threats"]  # nothing left to do
    s.trigger("signin_threats", done=results.append)
    s._tick()
    assert results == [True, True, False]  # a failed scan is reported as such


def test_same_report_ignores_only_the_timestamp():
    from radar.app import App
    from radar.plugin_api import Finding, Severity

    def report(as_of, rows):
        return Finding(key="k", title="MFA exposure report", severity=Severity.LOW, score=15,
                       fields={"Data as of": as_of, "Excluded from MFA": str(len(rows))}, evidence=rows)

    rows = [{"Account": "a@contoso.com", "Enabled": "yes"}]
    assert App._same_report(report("10:00", rows), report("16:00", rows))
    assert not App._same_report(report("10:00", rows), report("16:00", [{"Account": "a@contoso.com", "Enabled": "no"}]))


def test_age_texts():
    from radar.ui.freshness import age_text, describe

    now = datetime(2026, 11, 10, 16, 0, tzinfo=timezone.utc)
    ago = lambda **kw: now - timedelta(**kw)  # noqa: E731
    assert age_text(ago(seconds=40), now) == "just now"
    assert age_text(ago(minutes=7, seconds=59), now) == "7 min ago"  # rounded down, never younger than it is
    assert age_text(ago(hours=5, minutes=30), now) == "5 h ago"
    assert age_text(ago(days=3, hours=2), now) == "3 days ago"
    assert age_text(None, now) == "age unknown"
    assert describe(None, True) == "No data yet"
    text = describe(ago(minutes=7), True, now=now)
    assert text.endswith("(7 min ago)")  # that a refresh is running is said by the button only
    assert describe(ago(minutes=7), False, "sign-in required", now=now).endswith("refresh failed: sign-in required")
    assert ago(days=2).astimezone().strftime("%Y-%m-%d") in describe(ago(days=2), False, now=now)  # not today: date
