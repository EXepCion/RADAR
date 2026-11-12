"""Sortable detail tables and break-glass accounts (group + naming pattern)."""
import tkinter as tk
from datetime import timedelta
from tkinter import ttk

import pytest

from radar.plugin_api import Severity
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
from radar.plugins.signin_threats.rules import RuleContext
from radar.ui.tables import make_sortable, sort_key

from conftest import T0, make_signin


@pytest.fixture(scope="module")
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    yield r
    r.destroy()


def test_sort_key_orders_numbers_numerically_and_text_case_insensitive():
    values = ["10", "9", "1,234", "abc", "Abd", "2026-11-09 10:00:00", "2026-11-08 23:59:59"]
    assert sorted(values, key=sort_key) == ["9", "10", "1,234", "2026-11-08 23:59:59", "2026-11-09 10:00:00", "abc", "Abd"]


def test_make_sortable_toggles_and_shows_arrow(root):
    tree = ttk.Treeview(root, columns=("Time", "Count"), show="headings")
    for t, n in (("2026-11-09 10:00", "5"), ("2026-11-08 09:00", "12"), ("2026-11-10 08:00", "1")):
        tree.insert("", "end", values=(t, n))
    sort = make_sortable(tree, ["Time", "Count"])
    sort("Count")
    assert [tree.set(i, "Count") for i in tree.get_children()] == ["1", "5", "12"]
    assert tree.heading("Count", "text") == "Count ▲" and tree.heading("Time", "text") == "Time"
    sort("Count")
    assert [tree.set(i, "Count") for i in tree.get_children()] == ["12", "5", "1"]
    assert tree.heading("Count", "text") == "Count ▼"
    sort("Time")
    assert [tree.set(i, "Time") for i in tree.get_children()][0] == "2026-11-08 09:00"
    tree.destroy()


def test_details_window_evidence_is_sortable(root):
    from test_ui import FakeApp

    from radar.plugin_api import Finding
    from radar.ui import theme
    from radar.ui.details import DetailsWindow

    theme.init(root)
    app = FakeApp()
    alert = app.alerts.ingest("p", [Finding(key="k", title="T", severity=Severity.HIGH, evidence=[
        {"Time": "2026-11-09 10:00:00", "User": "b@x", "Sign-in ID": "2"},
        {"Time": "2026-11-08 10:00:00", "User": "a@x", "Sign-in ID": "1"}])])[0]
    win = DetailsWindow(root, app, alert, on_dismiss=lambda a: None)
    win.sort("User")
    assert [win.tree.set(i, "User") for i in win.tree.get_children()] == ["a@x", "b@x"]
    win.tree.selection_set(win.tree.get_children()[0])
    assert win.selected_row()["Sign-in ID"] == "1"  # row data stays attached after sorting
    win.top.destroy()


def bg_directory(synced_at):
    accounts = {
        "u-bg": AccountInfo(user_id="u-bg", upn="pat_break_glass@contoso.onmicrosoft.com", breakglass=True,
                            roles=["Global Administrator"]),
        "u-pattern": AccountInfo(user_id="u-pattern", upn="anna_break_glass@contoso.onmicrosoft.com"),
    }
    return AccountDirectory(accounts, synced_at)


def build(history, new, d, settings=None):
    history.add(new)
    return RuleContext.build(new, history, settings or {}, T0 + timedelta(hours=2), accounts=d)


def test_breakglass_background_session_is_high_weekly(history):
    d = bg_directory(T0 - timedelta(hours=1))
    bg = [make_signin(i * 60, user_id="u-bg", upn="pat_break_glass@contoso.onmicrosoft.com", interactive=False,
                      app="Microsoft Authentication Broker") for i in range(2)]
    out = rules.account_state(build(history, bg, d))
    assert len(out) == 1 and out[0].severity == Severity.HIGH  # both refreshes -> one weekly reminder
    assert "-W" in out[0].key and "in the background" in out[0].summary
    assert "BREAK-GLASS" in out[0].fields["Account context"]


def test_breakglass_by_pattern_and_failed_attempts(history):
    d = bg_directory(T0 - timedelta(hours=1))
    settings = {"breakglass_accounts": ["*_break_glass@contoso.onmicrosoft.com"]}
    ok = make_signin(0, user_id="u-pattern", upn="anna_break_glass@contoso.onmicrosoft.com")
    fail = make_signin(5, user_id="u-bg", upn="pat_break_glass@contoso.onmicrosoft.com", error_code=50126)
    out = {f.key.split("|")[1]: f for f in rules.account_state(build(history, [ok, fail], d, settings))}
    assert out["bg"].severity == Severity.HIGH
    assert out["bg-fail"].title.startswith("Sign-in attempts on break-glass account")


def test_breakglass_groups_change_forces_resync(tmp_path, monkeypatch):
    import threading

    from radar.config import ConfigManager
    from radar.plugin_manager import PluginManager
    from radar.plugins.signin_threats import SignInThreatsPlugin
    from radar.plugins.signin_threats import plugin as plugin_mod
    from radar.store import Store

    pm = PluginManager(ConfigManager(tmp_path / "c.json"), Store(":memory:"), graph_factory=lambda: None,
                       user_dir=tmp_path / "none", stop_event=threading.Event())
    pm.discover()
    calls = []
    monkeypatch.setattr(plugin_mod, "sync_directory",
                        lambda graph, now, groups: calls.append(groups) or AccountDirectory({}, now, breakglass_groups=groups))
    c = pm.build_context("signin_threats")
    p = SignInThreatsPlugin()
    p._accounts(c, T0)
    p._accounts(c, T0 + timedelta(minutes=10))  # fresh snapshot, same groups: no resync
    c.settings["breakglass_groups"] = ["00000000-0000-4000-8000-000000000001"]
    p._accounts(c, T0 + timedelta(minutes=20))  # groups changed: resync
    assert calls == [[], ["00000000-0000-4000-8000-000000000001"]]
