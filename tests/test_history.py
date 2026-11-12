"""Alert history: every kept alert in one window, a dismissed one can be reactivated; and the tray menu's layout."""
import tkinter as tk
from types import SimpleNamespace

import pytest

from radar.alerts import ACTIVE, DISMISSED, MUTED, SNOOZED, AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store


def center():
    c = AlertCenter(Store(":memory:"))
    c.ingest("p", [Finding(key="a", title="Password attack: bea@contoso.com", severity=Severity.MEDIUM, summary="rotating IPs"),
                   Finding(key="b", title="New country (BR): cy@contoso.com", severity=Severity.LOW),
                   Finding(key="c", title="Device registered by dan", severity=Severity.INFO),
                   Finding(key="d", title="Risky sign-in: eve@contoso.com", severity=Severity.HIGH)])
    return c


def by_title(c):
    return {a.title.split(":")[0].split(" by")[0]: a for a in c.recent(100)}


def test_reactivate_brings_a_dismissed_alert_back_as_new():
    c = center()
    a = by_title(c)
    assert a["Device registered"].status == MUTED  # below the notification level: logged only
    c.mark_seen([a["Password attack"].id])
    c.dismiss([a["Password attack"].id])
    c.snooze([a["New country (BR)"].id], 60)
    assert c.count_active() == 1 and c.get(a["Password attack"].id).status == DISMISSED
    assert c.reactivate([a["Password attack"].id, a["New country (BR)"].id, a["Device registered"].id, a["Risky sign-in"].id]) == 3
    assert c.count_active() == 4  # the open one was left as it was, the other three are back
    back = c.get(a["Password attack"].id)
    assert back.status == ACTIVE and not back.seen and back.snooze_until is None  # shown as new again
    assert c.get(a["New country (BR)"].id).status == ACTIVE and c.get(a["Device registered"].id).status == ACTIVE
    # a system note comes and goes with its cause: not reactivated by hand
    c.raise_system("signin", "Sign-in needed", "x")
    note = [x for x in c.recent(100) if x.is_system][0]
    c.dismiss([note.id])
    assert c.reactivate([note.id]) == 0 and c.get(note.id).status == DISMISSED


def test_history_filters():
    from radar.ui.history import can_reactivate, matches

    c = center()
    a = by_title(c)
    c.dismiss([a["Password attack"].id])
    a = by_title(c)
    attack, country, device = a["Password attack"], a["New country (BR)"], a["Device registered"]
    assert matches(attack, None, Severity.INFO, []) and matches(attack, {DISMISSED}, Severity.MEDIUM, ["bea", "rotating"])
    assert not matches(attack, {ACTIVE, SNOOZED}, Severity.INFO, [])        # state
    assert not matches(country, None, Severity.MEDIUM, [])                   # severity
    assert not matches(attack, None, Severity.INFO, ["bea", "nothing-like-this"])  # every word must occur
    assert can_reactivate(attack) and can_reactivate(device) and not can_reactivate(country)


@pytest.fixture(scope="module")
def root():
    from radar.ui import theme

    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - no desktop available
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    theme.init(r)
    yield r
    r.destroy()


def test_history_window_lists_filters_and_reactivates(root):
    from radar.ui.history import HistoryWindow

    class App:
        def __init__(self):
            self.alerts = center()
            self.cfg = SimpleNamespace(get=lambda *path, default=None: default)
            self.opened, self.reactivated = [], 0

        def describe_origin(self, alert):
            return "test rule"

        def open_alert(self, alert):
            self.opened.append(alert.title)

        def on_alerts_reactivated(self):
            self.reactivated += 1

    app = App()
    attack = by_title(app.alerts)["Password attack"]
    app.alerts.dismiss([attack.id])
    win = HistoryWindow(root, app)
    try:
        root.update()
        rows = {win.tree.set(i, "Alert"): win.tree.set(i, "State") for i in win.tree.get_children("")}
        assert rows == {"Password attack: bea@contoso.com": "dismissed", "New country (BR): cy@contoso.com": "open",
                        "Device registered by dan": "logged only", "Risky sign-in: eve@contoso.com": "open"}
        assert "4 alerts kept (4 shown): 2 open, 0 snoozed, 1 dismissed, 1 logged only" in win.summary.cget("text")
        assert str(win.reactivate_btn.cget("state")) == "disabled"            # nothing selected yet
        win.show_var.set("Dismissed")
        win.refresh()
        assert [win.tree.set(i, "Alert") for i in win.tree.get_children("")] == ["Password attack: bea@contoso.com"]
        win.show_var.set("All alerts")
        win.search_var.set("eve risky")                                       # (refreshes by itself)
        assert [win.tree.set(i, "Alert") for i in win.tree.get_children("")] == ["Risky sign-in: eve@contoso.com"]
        win.tree.selection_set(win.tree.get_children(""))
        win._selection_changed()
        assert str(win.reactivate_btn.cget("state")) == "disabled"            # an open alert needs no reactivating
        win.open_selected()
        assert app.opened == ["Risky sign-in: eve@contoso.com"]
        win.search_var.set("")
        win.tree.selection_set(str(attack.id))
        win._selection_changed()
        assert str(win.reactivate_btn.cget("state")) == "normal"
        win.reactivate_selected()
        assert app.alerts.get(attack.id).status == ACTIVE and app.reactivated == 1
        assert win.tree.set(str(attack.id), "State") == "open" and "1 alert reactivated" in win.hint.label.cget("text")
    finally:
        win.top.destroy()


def test_tray_menu_layout():
    """The menu a user sees: views on top, the two everyday switches, everything else under Settings - and no entry twice."""
    pytest.importorskip("pystray")
    from radar.tray import Tray

    rule = SimpleNamespace(id="r1", name="Rule one")
    rt = SimpleNamespace(plugin=SimpleNamespace(id="p1", name="Sign-in threats", rules=[rule]))
    app = SimpleNamespace(
        alerts=SimpleNamespace(count_active=lambda: 3, count_unseen=lambda: 1), status_line=lambda: "Last scan 12:00",
        plugins=SimpleNamespace(ordered=lambda: [rt], load_errors=[], is_enabled=lambda pid: True, rule_enabled=lambda pid, rid: True),
        auth=SimpleNamespace(account="me@contoso.com", state="ok", using_explicit_account=False),
        plugin_status_text=lambda rt: "ok", paused=False, exposure_reminder=True, dark_mode=False, animations=True,
        sound_enabled=True, respect_mute=True, identity_label="own app registration", setup_done=True,
        updates=SimpleNamespace(available=None), check_updates=True)
    for name in ("show_reminders_from_tray", "show_history", "show_incidents", "show_attacks", "show_map", "show_exposure_report", "scan_now", "toggle_pause",
                 "quit", "show_offices", "show_hosts", "toggle_exposure_reminder", "toggle_dark_mode", "toggle_animations", "toggle_startup",
                 "sign_in", "use_windows_account", "open_config", "open_log", "open_data_dir", "open_plugins_dir", "reload_plugins",
                 "toggle_sound", "toggle_respect_mute", "test_sound", "toggle_plugin", "toggle_rule", "show_setup", "toggle_check_updates", "look_for_update", "open_update_page"):
        setattr(app, name, lambda *a: None)
    tray = Tray(app)

    import pystray

    def texts(items):
        return [i.text for i in items if i is not pystray.Menu.SEPARATOR]

    top = list(tray._items())
    assert texts(top)[2:] == ["Show reminders (3, 1 new)", "Incidents...", "Alert history...", "Ongoing attacks...", "Live map...",
                              "MFA exposure report...", "Scan now", "Pause monitoring", "Settings", "Exit"]
    assert [i.text for i in top if i.default] == ["Show reminders (3, 1 new)"]
    settings = list(next(i for i in top if i.text == "Settings").submenu.items)
    assert texts(settings) == ["Detection", "Offices...", "Virtual desktops...", "Weekly MFA exposure reminder", "Reminder sound",
                               "Appearance", "Start with Windows", "Check for new versions", "Account: me@contoso.com", "Advanced"]
    sub = {i.text: texts(i.submenu.items) for i in settings if i.submenu}
    assert sub["Detection"] == ["Sign-in threats"]
    assert sub["Advanced"] == ["Edit settings file (config.json)", "Open log file", "Open data folder", "Open plugins folder", "Reload plugins", "Look for a new version now"]
    assert sub["Appearance"] == ["Dark mode", "Animations"] and sub["Account: me@contoso.com"][0] == "Sign in..."
    assert sub["Account: me@contoso.com"][-1] == "Set-up and connection check... (own app registration)"

    def everything(items):
        for i in items:
            if i is pystray.Menu.SEPARATOR:
                continue
            yield i.text
            if i.submenu:
                yield from everything(i.submenu.items)

    # a newer release puts one more line above Settings
    app.updates.available = SimpleNamespace(version="9.9.0")
    assert "New version 9.9.0 available..." in texts(list(tray._items()))
    app.updates.available = None
    seen = list(everything(top))
    assert len(seen) == len(set(seen)), "an entry appears twice in the menu"
