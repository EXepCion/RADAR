"""Drives the real Tk reminder/details windows (no mainloop) against a real AlertCenter."""
import tkinter as tk

import pytest

from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store


class FakeCfg:
    def get(self, *path, default=None):
        return {"default_snooze": "15 minutes", "flash_window": False}.get(path[-1], default)


class FakeApp:
    def __init__(self):
        self.cfg = FakeCfg()
        self.alerts = AlertCenter(Store(":memory:"))

    def describe_origin(self, alert):
        return "test"

    def play_reminder_sound(self):
        return False, "test"

    def on_alerts_changed(self):
        pass

    def open_link(self, url):
        pass

    def entry_id_field(self, alert):
        return "Sign-in ID"

    def view_entry(self, alert, row):
        self.viewed = row

    def entity_action(self, entity, action, row=None, alert=None, status=None):
        self.actions = getattr(self, "actions", []) + [(entity, action, row)]


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


@pytest.fixture
def ui(root):
    from radar.ui.reminder import ReminderWindow

    app = FakeApp()
    app.alerts.ingest("p", [Finding(key=f"k{i}", title=f"Alert {i}", severity=Severity.HIGH) for i in range(2)])
    win = ReminderWindow(root, app)
    win.show()
    root.update()
    yield app, win, root
    for d in win._details.values():
        if d.exists():
            d.top.destroy()
    win.top.destroy()
    root.update()


def test_open_item_does_not_dismiss(ui):
    app, win, root = ui
    first = win.tree.selection()[0]
    win.open_selected()                       # "Open Item" button
    root.update()
    details = win._details[int(first)]
    assert details.exists()
    assert app.alerts.count_active() == 2
    assert app.alerts.get(int(first)).status == "active"

    details.top.destroy()                     # closing the details window (X / Close)
    root.update()
    assert app.alerts.count_active() == 2

    win.top.focus_force()
    win.top.event_generate("<Return>")        # Enter key (same handler as double-click: open_selected)
    root.update()
    win.open_selected()                       # open again via the button
    root.update()
    assert app.alerts.count_active() == 2
    assert len(win.tree.get_children()) == 2  # still listed in the reminders window


def test_header_height_is_stable_across_selections(root):
    from radar.ui.reminder import ReminderWindow

    app = FakeApp()
    long_summary = " ".join(["Session of someone@contoso.com was used from Milano, IT and Academic City, AE "
                             "(2001:db8:1761:2a3:1088:99d3:487e:61d1) on a different device."] * 6)
    app.alerts.ingest("p", [
        Finding(key="short", title="Short", severity=Severity.LOW, summary="One line."),
        Finding(key="long", title="A very long title " * 8, severity=Severity.HIGH, summary=long_summary),
        Finding(key="empty", title="No summary", severity=Severity.MEDIUM),
    ])
    win = ReminderWindow(root, app)
    win.show()
    root.update()
    heights, list_tops = set(), set()
    for iid in list(win.tree.get_children()) * 2:
        win.tree.selection_set(iid)
        root.update()
        heights.add(win.header.winfo_height())
        list_tops.add(win.tree.winfo_rooty())
    win.tree.selection_set(win.tree.get_children())  # multi-select prefix makes the summary longer still
    root.update()
    heights.add(win.header.winfo_height())
    assert len(heights) == 1 and len(list_tops) == 1
    assert win.h_summary.cget("text").count("\n") <= 2 and win.h_summary.cget("text").endswith("…")
    assert "\n" not in win.h_title.cget("text")
    win.top.destroy()


def test_fit_lines(root):
    from tkinter import font as tkfont

    from radar.ui.reminder import fit_lines

    f = tkfont.Font(root=root, family="Segoe UI", size=9)
    assert fit_lines("short text", f, 400, 3) == "short text"
    out = fit_lines("word " * 200, f, 200, 3)
    assert out.count("\n") == 2 and out.endswith("…") and all(f.measure(line) <= 200 for line in out.split("\n"))
    ipv6 = fit_lines("x" * 300, f, 100, 2)  # unbreakable token is hard-wrapped
    assert ipv6.count("\n") == 1 and ipv6.endswith("…")
    assert fit_lines("", f, 100, 3) == ""


def test_new_reminders_are_marked_until_the_user_selects_them(root):
    from radar.ui.reminder import ReminderWindow

    app = FakeApp()
    old = app.alerts.ingest("p", [Finding(key="old", title="Old one", severity=Severity.HIGH)])[0]
    app.alerts.mark_seen([old.id])
    app.alerts.ingest("p", [Finding(key="n1", title="New 1", severity=Severity.MEDIUM),
                            Finding(key="n2", title="New 2", severity=Severity.LOW)])
    win = ReminderWindow(root, app)
    win.show()
    root.update()
    tags = {win._alerts[i].title: win.tree.item(i, "tags") for i in win.tree.get_children()}
    assert tags["Old one"] in ("", ()) and "new" in tags["New 1"] and "new" in tags["New 2"]
    assert win.top.title() == "3 Reminders (2 new)"
    assert app.alerts.count_unseen() == 2  # the automatic first-row selection did not mark anything seen

    new1 = next(i for i in win.tree.get_children() if win._alerts[i].title == "New 1")
    win.tree.selection_set(new1)
    win.tree.event_generate("<ButtonRelease-1>")  # user clicked the row
    root.update()
    assert win.tree.item(new1, "tags") in ("", ()) and win.top.title() == "3 Reminders (1 new)"
    assert app.alerts.count_unseen() == 1
    win.top.destroy()


def test_attention_flashes_until_user_interacts(root, monkeypatch):
    from radar.ui import theme
    from radar.ui.reminder import ATTENTION_BG, ReminderWindow

    from radar.ui import reminder

    calls = []
    monkeypatch.setattr(theme, "flash", lambda w, stop=False: calls.append("stop" if stop else "start"))
    monkeypatch.setattr(reminder, "FOCUS_GRACE_SECONDS", 60)  # independent of how fast the test machine is
    app = FakeApp()
    app.cfg = type("Cfg", (), {"get": lambda self, *p, default=None: True if p[-1] == "flash_window" else default})()
    app.alerts.ingest("p", [Finding(key="x", title="Alert", severity=Severity.HIGH)])
    win = ReminderWindow(root, app)
    win.show(attention=True)
    root.update()
    assert win.attention and calls == ["start"]
    assert win.header.cget("bg") == ATTENTION_BG  # header blinks
    assert win.h_title.cget("text") == "Alert"  # the new reminder is the one shown in the header
    win.top.event_generate("<FocusIn>")  # Windows activating the new window by itself: still waiting
    root.update()
    assert win.attention
    win.top.event_generate("<ButtonPress-1>")  # the user clicked into the window
    root.update()
    assert not win.attention and calls == ["start", "stop"]
    assert win.header.cget("bg") != ATTENTION_BG
    win.show(attention=True)  # the next new alert starts it again
    assert win.attention
    win.hide()
    assert not win.attention
    win.top.destroy()


def test_only_dismiss_button_in_details_dismisses(ui):
    app, win, root = ui
    first = int(win.tree.selection()[0])
    win.open_selected()
    root.update()
    win._details[first]._dismiss()            # "Dismiss" button inside the details window
    root.update()
    assert app.alerts.get(first).status == "dismissed"
    assert app.alerts.count_active() == 1
