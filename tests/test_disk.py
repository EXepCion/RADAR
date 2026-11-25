"""Is the disk RADAR keeps its data on encrypted? RADAR stores the sign-in history and its alerts as plain files; it
says so when Windows reports the drive as not protected - in the set-up page and, unless switched off, with a reminder.
It only informs: nothing stops working, and where Windows cannot say, RADAR says nothing."""
import sys
import tkinter as tk
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from radar import disk, identity

NOW = datetime(2025, 3, 1, 9, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ what Windows says, and what that means
def test_what_each_value_windows_reports_means():
    # (the values and their names are the property's own list: System.Volume.BitLockerProtection)
    assert [disk.judge(v)[0] for v in (1, 3, 6)] == [disk.ENCRYPTED] * 3            # on, encrypting, locked
    assert [disk.judge(v)[0] for v in (2, 4, 8)] == [disk.NOT_ENCRYPTED] * 3        # off, decrypting, not activated
    assert disk.judge(5)[0] == disk.SUSPENDED
    assert [disk.judge(v)[0] for v in (7, 0, 99, None)] == [disk.UNKNOWN] * 4       # not encryptable, no answer
    assert disk.judge(1)[1] == "BitLocker on" and "not activated" in disk.judge(8)[1]


def test_the_drive_of_the_data_folder_is_the_one_asked_about():
    assert disk.drive_of(r"D:\data\RADAR") == "D:" and disk.drive_of(r"c:\x") == "C:"
    assert disk.drive_of(r"\\server\share\RADAR") == ""                              # a network folder: nobody to ask
    asked = []
    status = disk.read(r"D:\data\RADAR", value_of=lambda drive: asked.append(drive) or 2)
    assert asked == ["D:"] and status == disk.Status("D:", disk.NOT_ENCRYPTED, "BitLocker off")
    assert disk.read(r"\\server\share\x", value_of=lambda drive: 1).state == disk.UNKNOWN


def test_a_question_windows_cannot_answer_is_no_alarm():
    def broken(_drive):
        raise OSError("no")

    assert disk.read(r"C:\x", value_of=broken).state == disk.UNKNOWN
    assert disk.read(r"C:\x", value_of=lambda _d: None).state == disk.UNKNOWN


@pytest.mark.skipif(sys.platform != "win32", reason="asks Windows")
def test_windows_can_be_asked_without_administrator_rights(tmp_path):
    status = disk.read(tmp_path)
    assert status.state in (disk.ENCRYPTED, disk.NOT_ENCRYPTED, disk.SUSPENDED, disk.UNKNOWN) and status.drive


# ------------------------------------------------------------------ when a reminder is due
class Clock:
    def __init__(self):
        self.t, self.now = 1000.0, NOW

    def forward(self, hours):
        self.t += hours * 3600
        self.now += timedelta(hours=hours)


def watch(values, enabled=True):
    clock, kept = Clock(), {}
    w = disk.Watch(read=lambda: disk.Status("C:", *disk.judge(values[0])), enabled=lambda: enabled if isinstance(enabled, bool) else enabled(),
                   since=lambda: kept.get("s", ""), remember=lambda v: kept.__setitem__("s", v),
                   clock=lambda: clock.t, now=lambda: clock.now)
    return w, clock, kept


def test_it_looks_soon_after_the_start_and_then_every_hour():
    w, clock, _ = watch([1])
    assert not w.due()
    clock.forward(disk.FIRST_CHECK_AFTER / 3600)
    assert w.due()
    w.check()
    assert not w.due()
    clock.forward(1)
    assert w.due()


def test_a_disk_that_is_not_encrypted_is_a_reminder_and_an_encrypted_one_is_not():
    values = [2]
    w, _clock, _ = watch(values)
    status, remind = w.check()
    assert status.state == disk.NOT_ENCRYPTED and remind
    values[0] = 1
    assert w.check() == (disk.Status("C:", disk.ENCRYPTED, "BitLocker on"), False)
    values[0] = 7
    assert w.check()[1] is False                                   # Windows cannot say: no alarm on a guess


def test_switched_off_means_no_reminder_but_the_state_is_still_known():
    w, _clock, _ = watch([2], enabled=False)
    status, remind = w.check()
    assert status.state == disk.NOT_ENCRYPTED and remind is False


def test_suspended_protection_is_a_reminder_only_when_it_lasts_a_day():
    values = [5]
    w, clock, kept = watch(values)
    assert w.check()[1] is False and kept["s"] == NOW.isoformat()   # Windows suspends it during some updates
    clock.forward(23)
    assert w.check()[1] is False
    clock.forward(1)
    assert w.check()[1] is True
    values[0] = 1                                                   # protection is back: forgotten
    assert w.check()[1] is False and kept["s"] == ""
    values[0] = 5                                                   # ... and a new suspension counts from its start
    assert w.check()[1] is False and kept["s"] == clock.now.isoformat()


def test_since_when_it_is_suspended_survives_a_restart():
    values = [5]
    w, clock, kept = watch(values)
    w.check()
    clock.forward(30)
    again = disk.Watch(read=lambda: disk.Status("C:", *disk.judge(5)), enabled=lambda: True, since=lambda: kept["s"],
                       remember=lambda v: kept.__setitem__("s", v), clock=lambda: clock.t, now=lambda: clock.now)
    assert again.check()[1] is True


# ------------------------------------------------------------------ the app: one reminder, gone when it is over
def make_app(monkeypatch, value):
    from radar.app import App

    box = [value]
    monkeypatch.setattr(disk, "read", lambda path, value_of=None: disk.Status("C:", *disk.judge(box[0])))
    app = App()
    app.ui_call = lambda fn, *a, **k: None
    return app, box


def disk_alerts(app):
    return [a for a in app.alerts.active() if a.key.endswith(":" + disk.ALERT_KEY)]


def test_the_app_reminds_once_and_takes_it_back_when_the_disk_is_encrypted(monkeypatch):
    app, box = make_app(monkeypatch, 2)
    try:
        assert app.remind_disk is True                               # the default
        app.check_disk()
        (alert,) = disk_alerts(app)
        assert "not encrypted" in alert.title and "C:" in alert.summary and "sign-in history" in alert.summary
        assert ("Open the Windows encryption settings", disk.SETTINGS_LINK) in [tuple(x) for x in alert.links]
        assert "Settings > Account and connection" in alert.recommendation      # where it is switched off
        assert app.last_error is None                                # RADAR itself is working
        app.check_disk()
        assert len(disk_alerts(app)) == 1
        box[0] = 1
        app.check_disk()
        assert disk_alerts(app) == []
    finally:
        app.store.close()


def test_switching_the_reminder_off_takes_it_away_at_once(monkeypatch):
    app, _box = make_app(monkeypatch, 2)
    try:
        app.check_disk()
        assert disk_alerts(app)
        app.toggle_remind_disk()
        assert app.remind_disk is False and disk_alerts(app) == []
        app.check_disk()
        assert disk_alerts(app) == []
        app.toggle_remind_disk()                                     # ... and back on: it is there again
        assert disk_alerts(app)
        assert app.disk_status().state == disk.NOT_ENCRYPTED
    finally:
        app.store.close()


def test_the_link_of_the_reminder_opens_the_windows_settings(monkeypatch):
    app, _box = make_app(monkeypatch, 2)
    opened = []
    monkeypatch.setattr(disk, "open_settings", lambda: opened.append(1))
    try:
        app.open_link(disk.SETTINGS_LINK)
        assert opened == [1]
    finally:
        app.store.close()


def test_which_windows_page_has_the_switch():
    assert disk.settings_command("Core") == ["ms-settings:deviceencryption"]          # Home: device encryption
    assert disk.settings_command("CoreSingleLanguage") == ["ms-settings:deviceencryption"]
    assert disk.settings_command("Professional")[0].lower().endswith("control.exe")   # BitLocker's own page
    assert disk.settings_command("") == ["ms-settings:deviceencryption"]


# ------------------------------------------------------------------ the set-up page: section 3
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


class FakeApp:
    def __init__(self, value):
        self.value, self.remind_disk, self.opened, self.runs = value, True, 0, []
        auth = identity.check(identity.AZURE_CLI)[0]
        self.cfg = SimpleNamespace(get=lambda *path, default=None: auth if path == ("auth",) else default)

    def disk_status(self):
        return disk.Status("C:", *disk.judge(self.value))

    def toggle_remind_disk(self):
        self.remind_disk = not self.remind_disk

    def open_disk_settings(self):
        self.opened += 1

    def run_setup_check(self, win, other_account=False):
        self.runs.append(other_account)

    def open_link(self, url):
        pass


def shown(widget):
    return bool(widget.winfo_manager())


def test_the_set_up_page_says_whether_the_disk_is_encrypted(root):
    from radar.ui import setup as ui

    app = FakeApp(1)
    win = ui.SetupWindow(root, app)
    root.update()
    try:
        mark, title, detail = win.disk_mark, win.disk_title, win.disk_detail
        assert mark.cget("text") == ui.MARK[ui.OK] and title.cget("text") == "The disk RADAR keeps its data on is encrypted"
        assert detail.cget("text") == "Drive C: · BitLocker on"
        assert shown(win.disk_remind) and not shown(win.disk_button)
        height = win.disk_row.winfo_height()
        # it is told without a sign-in and is no step of the connection check: nothing ran, nothing was judged
        assert app.runs == [] and win.headline.cget("text") == ""
        # the switch is the app's setting
        assert win.disk_remind.instate(["selected"])
        win.disk_remind.invoke()
        assert app.remind_disk is False and win.disk_remind.instate(["!selected"])
        # not encrypted: said plainly, with the way to the Windows setting
        app.value = 2
        win.refresh_disk()
        root.update()
        assert mark.cget("text") == ui.MARK[ui.FAILED] and "is not encrypted" in title.cget("text")
        assert "sign-in history" in detail.cget("text") and shown(win.disk_button) and shown(win.disk_remind)
        win.disk_button.invoke()
        assert app.opened == 1
        assert win.disk_row.winfo_height() == height                   # nothing moves when the state changes
        # suspended: not the same as off
        app.value = 5
        win.refresh_disk()
        assert "suspended" in title.cget("text") and "a day" in detail.cget("text") and shown(win.disk_button)
        # Windows cannot say: no mark of failure, and nothing to remind of
        app.value = 7
        win.refresh_disk()
        root.update()
        assert mark.cget("text") == ui.MARK[ui.SKIPPED] and "could not be determined" in title.cget("text")
        assert not shown(win.disk_remind) and not shown(win.disk_button)
        assert win.disk_row.winfo_height() == height
        # the verdict of the connection check does not depend on the disk
        app.value = 2
        win.refresh_disk()
        from radar import setup_check
        from radar.setup_check import Check
        win.finished([Check(k, t, True, True, "readable") for k, t in setup_check.STEPS])
        assert win.headline.cget("text") == ui.WORKING
    finally:
        win.top.destroy()


def test_the_new_section_is_inside_the_window_and_nothing_is_cut_off(root):
    from radar.ui import setup as ui
    from radar import setup_check
    from radar.ui.theme import px

    win = ui.SetupWindow(root, FakeApp(2))
    win.top.deiconify()
    root.update()
    try:
        top, row = win.top, win.disk_row
        bottom = row.winfo_rooty() + row.winfo_height()
        # no hole above it: the section follows the last step of the connection check directly, and what the
        # check comes to - with the room kept for its longest message - stands below, at the end
        last = win.rows[setup_check.STEPS[-1][0]][0].master
        assert 0 < row.winfo_rooty() - (last.winfo_rooty() + last.winfo_height()) < px(45)
        assert win.headline.winfo_rooty() >= bottom
        assert row.winfo_height() > 20 and bottom <= top.winfo_rooty() + top.winfo_height()
        # ... and the texts of the row are not cut off at the right edge by the button and the switch
        from tkinter import ttk
        for cell in win._choices.values():   # the two ways to sign in above still show their whole title
            for radio in (w for w in cell.winfo_children() if isinstance(w, ttk.Radiobutton)):
                assert radio.winfo_reqwidth() <= cell.winfo_width() - 2 * radio.winfo_x()
        for value in (2, 4, 8, 5, 1, 3, 7):
            win.app.value = value
            win.refresh_disk()
            root.update()
            assert win.disk_title.winfo_reqwidth() <= win.disk_title.winfo_width(), value
            assert win.disk_detail.winfo_reqwidth() <= win.disk_detail.winfo_width(), value
    finally:
        win.top.destroy()


def test_on_a_small_screen_the_page_scrolls_to_the_section(root):
    """The window is at most 90% of the screen high; in the main window the page is lower still. Nothing is cut off
    for good: the page scrolls, and its last row can be reached."""
    from radar.ui import setup as ui
    from radar.ui.theme import px

    win = ui.SetupWindow(root, FakeApp(2))
    win.top.deiconify()
    win.top.geometry(f"{px(ui.WIDTH)}x{px(600)}")
    root.update()
    try:
        top, row, canvas = win.top, win.disk_row, win.scroll.canvas
        assert win.scroll.body.winfo_reqheight() > canvas.winfo_height()          # it does not fit ...
        assert row.winfo_rooty() + row.winfo_height() > top.winfo_rooty() + top.winfo_height()
        canvas.yview_moveto(1.0)                                                   # ... and scrolls to its end
        root.update()
        assert row.winfo_rooty() + row.winfo_height() <= top.winfo_rooty() + top.winfo_height()
    finally:
        win.top.destroy()
