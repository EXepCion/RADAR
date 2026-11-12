"""No window keeps showing what was true when it was opened: details, incidents and history follow every change."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from test_ui import FakeApp, root  # noqa: F401  (the Tk fixture)

from radar.app import App
from radar.plugin_api import Finding, Severity

NOW = datetime.now(timezone.utc)


def finding(score=45, fields=None, rows=2, key="k1", rule="new_country", user="anna@contoso.com", days_ago=1.0):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule}: {user}", summary="Something happened.",
                   occurred_at=NOW - timedelta(days=days_ago), fields={"User": user, **(fields or {})},
                   factors=[(score, "Base")], recommendation="Look at it.",
                   evidence=[{"Time": f"2026-11-10 10:0{i}:00", "User": user, "IP address": "203.0.113.77",
                              "Sign-in ID": f"s{i}"} for i in range(rows)])


def test_open_alert_details_follow_the_stored_alert(root):  # noqa: F811
    from radar.ui.reminder import ReminderWindow

    app = FakeApp()
    app.alerts.ingest("signin_threats", [finding()])
    reminders = ReminderWindow(root, app)
    try:
        reminders.show()
        root.update()
        alert = app.alerts.active()[0]
        reminders.open_details(alert)
        root.update()
        win = reminders._details[alert.id]
        before = win.info
        assert "Score 45" not in win.info.get("1.0", "end") and win.score_text() == "45"
        win.tree.selection_set("1")

        # nothing changed: the window is left alone (same widgets, nothing redrawn)
        assert reminders.refresh_details() == 0 and win.info is before

        # the next scan finds more: higher score, a new field, one more evidence row
        app.alerts.ingest("signin_threats", [finding(score=80, fields={"Known attacker address": "203.0.113.77 - a stolen session"}, rows=3)])
        assert reminders.refresh_details() == 1
        root.update()
        assert win.exists() and win.info is not before                     # drawn again, in the same window
        text = win.info.get("1.0", "end") + (win.facts.get("1.0", "end") if win.facts is not None else "")
        assert "Known attacker address" in text and win.score_text() == "80"
        assert len(win.tree.get_children("")) == 3 and win.tree.selection() == ("1",)   # the selected row is kept
        assert "this alert changed while the window was open" in win.status.text
        assert reminders.refresh_details() == 0                            # up to date: not drawn again

        # dismissed somewhere else (the incident window, the reminder list): the details show it
        app.alerts.dismiss([alert.id])
        assert reminders.refresh_details() == 1
        assert win.alert.status == "dismissed"
        win.top.destroy()
        root.update()
        assert reminders.refresh_details() == 0 and alert.id not in reminders._details   # closed windows are forgotten
    finally:
        for d in reminders._details.values():
            if d.exists():
                d.top.destroy()
        reminders.top.destroy()
        root.update()


def test_details_show_a_new_incident_as_soon_as_another_alert_joins(root):  # noqa: F811
    from radar.ui.details import DetailsWindow

    app = FakeApp()
    app.incident_of = lambda a: App.incident_of(app, a)
    app.alerts.ingest("signin_threats", [finding(key="first")])
    alert = app.alerts.active()[0]
    win = DetailsWindow(root, app, alert, on_dismiss=lambda a: None)
    try:
        root.update()
        assert "Part of an incident" not in win.info.get("1.0", "end")
        app.alerts.ingest("signin_threats", [finding(key="second", rule="legacy_auth", score=30, days_ago=0.5)])
        assert win.update_alert(app.alerts.get(alert.id))   # the alert itself is unchanged - what it belongs to is not
        assert "Part of an incident" in win.info.get("1.0", "end")
    finally:
        win.top.destroy()


def test_every_change_reaches_every_open_window():
    """After a scan - with or without a new reminder - and after any change made in a window."""
    calls = []
    win = SimpleNamespace(exists=lambda: True, refresh=lambda: calls.append("window"))
    app = SimpleNamespace(_history=win, _incidents=win, tray=None, ui_call=lambda fn, *a: fn(*a),
                          reminders=SimpleNamespace(visible=False, refresh_details=lambda: calls.append("details"),
                                                    show=lambda attention: calls.append("reminders")),
                          alerts=SimpleNamespace(ingest=lambda plugin, findings, level: findings),
                          min_severity=lambda: Severity.LOW, _update_chains=lambda: [])
    for name in ("_refresh_open_windows", "_refresh_history_if_open", "_refresh_reminders_if_visible", "_refresh_tray"):
        setattr(app, name, getattr(App, name).__get__(app))
    App.deliver(app, "p", [SimpleNamespace(title="new")])          # a new reminder pops up
    assert calls == ["reminders", "window", "window", "details"]
    calls.clear()
    App.deliver(app, "p", [])                                       # a scan that only updated what was there
    assert calls == ["window", "window", "details"]
    calls.clear()
    App.on_alerts_changed(app)                                      # dismissed / seen / reactivated in some window
    assert calls == ["window", "window", "details"]


def test_cards_stand_side_by_side_when_there_is_room_and_one_below_the_other_when_not(root):  # noqa: F811
    from radar.ui.details import TWO_COLUMNS_FROM, DetailsWindow
    from radar.ui.theme import px

    app = FakeApp()
    app.alerts.ingest("signin_threats", [finding(fields={"IP addresses": "203.0.113.77", "Errors": "50074"})])
    win = DetailsWindow(root, app, app.alerts.active()[0], on_dismiss=lambda a: None)
    try:
        def settle(size):
            win.top.geometry(size)
            for _ in range(8):
                root.update()
            win._fit_panes()
            root.update()

        settle(f"{px(1500)}x{px(900)}")
        if win._cards_box.winfo_width() < px(TWO_COLUMNS_FROM):
            import pytest
            pytest.skip("screen too narrow for the two-column cards")
        assert win._two_columns is True and win._facts_frame.winfo_ismapped()
        assert "Errors" in win.facts.get("1.0", "end")
        # the story is complete and the details are not shown twice: hidden in the story's text while beside it
        assert win.info.tag_cget("facts_card", "elide") in ("1", 1, True) and "Look at it." in win.info.get("1.0", "end")
        assert win.info.text_height() < px(420)          # three short cards: nothing to scroll
        settle(f"{px(1000)}x{px(900)}")
        assert win._two_columns is False and not win._facts_frame.winfo_ismapped()
        assert win.info.tag_cget("facts_card", "elide") in ("0", 0, False, "")
        story = win.info.get("1.0", "end")
        assert story.index("Recommended action") < story.index("Details")   # the action stays in view, the facts follow
    finally:
        win.top.destroy()


def test_windows_stay_responsive_while_a_scan_works():
    """Opening a window is thousands of small Tk calls; with Python's default hand-over time a busy scan thread
    made each of them wait (a details window took 16 s instead of 0.4 s). The app shortens that time at start."""
    import inspect
    import sys

    from radar.ui import theme

    before = sys.getswitchinterval()
    try:
        sys.setswitchinterval(0.005)
        theme.keep_ui_responsive()
        assert sys.getswitchinterval() <= 0.001
        sys.setswitchinterval(0.0001)
        theme.keep_ui_responsive()
        assert sys.getswitchinterval() <= 0.00011   # never made slower than it already is
    finally:
        sys.setswitchinterval(before)
    assert "keep_ui_responsive()" in inspect.getsource(App.run)


def test_the_entra_links_are_shown_once_in_every_arrangement(root):  # noqa: F811
    from radar.ui.details import DetailsWindow
    from radar.ui.theme import px

    def visible(text):
        """The card titles a text shows (hidden parts left out)."""
        return text.get("1.0", "end", displaychars=True) if hasattr(text, "get") else ""

    def count(win):
        shown = 0
        for text, frame in ((win.info, win.info), (win.facts, win._facts_frame), (getattr(win, "side_text", None), win.side)):
            if text is not None and frame is not None and frame.winfo_ismapped():
                shown += text.tk.call(text._w, "get", "-displaychars", "1.0", "end").count("Open in Entra")
        return shown

    app = FakeApp()
    scored = finding(fields={"IP addresses": "203.0.113.77"})
    unscored = finding(key="k2", fields={"IP addresses": "203.0.113.77"})
    unscored.factors, unscored.score = [], None
    app.alerts.ingest("signin_threats", [scored, unscored])
    for alert in app.alerts.active():
        win = DetailsWindow(root, app, alert, on_dismiss=lambda a: None)
        try:
            for size in (f"{px(1500)}x{px(900)}", f"{px(1000)}x{px(900)}", f"{px(1500)}x{px(900)}"):
                win.top.geometry(size)
                for _ in range(8):
                    root.update()
                win._fit_panes()
                root.update()
                assert count(win) == 1, (alert.key, size, bool(alert.factors), win._two_columns)
        finally:
            win.top.destroy()
