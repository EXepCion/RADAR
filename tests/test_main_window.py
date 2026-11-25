"""The main window: one place for incidents, attacks, history, reports and the settings."""
import logging
import time

import pytest
from test_ui import root  # noqa: F401  (the Tk fixture)

from radar.ui import theme


@pytest.fixture
def app(tmp_path, monkeypatch, root):  # noqa: F811
    """A real App on an empty data folder, with its background work run on the Tk loop."""
    monkeypatch.setenv("RADAR_HOME", str(tmp_path))
    from radar.app import App

    a = App(demo=True)
    a.cfg.set("general", "setup_done", value=True)
    a.root, a.tray = root, None
    a.ui_call = lambda fn, *args: root.after(0, lambda: fn(*args))
    a._background = lambda fn, *args, name="": root.after(0, lambda: fn(*args))
    a.refresh_threat_data = lambda: ""
    a.maps = []
    a.show_map = lambda: a.maps.append(1)
    yield a
    win = getattr(a, "_main", None)
    if win is not None and win.exists():
        win.top.destroy()
    for _ in range(5):
        root.update()
    a.store.close()


def settle(root, n=12):  # noqa: F811
    for _ in range(n):
        root.update()
        time.sleep(0.005)


def test_every_page_opens_and_the_old_windows_live_in_it(app, root, caplog):  # noqa: F811
    from radar.ui.main import SECTIONS, SETTINGS_PAGES, MainWindow

    caplog.set_level(logging.ERROR)
    win = app._open_main()
    assert isinstance(win, MainWindow) and win.current == "incidents"
    for key, _label, _icon in SECTIONS:
        win.show(key)
        settle(root)
        assert win.current == key
        look = win.nav.look(key)                                       # the chosen entry: tinted, with the accent bar
        assert look["background"] == theme.color("rail_select") and look["bar"] == theme.color("link")
        assert all(win.nav.look(k)["bar"] != theme.color("link") for k, _l, _i in SECTIONS if k != key)
    for key, _label in SETTINGS_PAGES:
        win.show("settings", key)
        settle(root)
        assert (win.current, win.current_settings) == ("settings", key)
        assert win.sub_nav.look(key)["bar"] == theme.color("link")
        assert win.settings_intro.cget("text") == ""                    # (which page it is, the list beside it says)
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], [r.getMessage() for r in caplog.records]
    # the windows of before are pages now: the same objects the app refreshes after every scan
    assert theme.is_panel(app._incidents.top) and theme.is_panel(app._history.top) and theme.is_panel(app._attacks_win.top)
    assert theme.is_panel(app._setup.top) and theme.is_panel(win.sub_object("offices").top)
    assert app._incidents is win.page("incidents") and app._history is win.page("history")
    # asking again brings the same window to the front, on the page asked for
    assert app._open_main("history") is win and win.current == "history"
    app._refresh_open_windows()                      # (what the app does after a scan: nothing breaks)
    # the old entry points lead to their pages
    for call, expected in ((app.show_attacks, ("attacks", "")), (app.show_offices, ("settings", "offices")),
                           (app.show_hosts, ("settings", "hosts")), (app.show_history, ("history", "hosts")),
                           (app.show_setup, ("settings", "account"))):
        call()
        settle(root)
        assert (win.current, win.current_settings if expected[1] else "") == expected
    # "Live map" in the rail starts the map and stays where it was
    before = win.current
    win.nav.click("map")
    assert app.maps == [1] and win.current == before and win.nav.selected == before
    # closing the window lets go of the pages
    win.top.destroy()
    settle(root)
    assert app._history is None and app._incidents is None and not win.exists()


def test_first_start_opens_on_set_up_and_keeps_the_rest_switched_off(app, root):  # noqa: F811
    from radar.ui.main import SETUP_DONE, SETUP_HINT, SETUP_INTRO, WELCOME

    app.cfg.set("general", "setup_done", value=False)
    win = app._open_main("history")                       # whatever is asked for: set-up comes first
    settle(root)
    assert (win.current, win.current_settings) == ("settings", "account")
    assert win.settings_title.cget("text") == WELCOME and win.settings_intro.cget("text") == SETUP_INTRO
    assert win.status_detail.cget("text") == SETUP_HINT and win.status.cget("text") == "Set-up not finished"
    assert win.status_now()[0] == "warn" and win.account_now()[0] == "Nobody yet"
    assert win.app_now() == ("", "")
    auth, real = app.auth, (app.auth.account, win._setup_mode)
    win._setup_mode = False
    auth.account, auth.display_name = "alex@contoso.com", "Alex Morgan"
    auth.app_name, auth.app_id = "RADAR sign-in", "11111111-2222-3333-4444-555555555555"
    assert win.account_now() == ("Alex Morgan", "alex@contoso.com")   # the name on the card, the address as its hint
    assert win.app_now() == ("via RADAR sign-in", "Application ID 11111111-2222-3333-4444-555555555555")
    auth.display_name = None
    assert win.account_now() == ("alex", "alex@contoso.com")          # (no name known: the part before the @)
    auth.account, auth.app_name, auth.app_id = real[0], None, None
    win._setup_mode = real[1]
    for key in ("incidents", "attacks", "history", "reports", "map"):
        assert not win.nav.enabled(key)
        assert win.nav.look(key)["text"] == theme.color("disabled")
        win.nav.click(key)                                 # a click on a switched-off entry does nothing
    assert win.current == "settings" and app.maps == []
    assert not win.sub_nav.enabled("detection") and win.sub_nav.enabled("account")
    win.show_settings("offices")
    assert win.current_settings == "account"

    app.cfg.set("general", "setup_done", value=True)
    win.setup_finished()                                   # the connection check passed
    settle(root)
    assert all(win.nav.enabled(k) for k in ("incidents", "attacks", "history", "reports", "map"))
    assert win.settings_title.cget("text") == "Settings" and win.settings_intro.cget("text") == SETUP_DONE
    assert win.status.cget("text") == "Waiting for first scan" and win.sub_nav.enabled("detection")
    win.show("incidents")
    assert win.current == "incidents"


def test_settings_rows_write_what_they_show(app, root):  # noqa: F811
    from tkinter import ttk

    from radar.ui.main import Rows

    frame = ttk.Frame(root)
    state = {"on": False, "level": ""}
    rows = Rows(frame)
    var = rows.switch("A switch", "what it does", lambda: state["on"], lambda: state.__setitem__("on", not state["on"]))
    def find(widget):
        if isinstance(widget, ttk.Checkbutton):
            return widget
        return next((f for f in map(find, widget.winfo_children()) if f is not None), None)
    switch = find(frame)
    switch.invoke()
    assert state["on"] is True and var.get() is True
    switch.invoke()
    assert state["on"] is False and var.get() is False
    box = rows.choice("A choice", "", ["Low", "High"], "Low", lambda v: state.__setitem__("level", v))
    box.set("High")
    box.event_generate("<<ComboboxSelected>>")
    root.update()
    assert state["level"] == "High"
    frame.destroy()

    # the real pages: the reminder level and the start switch end up in the settings file
    win = app._open_main("settings", "reminders")
    settle(root)
    assert app.cfg.get("general", "open_main_at_start", default=None) is False
    win.show_settings("appearance")
    settle(root)
    win.show_settings("advanced")
    win.show_settings("plugins")
    settle(root)
    assert win.current_settings == "plugins"


def test_the_rail_counts_open_incidents_and_accounts_under_attack(app, root):  # noqa: F811
    from radar.ui.main import NavList

    app.count_attacked_accounts = lambda hours=72: 4
    win = app._open_main()
    settle(root)
    assert win.nav.badge("attacks") == "4"                 # counted in the background when the window opens
    assert win.nav.badge("incidents") == ""                # nothing open: no badge at all
    win.nav.set_badge("incidents", 2)
    settle(root)
    assert win.nav.badge("incidents") == "2"
    canvas, pill = win.nav.canvas, win.nav.items["incidents"]["pill"]
    assert canvas.itemcget(pill, "image")                  # the pill is drawn (a smooth image), on the right of its entry
    assert 0 < canvas.coords(pill)[0] <= canvas.winfo_width()
    win.nav.set_badge("incidents", 0)
    assert win.nav.badge("incidents") == ""
    assert not canvas.itemcget(pill, "image")
    app.count_attacked_accounts = lambda hours=72: None    # no sign-in data: the badge stays as it was
    win._attacks_counted = -1e9
    win.refresh()
    settle(root)
    assert win.nav.badge("attacks") == "4"

    # entries at the bottom stay at the bottom; a click chooses, the pointer only tints
    nav = NavList(root, lambda key: None)
    nav.add("a", "First")
    nav.add("z", "Last", bottom=True)
    nav.canvas.configure(height=400)
    nav.pack(fill="both", expand=True)
    settle(root)
    assert nav.items["z"]["top"] > nav.items["a"]["top"] + nav._row
    nav.click("z")
    assert nav.selected == "z" and nav.key_at(nav.items["a"]["top"] + 2) == "a"
    nav.canvas.destroy()


def test_scale_follows_the_screen_a_window_opens_on(root, monkeypatch):  # noqa: F811
    """A change of scale resizes the fonts and tells the windows built in advance; without one nothing happens."""
    import tkinter.font as tkfont

    before, told = theme._scale, []
    theme.on_rescale(lambda: told.append(theme._scale))
    try:
        assert theme.set_scale(root, before) is False and told == []
        assert theme.set_scale(root, before * 2) is True and told == [before * 2]
        assert tkfont.nametofont(theme.FONT, root=root).cget("size") == -theme.px(14) == -round(14 * before * 2)
        # only when Windows was told that RADAR handles each screen itself, and only while no window is showing
        monkeypatch.setattr(theme, "_per_monitor", False)
        monkeypatch.setattr(theme, "pointer_scale", lambda: before)
        assert theme.adapt_to_monitor(root) is False and theme._scale == before * 2
        monkeypatch.setattr(theme, "_per_monitor", True)
        assert theme.adapt_to_monitor(root) is True and theme._scale == before
    finally:
        theme._rescale_listeners.pop()
        theme.set_scale(root, before)


def test_dismissing_a_chain_takes_its_steps_along_when_asked_and_the_report_marks_the_rail(app, root, monkeypatch):  # noqa: F811
    from datetime import datetime, timedelta, timezone

    from radar import chains, correlation
    from radar.plugin_api import Finding, Severity

    now = datetime.now(timezone.utc)

    def step(key, rule, score, days):
        return Finding(key=key, rule_id=rule, severity=Severity.MEDIUM if score >= 45 else Severity.LOW, score=score,
                       title=f"{rule}: dana@contoso.com", occurred_at=now - timedelta(days=days), fields={"User": "dana@contoso.com"})

    app.alerts.ingest("signin_threats", [step("g", "distributed_attack", 50, 3), step("p", "password_not_completed", 40, 2),
                                         step("m", "mfa_change", 30, 1)])
    app._update_chains()
    chain = next(a for a in app.alerts.active() if a.plugin_id == chains.CHAIN_PLUGIN)
    asked = []
    monkeypatch.setattr(type(app), "ask_companions", lambda self, extra, parent=None: asked.append(len(extra)) or True)
    assert len(app.dismiss_alerts([chain.id])) == 4 and asked == [3]      # the chain and, on a yes, its three steps
    assert app.alerts.count_active() == 0

    report = Finding(key="mfaexposure|w", rule_id="mfa_exposure_report", severity=Severity.LOW, score=35, title="MFA exposure report",
                     occurred_at=now, fields={"Excluded from MFA": "4", "To review": "2"}, signal=correlation.REPORT_SIGNAL)
    assert app.alerts.ingest("signin_threats", [report]) == [] and app.alerts.count_active() == 0   # no reminder ...
    win = app._open_main("incidents")
    settle(root)
    win.refresh()
    assert app.report_news() == 1 and win.nav.badge("reports") == "1"      # ... a mark on Reports instead
    win.show("reports")
    settle(root)
    assert app.report_news() == 0 and win.nav.badge("reports") == ""       # looked at: the mark is gone
    report.fields = {"Excluded from MFA": "5", "To review": "2"}
    report.key = "mfaexposure|w2"
    app.alerts.ingest("signin_threats", [report])
    assert app.report_news() == 1                                           # other figures: it is back


def test_low_alerts_close_by_themselves_after_the_days_set(app):  # noqa: F811
    from datetime import datetime, timedelta, timezone

    from radar.plugin_api import Finding, Severity

    long_ago = datetime.now(timezone.utc) - timedelta(days=9)
    app.alerts.ingest("signin_threats", [Finding(key="low", rule_id="new_country", severity=Severity.LOW, score=30, title="Low one",
                                                 occurred_at=long_ago, fields={"User": "dana@contoso.com"})], now=long_ago)
    app.alerts.mark_seen([a.id for a in app.alerts.active()])
    app.cfg.set("general", "auto_close_low_days", value=0)
    assert app.close_stale_alerts() == 0 and app.alerts.count_active() == 1     # switched off
    app.cfg.set("general", "auto_close_low_days", value=7)
    assert app.close_stale_alerts() == 1 and app.alerts.count_active() == 0


def test_after_an_update_open_reminders_are_judged_with_the_new_rules_once(app, monkeypatch):  # noqa: F811
    from datetime import datetime, timezone

    from radar import __version__
    from radar.plugin_api import Finding, Severity

    def finding(key, score, title, **kw):
        return Finding(key=key, rule_id="distributed_attack", severity=Severity.MEDIUM if score >= 45 else Severity.INFO,
                       score=score, title=title, occurred_at=datetime.now(timezone.utc), **kw)

    app.alerts.ingest("signin_threats", [finding("a", 50, "Attack: ann@contoso.com", fields={"Account": "ann@contoso.com"}),
                                         finding("b", 50, "Attack: bob@contoso.com", fields={"Account": "bob@contoso.com"}),
                                         finding("c", 50, "Attack: cy@contoso.com", fields={"Account": "cy@contoso.com"})])
    plugin = app.plugins.get("signin_threats").plugin
    calls = []
    now = [finding("both", 50, "Attack on 2 accounts", subjects=["ann@contoso.com", "bob@contoso.com"], supersedes=["a", "b"]),
           finding("c", 10, "Attack: cy@contoso.com", fields={"Account": "cy@contoso.com"})]   # judged harmless now
    monkeypatch.setattr(type(plugin), "reevaluate", lambda self, ctx, hours: calls.append(hours) or now)
    app.cfg.set("general", "rules_settled_for", value="")
    assert app.settle_after_update() == 2 and calls == [app.SETTLE_HOURS]
    assert [a.key for a in app.alerts.active()] == ["both"]            # one reminder where there were three
    assert app.cfg.get("general", "rules_settled_for") == __version__
    assert app.settle_after_update() == 0 and len(calls) == 1          # once per version


def test_the_question_when_dismissing_is_a_window_of_radar_and_answers_by_its_buttons(app, root):  # noqa: F811
    from radar.ui import confirm

    def buttons(widget):
        for child in widget.winfo_children():
            if child.winfo_class() == "TButton":
                yield child
            yield from buttons(child)

    seen = []

    def press(accent):
        top = [w for w in root.winfo_children() if w.winfo_class() == "Toplevel" and w.title() == "RADAR"][-1]
        found = list(buttons(top))
        seen.append([b.cget("text") for b in found])
        next(b for b in found if (str(b.cget("style")) == "Accent.TButton") == accent).invoke()

    for accent, expected in ((True, True), (False, False)):
        root.after(200, lambda a=accent: press(a))
        assert confirm.ask(root, None, "One more reminder belongs to what you dismiss", ["Possible attack chain: dana@contoso.com"],
                           "Dismiss it as well?", yes="Dismiss it as well", no="Only what I chose") is expected
    assert seen[0] == ["Dismiss it as well", "Only what I chose"]


def test_coming_back_to_the_attacks_page_tells_it_so(app, root):  # noqa: F811
    """Opened from the navigation the page starts on the most dangerous kind again - not while it stays in view."""
    app.count_attacked_accounts = lambda hours=72: 0
    app.load_attacks = lambda win, hours, refresh=False, then_refresh=False: None
    win = app._open_main()
    settle(root)
    win.show("attacks")
    page, calls = win.page("attacks"), []
    page.opened = lambda: calls.append(1)
    win.show("attacks")                        # it is in view already
    assert calls == []
    win.show("incidents")
    win.show("attacks")
    assert calls == [1]


def test_after_a_start_it_is_known_at_once_who_is_signed_in(app, root):  # noqa: F811
    """Not 'Nobody yet' until the first scan has its turn (so it looked after every update): RADAR signs in
    quietly when it starts, and until that has answered the card says that it is checking."""
    calls = []
    app.auth.get_token = lambda force_refresh=False: calls.append(1) or "token"
    app.cfg.set("general", "setup_done", value=True)
    app.cfg.set("auth", "client_id", value="11111111-2222-4333-8444-555555555555")
    if True:
        win = app._open_main()
        settle(root)
        app.auth.account, app.auth.state = None, "unknown"
        assert win.account_now() == ("Checking...", "")
        app.sign_in_quietly()
        assert calls == [1]
        app.auth.account, app.auth.state = "alex.morgan@contoso.com", "ok"
        assert win.account_now() == ("alex.morgan", "alex.morgan@contoso.com")
        app.auth.account, app.auth.state = None, "required"      # the sign-in did not work: nobody
        assert win.account_now() == ("Nobody yet", "")

        def fails(force_refresh=False):
            raise RuntimeError("no network")

        app.auth.get_token = fails
        app.sign_in_quietly()                                    # (the next scan reports it: nothing breaks here)
        app.cfg.set("general", "setup_done", value=False)
        app.auth.get_token = lambda force_refresh=False: calls.append(2)
        app.sign_in_quietly()                                    # not set up yet: the set-up signs in, with a window
        assert calls == [1]


def test_the_attacks_page_opens_with_what_the_figure_was_counted_from(app, root):  # noqa: F811
    """The figure on the navigation and the page are one computation: the page does not start empty, and when it
    has loaded the figure is the one of what it shows."""
    from datetime import datetime, timezone
    from types import SimpleNamespace

    def overview(hours, active):
        row = lambda name, status: SimpleNamespace(account=name, status=status)  # noqa: E731
        return SimpleNamespace(hours=hours, attacked_now=active, accounts=[row("a@contoso.com", "Active")] * active)

    shown, computed = [], []

    class Plugin:
        def ongoing(self, ctx, hours):
            computed.append(hours)
            return overview(hours, 2 if len(computed) == 1 else 3)

    app.plugins.get = lambda plugin_id: SimpleNamespace(plugin=Plugin())
    app.plugins.build_context = lambda plugin_id: None
    app.threat_data_as_of = lambda: datetime.now(timezone.utc)
    app._background = lambda fn, *a, name="": fn(*a)
    app.ui_call = lambda fn, *a: fn(*a)
    win = app._open_main()
    settle(root)
    assert computed == [72] and win.nav.badge("attacks") == "2" and app.kept_attacks(72)[0].attacked_now == 2
    assert app.kept_attacks(24) is None

    page = SimpleNamespace(hours=72, show=lambda result, reminder, as_of=None, busy=False, error="": shown.append(
        (result.attacked_now, busy)), show_error=lambda message: shown.append(message))
    app.load_attacks(page, 72)
    # at once what was counted (marked as still being brought up to date), then the fresh result - and its figure
    assert shown == [(2, True), (3, False)]
    assert win.nav.badge("attacks") == "3"
    shown.clear()
    page.hours = 24
    app.load_attacks(page, 24)                              # another period: nothing kept for it - and the figure on
    assert shown == [(3, False)] and win.nav.badge("attacks") == "3" and computed[2:] == [24]   # the navigation follows
    assert app.count_attacked_accounts() == 3 and computed[2:] == [24, 24]   # the page: counted for the period it shows


def test_the_search_button_always_leads_to_the_search_field(app, root):  # noqa: F811
    """A click on Search in the navigation shows the field, ready to be typed into - also from a page that was opened
    from the search (an account, a device ...), which is part of the same section. A page that opens another page
    goes through the same door and must not be sent back to the field."""
    win = app._open_main()
    settle(root)
    win.show("search")
    page = win.page("search")
    focused = []
    focus = page.focus
    page.focus = lambda: (focused.append(1), focus())[1]
    page.background = False                          # (read here and now: the test has no loop for a worker to call back into)
    page.show_thing("account", "no-such-account", "Somebody")
    for _ in range(200):                             # (it comes forward when it has been read)
        settle(root, 2)
        if page.stack.winfo_children()[-1] is page.account_view().top:
            break
    assert page.path and page.stack.winfo_children()[-1] is page.account_view().top      # a page is in view
    win.show("search")                               # (what the app does before it opens the next page: nothing moves)
    assert page.path and focused == []
    win._nav_chosen("search")                        # the click
    settle(root)
    assert focused == [1] and page.path == [] and page.stack.winfo_children()[-1] is page.find
    win.show("incidents")
    win._nav_chosen("search")                        # ... and from another section
    assert focused == [1, 1] and page.stack.winfo_children()[-1] is page.find
