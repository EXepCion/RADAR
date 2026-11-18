"""'Don't remind me about this again': a rule about one account or app, switched off from an alert for a time."""
from datetime import datetime, timedelta, timezone

from radar import quiet
from radar.alerts import ACTIVE, DISMISSED, MUTED, AlertCenter
from radar.config import ConfigManager
from radar.plugin_api import Finding, Severity
from radar.store import Store
from test_main_window import app  # noqa: F401  (a real App on an empty data folder)
from test_ui import root  # noqa: F401

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
ALICE, BOB = "alice@contoso.com", "bob@contoso.com"


def finding(key, rule="new_country_background", severity=Severity.LOW, score=30, user=ALICE, **kw):
    return Finding(key=key, rule_id=rule, severity=severity, score=score, title=f"Finding {key}", summary="what happened",
                   fields={"User": user}, **kw)


def center():
    return AlertCenter(Store(":memory:"))


def switched_off(tmp_path, ac, days=30):
    """Alice's Low alert comes up and is switched off for the rule and her account."""
    cfg = ConfigManager(tmp_path / "config.json")
    alert, = ac.ingest("signin_threats", [finding("a1")], now=NOW)
    return cfg, alert, quiet.add(cfg, alert, ALICE, days, NOW)


def test_what_is_switched_off_is_kept_with_its_end_and_its_level(tmp_path):
    cfg, alert, q = switched_off(tmp_path, center())
    assert (q.rule_id, q.subject, q.severity, q.until, q.since) == (
        "new_country_background", ALICE, int(Severity.LOW), NOW + timedelta(days=30), NOW)
    assert q.title == alert.title
    assert quiet.load(ConfigManager(tmp_path / "config.json")) == [q]           # in the settings file
    again = quiet.add(cfg, alert, ALICE, 90, NOW)                               # once more: the entry is replaced
    assert quiet.load(cfg) == [again] and again.until == NOW + timedelta(days=90)


def test_the_same_rule_about_the_same_account_is_logged_not_shown(tmp_path):
    ac = center()
    cfg, _alert, q = switched_off(tmp_path, ac)
    later = NOW + timedelta(days=3)
    popped = ac.ingest("signin_threats", [finding("a2")], now=later, quiet=quiet.active(cfg, later))
    assert popped == []
    kept = next(a for a in ac.recent() if a.key == "a2")
    assert kept.status == MUTED and kept.fields[quiet.NOTE_FIELD].startswith("Switched off for alice@contoso.com until")
    assert ac.ingest("signin_threats", [finding("a2")], now=later, quiet=quiet.active(cfg, later)) == []   # seen again
    assert next(a for a in ac.recent() if a.key == "a2").status == MUTED


def test_everything_else_still_comes(tmp_path):
    ac = center()
    cfg, _alert, _q = switched_off(tmp_path, ac)
    later = NOW + timedelta(days=3)
    on = quiet.active(cfg, later)
    shown = lambda f: [a.key for a in ac.ingest("signin_threats", [f], now=later, quiet=on)]  # noqa: E731
    assert shown(finding("b1", user=BOB)) == ["b1"]                                  # another account
    assert shown(finding("c1", rule="risky_signin")) == ["c1"]                       # another rule
    assert shown(finding("d1", severity=Severity.MEDIUM, score=50)) == ["d1"]        # worse than what was switched off
    assert shown(finding("e1", severity=Severity.INFO, score=10)) == []              # (below the reminders anyway)
    # one that was logged for being switched off and then gets worse: back on screen
    assert shown(finding("f1")) == []
    assert shown(finding("f1", severity=Severity.HIGH, score=80)) == ["f1"]


def test_it_ends_by_itself_and_can_be_taken_back(tmp_path):
    ac = center()
    cfg, _alert, q = switched_off(tmp_path, ac)
    after = NOW + timedelta(days=31)
    assert quiet.active(cfg, after) == [] and quiet.load(cfg) == []                  # (what is over is cleared away)
    assert [a.key for a in ac.ingest("signin_threats", [finding("g1")], now=after, quiet=quiet.active(cfg, after))] == ["g1"]
    cfg2, _alert, q = switched_off(tmp_path / "second", center())
    assert quiet.remove(cfg2, q.rule_id, q.subject) and quiet.load(cfg2) == []
    assert not quiet.remove(cfg2, q.rule_id, q.subject)


def test_what_can_be_switched_off(tmp_path):
    ac = center()
    by_admin, = ac.ingest("directory_audit", [Finding(
        key="x1", rule_id="app_credentials", severity=Severity.MEDIUM, score=50, title="App credentials", summary="s",
        subjects=["admin1@contoso.com", "app:example app"])], now=NOW)
    assert quiet.choices(by_admin) == ["admin1@contoso.com", "app:example app"]
    assert quiet.label("app:example app") == "the application example app" and quiet.label(ALICE) == ALICE
    chain, = ac.ingest("correlation", [finding("chain1", rule="attack_chain", severity=Severity.HIGH, score=80)], now=NOW)
    assert quiet.choices(chain) == []                                # a chain is a conclusion, not a habit
    system = ac.raise_system("sys1", "Sign-in required", "s")
    assert quiet.choices(system) == []
    nobody, = ac.ingest("signin_threats", [Finding(key="n1", rule_id="password_spray", severity=Severity.HIGH, score=80,
                                                   title="Spray", summary="s")], now=NOW)
    assert quiet.choices(nobody) == []                               # about no account in particular
    high, = ac.ingest("signin_threats", [finding("h1", severity=Severity.HIGH, score=85)], now=NOW)
    cfg = ConfigManager(tmp_path / "config.json")
    q = quiet.add(cfg, high, ALICE, 30, NOW)
    assert q.severity == int(Severity.HIGH)
    assert quiet.match([q], "new_country_background", [BOB, ALICE], Severity.HIGH, NOW + timedelta(days=1)) == q
    assert quiet.match([q], "new_country_background", [BOB], Severity.LOW, NOW + timedelta(days=1)) is None


def test_switching_off_from_an_alert_dismisses_it_and_the_next_one_stays_away(app):  # noqa: F811
    from types import SimpleNamespace

    app.reminders = SimpleNamespace(show=lambda *args, **kw: None, refresh=lambda *args, **kw: None)
    first, = app.deliver("signin_threats", [finding("a1")])
    q = app.quiet_alert(first, ALICE, 30)
    assert app.alerts.get(first.id).status == DISMISSED
    assert [(x.rule_id, x.subject) for x in app.quiet_entries()] == [("new_country_background", ALICE)] and q.title == first.title
    assert app.deliver("signin_threats", [finding("a2")]) == []
    assert app.alerts.count_active() == 0
    assert [a.key for a in app.deliver("signin_threats", [finding("b1", user=BOB)])] == ["b1"]
    app.unquiet(q.rule_id, q.subject)
    assert app.quiet_entries() == []
    assert [a.key for a in app.deliver("signin_threats", [finding("a3")])] == ["a3"]


# ------------------------------------------------------------------ in the windows
def _stub_reminders(app):  # noqa: F811
    from types import SimpleNamespace

    app.reminders = SimpleNamespace(show=lambda *args, **kw: None, refresh=lambda *args, **kw: None)


def _buttons(widget):
    for child in widget.winfo_children():
        if child.winfo_class() == "TButton":
            yield child
        yield from _buttons(child)


def _labels(widget):
    out = [str(widget.cget("text"))] if widget.winfo_class() in ("TLabel", "Label") else []
    return out + [t for child in widget.winfo_children() for t in _labels(child)]


def test_the_alert_window_offers_to_switch_its_kind_off(app, root):  # noqa: F811
    from radar.ui.details import DetailsWindow

    _stub_reminders(app)
    alert, = app.deliver("signin_threats", [finding("a1")])
    win = DetailsWindow(root, app, alert, on_dismiss=lambda _a: None)
    root.update()
    assert win.quiet_button is not None and "remind" in str(win.quiet_button.cget("text")).lower()
    menu = win.quiet_menu()
    assert menu.labels == [label for label, _days in quiet.PERIODS]       # one account: only "how long" is asked
    menu.invoke("for 90 days")
    for _ in range(5):
        root.update()
    entry, = app.quiet_entries()
    assert (entry.rule_id, entry.subject) == ("new_country_background", ALICE)
    assert 89 < (entry.until - datetime.now(timezone.utc)).days + 1 <= 91
    assert app.alerts.get(alert.id).status == DISMISSED and not win.top.winfo_exists()


def test_an_alert_about_two_things_asks_which_and_a_chain_has_no_such_button(app, root):  # noqa: F811
    from radar.ui.details import DetailsWindow

    _stub_reminders(app)
    by_admin, = app.deliver("directory_audit", [Finding(
        key="x1", rule_id="app_credentials", severity=Severity.MEDIUM, score=50, title="App credentials", summary="s",
        subjects=["admin1@contoso.com", "app:example app"])])
    win = DetailsWindow(root, app, by_admin, on_dismiss=lambda _a: None)
    root.update()
    menu = win.quiet_menu()
    assert "admin1@contoso.com - for 30 days" in menu.labels and "the application example app - for 30 days" in menu.labels
    menu.close()
    win.top.destroy()
    chain, = app.alerts.ingest("correlation", [finding("chain1", rule="attack_chain", severity=Severity.HIGH, score=80)])
    win = DetailsWindow(root, app, chain, on_dismiss=lambda _a: None)
    root.update()
    assert win.quiet_button is None
    win.top.destroy()


def test_settings_list_what_is_switched_off_and_switch_it_on_again(app, root):  # noqa: F811
    _stub_reminders(app)
    alert, = app.deliver("signin_threats", [finding("a1")])
    app.quiet_alert(alert, ALICE, 30)
    win = app._open_main()
    win.show("settings")
    win.show_settings("reminders")
    for _ in range(8):
        root.update()
    page = win._sub_frames["reminders"]
    shown = " | ".join(_labels(page))
    assert "Switched off" in shown and f"New country, background activity only: {ALICE}" in shown
    again = next(b for b in _buttons(page) if str(b.cget("text")) == "Remind me again")
    again.invoke()
    for _ in range(8):
        root.update()
    assert app.quiet_entries() == []
    assert ALICE not in " | ".join(_labels(win._sub_frames["reminders"]))    # the page was built again without it
