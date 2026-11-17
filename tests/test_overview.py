"""'Ongoing attacks' overview: live from the history, independent of (dismissed) reminders."""
import tkinter as tk
from datetime import timedelta

import pytest

from radar.alerts import Alert, AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins.signin_threats.accounts import AccountDirectory, AccountInfo
from radar.plugins.signin_threats.overview import ongoing_attacks, status_of
from radar.plugins.signin_threats.rules import RuleContext
from radar.store import Store

from conftest import T0, make_signin
from test_distributed_attack import HOME, campaign

NOW = T0 + timedelta(hours=2)


def build(history):
    history.add([make_signin(-60 * 24 * 5 - i, user_id="u1", upn="priya@contoso.com", **HOME) for i in range(5)])
    history.add(campaign())  # 20 attempts from 20 IPs over ~50 h, last one ~10 h ago
    # MFA-excluded scanner: only 3 failures, but that is enough for a password-only account
    history.add([make_signin(-30 - i, user_id="u7", upn="scanner@contoso.com", ip="203.0.113.9", asn=9009,
                             country="RO", error_code=50126) for i in range(3)])
    # a user mistyping at home: never an attack
    history.add([make_signin(-60 * 24 * 5, user_id="u2", upn="bob@contoso.com", **HOME)])
    history.add([make_signin(-i, user_id="u2", upn="bob@contoso.com", error_code=50126, **HOME) for i in range(12)])
    # one IP trying two accounts
    history.add([make_signin(-5, user_id="u1", upn="priya@contoso.com", ip="198.51.100.66", asn=60068,
                             country="NL", error_code=50126),
                 make_signin(-4, user_id="u7", upn="scanner@contoso.com", ip="198.51.100.66", asn=60068,
                             country="NL", error_code=50126)])
    # password known: carol's correct password from a datacenter, MFA stopped it (two days)
    history.add([make_signin(-60 * 24 * 5 - i, user_id="u8", upn="carol@contoso.com", **HOME) for i in range(3)])
    history.add([make_signin(m, user_id="u8", upn="carol@contoso.com", ip="164.90.1.1", asn=14061, country="DE",
                             city="Frankfurt", error_code=50074) for m in (-60, -60 * 25)])
    # stolen session: dave's phone in CA, the same session minutes later from another country without device
    history.add([make_signin(-60 * 24 * 5 - i, user_id="u9", upn="dave@contoso.com", **HOME) for i in range(3)])
    history.add([make_signin(-30, user_id="u9", upn="dave@contoso.com", session_id="S1", device_id="iph", os="Ios",
                             interactive=False, **{k: v for k, v in HOME.items() if k not in ("device_id",)}),
                 make_signin(-27, user_id="u9", upn="dave@contoso.com", session_id="S1", ip="45.1.1.1", asn=14061,
                             country="NL", city="Amsterdam", os="Windows10", browser="Chrome 141.0",
                             app="One Outlook Web", interactive=False, user_agent="Mozilla/5.0")])
    accounts = AccountDirectory({"u7": AccountInfo(user_id="u7", upn="scanner@contoso.com",
                                                   mfa_excluded=["MFA_Exempt group"])}, NOW)
    return RuleContext.build([], history, {}, NOW, accounts=accounts)


def test_password_known_and_stolen_sessions_sections(history):
    result = ongoing_attacks(build(history), hours=72)
    known = {k.account: k for k in result.password_known}
    carol = known["carol@contoso.com"]
    assert carol.kinds == "MFA stopped it" and carol.days == 2 and carol.events == 2 and carol.status == "Active"
    assert "AS14061" in carol.networks and carol.as_finding().evidence
    assert carol.password_reset == "?"  # not in the account directory of this test
    sessions = {s.account: s for s in result.sessions}
    dave = sessions["dave@contoso.com"]
    assert dave.kind == "Session theft" and dave.status == "Active" and "45.1.1.1" in dave.suspicious
    assert dave.as_finding().fields["Session ID"] == "S1"
    assert "carol@contoso.com" not in {a.account for a in result.accounts}  # not a guessing attack


def test_overview_lists_rotating_campaign_and_mfa_excluded_target(history):
    result = ongoing_attacks(build(history), hours=72)
    by = {a.account: a for a in result.accounts}
    assert set(by) == {"priya@contoso.com", "scanner@contoso.com"}  # bob mistyping at home is not an attack
    p = by["priya@contoso.com"]
    assert p.kind == "Rotating IPs" and p.score is not None and p.past_password == "No"
    assert p.status == "Active" and p.ips == 21 and p.last_24h >= 1
    s = by["scanner@contoso.com"]
    assert s.kind == "Repeated failures" and s.mfa_excluded and s.attempts == 4 and s.status == "Active"
    assert s.as_finding().evidence  # the details window gets the attempts
    by_ip = {x.ip: x for x in result.sources}
    assert by_ip["198.51.100.66"].accounts == 2 and by_ip["198.51.100.66"].pattern == "Several accounts (2)"
    assert by_ip["198.51.100.66"].network_type == "VPN / proxy"  # Datacamp
    assert by_ip["203.0.113.9"].pattern == "Repeated (3 attempts)"
    # the rotating proxies of priya's campaign are listed too (they used to be only counted -> empty tab)
    rotating = [x for x in result.sources if x.pattern.startswith("Rotating IP")]
    assert len(rotating) >= 15 and result.single_attempt_ips == len(rotating)
    assert all(x.targets == "priya@contoso.com" for x in rotating)
    assert result.sources[0].accounts == 2  # several-account / repeated sources first
    assert not any("bob" in x.targets for x in result.sources)  # mistyping at home is not an attacking IP


def test_window_period_and_status():
    assert status_of(NOW - timedelta(hours=2), NOW) == "Active"
    assert status_of(NOW - timedelta(hours=10), NOW) == "Quiet"
    assert status_of(NOW - timedelta(days=2), NOW) == "Ended"


def test_shorter_window_drops_finished_attacks(history):
    rc = build(history)
    rc.history.add([])
    short = ongoing_attacks(rc, hours=1)
    assert "priya@contoso.com" not in {a.account for a in short.accounts if a.kind == "Rotating IPs"}


def test_dismissed_reminder_is_still_found_and_live_finding_is_viewable():
    ac = AlertCenter(Store(":memory:"))
    f = Finding(key="dpa|u1|2026-W45", rule_id="distributed_attack", severity=Severity.MEDIUM, score=50,
                title="Password attack from rotating IPs: priya@contoso.com", fields={"Account": "priya@contoso.com"})
    alert = ac.ingest("signin_threats", [f])[0]
    ac.dismiss([alert.id])
    found = ac.latest_about("Priya@contoso.com", ["distributed_attack", "brute_force"])
    assert found and found.status == "dismissed"
    live = Alert.from_finding("signin_threats", f)
    assert live.status == "live" and live.id == 0 and live.score == 50
    # alerts created before "Account" held the UPN: subjects empty -> found by the user id in the key,
    # and the next update fills the subjects in
    ac._store.execute("UPDATE alerts SET subjects='[]'")
    assert ac.latest_about("other@contoso.com", ["distributed_attack"], user_id="u1").status == "dismissed"
    ac.ingest("signin_threats", [f])
    assert ac.latest_about("priya@contoso.com", ["distributed_attack"]) is not None


@pytest.fixture(scope="module")
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    yield r
    r.destroy()


def test_attacks_page_lists_each_kind_and_opens_the_assessment(root, history):
    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow, note

    theme.init(root)
    opened = []

    class App:
        def load_attacks(self, win, hours):
            win.show(ongoing_attacks(build(history), hours),
                     lambda section, row: "dismissed" if getattr(row, "user_id", "") == "u1" else "-")

        def open_attack_details(self, account):
            opened.append(account.account)

    win = AttacksWindow(root, App())
    win.load()
    # the filter names the four kinds with their counts, the most dangerous first - and opens on the first there is
    assert [win.filter.text(k) for k in ("known", "sessions", "guessing")] == ["Password known 1", "Stolen sessions 1",
                                                                              "Password guessing 2"]
    assert win.filter.text("ips").startswith("Attacking IPs ") and win.section == "known"
    assert win.status.cget("text") == ""                    # (what there is to say about the addresses: with their list)
    # a row of the list: is it going on, who, and under the name the facts that tell how bad
    tree = win.accounts_tree
    rows = {tree.set(i, "Who"): i for i in tree.get_children()}
    assert set(rows) == {"priya@contoso.com", "scanner@contoso.com"} and list(tree["columns"]) == ["Status", "Who", "Last"]
    facts = win.facts(rows["priya@contoso.com"])
    assert facts["Reminder"] == "dismissed" and win.facts(rows["scanner@contoso.com"])["MFA"] == "EXCLUDED"
    assert note("guessing", facts).startswith(f"{facts['Attempts']} attempts \u00b7 {facts['IPs']} IPs")
    # the first row is selected: everything about it on the right, an arrowhead pointing at it
    root.update()
    first = win.known_tree.get_children()[0]
    assert win.known_tree.selection() == (first,) and win.pointer.shown_at is not None and win.frame._edge == "link"
    shown = win.row_text.get("1.0", "end")
    assert "carol@contoso.com" in shown and "Pattern" in shown and str(win.open_btn.cget("state")) == "normal"
    win.open_selected()
    assert opened == ["carol@contoso.com"]
    win.show_filter("guessing")
    root.update()
    assert win._current_tree() is tree and tree.selection() and "Attempts" in win.row_text.get("1.0", "end")
    tree.selection_set(rows["priya@contoso.com"])
    win._selection_changed()
    win.open_selected()
    assert opened[-1] == "priya@contoso.com"
    win.show_filter("ips")                                  # an address has no assessment: it is looked up
    root.update()
    assert "tried only once or twice" in win.status.cget("text")
    assert win.open_btn.cget("text") == "Look up address" and win.selected_account() is None
    win.top.destroy()


def _geometry(win):
    """Position and size of everything whose movement the user would see."""
    win.top.update()
    widgets = {"status": win.status, "filter": win.filter, "list": win.accounts_tree.outer, "panel": win.frame.outer,
               "row": win.row_text, "button": win.open_btn, "hint": win.hint.label}
    x0, y0 = win.top.winfo_rootx(), win.top.winfo_rooty()  # inside the window: where it is on the screen is not layout
    return {name: (w.winfo_rootx() - x0, w.winfo_rooty() - y0, w.winfo_width(), w.winfo_height()) for name, w in widgets.items()}


def test_attacks_window_does_not_move_when_the_data_arrives(root, history):
    """A security tool must not rearrange itself while one reads it: same layout empty, loading, loaded, failed."""
    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow

    theme.init(root)
    results = []

    class App:
        def load_attacks(self, win, hours):
            results.append(hours)  # like the app: the result arrives later

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    empty = _geometry(win)
    win.load()
    assert _geometry(win) == empty and win.empty_title.cget("text") == "Reading the sign-in history..."
    result = ongoing_attacks(build(history), 72)
    win.show(result, lambda section, row: "-")
    assert _geometry(win) == empty
    win.show_error("x" * 400)  # even a very long error message stays inside the reserved lines
    assert _geometry(win) == empty
    for key in ("known", "sessions", "guessing", "ips"):     # the counts on the filter change, its buttons stay
        win.show_filter(key)
        assert _geometry(win) == empty
    win.top.destroy()


def test_a_kind_with_nothing_says_so_plainly(root, history):
    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)
    result.sessions.clear()

    class App:
        def load_attacks(self, win, hours):
            win.show(result, lambda section, row: "-")

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.load()
    win.show_filter("sessions")
    root.update()
    assert win.filter.text("sessions") == "Stolen sessions 0"
    assert win.empty_title.cget("text") == "Stolen sessions: nothing in the last 72 hours"
    assert win.pointer.shown_at is None and win.frame._edge == "window"          # the panel is nobody's
    assert win.row_text.get("1.0", "end").strip() == "" and str(win.open_btn.cget("state")) == "disabled"
    win.top.destroy()


def test_attacks_refresh_keeps_sort_order_and_selection(root, history):
    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)

    class App:
        def load_attacks(self, win, hours):
            win.show(result, lambda section, row: "-")

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.load()
    win.show_filter("guessing")
    tree = win.accounts_tree
    accounts = lambda: [tree.set(i, "Who") for i in tree.get_children()]  # noqa: E731
    win._sorts["guessing"]("Who")
    win._sorts["guessing"]("Who")  # descending
    ordered = accounts()
    assert ordered == sorted(ordered, reverse=True) and len(ordered) > 1
    tree.selection_set(tree.get_children()[-1])
    chosen = tree.set(tree.selection()[0], "Who")
    win.load()  # refresh
    assert win.section == "guessing", "the kind the user chose stays"
    assert accounts() == ordered, "the sort arrow and the rows still agree"
    assert tree.selection() and tree.set(tree.selection()[0], "Who") == chosen
    assert chosen in win.row_text.get("1.0", "end")
    win.top.destroy()


def test_switching_the_kind_keeps_every_list_mapped(root, history):
    """Lists are raised, never unmapped and re-mapped (that showed the empty pane for a moment: a flash)."""
    from radar.ui import theme
    from radar.ui.attacks import SECTION_KEYS, AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)

    class App:
        def load_attacks(self, win, hours):
            win.show(result, lambda section, row: "-")

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.load()
    import time
    end = time.monotonic() + 2
    while time.monotonic() < end and float(win.top.attributes("-alpha")) < 1.0:  # until the window is revealed
        win.top.update()
    unmapped = []
    for tree in win._trees:
        tree.outer.bind("<Unmap>", lambda _e: unmapped.append(1), add="+")
    place = lambda w: (w.winfo_rootx() - win.top.winfo_rootx(), w.winfo_rooty() - win.top.winfo_rooty(),  # noqa: E731
                       w.winfo_width(), w.winfo_height())
    first = place(win.accounts_tree.outer)
    for key in SECTION_KEYS + ["guessing"]:
        win.show_filter(key)
        win.top.update()
        tree = win.lists[key]
        assert win._current_tree() is tree and tree.outer.winfo_ismapped()
        assert place(tree.outer) == first, "every list has the same place"
        # the chosen list is the top one of the stack (asked from Windows: independent of other windows)
        import ctypes
        assert ctypes.windll.user32.GetTopWindow(win.body.winfo_id()) == tree.outer.winfo_id()
    assert not unmapped
    win.top.destroy()


def test_attacks_window_shows_cached_data_then_refreshes_and_shows_the_age(root, history):
    from datetime import datetime, timedelta, timezone

    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)
    calls = []

    class App:
        def load_attacks(self, win, hours, refresh=False, then_refresh=False):
            calls.append((refresh, then_refresh))

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.load(then_refresh=True)  # what the app does when the window opens
    assert calls == [(False, True)]
    assert not win.age.pressable and win.age.text == "No data yet"
    before = _geometry(win)
    old = datetime.now(timezone.utc) - timedelta(minutes=42)
    win.show(result, lambda s, r: "-", as_of=old, busy=True)  # cached data is there, the refresh still runs
    assert win.accounts_tree.get_children() and "(42 min ago)" in win.age.text
    assert not win.age.pressable and "Refreshing" in str(win.refresh_btn.cget("text"))
    win.refresh()
    assert len(calls) == 1  # not twice at the same time
    win.show(result, lambda s, r: "-", as_of=datetime.now(timezone.utc), busy=False)  # fresh data
    assert "(just now)" in win.age.text and win.age.pressable
    assert _geometry(win) == before
    win.refresh_btn.invoke()
    assert calls[-1] == (True, False) and not win.age.pressable
    assert "(just now)" in win.age.text  # the age of what is shown stays visible during the refresh
    win.show(result, lambda s, r: "-", as_of=old, busy=False, error="sign-in required")
    assert "refresh failed: sign-in required" in win.age.text and "(42 min ago)" in win.age.text
    win.period.set("Last 24 hours")
    win.load()  # another period: computed from the local data, no new read from Entra
    assert calls[-1] == (False, False)
    assert _geometry(win) == before
    win.top.destroy()


def test_the_facts_of_a_row_start_at_one_place_whatever_the_row(root, history):
    """The longest name there is does not push its value out of the column."""
    from radar.ui import theme
    from radar.ui.attacks import SECTION_KEYS, AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)
    for n, a in enumerate(result.accounts):
        a.past_password = "No" if n else "Yes: 2 successful sign-in(s) from unfamiliar networks"

    class App:
        def load_attacks(self, win, hours):
            win.show(result, lambda section, row: "open")

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.load()
    starts, text, seen = set(), win.row_text, set()
    for key in SECTION_KEYS:
        win.show_filter(key)
        tree = win.lists[key]
        for iid in tree.get_children()[:3]:
            tree.selection_set(iid)
            win._selection_changed()
            win.top.update()
            for line in range(2, int(text.index("end").split(".")[0])):
                content = text.get(f"{line}.0", f"{line}.end")
                at = f"{line}.{content.index(chr(9)) + 1}" if chr(9) in content else ""
                box = text.bbox(at) if at else None
                if box and not text.dump(at, f"{at}+1c", image=True):   # (a link's icon has its own small margin)
                    starts.add(box[0])
                    seen.add(content.split(chr(9))[0])
    assert "Got past password" in seen and len(starts) == 1, (starts, seen)
    win.top.destroy()


def test_opening_the_page_again_starts_on_the_most_dangerous_kind(root, history):
    """The kind the user chose stays through every refresh while the page is in view - and no longer."""
    from radar.ui import theme
    from radar.ui.attacks import AttacksWindow

    theme.init(root)
    result = ongoing_attacks(build(history), 72)

    class App:
        def load_attacks(self, win, hours):
            win.show(result, lambda section, row: "-")

        def open_attack_details(self, account):
            pass

    win = AttacksWindow(root, App())
    win.opened()                               # before there is data: nothing to choose from, nothing breaks
    win.load()
    assert win.section == "known"
    win.show_filter("ips")
    win.load()                                 # a refresh
    assert win.section == "ips"
    win.opened()                               # the page comes into view again
    assert win.section == "known" and win._current_tree() is win.lists["known"]
    win.load()
    assert win.section == "known"
    result.password_known.clear()              # nothing of the most dangerous kind any more: the next there is
    win.load()
    win.show_filter("ips")
    win.opened()
    assert win.section == "sessions"
    result.sessions.clear(); result.accounts.clear(); result.sources.clear()
    win.load()
    win.opened()
    assert win.section == "guessing"           # nothing at all: the page says so on one kind
    win.top.destroy()
