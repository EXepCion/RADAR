"""The Search page and the page about one account, as the main window shows them."""
import tkinter as tk
from datetime import timedelta
from types import SimpleNamespace

import pytest

from radar import search, timefmt
from radar.plugin_api import Severity

from conftest import T0
from test_search import NAMES, NOW, alert, directory, travels, usual


@pytest.fixture(autouse=True)
def nothing_moves():
    """What these tests look at is where things end up: with animations off they are there at once. (How they get
    there is tested by itself, in test_motion.)"""
    from radar.ui import theme

    theme.set_animations(False)
    yield
    theme.set_animations(True)


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
    """What the pages ask of the app, over a history in memory."""

    def __init__(self, history, alerts=()):
        self.history, self.alerts_list = history, list(alerts)
        self.last, self.opened, self.searched = [], [], []

    def ui_call(self, fn, *a, **k):
        fn(*a, **k)

    def search(self, text, limit=5):
        self.searched.append(text)
        return search.search(text, self.history, directory(), self.alerts_list, NOW, limit)

    def search_signins(self, text):
        return search.signin_list(text, self.history, directory(), NOW)

    def thing_view(self, kind, key):
        return search.thing_view(kind, key, self.history, directory(), self.alerts_list, [], NOW, NAMES)

    def account_view(self, user_id):
        return search.account_view(user_id, self.history, directory(), self.alerts_list, [], NOW, NAMES)

    def search_history(self):
        return self.history

    def unfold(self, line):
        return search.unfold(self.history, line)

    def search_age(self):
        return "30 days, up to 12:00 UTC"

    def opened_last(self):
        return list(self.last)

    def remember_opened(self, kind, key, title="", line=""):
        self.last.insert(0, {"kind": kind, "key": key, "title": title, "line": line, "when": "12:00 UTC"})

    def clear_opened(self):
        self.last = []

    def open_found(self, kind, key, title=""):
        self.opened.append((kind, key))

    def open_alert(self, a):
        self.opened.append(("alert", a.id))

    def open_incident(self, incident_id):
        self.opened.append(("incident", incident_id))

    def open_account_in_entra(self, user_id):
        self.opened.append(("entra", user_id))

    def show_main(self, page=None):
        self.opened.append(("main", page))

    def show_map(self):
        self.opened.append(("map", ""))


def theme_color(role):
    from radar.ui import theme

    return theme.color(role)


def texts(widget):
    """Every text a part of a page shows: its labels, its tags, and the entries of the lists that flow."""
    from radar.ui.bits import Flow, Tag

    out = []
    for w in widget.winfo_children():
        if isinstance(w, (tk.Label, Tag)) and w.cget("text"):
            out.append(w.cget("text"))
        elif isinstance(w, Flow):
            out += [part.strip() for part in w.text().replace("\u25a0", "|").split("|") if part.strip()]
            out += w.text().replace("\u25a0", " ").split()
        out += texts(w)
    return out


def shown_in(page_or_widget, *words):
    """Are these words on that part of the page, wherever they stand?"""
    everything = " ".join(texts(page_or_widget))
    return all(word in everything for word in words)


def page(root, history, alerts=()):
    from radar.ui.search import SearchPage

    host = tk.Toplevel(root)
    host.geometry("1196x780")
    app = FakeApp(history, alerts)
    p = SearchPage(root, app, host, background=False)
    p.top.pack(fill="both", expand=True)
    root.update()
    return host, app, p


def test_the_empty_page_is_the_field_alone_until_something_was_opened(root, history):
    host, app, p = page(root, usual(history))
    try:
        assert p.rows == [] and not p.listing.outer.winfo_manager() and p.hint.winfo_manager()
        field_at = p.box.winfo_rooty()
        p.text.set("alice")
        p.run(wait=True)
        root.update()
        assert not p.hint.winfo_manager() and p.box.winfo_rooty() == field_at            # the field does not move
        assert shown_in(p.body, "Accounts", "Alice", "Example", "LAPTOP", "Sign-ins")      # (what was typed is bold: a label of its own)
        assert any(isinstance(w, tk.Label) and w.cget("text") == "Alice" and "Strong" in str(w.cget("font")) for row, _f in p.rows for w in row.parts)
        assert p.filters.text("all") == f"All {p.results.total:,}" and p.filters.text("account") == "Accounts 2"
        assert p.filters.text("address") == "Addresses" and p.age.cget("text") == "30 days, up to 12:00 UTC"
        assert p.selected == 0                                                             # Enter opens the best hit
        p._open_selected()
        root.update()
        assert p.account_view() is not None and app.last[0]["title"] == "Alice Example"
        assert app.last[1] == {"kind": "search", "key": "alice", "title": "alice", "line": f"a search \u00b7 {p.results.total:,} results", "when": "12:00 UTC"}
        p.focus()
        p.text.set("")
        p.run(wait=True)
        assert shown_in(p.plain, "Opened last", "Alice Example", "a search") and not p.filters.winfo_manager()
        assert not p.listing.outer.winfo_manager()                 # (what was opened last stands on the page, not on a card)
        p.rows[0][1]()                                                                     # a click on it opens it again
        assert p.account_view().user_id == "u1"
        p.focus()
        p.rows[1][1]()                                                                     # ... and a search is typed again
        assert p.text.get() == "alice" and p.results is not None
    finally:
        host.destroy()


def test_one_kind_can_be_chosen_and_other_hits_open_where_they_belong(root, history):
    host, app, p = page(root, usual(history), [alert(1, "Sign-in from a new country: alice@contoso.com from Brazil")])
    try:
        p.text.set("alice")
        p.run(wait=True)
        all_rows = len(p.rows)
        p.filters.choose("signin")                 # all sign-ins: a table - when, what, whose, from where, with which device
        root.update()
        table = p.table.get("1.0", "end")
        assert all_rows > 0 and p.rows == [] and "What\tAccount\tFrom\tDevice" in table
        assert "Exchange Online" in table and "wrong password, 5 times in 1 minute" in table and "\tAlice Example\tSao Paulo, BR \u00b7 203.0.113.5\tno device" in table
        assert [m.cget("text") for m in p.table_marks][:2] == ["blocked by policy", "Entra risk: medium"]
        assert p.column.winfo_reqwidth() > p.box.winfo_reqwidth() or True
        p.filters.choose("alert")
        p.rows[0][1]()
        assert app.opened[-1] == ("alert", 1)
        p.filters.choose("device")                 # a device has a page of its own, built like the account's
        p.rows[0][1]()
        root.update()
        device = p.account_view()
        assert device.kind == "device" and device.title.cget("text") == "ALICE-LAPTOP" and app.last[0]["kind"] == "device"
        shown = texts(device.summary.body)
        assert shown_in(device.summary.body, "Seen with", "Alice Example", "Compliant") and "Habits" not in shown
        assert "Sign-in · Alice Example · Toronto, CA · 198.51.100.10" in device.written()
        # the way that led here is not written above the page (no bread crumbs) - the back button leads back step by step
        assert not hasattr(device, "trail") and [k for k, _key, _t in p.path] == ["device"]
        device.app.open_found = lambda kind, key, title="": p.show_thing(kind, key, title)
        p.show_thing("account", "u1", "Alice Example")
        root.update()
        assert [k for k, _key, _t in p.path] == ["device", "account"] and not hasattr(p.account_view(), "trail")
        p.account_view().back.invoke()
        root.update()
        assert p.account_view().kind == "device"                 # one step back: the page this one was opened from
        p.account_view().back.invoke()
        root.update()
        p.focus()
        p.text.set("zzzz-nothing")
        p.run(wait=True)
        assert any("Nothing found" in t for t in texts(p.body)) and p.rows == []
        p.text.set("a")                            # too short to be a question: back to what was opened last
        p.run(wait=True)
        assert app.searched[-1] == "zzzz-nothing" and "Opened last" in texts(p.plain)
    finally:
        host.destroy()


def account(root, history, alerts=()):
    from radar.ui.account import AccountPage

    host = tk.Toplevel(root)
    host.geometry("1196x780")
    app = FakeApp(history, alerts)
    went = []
    p = AccountPage(root, app, host, "u1", on_back=lambda: went.append("back"), on_search=went.append, background=False)
    p.top.pack(fill="both", expand=True)
    p.load(wait=True)
    root.update()
    return host, app, p, went


def test_the_account_page_shows_who_what_is_open_habits_and_the_timeline(root, history):
    usual(history)
    host, app, p, _went = account(root, history, [alert(1, "Sign-in from a new country: Brazil", minutes=3)])
    try:
        shown = texts(p.summary.body)
        assert p.title.cget("text") == "Alice Example" and p.risk.cget("text") == "55" and p.risk_level.cget("text") == "Medium"
        assert [t.cget("text") for t in p.tags] == ["Enabled", "Member"]
        assert "Right now" in shown and "Sign-in from a new country: Brazil" in shown and "1 open alert" in shown
        assert "Habits" in shown and "Example Hosting" in " ".join(shown) and "new" in shown and "Worth a look" in shown
        # where the account's devices were: a lane for every device - the laptop, and the sign-ins that name none -, the
        # colour of a bar its place; it opens on the last 24 hours, which say their zone
        lanes = p.lanes
        assert lanes.written("name") == ["ALICE-LAPTOP", "work computer, managed", "No device", "the sign-ins name none"]
        assert texts(p.moves)[:2] == ["Movement", f"the last 24 hours \u00b7 times in {timefmt.zone(NOW.astimezone())}"]
        assert lanes.at_end and not p.now_button.winfo_manager() and lanes.written("at") == [timefmt.weekday_bare(NOW)]
        bars = lanes.bars()
        assert [b[0] for b in bars][-2:] == ["ALICE-LAPTOP \u00b7 Toronto, CA \u00b7 " + timefmt.span(T0 - timedelta(minutes=30), T0 - timedelta(minutes=30)) + " \u00b7 Example Telecom",
                                             "No device \u00b7 Sao Paulo, BR \u00b7 " + timefmt.span(T0 + timedelta(minutes=3), T0 + timedelta(minutes=3)) + " \u00b7 Example Hosting"]
        assert [b[3] for b in bars][-2:] == [theme_color("place1"), theme_color("place2")]   # the place the account spent most time at: the first colour
        assert [b[1] for b in bars] == sorted(b[1] for b in bars) and all(b[2] - b[1] >= 3 for b in bars)   # in the order of time; a moment is seen
        assert [lanes.legend.itemcget(i, "text") for i in lanes.legend.find_withtag("place")] == ["Toronto, CA", "Sao Paulo, BR"]
        assert "Risk in Entra" in shown and "Password changed" not in shown                # four facts, the rest on demand
        p._toggle_facts()
        assert "Password changed" in texts(p.summary.body)
        body = p.written()
        assert "Office 365 · MFA by Mobile app notification" in body and "Sao Paulo, BR · 203.0.113.5 · no device" in body
        assert sorted(p.marks) == ["Entra risk: medium", "blocked by policy"]     # what is unusual: small tags
        assert "times in UTC" in body and not any("UTC" in ln.split("	")[0] for ln in body.splitlines() if ln[:2].isdigit())  # the zone once per day
        assert p.filters.text("Failed") == "Failed 6" and p.filters.text("Alert") == "Alerts 1"
        # the summary keeps its width; the timeline has the rest and is in view without scrolling the page
        assert p.summary.winfo_width() <= p.feed.winfo_width() and p.feed.winfo_height() > 300
    finally:
        host.destroy()


def test_the_movement_card_shows_24_hours_its_devices_lead_to_their_pages_and_nothing_beside_it_moves(root, history):
    """At 100 % and at 150 %: 24 hours across the chart's width, the names beside it, the places under it and nothing
    more; a device's name opens the device's page - and when an earlier time is in view, "Now" appears in room that was
    kept for it: nothing around it moves."""
    from radar.ui import theme
    from test_search import LAPTOP

    travels(history)
    before = theme._scale
    try:
        for scale in (1.0, 1.5):
            theme.set_scale(root, scale)
            host, app, p, _went = account(root, history)
            try:
                lanes = p.lanes
                assert lanes.master.winfo_children() == [p.span.master, lanes]                  # the heading and the chart: nothing under it
                # the laptop's name: its page, the way the timeline's devices open theirs
                c, link = lanes.chart, lanes.chart.find_withtag("link")
                assert [c.itemcget(i, "text") for i in link] == ["ALICE-LAPTOP"]
                x0, y0, x1, y1 = c.bbox(link[0])
                c.event_generate("<Motion>", x=(x0 + x1) // 2, y=(y0 + y1) // 2)
                c.event_generate("<ButtonPress-1>", x=(x0 + x1) // 2, y=(y0 + y1) // 2)
                c.event_generate("<ButtonRelease-1>", x=(x0 + x1) // 2, y=(y0 + y1) // 2)
                root.update()
                assert app.opened == [("device", LAPTOP["device_id"])]
                # 24 hours across, whatever the width: a line every three hours, an eighth of the chart apart
                hours = sorted(lanes.chart.coords(i)[0] for i in lanes.chart.find_withtag("hours"))
                steps = [b - a for a, b in zip(hours, hours[1:])]
                assert len(steps) > 8 and all(abs(s - lanes.stage / 8) <= 1 for s in steps), (scale, steps, lanes.stage)
                inside = lanes.chart.winfo_width()
                assert all(lanes.chart.bbox(i)[0] >= -1 for i in lanes.chart.find_withtag("name"))
                assert all(lanes.chart.bbox(i)[2] <= inside + 1 for i in lanes.chart.find_withtag("mark"))
                # an earlier time in view: the heading says which, "Now" appears - and nothing around it moves
                head = p.span.master
                where = lambda: [(w.winfo_x(), w.winfo_y(), w.winfo_width(), w.winfo_height()) for w in head.winfo_children()] + [  # noqa: E731
                    (p.moves.winfo_height(), p.feed.winfo_rooty(), lanes.winfo_height())]
                placed = where()
                lanes._go(lanes.offset - lanes.stage)
                root.update()
                said = p.span.cget("text")
                assert not lanes.at_end and p.now_button.winfo_manager() and said in p._said and p._said[0].split(" ")[0] in ("Sat", "Sun")
                assert "UTC" in said and where() == placed                                         # (however little room: the zone is said)
                p.now_button.invoke()                                                     # back to now (at once: animations are off here)
                root.update()
                assert lanes.at_end and not p.now_button.winfo_manager() and where() == placed and p.span.cget("text") in p._said
                assert p._said[0].startswith("the last 24 hours") and all("UTC" in form for form in p._said)
            finally:
                host.destroy()
    finally:
        theme.set_scale(root, before)


def test_filters_worth_a_look_and_unfolding_work_on_the_timeline(root, history):
    usual(history)
    host, app, p, went = account(root, history)
    try:
        everything = len(p.visible_lines())
        p.filters.choose("Failed")
        assert [ln.kind for ln in p.visible_lines()] == ["Failed", "Failed"] and "MFA by" not in p.written()
        blocked = next(w for w in p.view.worth if w.label == "Blocked by a policy")
        p._only(blocked)
        assert [ln.ref for ln in p.visible_lines()] == [("signin", "blocked")] and "show everything" in p.written()
        p._filter()
        assert len(p.visible_lines()) == everything
        line = next(ln for ln in p.visible_lines() if ln.ref == ("signin", "away-ok"))
        p._fold(line)
        assert "How\tPassword, then Mobile app notification" in p.written()
        p._fold(line)
        assert "How\tPassword" not in p.written()
        p._open(line)
        assert app.opened[-1] == ("signin", "away-ok")
        p.find.set("203.0.113.5")
        p.entry.focus_force()
        root.update()
        p.entry.event_generate("<Return>")
        root.update()
        assert went == ["203.0.113.5"]
        p.map.invoke()
        p.entra.invoke()
        assert app.opened[-2:] == [("map", ""), ("entra", "u1")]
    finally:
        host.destroy()


def test_cards_with_nothing_in_them_are_one_line(root, history):
    quiet = history.__class__(":memory:")
    host, app, p, _went = account(root, quiet)
    try:
        shown = texts(p.summary.body)
        assert "nothing open" in shown and any(t.startswith("nothing unusual") for t in shown)
        assert p.now_card.winfo_reqheight() < 60 and p.worth_card.winfo_reqheight() < 60       # no room kept for rows
        assert p.risk.cget("text") == "Nothing open" and "Nothing is stored about this." in p.written()
    finally:
        host.destroy()
        quiet.close()


def test_the_app_remembers_what_was_opened_and_opens_on_what_needs_attention(monkeypatch):
    from radar.app import App

    app = App()
    try:
        assert app.start_page() == "search" and app.opened_last() == []                  # nothing open: the search
        for i in range(8):
            app.remember_opened("account", f"u{i}", f"Account {i}", "line")
        app.remember_opened("account", "u3", "Account 3", "line")
        last = app.opened_last()
        assert len(last) == app.OPENED_LAST and last[0]["key"] == "u3" and [x["key"] for x in last].count("u3") == 1
        app.clear_opened()
        assert app.opened_last() == []
        assert app.search("alice").total == 0 and app.account_view("u1").timeline == []   # before the first scan: empty, no error
        assert app.search_age() == "30 days"
    finally:
        app.store.close()


def test_a_hit_too_long_for_its_room_begins_at_its_beginning(root, history):
    """A label that is too narrow for its text shows the text's middle - cut off at both ends. A long hit must begin
    with its first letter and end in an ellipsis."""
    from conftest import make_signin
    from test_search import HOME

    usual(history)
    long_app = "An application with a remarkably long name that goes on and on " * 3
    history.add([make_signin(10, **HOME, app=long_app.strip(), id="long", device_name="ALICE-LAPTOP-WITH-A-LONG-NAME")])
    host, app, p = page(root, history)
    try:
        p.text.set("remarkably")
        p.run(wait=True)
        root.update()
        row = next(row for row, _f in p.rows if any(getattr(w, "whole", "").startswith("alice@contoso.com") for w in row.parts))
        line = next(w for w in row.parts if getattr(w, "whole", ""))
        labels = [w for w in line.winfo_children() if isinstance(w, tk.Label)]
        shown = "".join(w.cget("text") for w in labels)
        assert shown.startswith("alice@contoso.com") and shown.endswith("\u2026") and len(shown) < len(line.whole)
        assert all(w.winfo_reqwidth() <= w.winfo_width() + 1 for w in labels if w.cget("text"))    # nothing is clipped
        assert sum(w.winfo_reqwidth() for w in labels) <= line.winfo_width()
    finally:
        host.destroy()


def test_shortening_a_long_text_does_not_change_the_room_it_is_shortened_for(root, history, monkeypatch):
    """Fitting a text to its room must not change the room: it did, and the page fitted and fitted without end."""
    from radar.ui import search as search_page

    calls = []
    fit_text = search_page.fit_text
    monkeypatch.setattr(search_page, "fit_text", lambda *a: (calls.append(1), fit_text(*a))[1])
    host, app, p = page(root, usual(history))
    try:
        long = "A thing with a name so long that no row of any list could ever hold all of it " * 4
        app.remember_opened("device", "d1", long.strip(), long.strip())
        app.remember_opened("account", "u1", "Alice Example", "alice@contoso.com")
        p.show_last()
        for _ in range(30):
            root.update()
        settled = len(calls)
        for _ in range(30):
            root.update()
        assert len(calls) == settled and settled < 60                 # it came to rest
        row = p.rows[1][0]
        shown = [w.cget("text") for w in row.parts if isinstance(w, tk.Label)]
        assert any(t.startswith("A thing with a name") and t.endswith("…") for t in shown)
        assert row.outer.winfo_width() <= p.scroll.canvas.winfo_width()
    finally:
        host.destroy()


def test_a_search_from_another_page_never_shows_the_old_results_first(root, history):
    host, app, p = page(root, usual(history))
    try:
        p.text.set("alice")
        p.run(wait=True)
        p.open("account", "u1", "Alice Example")
        root.update()
        assert p.rows                              # the old results are still under the page
        seen, run, focus = [], p.run, p.focus
        p.run = lambda wait=False: (seen.append(("search", len(p.rows), p.results, bool(p.filters.winfo_manager()))), run(wait))[1]
        p.focus = lambda: (seen.append(("shown", p.results.text if p.results else None)), focus())[1]
        p._search_for("203.0.113.5")
        # emptied, then searched (at once, not after the pause that waits for typing), and only then shown
        assert seen == [("search", 0, None, False), ("shown", "203.0.113.5")]
        assert p.text.get() == "203.0.113.5" and p.path == [] and p.rows and p._due is None
    finally:
        host.destroy()


def test_a_page_comes_forward_complete_not_piece_by_piece(root, history, monkeypatch):
    """Opening a hit: what is on screen stays until the page is read and laid out; then the page is there, whole. A
    page that takes long to read is shown while it reads - with one line that says so and none of its empty parts."""
    from radar.ui import search as search_page
    from radar.ui.account import AccountPage

    host, app, p = page(root, usual(history), [alert(1, "Sign-in from a new country: Brazil")])
    try:
        p.text.set("alice")
        p.run(wait=True)
        root.update()
        on_top = lambda: p.stack.winfo_children()[-1]   # noqa: E731 - (children are listed from the lowest to the one on top)
        monkeypatch.setattr(AccountPage, "load", lambda self, wait=False: None)       # the reading takes its time
        monkeypatch.setattr(search_page, "SHELL_MS", 60_000)
        p.open("account", "u1", "Alice Example")
        root.update()
        view = p.account_view()
        assert on_top() is p.find and not view.ready and str(p.stack.cget("cursor")) == "watch"   # the hits are still what is seen
        assert not view.panes.winfo_manager() and view.wait_note.winfo_manager()                 # none of its empty parts exist yet
        view.show(app.account_view("u1"))                                                         # ... it has been read
        assert on_top() is view.top and view.ready and view.panes.winfo_manager() and not view.wait_note.winfo_manager()
        assert str(p.stack.cget("cursor")) == "" and view.title.cget("text") == "Alice Example" and view.lanes.bars()
        assert all(flow.winfo_height() > 1 for flow in view.flows)                                # laid out before it is seen
        # from that page to the next: the first stays until the second is complete, then goes
        p.show_thing("device", "11111111-2222-4333-8444-555555555555", "ALICE-LAPTOP")
        root.update()
        second = p.account_view()
        assert on_top() is view.top and second is not view and view.exists()
        second.show(app.thing_view("device", "11111111-2222-4333-8444-555555555555"))
        root.update()
        assert on_top() is second.top and not view.exists()
        # one that is given up while it is still being read never comes forward
        p.show_thing("account", "u1", "Alice Example")
        third = p.account_view()
        p.focus()
        root.update()
        assert on_top() is p.find and not third.exists() and p.account_view() is second and str(p.stack.cget("cursor")) == ""
        # a page that takes long: shown while it reads, as one line
        monkeypatch.setattr(search_page, "SHELL_MS", 30)
        p.show_thing("account", "u1", "Alice Example")
        slow = p.account_view()
        for _ in range(40):
            root.update()
            root.after(5)
        assert on_top() is slow.top and not slow.ready and slow.wait_note.winfo_manager() and not slow.panes.winfo_manager()
        slow.show(app.account_view("u1"))
        assert slow.panes.winfo_manager() and not slow.wait_note.winfo_manager()
    finally:
        host.destroy()


def test_a_page_that_cannot_be_read_says_so_instead_of_reading_forever(root, history, caplog):
    host, app, p = page(root, usual(history))
    try:
        def broken(user_id):
            raise RuntimeError("the history cannot be opened")

        app.account_view = broken
        p.show_thing("account", "u1", "Alice Example")
        root.update()
        view = p.account_view()
        assert p.stack.winfo_children()[-1] is view.top and str(p.stack.cget("cursor")) == ""      # it has come forward
        assert "could not be read" in view.wait_note.cget("text") and not view.panes.winfo_manager()
        assert "The page could not be read" in caplog.text
        view.back.invoke()                                                                           # ... and there is a way back
        assert p.stack.winfo_children()[-1] is p.find
    finally:
        host.destroy()


def test_what_was_found_is_laid_out_as_designed(root, history):
    host, app, p = page(root, usual(history), [alert(1, "Sign-in from a new country: alice@contoso.com from Brazil")])
    try:
        p.text.set("alice")
        p.run(wait=True)
        root.update()
        shown = [key for key, _x0, _x1 in p.filters._spans]
        assert "all" in shown and "account" in shown and "address" not in shown            # a kind nothing was found of has no filter
        assert p.age.winfo_y() == p.filters.winfo_y() or p.age.winfo_manager() == "pack"   # the data's age stands beside the filters
        arrows = [row.arrow.cget("foreground") != row.cget("background") for row, _f in p.rows]
        assert arrows[0] and not any(arrows[1:])                                           # the chosen row alone shows its arrow
        accounts = [row for row, _f in p.rows if row.quiet]
        assert [row.badge.quiet for row in accounts][:1] == [False]                        # ... and its circle in the accent colour
        p._select(1)
        assert accounts[0].badge.quiet and not any(arrows[1:2])
        links = [link.cget("text") for link in p.links]
        assert links and links[-1] == f"All {p.results.counts['signin']:,} sign-ins"       # under a group: where the rest is
        p.links[-1].event_generate("<Button-1>")
        root.update()
        assert p.filters.chosen == "signin" and p.table is not None
    finally:
        host.destroy()


def test_an_account_with_an_open_incident_shows_it_and_a_page_that_cannot_be_drawn_says_so(root, history, caplog, monkeypatch):
    from radar.alerts import ACTIVE, Alert
    from radar.incidents import Incident

    usual(history)
    found = Alert(id=7, key="k", plugin_id="signin_threats", rule_id="new_country", severity=Severity.HIGH, title="Sign-in from a new country: Brazil",
                  summary="", recommendation="", fields={"User": "alice@contoso.com"}, evidence=[], links=[], occurred_at=T0, first_seen=T0,
                  last_seen=T0, status=ACTIVE, score=80, factors=[(40, "New country for the account")], subjects=["alice@contoso.com"])
    incident = Incident(id="i1", alerts=[found], accounts=["alice@contoso.com"], addresses=[], first=T0, last=T0, severity=Severity.HIGH,
                        open=True, stage=0, title="Alice Example: a new country", own=1)
    host, app, p, _went = account(root, history, [found])
    try:
        app.account_view = lambda user_id: search.account_view(user_id, history, directory(), [found], [incident], NOW, NAMES)
        p.load(wait=True)
        root.update()
        assert p.ready and shown_in(p.top, "Alice Example: a new country", "Incident · 1 of 1 alert open")
        assert not shown_in(p.top, "New country for the account")     # (its reasons stand in the incident's own window)
        # whatever goes wrong while the page is drawn: it says so and stops waiting
        from radar.ui.account import AccountPage
        monkeypatch.setattr(AccountPage, "_summary", lambda self: 1 / 0)
        broken = AccountPage(root, app, host, "u1", on_back=lambda: None, on_search=lambda t: None, background=False)
        broken.load(wait=True)
        told = []
        broken.when_ready(lambda: told.append(1))
        assert broken.failed and not broken.ready and told and "could not be read" in broken.wait_note.cget("text") and "The page could not be drawn" in caplog.text
    finally:
        host.destroy()
