"""Fluent theme: light/dark palettes, live switching, animations (on by default, switchable), Style A windows."""
import time
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace

import pytest

from radar.plugin_api import Finding, Severity
from radar.ui import theme


@pytest.fixture(scope="module")
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    theme.init(r, dark=False, animations=False)
    yield r
    if theme.is_dark():
        theme.set_mode(r, False)
    r.destroy()


def test_palettes_map_role_for_role():
    """Switching maps every colour of one palette to the same role of the other: roles may share a value only if
    they share it in both palettes, else a recolour would be ambiguous."""
    assert set(theme.LIGHT) == set(theme.DARK)
    for a in theme.LIGHT:
        for b in theme.LIGHT:
            assert (theme.LIGHT[a] == theme.LIGHT[b]) == (theme.DARK[a] == theme.DARK[b]), (a, b)


def test_live_switch_recolours_widgets_tags_items_and_keeps_ttk_styles(root):
    from radar.ui.richtext import RichText, card

    top = tk.Toplevel(root)
    box = card(top)
    box.pack()
    text = RichText(box)
    text.pack()
    text.write("muted", "muted")
    canvas = tk.Canvas(box, background=theme.color("track"))
    item = canvas.create_rectangle(0, 0, 5, 5, fill=theme.color("border"))
    canvas.pack()
    tree = ttk.Treeview(box)
    tree.tag_configure("Active", foreground=theme.color("error"))
    tree.pack()
    label = ttk.Label(top, text="x", style="Muted.TLabel")
    label.pack()
    blocks = RichText(top)
    blocks.card_blocks()
    blocks.begin_card("Details", first=True)
    blocks.end_card()
    blocks.pack()
    root.update()

    theme.set_mode(root, True)
    root.update()
    assert theme.is_dark()
    assert box.cget("background") == theme.DARK["card"] and box.cget("highlightbackground") == theme.DARK["border"]
    assert text.cget("background") == theme.DARK["card"] and text.cget("foreground") == theme.DARK["text"]
    assert text.tag_cget("muted", "foreground") == theme.DARK["muted"]
    assert canvas.cget("background") == theme.DARK["track"] and canvas.itemcget(item, "fill") == theme.DARK["border"]
    assert str(tree.tag_configure("Active", "foreground")) == theme.DARK["error"]
    # ttk labels stay style-driven (sv-ttk's tk_setPalette would pin explicit colours on them)
    assert str(label.cget("background")) == "" and str(label.cget("foreground")) == ""
    assert ttk.Style(root).lookup("Muted.TLabel", "foreground") == theme.DARK["muted"]
    # card blocks inside a text: background and both margin colours follow (white edges otherwise)
    assert blocks.cget("background") == theme.DARK["window"]
    assert {blocks.tag_cget("card", o) for o in ("background", "lmargincolor", "rmargincolor")} == {theme.DARK["card"]}

    theme.set_mode(root, False)
    root.update()
    assert box.cget("background") == theme.LIGHT["card"] and text.tag_cget("muted", "foreground") == theme.LIGHT["muted"]
    top.destroy()


def test_tables_have_flat_headings_aligned_with_cells(root):
    style = ttk.Style(root)
    assert style.layout("Treeview.Heading")[0][0] == "Treeitem.row"  # flat tinted row, not the theme's boxed cells
    assert "Treeitem.indicator" not in str(style.layout("Treeview.Item"))  # flat lists: no expander column
    head = [int(str(v)) for v in root.tk.splitlist(style.lookup("Treeview.Heading", "padding"))]
    cell = [int(str(v)) for v in root.tk.splitlist(style.lookup("Treeview.Cell", "padding"))]
    assert head[0] == cell[0] + theme.px(theme.HEADING_TEXT_SHIFT)
    assert style.lookup("Treeview", "font") == theme.FONT_TABLE
    assert style.lookup("Treeview.Heading", "font") == theme.FONT_TABLE_BOLD


def test_animate_is_instant_when_off_and_runs_to_the_end_when_on(root):
    seen = []
    theme.set_animations(False)
    theme.animate(root, 500, seen.append)
    assert seen == [1.0]

    theme.set_animations(True)
    steps, done = [], []
    theme.animate(root, 120, steps.append, done=lambda: done.append(True))
    end = time.monotonic() + 2
    while not done and time.monotonic() < end:
        root.update()
        time.sleep(0.01)
    assert done and steps[-1] == 1.0 and len(steps) > 2 and steps == sorted(steps)
    assert theme.mix("#000000", "#ffffff", 0.5) == "#808080"


def test_fade_in_always_ends_fully_visible(root):
    theme.set_animations(True)
    top = tk.Toplevel(root)
    theme.fade_in(top, 60)
    assert float(top.attributes("-alpha")) < 1.0
    end = time.monotonic() + 2
    while time.monotonic() < end and float(top.attributes("-alpha")) < 1.0:
        root.update()
        time.sleep(0.01)
    assert float(top.attributes("-alpha")) == 1.0
    top.destroy()


def _details(root, app, finding, **kw):
    from radar.ui.details import DetailsWindow

    alert = app.alerts.ingest("directory_audit", [finding])[0]
    return DetailsWindow(root, app, alert, on_dismiss=lambda a: None, **kw)


def test_details_quick_links_risk_animation_and_snooze(root):
    from test_ui import FakeApp

    from radar.ui.details import quick_links

    app = FakeApp()
    snoozed = []
    finding = Finding(
        key="k", title="Cross-tenant trust changed", severity=Severity.LOW, score=40,
        factors=[(40, "Trusts MFA of the partner"), (0, "App-only change")],
        fields={"Not counted": "an MFA prompt from the user's own IP 198.51.100.7",
                "Initiated by": "Ops Automation", "Partner": "Fabrikam Finance AG (fabrikam.onmicrosoft.com)",
                "Partner users seen (14 d)": "a@fabrikam.com, b@fabrikam.com, c@fabrikam.com",
                "App signed in from": "203.0.113.66 (Toronto, CA)"})
    theme.set_animations(True)
    win = _details(root, app, finding, on_snooze=snoozed.append, snooze_label="1 hour")
    labels = [label for _e, _a, label in quick_links(win.alert)]
    # context fields ("Not counted") are skipped, at most 2 users, at most 5 links
    assert labels == ["Ops Automation – enterprise app", "Ops Automation – certificates & secrets",
                      "Fabrikam Finance AG (fabrikam.onmicrosoft.com) – cross-tenant settings",
                      "a@fabrikam.com – user in Entra", "b@fabrikam.com – user in Entra"]
    quick_actions = sorted(win.quick_text.actions.values())
    assert quick_actions == sorted(["app", "app_credentials", "xtenant", "user", "user"])
    end = time.monotonic() + 3
    while time.monotonic() < end and win.score_text() != "40":
        root.update()
        time.sleep(0.01)
    assert win.score_text() == "40"  # counted up to the score
    x0, _y0, x1, _y1 = win.bar.coords(win._bar_fill)
    assert x1 == pytest.approx(int(win.bar.cget("width")) * 0.4, abs=1)
    win._snooze()
    assert snoozed and not win.exists()


def test_app_toggles_are_stored_and_applied(root):
    from radar.app import App

    store = {"dark_mode": False, "animations": True}
    calls = []
    fake = SimpleNamespace(
        cfg=SimpleNamespace(get=lambda *p, default=None: store.get(p[-1], default),
                            set=lambda *p, value=None: store.__setitem__(p[-1], value)),
        root=root, ui_call=lambda fn, *a: calls.append((fn.__name__, a)), dark_mode=False, animations=True)
    App.toggle_dark_mode(fake)
    App.toggle_animations(fake)
    assert store == {"dark_mode": True, "animations": False}
    assert calls == [("set_mode", (root, True)), ("set_animations", (False,))]


def test_details_window_is_laid_out_before_it_is_shown(root):
    """No timer rearranges the window after it appeared; hovering a link (status line) moves nothing either."""
    from test_ui import FakeApp

    finding = Finding(
        key="stable", title="Cross-tenant trust changed " * 6, severity=Severity.MEDIUM, score=55,
        factors=[(55, "Trusts MFA of the partner")], fields={"Initiated by": "Ops Automation", "User": "a@contoso.com"},
        evidence=[{"Time": "2026-11-10 10:02", "User": "a@contoso.com", "IP": "203.0.113.5"}] * 5)
    win = _details(root, FakeApp(), finding)

    def places():
        root.update()
        widgets = [win.info, win.side_text, win.tree, win.row_text, win.hint]
        return [(w.winfo_rootx(), w.winfo_rooty(), w.winfo_width(), w.winfo_height()) for w in widgets] + [
            win.paned.sashpos(0)]

    first = places()
    end = time.monotonic() + 0.6
    while time.monotonic() < end:
        root.update()
        time.sleep(0.02)
    assert places() == first
    win.status.hover("Click: open the user in Entra   ·   right-click: more options " * 6)
    assert places() == first
    win.top.destroy()


@pytest.mark.parametrize("animations", [False, True])
def test_windows_open_without_flicker(root, animations):
    """A new window is invisible while it is built and laid out and then appears exactly once: its opacity never
    goes down again, and it is never opaque before it is finished."""
    from test_ui import FakeApp

    from radar.ui.attacks import AttacksWindow
    from radar.ui.entry import AuditWindow, EntryWindow

    theme.set_animations(animations)
    seen: dict[str, list[tuple[bool, float]]] = {}
    original = tk.Misc.update_idletasks

    def recording(widget):  # every point at which Tk may put a window on the screen while it is being built
        original(widget)
        top = widget.winfo_toplevel()
        if top is not root:
            seen.setdefault(str(top), []).append((bool(top.winfo_ismapped()), float(top.attributes("-alpha"))))

    class Attacks:
        def load_attacks(self, win, hours):
            pass

    finding = Finding(key="flicker", title="MFA exposure report", severity=Severity.MEDIUM, score=55,
                      factors=[(55, "Accounts without MFA")], fields={"User": "a@contoso.com"},
                      evidence=[{"Time": "2026-11-10 10:02", "User": "a@contoso.com"}] * 4)
    tk.Misc.update_idletasks = recording
    try:
        tops = [AttacksWindow(root, Attacks()).top, _details(root, FakeApp(), finding).top,
                EntryWindow(root, "r1", "sub", app=FakeApp()).top, AuditWindow(root, FakeApp(), "sub").top]
    finally:
        tk.Misc.update_idletasks = original
    for top in tops:
        during_build = seen.get(str(top), [])
        assert during_build and any(mapped for mapped, _ in during_build)  # it was on screen while being built ...
        assert all(alpha == 0.0 for _mapped, alpha in during_build), "... but never visible"
    history = {str(top): [float(top.attributes("-alpha"))] for top in tops}
    end = time.monotonic() + 1.5
    while time.monotonic() < end and any(h[-1] < 1.0 for h in history.values()):
        root.update()
        for top in tops:
            history[str(top)].append(float(top.attributes("-alpha")))
        time.sleep(0.005)
    for top in tops:
        values = history[str(top)]
        assert values[0] == 0.0 and values[-1] == 1.0
        assert values == sorted(values), "opacity only rises: the window appears once"
        top.destroy()


def test_live_report_window_shows_data_age_and_refresh_button(root):
    """Cached data first, 'Refreshing...' while the background refresh runs, then the age and a usable button -
    and none of these states moves anything."""
    from datetime import datetime, timedelta, timezone

    from test_ui import FakeApp

    pressed = []
    finding = Finding(key="age", title="MFA exposure report", severity=Severity.LOW, score=15,
                      fields={"Data as of": "2026-11-10 11:25"},
                      evidence=[{"Account": "a@contoso.com", "Enabled": "yes"}] * 3)
    win = _details(root, FakeApp(), finding, on_refresh=lambda: pressed.append(1))
    age = win.age

    def places():
        root.update()
        widgets = [age.button, age.label, win.info, win.tree]
        return [(w.winfo_rootx(), w.winfo_rooty(), w.winfo_width(), w.winfo_height()) for w in widgets]

    old = datetime.now(timezone.utc) - timedelta(hours=5, minutes=3)
    age.set(old, busy=True)  # opened with cached data, refresh running
    first = places()
    assert not age.pressable and "Refreshing" in str(age.button.cget("text"))
    assert age.text.endswith("(5 h ago)")  # 'refreshing' is said by the button only, not twice
    age.button.invoke()
    assert not pressed  # no second refresh while one is running
    age.set(datetime.now(timezone.utc), busy=False)  # refreshed
    assert age.pressable and str(age.button.cget("text")).strip() == "Refresh"
    assert "(just now)" in age.text and "refreshing" not in age.text
    assert places() == first
    age.button.invoke()
    assert pressed == [1]
    age.set(busy=True, keep_time=True)  # a refresh by button keeps showing the age of what is on screen
    assert "(just now)" in age.text
    age.set(old, busy=False, error="sign-in required " * 20)  # failed: old age, reason, button usable again
    assert "refresh failed: sign-in required" in age.text and age.pressable
    assert places() == first
    win.top.destroy()


def _report(rows=60):
    return Finding(
        key="layout", title="MFA exposure report: 34 excluded from MFA, 158 without MFA registered", score=35,
        severity=Severity.LOW, factors=[(35, "34 accounts excluded from MFA, 158 without any MFA method")],
        summary="34 accounts are excluded from MFA and 158 enabled accounts have no MFA method registered. " * 3,
        fields={"Data as of": "2026-11-10 17:05", "Excluded via": "MFA_Exempt", "Excluded from MFA": "34",
                "No MFA registered": "158", "To review": "187", "Under password attack": "0"},
        recommendation="Block sign-in or set a new long password and register MFA now. Disable unused accounts. " * 3,
        evidence=[{"Account": f"user{i}@contoso.com", "Exposure": "NO MFA registered", "Flags": "never signed in",
                   "Enabled": "yes"} for i in range(rows)])


def _wait(root, seconds=0.4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        time.sleep(0.01)


def test_recommended_action_is_visible_above_a_long_evidence_table(root):
    """The cards get the room they need before the evidence table takes the rest (the table scrolls anyway)."""
    from test_ui import FakeApp

    win = _details(root, FakeApp(), _report())
    _wait(root)
    if win.top.winfo_height() < theme.px(1000):
        win.top.destroy()
        pytest.skip("screen too low for the full-height window")
    assert not win._wide
    info = win.info
    assert info.yview() == (0.0, 1.0), "all cards are visible without scrolling"
    assert "Recommended action" in info.get("1.0", "end")
    assert win._evidence_pane.winfo_height() >= theme.px(250)  # and the evidence keeps a usable size
    win.top.destroy()


def test_wide_window_puts_evidence_beside_the_cards_and_refits_on_resize(root):
    from test_ui import FakeApp

    win = _details(root, FakeApp(), _report())
    _wait(root)
    top = win.top
    screen = top.winfo_screenwidth()
    if screen < theme.px(1900):
        top.destroy()
        pytest.skip("screen too narrow for the wide layout")
    tall_sash = win.paned.sashpos(0)
    top.geometry(f"{theme.px(1880)}x{top.winfo_height()}+0+0")
    _wait(root)
    assert win._wide and str(win.paned.cget("orient")) == "horizontal"
    cards, evidence = win._info_pane, win._evidence_pane
    assert cards.winfo_rooty() == evidence.winfo_rooty() and evidence.winfo_rootx() > cards.winfo_rootx()
    assert theme.px(900) <= cards.winfo_width() <= theme.px(1160)  # a readable column, not the full width
    assert abs(evidence.winfo_height() - win.body.winfo_height()) <= 2  # the table uses the full height
    assert win.info.yview() == (0.0, 1.0) and win.tree.winfo_ismapped() and win.info.winfo_ismapped()
    top.geometry(f"{theme.px(1120)}x{top.winfo_height()}")
    _wait(root)
    assert not win._wide and str(win.paned.cget("orient")) == "vertical"
    assert cards.winfo_rooty() < evidence.winfo_rooty()
    assert abs(win.paned.sashpos(0) - tall_sash) <= 2  # back to the same split as before
    top.destroy()


def test_refresh_button_animates_start_and_end_of_a_refresh(root):
    from datetime import datetime, timezone

    from radar.ui import freshness
    from radar.ui.freshness import DataAge

    top = tk.Toplevel(root)
    theme.set_animations(True)
    age = DataAge(top, lambda: None)
    age.pack()
    if age._photo is None:
        top.destroy()
        pytest.skip("icon font not available")
    assert age.phase == "idle"
    age.set(busy=True)
    assert age.phase == "spinning"
    end = time.monotonic() + 1.0
    while time.monotonic() < end and age.frame < 5:
        root.update()
        time.sleep(0.01)
    assert age.frame >= 5  # the icon turns while the refresh runs
    age.set(datetime.now(timezone.utc), busy=False)
    assert age.phase == "done"  # a check mark confirms the end ...
    end = time.monotonic() + freshness.DONE_MS / 1000 + 1.0
    while time.monotonic() < end and age.phase != "idle":
        root.update()
        time.sleep(0.01)
    assert age.phase == "idle"  # ... and then the normal icon is back
    turned = age.frame
    _wait(root, 0.2)
    assert age.frame == turned  # nothing keeps running
    age.set(busy=True)
    age.set(busy=False, error="sign-in required", keep_time=True)
    assert age.phase == "idle"  # a failed refresh gets no check mark
    theme.set_animations(False)
    age.set(busy=True)
    _wait(root, 0.15)
    assert age.frame == 0  # animations off: the icon does not turn
    age.set(datetime.now(timezone.utc), busy=False)
    assert age.phase == "idle"
    top.destroy()


def test_hand_pointer_over_buttons(root):
    top = tk.Toplevel(root)
    button = ttk.Button(top, text="Dismiss")
    button.pack()
    root.update()
    button.event_generate("<Enter>")
    assert str(button.cget("cursor")) == "hand2"
    button.state(["disabled"])
    button.event_generate("<Enter>")
    assert str(button.cget("cursor")) == ""  # nothing to click
    top.destroy()
