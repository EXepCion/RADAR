"""What answers to the pointer on the Search page and the pages about one thing: scroll areas that take the mouse
wheel wherever the pointer is on them, rows and buttons that show they are under the pointer, and the small
animations with which they do it - which end exactly where they would be without animation."""
import time
import tkinter as tk

import pytest

from radar.ui import theme
from radar.ui.bits import STEPS, Chips, FieldBox, Flow, Glide, Pill, RowGlow, SplitBar, Tag, between, stepped, underline_on_hover, watch_hover
from radar.ui.feed import Feed
from radar.ui.parts import ScrollFrame

from conftest import make_signin
from test_search import AWAY, alert, usual
from test_search_pages import account, page, root  # noqa: F401


def settle(root, ms=450):  # noqa: F811
    """Let what is moving arrive."""
    end = time.monotonic() + ms / 1000
    while time.monotonic() < end:
        root.update()
        time.sleep(0.004)


@pytest.fixture
def host(root):  # noqa: F811
    top = tk.Toplevel(root)
    top.geometry("500x300+20+20")
    theme.set_animations(True)
    yield top
    theme.set_animations(True)
    top.destroy()


# ------------------------------------------------------------------------------------------------ gliding
def test_a_glide_moves_in_steps_and_arrives_exactly_and_is_there_at_once_without_animations(root, host):  # noqa: F811
    seen = []
    glide = Glide(host, seen.append, ms=80)
    glide.to(1)
    settle(root, 250)
    assert seen[-1] == 1.0 and glide.at == 1.0 and len(seen) > 2 and seen == sorted(seen)      # on its way, then exactly there
    seen.clear()
    glide.to(0)
    glide.to(1)                                                                                 # sent back before it arrived
    settle(root, 250)
    assert seen[-1] == 1.0 and glide.at == 1.0
    theme.set_animations(False)
    seen.clear()
    glide.to(0)
    assert seen == [0.0]                                                                        # at once
    glide.to(0)
    assert seen == [0.0]                                                                        # (already there: nothing is drawn)


def test_colours_on_the_way_are_few_and_rest_on_palette_roles(root):  # noqa: F811
    assert between(("card", "menu_hover"), 0) == "card" and between(("card", "menu_hover"), 1) == "menu_hover"
    assert between(("card", "menu_hover", "track"), 2) == "track" and between(("card", "menu_hover", "track"), 7) == "track"
    half = between(("card", "text"), 0.5)
    assert half.startswith("#") and half == theme.mix(theme.color("card"), theme.color("text"), 0.5)
    assert len({between(("card", "text"), i / 100) for i in range(101)}) == STEPS + 1           # (every step of a shape is an image)
    assert stepped(0.49) == 0.5 and stepped(0.01) == 0.0


# ------------------------------------------------------------------------------------------------ the mouse wheel
def test_a_scroll_area_takes_the_wheel_wherever_the_pointer_is_on_it(root, host):  # noqa: F811
    area = ScrollFrame(host)
    area.pack(fill="both", expand=True)
    rows = []
    for i in range(40):
        row = tk.Frame(area.body)
        row.pack(fill="x")
        rows.append(tk.Label(row, text=f"row {i}"))
        rows[-1].pack(side="left")
    tag = Tag(rows[0].master, "new", "warn")
    tag.pack(side="left")
    flow = Flow(area.body)
    flow.add("Canada")
    flow.pack(fill="x")
    own = tk.Text(area.body, height=3)
    own.insert("end", "\n".join(str(i) for i in range(50)))
    own.pack(fill="x")
    root.update()

    def turned(widget, delta=-120):
        before = area.canvas.canvasy(0)
        widget.event_generate("<MouseWheel>", delta=delta)
        settle(root, 260)
        return area.canvas.canvasy(0) - before

    assert turned(rows[3]) == area.NOTCH  # over a label on a row: softly, and exactly one notch far
    assert turned(rows[3].master) > 0     # over the row
    assert turned(tag) > 0                # over a small picture
    assert turned(flow) > 0               # over a list that only flows (it is a text, but nothing in it scrolls)
    assert turned(area.canvas) > 0        # over the bare ground
    assert turned(rows[3], delta=120) < 0
    assert turned(own) == 0               # a text that scrolls by itself keeps the wheel
    assert own.yview()[0] > 0
    # an area whose rows all fit does not move
    small = tk.Toplevel(root)
    try:
        fits = ScrollFrame(small)
        fits.pack(fill="both", expand=True)
        one = tk.Label(fits.body, text="one row")
        one.pack()
        root.update()
        one.event_generate("<MouseWheel>", delta=-120)
        assert fits.canvas.yview()[0] == 0
    finally:
        small.destroy()


def test_the_keyboard_never_chooses_a_row_out_of_view(root, history):  # noqa: F811
    theme.set_animations(False)
    top, app, p = page(root, usual(history), [alert(i, f"Alert {i} about alice@contoso.com") for i in range(1, 6)])
    try:
        p.text.set("alice")
        p.run(wait=True)
        root.update()
        for _ in range(len(p.rows) - 1):
            p._move(1)
        root.update()
        last = p.rows[-1][0].outer
        assert p.selected == len(p.rows) - 1 and p.scroll.canvas.yview()[0] > 0
        assert last.winfo_rooty() + last.winfo_height() <= p.scroll.canvas.winfo_rooty() + p.scroll.canvas.winfo_height() + 1
        for _ in range(len(p.rows)):
            p._move(-1)
        root.update()
        assert p.selected == 0 and p.rows[0][0].outer.winfo_rooty() >= p.scroll.canvas.winfo_rooty() - 1
    finally:
        theme.set_animations(True)
        top.destroy()


def test_a_scroll_area_moves_softly_and_notches_add_up(root, host):  # noqa: F811
    area = ScrollFrame(host)
    area.pack(fill="both", expand=True)
    for i in range(60):
        tk.Label(area.body, text=f"row {i}").pack()
    root.update()
    area.body.event_generate("<MouseWheel>", delta=-120)
    root.update()
    assert 0 <= area.canvas.canvasy(0) < area.NOTCH                # on its way
    area.body.event_generate("<MouseWheel>", delta=-120)           # a second notch before the first has arrived
    settle(root, 320)
    assert area.canvas.canvasy(0) == 2 * area.NOTCH                # both count
    for _ in range(40):
        area.body.event_generate("<MouseWheel>", delta=120)
    settle(root, 320)
    assert area.canvas.canvasy(0) == 0                             # not beyond the beginning
    theme.set_animations(False)
    area.body.event_generate("<MouseWheel>", delta=-120)
    root.update()
    assert area.canvas.canvasy(0) == area.NOTCH                    # at once


def test_letting_go_is_gentler_than_answering_and_half_the_way_takes_half_as_long(root, host):  # noqa: F811
    glide = Glide(host, lambda _t: None, ms=100)
    assert glide.duration(1) == 100
    glide.jump(1)
    assert glide.duration(0) == 200                                # leaving takes longer than arriving
    glide.jump(0.5)
    assert glide.duration(1) == 50 and glide.duration(0) == 100   # from half way: half as long
    glide.jump(0.99)
    assert glide.duration(1) == 40                                 # (never shorter than the eye can follow)


# ------------------------------------------------------------------------------------------------ under the pointer
def test_a_button_darkens_under_the_pointer_and_more_while_pressed(root, host):  # noqa: F811
    done = []
    pill = Pill(host, "Live map", lambda: done.append(1))
    pill.pack()
    root.update()
    pill.event_generate("<Enter>")
    settle(root)
    assert pill._glide.at == 1.0                                 # under the pointer
    pill.event_generate("<Button-1>")
    assert done == [1] and pill._glide.goal == 1.0               # pressed: it does its work, and comes back to "under the pointer"
    settle(root)
    pill.event_generate("<Leave>")
    settle(root)
    assert pill._glide.at == 0.0 and str(pill.cget("cursor")) == "hand2"


def test_the_filter_pills_follow_the_pointer_and_the_fill_moves_to_the_chosen_one(root, host):  # noqa: F811
    told = []
    chips = Chips(host, [("all", "All 63"), ("account", "Accounts 2"), ("signin", "Sign-ins 58")], told.append)
    chips.pack()
    chips.choose("all", tell=False)
    settle(root)
    x = chips._spans[1][1] + 4
    chips.event_generate("<Motion>", x=x, y=5)
    settle(root)
    assert chips._hover == "account" and chips._hovers["account"].at == 1.0 and str(chips.cget("cursor")) == "hand2"
    chips.event_generate("<Button-1>", x=x, y=5)
    assert told == ["account"] and chips.chosen == "account" and chips._was == "all" and chips._pick.at < 1   # on its way
    widths = [b - a for _k, a, b in chips._spans]
    settle(root)
    assert chips._pick.at == 1.0 and [b - a for _k, a, b in chips._spans] == widths       # nothing moved while it changed
    chips.event_generate("<Leave>")
    settle(root)
    assert chips._hover == "" and chips._hovers["account"].at == 0.0


def test_a_field_shows_that_it_has_the_keyboard(root, host):  # noqa: F811
    box = FieldBox(host, 36, "border", width=200, glow=True)
    box.pack()
    entry = tk.Entry(box.inner)
    entry.pack()
    box.watch(entry)
    root.update()
    height = box.winfo_reqheight()
    entry.event_generate("<FocusIn>")
    settle(root)
    assert box.focus_glide.at == 1.0 and box.winfo_reqheight() == height     # the ring has its room already: nothing moves
    entry.event_generate("<FocusOut>")
    settle(root)
    assert box.focus_glide.at == 0.0


def test_rows_of_a_text_light_up_under_the_pointer_with_the_tags_set_into_them(root, host):  # noqa: F811
    text = tk.Text(host, background=theme.color("card"))
    text.pack(fill="both", expand=True)
    glow = RowGlow(text)
    marks = []
    for n in range(3):
        begin = text.index("end-1c")
        text.insert("end", f"line {n}  ")
        if n == 1:
            marks.append(Tag(text, "blocked by policy", "warn", small=True))
            text.window_create("end", window=marks[-1])
        text.insert("end", "\n")
        text.tag_add(f"row{n}", begin, "end-1c")
        glow.add(n, "card", marks if n == 1 else [])
    root.update()
    x, y, _w, h = text.bbox("2.1")
    text.event_generate("<Motion>", x=x, y=y + h // 2)
    settle(root)
    lit = theme.mix(theme.color("card"), theme.color("text"), 0.05)
    assert glow.at == 1 and text.tag_cget("row1", "background") == lit and marks[0]._fill == lit
    x, y, _w, h = text.bbox("1.1")
    text.event_generate("<Motion>", x=x, y=y + h // 2)
    settle(root)
    assert glow.at == 0 and text.tag_cget("row1", "background") == "" and marks[0]._fill == "card" and text.tag_cget("row0", "background") == lit
    text.event_generate("<Motion>", x=x, y=280)      # under the last line: on no row
    settle(root)
    assert glow.at is None and text.tag_cget("row0", "background") == ""


def test_links_underline_and_a_row_knows_when_the_pointer_has_left_it(root, host):  # noqa: F811
    link = tk.Label(host, text="7 more facts", font=theme.FONT_CAPTION)
    link.pack()
    underline_on_hover(link)
    root.update()
    link.event_generate("<Enter>")
    assert str(link.cget("cursor")) == "hand2" and link._lined.actual("underline") == 1
    link.event_generate("<Leave>")
    assert str(link.cget("font")) == theme.FONT_CAPTION
    row = tk.Frame(host)
    row.pack()
    a, b = tk.Label(row, text="a"), tk.Label(row, text="b")
    a.pack(side="left")
    b.pack(side="left")
    seen = []
    watch_hover([row, a, b], seen.append)
    root.update()
    a.event_generate("<Enter>")
    b.event_generate("<Enter>")                       # from one part onto the next: still on the row
    assert seen == [True]
    b.event_generate("<Leave>")                       # (the pointer is not really there: it has left)
    settle(root, 60)
    assert seen == [True, False]


def test_an_underlined_text_is_exactly_as_large_as_it_was_at_every_scale(root, host):  # noqa: F811
    """A link is underlined while the pointer is on it. If the underlined text were a pixel smaller, a pointer resting
    on its last pixels would no longer be on it - it would go back, be under the pointer again, shrink again ... and
    the window would stop answering. (It did, at 150 %: the usual way of copying a font gives it another size.)"""
    import tkinter.font as tkfont

    from radar.ui.bits import underline_on_hover

    text, before = "Toronto, CA 203.0.113.5 Example Hosting", theme._scale
    try:
        for scale in (1.0, 1.25, 1.5, 1.75, 2.0, 2.5):
            theme.set_scale(root, scale)
            for name in (theme.FONT, theme.FONT_BOLD, theme.FONT_CAPTION, theme.FONT_CAPTION_BOLD):
                plain, lined = tkfont.nametofont(name, root=root), theme.underlined(root, name)
                assert (lined.measure(text), lined.metrics("linespace"), lined.cget("size")) == (
                    plain.measure(text), plain.metrics("linespace"), plain.cget("size")), (scale, name)
                assert lined.actual("underline") == 1 and plain.actual("underline") == 0
        theme.set_scale(root, 1.5)                                        # the scale it happened at
        # a link that is a label, underlined under the pointer at the scale it happened at
        link = tk.Label(host, text="7 more facts", font=theme.FONT_CAPTION)
        link.pack()
        underline_on_hover(link)
        root.update()
        size = (link.winfo_reqwidth(), link.winfo_reqheight())
        link.event_generate("<Enter>")
        root.update()
        assert "Underlined" in str(link.cget("font")) and (link.winfo_reqwidth(), link.winfo_reqheight()) == size
    finally:
        theme.set_scale(root, before)
        theme.set_animations(True)


def test_a_bar_runs_in_and_has_round_ends(root, host):  # noqa: F811
    bar = SplitBar(host, [(51, "link"), (1, "warn")])
    bar.pack(fill="x")
    root.update()
    full = bar.bbox("all")
    bar.grow(0)
    assert bar.find_all() == ()
    bar.grow(0.5)
    assert 0 < bar.bbox("all")[2] < full[2]
    bar.grow(1)
    assert bar.bbox("all") == full and len(bar.find_withtag("all")) == 6      # two parts, each: its colour and a round end at either side


# ------------------------------------------------------------------------------------------------ the Movement chart
def movement_chart(root, host, history, width=760):  # noqa: F811
    from radar.ui.lanes import Lanes
    from test_search import travels, view

    told = []
    lanes = Lanes(host, view(travels(history)).movement, on_view=lambda said, end: told.append((said[0], end)))
    lanes.pack(fill="x")
    host.geometry(f"{width}x420")
    root.update()
    return lanes, told


def flick(lanes, x, start, steps=5, step_px=30, step_ms=10, rest_ms=0):
    """Take hold of the chart at ``x``, move it to the right (towards earlier hours) and let go - ``rest_ms`` after the
    last move."""
    c, y = lanes.chart, 60
    c.event_generate("<ButtonPress-1>", x=x, y=y, time=start)
    for n in range(1, steps + 1):
        c.event_generate("<B1-Motion>", x=x + step_px * n, y=y, time=start + step_ms * n)
    c.event_generate("<ButtonRelease-1>", x=x + step_px * steps, y=y, time=start + step_ms * steps + rest_ms)


def test_the_chart_follows_the_pointer_and_rolls_on_when_let_go_while_moving(root, host, history):  # noqa: F811
    lanes, told = movement_chart(root, host, history)
    assert lanes.at_end and lanes.offset == lanes.most > 2 * lanes.stage and told == [(lanes.said, True)]   # it opens on the end: now
    x, start = lanes.stage_x + 200, lanes.offset
    c = lanes.chart
    c.event_generate("<Motion>", x=10, y=60)
    assert str(c.cget("cursor")) == ""                                        # over the names: nothing to move
    c.event_generate("<Motion>", x=x, y=60)
    assert str(c.cget("cursor")) == "fleur"                                   # over the chart: it can be moved
    c.event_generate("<ButtonPress-1>", x=x, y=60, time=1000)
    for n in range(1, 6):
        c.event_generate("<B1-Motion>", x=x + 30 * n, y=60, time=1000 + 10 * n)
    assert lanes.offset == start - 150 and not lanes.at_end and told[-1] == (lanes.said, False)   # it follows the pointer, to the pixel
    c.event_generate("<ButtonRelease-1>", x=x + 150, y=60, time=1060)
    root.update()
    let_go = lanes.offset
    settle(root, 150)
    assert lanes.offset < let_go - 40                                         # let go while moving: it rolls on ...
    settle(root, 1800)
    rolled = lanes.offset
    settle(root, 200)
    assert lanes.offset == rolled and 300 < let_go - rolled < 1200            # ... slows down, and comes to rest by itself
    # held still before letting go: no push
    flick(lanes, x, 5000, rest_ms=200)
    root.update()
    held = lanes.offset
    settle(root, 300)
    assert lanes.offset == held
    # a click stops a roll where it is
    flick(lanes, x, 9000)
    settle(root, 120)
    c.event_generate("<ButtonPress-1>", x=x, y=60, time=9500)
    c.event_generate("<ButtonRelease-1>", x=x, y=60, time=9600)
    stopped = lanes.offset
    settle(root, 300)
    assert lanes.offset == stopped
    # ... and so does the wheel - which turns the chart sideways itself: up towards earlier hours; notches add up
    lanes._go(lanes.most // 2)
    flick(lanes, x, 12000)
    settle(root, 60)
    c.event_generate("<MouseWheel>", delta=120, x=x, y=60)
    c.event_generate("<MouseWheel>", delta=120, x=x, y=60)                    # a second notch before the first has arrived
    turned = lanes._going
    settle(root, 400)
    assert lanes.offset == turned and turned < stopped
    c.event_generate("<MouseWheel>", delta=-120, x=x, y=60)
    settle(root, 300)
    assert lanes.offset == turned + theme.px(100)
    # the arrow keys move it too, once it has the keyboard (a click gives it)
    c.focus_force()
    root.update()
    c.event_generate("<Left>")
    settle(root, 300)
    assert lanes.offset == turned + theme.px(100) - theme.px(40)
    # "Now": back to the end, softly
    lanes.to_end()
    assert not lanes.at_end
    settle(root, 700)
    assert lanes.at_end and lanes.offset == lanes.most and told[-1] == (lanes.said, True) and lanes.said.startswith("the last 24 hours")


def test_without_animations_the_chart_does_not_roll(root, host, history):  # noqa: F811
    lanes, _told = movement_chart(root, host, history)
    theme.set_animations(False)
    flick(lanes, lanes.stage_x + 100, 1000)
    root.update()
    let_go = lanes.offset
    settle(root, 300)
    assert lanes.offset == let_go == lanes.most - 150                         # where the pointer left it, and no further
    lanes.chart.event_generate("<MouseWheel>", delta=120, x=200, y=60)
    assert lanes.offset == let_go - theme.px(100)                             # (at once)
    lanes.to_end()
    assert lanes.at_end


def test_a_devices_name_leads_to_its_page_and_is_underlined_under_the_pointer_without_growing(root, host, history):  # noqa: F811
    """A device's name beside its lane is a link to the device's page: a hand over it, underlined under the pointer -
    in a font exactly as large, at 100 % and at 150 % (where a link that changed its size under the pointer once froze
    the window: see test_an_underlined_text_is_exactly_as_large_as_it_was_at_every_scale). What is not one device - the
    unregistered iPhones, the sign-ins that name none - is no link. A click on a name takes no hold of the chart, and
    taking hold of the chart and letting go over a name is no click on it."""
    from radar.ui.lanes import Lanes
    from test_search import LAPTOP, travels, view

    theme.set_animations(False)
    movement = view(travels(history)).movement
    before = theme._scale
    try:
        for scale in (1.0, 1.5):
            theme.set_scale(root, scale)
            opened = []
            lanes = Lanes(host, movement, on_device=lambda key, name: opened.append((key, name)))
            lanes.pack(fill="x")
            host.geometry("760x420")
            root.update()
            c = lanes.chart
            names = {c.itemcget(i, "text"): i for i in c.find_withtag("name")}
            assert [c.itemcget(i, "text") for i in c.find_withtag("link")] == ["ALICE-LAPTOP"]      # (not "Phone", not "No device")
            link = names["ALICE-LAPTOP"]
            plain = c.bbox(link)
            x, y = (plain[0] + plain[2]) // 2, (plain[1] + plain[3]) // 2
            c.event_generate("<Motion>", x=lanes.stage_x + 100, y=y)
            assert str(c.cget("cursor")) == "fleur"
            c.event_generate("<Motion>", x=x, y=y)                                         # from the chart onto the name
            root.update()
            assert str(c.cget("cursor")) == "hand2" and "Underlined" in c.itemcget(link, "font")
            assert c.bbox(link) == plain, scale                                            # not a pixel larger or smaller
            c.event_generate("<Motion>", x=x, y=y + 1)
            root.update()
            assert c.bbox(link) == plain and "Underlined" in c.itemcget(link, "font")      # (it stays as it is under the pointer)
            c.event_generate("<Motion>", x=lanes.stage_x + 100, y=y)                       # ... and is plain again when it has gone
            root.update()
            assert str(c.cget("cursor")) == "fleur" and c.itemcget(link, "font") == theme.FONT_TABLE_BOLD and c.bbox(link) == plain
            # a click on it: the device's page - and the chart is not taken hold of
            c.event_generate("<Motion>", x=x, y=y)
            c.event_generate("<ButtonPress-1>", x=x, y=y, time=1000)
            assert opened == [(LAPTOP["device_id"], "ALICE-LAPTOP")] and lanes._grab is None
            c.event_generate("<B1-Motion>", x=x + 200, y=y, time=1020)
            c.event_generate("<ButtonRelease-1>", x=x + 200, y=y, time=1040)
            assert lanes.offset == lanes.most                                              # (nothing moved)
            # the chart taken hold of and let go over the name: no click on it
            start = lanes.stage_x + 60
            c.event_generate("<Motion>", x=start, y=y)
            c.event_generate("<ButtonPress-1>", x=start, y=y, time=2000)
            assert lanes._grab is not None
            for n in range(1, 4):
                c.event_generate("<B1-Motion>", x=start - (start - x) * n // 3, y=y, time=2000 + 10 * n)
            assert str(c.cget("cursor")) == "fleur"
            c.event_generate("<ButtonRelease-1>", x=x, y=y, time=2040)
            root.update()
            assert len(opened) == 1 and lanes._grab is None
            # what is no one device: no hand, no underline, no page
            for text in ("Phone", "No device"):
                box = c.bbox(names[text])
                c.event_generate("<Motion>", x=(box[0] + box[2]) // 2, y=(box[1] + box[3]) // 2)
                root.update()
                assert str(c.cget("cursor")) == "" and c.itemcget(names[text], "font") == theme.FONT_TABLE_BOLD
                c.event_generate("<ButtonPress-1>", x=(box[0] + box[2]) // 2, y=(box[1] + box[3]) // 2, time=3000)
                c.event_generate("<ButtonRelease-1>", x=(box[0] + box[2]) // 2, y=(box[1] + box[3]) // 2, time=3010)
                assert len(opened) == 1, text
            lanes.destroy()
    finally:
        theme.set_scale(root, before)
        theme.set_animations(True)


def test_the_chart_draws_what_is_near_the_part_in_view_and_appears_out_of_its_ground(root, host, history):  # noqa: F811
    lanes, _told = movement_chart(root, host, history)
    every = sum(len(lane.runs) for lane in lanes.lanes)
    near = len(lanes.bars())
    assert 0 < near < every                                                   # the days long before are not drawn ...
    oldest = min((run.begin, lane.name) for lane in lanes.lanes for run in lane.runs)
    lanes._go(0)
    root.update()
    assert any(text.startswith(oldest[1]) for text, *_ in lanes.bars()) and lanes.written("day")   # ... until they are in view
    shown = lanes.bars()
    assert all(right >= 0 and left <= lanes.chart.winfo_width() + 2 * lanes.stage for _t, left, right, _f in shown)
    # appearing: from the card's colour to its own
    lanes.appear(0)
    card = theme.color("card")
    names = [i for i in lanes.chart.find_withtag("name")]
    assert {lanes.chart.itemcget(i, "fill") for i in names} == {card} and {f for _t, _l, _r, f in lanes.bars()} == {card}
    lanes.appear(1)
    assert lanes.chart.itemcget(names[0], "fill") == theme.color("text") and {f for _t, _l, _r, f in lanes.bars()} <= {theme.color(r) for r in lanes.role.values()}


# ------------------------------------------------------------------------------------------------ on the pages
def test_the_chosen_hit_is_tinted_softly_and_ends_as_without_animation(root, history):  # noqa: F811
    theme.set_animations(True)
    top, app, p = page(root, usual(history))
    try:
        p.text.set("alice")
        p.run(wait=True)
        root.update()
        first, second = p.rows[0][0], p.rows[1][0]
        chosen, ground = theme.color("new_row"), theme.color("card")
        assert first.cget("background") == chosen and second.cget("background") == ground          # it appears chosen: nothing moves
        p._move(1)
        assert p.selected == 1 and second.cget("background") != chosen                              # on its way
        settle(root)
        assert second.cget("background") == chosen and first.cget("background") == ground
        assert all(w.cget("background") == chosen for w in second.parts) and second.arrow.cget("foreground") == theme.color("link")
        assert first.arrow.cget("foreground") == ground
    finally:
        top.destroy()


def test_a_row_unfolds_where_it_stands_and_what_unfolds_comes_out_of_its_ground(root, history):  # noqa: F811
    theme.set_animations(True)
    top, app, p, _went = account(root, usual(history, days=25))
    try:
        settle(root)
        feed = p.feed
        row = next(r for r in p.rows if r.line.ref == ("signin", "away-ok"))
        index = feed.items.index(row)
        p.feed.canvas.yview_moveto(0.2)
        root.update()
        place, tops = feed.canvas.canvasy(0), list(feed.tops)
        assert place > feed.tops[index] + feed.heights[index]                                  # the row is above what is in view
        p._fold(row.line)
        root.update()
        grown = feed.heights[index] - (tops[index + 1] - tops[index])
        assert grown > 0 and row.detail is not None and row.arrow() == "\u2304"
        assert feed.tops[:index + 1] == tops[:index + 1] and feed.tops[index + 1] == tops[index + 1] + grown   # what is under it made room
        assert feed.canvas.canvasy(0) == place + grown                                         # ... and the reader is where they were
        assert row.colour_of("value") != theme.color("text")                                   # coming out of its ground
        settle(root)
        assert row.colour_of("value") == theme.color("text")
        feed.canvas.yview_moveto(0)
        root.update()
        assert "How\tPassword" in p.written()
        p._fold(row.line)
        root.update()
        assert row.detail is None and row.arrow() == "\u203a" and "How\tPassword" not in p.written() and feed.tops[index + 1] == tops[index + 1]
    finally:
        top.destroy()


def test_the_timeline_goes_on_as_it_is_scrolled_and_only_what_is_near_is_drawn(root, history):  # noqa: F811
    theme.set_animations(False)
    spread = [make_signin(-(d * 1440) - 600 + i * 7, **AWAY, app=f"App {d}-{i}", id=f"x{d}-{i}") for d in range(1, 29) for i in range(12)]
    usual(history).add(spread)
    top, app, p, _went = account(root, history)
    try:
        root.update()
        feed = p.feed
        everything = len(feed.items)
        assert everything > 300 and len(feed.tops) < everything // 3                             # laid out only as far as it is looked at
        assert "The list goes on as you scroll" in p.written()
        most = 0
        for _ in range(400):                                                                      # scrolled to its end, again and again
            feed.canvas.yview_moveto(1.0)
            root.update()
            most = max(most, len(feed.drawn))
            if len(feed.tops) == everything:
                break
        assert len(feed.tops) == everything and "The list goes on" not in p.written()
        assert most < 120 and 0 not in feed.drawn                                                 # however long the list: what is far is not drawn
        last = feed.items[-1]
        assert last in p.rows and feed.end == feed.tops[-1] + feed.heights[-1]
        feed.canvas.yview_moveto(0)                                                               # ... and back at the beginning it is there again
        root.update()
        assert 0 in feed.drawn and len(feed.items) - 1 not in feed.drawn
        p.filters.choose("Failed")
        root.update()
        assert feed.canvas.canvasy(0) == 0 and all(r.line.kind == "Failed" for r in p.rows)     # another list: from its beginning
    finally:
        theme.set_animations(True)
        top.destroy()


def test_the_timeline_takes_the_wheel_softly(root, history):  # noqa: F811
    theme.set_animations(True)
    top, app, p, _went = account(root, usual(history, days=25))
    try:
        settle(root)
        feed = p.feed
        feed.canvas.event_generate("<MouseWheel>", delta=-120)
        feed.canvas.event_generate("<MouseWheel>", delta=-120)       # a second notch before the first has arrived: both count
        settle(root, 350)
        assert feed.canvas.canvasy(0) == 2 * feed.NOTCH and p.summary.canvas.canvasy(0) == 0     # (and nothing else scrolled with it)
        for _ in range(8):
            feed.canvas.event_generate("<MouseWheel>", delta=120)
        settle(root, 350)
        assert feed.canvas.canvasy(0) == 0
    finally:
        top.destroy()


def test_what_runs_in_when_a_page_appears_ends_where_it_belongs(root, history):  # noqa: F811
    theme.set_animations(True)
    top, app, p, _went = account(root, usual(history), [alert(1, "Sign-in from a new country: Brazil")])
    try:
        settle(root, 600)
        assert p.risk.cget("text") == "55" and p._grown == 1.0 and p.lanes.seen == 1.0
        p._grow(0.5)
        assert p.risk.cget("text") == "55" and all(bar.shown == 0.5 for bar in p.splits)   # (a number never reads something it is not)
        p._grow(1)
    finally:
        top.destroy()


def test_what_is_written_on_a_page_comes_out_of_its_ground_and_ends_exactly_as_it_is(root, history):  # noqa: F811
    from radar.ui.account import AccountPage
    from test_search_pages import FakeApp

    def colours(page):
        seen = []

        def walk(w):
            for x in w.winfo_children():
                if isinstance(x, tk.Label):
                    seen.append(str(x.cget("foreground")))
                elif isinstance(x, Tag):
                    seen.append(getattr(x, "_seen", 1.0))
                elif isinstance(x, Feed):
                    seen.extend([x.seen] + [str(x.canvas.itemcget(i, "fill")) for i in x.canvas.find_all() if x.canvas.type(i) == "text"])
                walk(x)

        walk(page.panes)
        return seen

    usual(history)

    def opened(moving):
        theme.set_animations(moving)
        top = tk.Toplevel(root)
        top.geometry("1196x780")
        page = AccountPage(root, FakeApp(history, [alert(1, "Sign-in from a new country: Brazil")]), top, "u1",
                           on_back=lambda: None, on_search=lambda t: None, background=False)
        page.top.pack(fill="both", expand=True)
        return top, page, colours(page)       # (as it is the moment it is complete - before anything is drawn)

    still_top, still, _at_rest = opened(False)
    top, p, at_first = opened(True)
    try:
        assert p.title.cget("foreground") == theme.color("card") and p.feed.seen < 0.05                 # not to be seen yet
        settle(root, 700)
        alert_row = next(r for r in p.rows if r.line.kind == "Alert")
        assert alert_row.ground() == theme.color("alert_bg") and alert_row.colour_of("title") == theme.color("text") and p.marks
        assert colours(p) == colours(still) and at_first != colours(p)                                  # exactly as without animation
        assert p.title.cget("foreground") == theme.color("text") and p.feed.seen == 1.0
    finally:
        theme.set_animations(True)
        top.destroy()
        still_top.destroy()


def test_what_can_be_clicked_on_a_page_answers_to_the_pointer(root, history):  # noqa: F811
    theme.set_animations(True)
    top, app, p, _went = account(root, usual(history), [alert(1, "Sign-in from a new country: Brazil")])
    try:
        settle(root)
        assert p.splits and all(bar.shown == 1.0 for bar in p.splits)                                   # the bars have run in
        row = next(w for w in p.worth_card.winfo_children() if isinstance(w, tk.Frame) and str(w.cget("cursor")) == "hand2")
        words = next(w for w in row.winfo_children()[-1].winfo_children() if isinstance(w, tk.Label))
        row.event_generate("<Enter>")
        settle(root)
        assert words.cget("foreground") == theme.color("link")
        row.event_generate("<Leave>")
        settle(root)
        assert words.cget("foreground") == theme.color("text")
        line = next(r for r in p.rows if r.marks)                                                    # a row with a small tag set into it
        lit = theme.mix(theme.color("card"), theme.color("text"), 0.05)
        canvas = p.feed.canvas
        x, y = line.spot()
        canvas.event_generate("<Motion>", x=x, y=y)
        settle(root)
        assert line.ground() == lit and line.colour_of("fill") == lit
        assert line.colour_of("arrow") == theme.color("text")                                        # its arrow comes forward with it
        other = next(r for r in p.rows if r is not line)
        x, y = other.spot()
        canvas.event_generate("<Motion>", x=x, y=y)                                                  # on to another row: this one lets go
        settle(root)
        assert line.ground() == theme.color("card") and line.colour_of("arrow") == theme.color("muted") and other.ground() == lit
        canvas.event_generate("<Leave>")
        settle(root)
        assert other.ground() == theme.color("card")
        # a row is one shape with round corners: a smooth quarter in each corner, the colour between them
        assert len(canvas.find_withtag(f"{line.tag}&&corner")) == 4 and len(canvas.find_withtag(f"{line.tag}&&fill")) == 2
        # ... and what it names can be clicked
        n = len(app.opened)
        line.click("203.0.113.5")
        assert app.opened[n:] == [("address", "203.0.113.5")] and str(canvas.cget("cursor")) == "hand2"
        line.click(line.what)
        assert app.opened[-1][0] == "signin"
    finally:
        top.destroy()
