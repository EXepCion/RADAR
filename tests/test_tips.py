"""Wherever a text is cut off ("…"), the whole of it can be read by pointing at it: a small note under the pointer.
That is a rule of the whole app; here it is checked for the pages that draw their texts themselves - the search, the
timeline, the Movement card - and for the note itself."""
import tkinter as tk

import pytest

from radar.ui import theme
from radar.ui.feed import Day, Feed, Row
from radar.ui.parts import Tips
from radar.ui.lanes import Lanes

from conftest import make_signin
from test_search import HOME, usual
from test_search_pages import page, root  # noqa: F401

ELLIPSIS = "…"


@pytest.fixture
def host(root):  # noqa: F811
    top = tk.Toplevel(root)
    top.geometry("420x300+20+20")
    theme.set_animations(False)
    yield top
    theme.set_animations(True)
    top.destroy()


def note_of(tips, root):  # noqa: F811
    """What the note says that is due now (shown at once, without the wait)."""
    tips.hint.show()
    root.update()
    tip = tips.hint._tip
    text = tip.winfo_children()[0].cget("text") if tip is not None else ""
    tips.hint.hide()
    return text


def point_at(canvas, item, root):  # noqa: F811
    x0, y0, x1, y1 = canvas.bbox(item)
    canvas.event_generate("<Motion>", x=(x0 + x1) // 2, y=(y0 + y1) // 2 - int(canvas.canvasy(0)))
    root.update()


def test_the_note_shows_the_whole_text_of_the_part_under_the_pointer_and_goes_with_it(root, host):  # noqa: F811
    canvas = tk.Canvas(host, width=300, height=100)
    canvas.pack()
    tips = Tips(canvas)
    short = canvas.create_text(10, 10, text="A long te" + ELLIPSIS, anchor="nw")
    other = canvas.create_text(10, 50, text="all of it", anchor="nw")
    clicked = []
    canvas.tag_bind(short, "<Enter>", lambda _e: clicked.append("entered"))          # what else is bound to it stays bound
    tips.add(short, "A long text that did not fit")
    root.update()
    point_at(canvas, short, root)
    assert clicked == ["entered"] and tips.hint._due is not None                      # it waits a moment, then:
    assert note_of(tips, root) == "A long text that did not fit"
    point_at(canvas, short, root)
    tips.hint.show()
    assert tips.hint._tip is not None
    point_at(canvas, other, root)                                                     # the pointer moves on: the note goes
    assert tips.hint._tip is None and tips.hint._due is None
    point_at(canvas, short, root)
    canvas.event_generate("<ButtonPress-1>", x=12, y=12)                              # ... and with a click
    assert tips.hint._due is None
    tips.clear()
    assert tips.whole == {}


def test_what_is_cut_on_the_movement_card_and_what_a_bar_stands_for_can_be_read_by_pointing_at_it(root, host, history):  # noqa: F811
    from radar import timefmt
    from test_search import DEVICE_SIGNIN, LAPTOP, travels, view

    long_name = "ALICE-LAPTOP-WITH-A-REMARKABLY-LONG-NAME-0042"
    travels(history).add([make_signin(-10, **HOME, **{**LAPTOP, "device_name": long_name}, **DEVICE_SIGNIN)])
    opened = []
    lanes = Lanes(host, view(history).movement, on_device=lambda key, name: opened.append((key, name)))
    lanes.pack(fill="x")
    root.update()
    name = lanes.chart.find_withtag("name")[0]                       # a device's name too long for its column: cut ...
    assert lanes.chart.itemcget(name, "text").endswith(ELLIPSIS) and lanes.tips.whole[name] == long_name
    point_at(lanes.chart, name, root)
    assert note_of(lanes.tips, root) == long_name                     # ... and whole under the pointer
    # ... and still a link to the device's page: underlined under the pointer, and a click opens the page it names whole
    assert name in lanes.chart.find_withtag("link") and "Underlined" in lanes.chart.itemcget(name, "font")
    point_at(lanes.chart, name, root)
    lanes.tips.hint.show()
    root.update()
    assert lanes.tips.hint._tip is not None
    x0, y0, x1, y1 = lanes.chart.bbox(name)
    lanes.chart.event_generate("<ButtonPress-1>", x=(x0 + x1) // 2, y=(y0 + y1) // 2)
    root.update()
    assert opened == [(LAPTOP["device_id"], long_name)] and lanes.tips.hint._tip is None   # (the note goes with the click)
    fits = lanes.chart.find_withtag("name")[1]
    assert lanes.chart.itemcget(fits, "text") == "work computer, managed" and fits not in lanes.tips.whole
    # a bar: which device, which place, from when until when (with the zone) and through which network
    lanes._go(lanes.offset - lanes.stage // 2)
    root.update()
    c, inside = lanes.chart, (lanes.stage_x + 10, lanes.chart.winfo_width() - 60)
    tag = next(t for t in lanes._bar_text if inside[0] < sum(c.bbox(t)[::2]) / 2 < inside[1])
    point_at(c, tag, root)
    said = note_of(lanes.tips, root)
    assert said == lanes._bar_text[tag] and said.startswith(long_name + " · ")
    assert timefmt.unzoned(said.replace(" – ", " UTC – ")) == []        # (from - until: the zone once, at the end)
    assert said.split(" · ")[1] in {p.label for p in lanes.places} and said.endswith("Example Telecom")


def test_what_is_cut_in_a_timeline_row_can_be_read_by_pointing_at_it(root, host):  # noqa: F811
    feed = Feed(host)
    feed.pack(fill="both", expand=True)
    pieces = [("Sign-in", "muted", False, None), (" · ", "muted", False, None), ("Somebody With A Very Long Name Indeed", "link", False, lambda: None),
              (" · A place with a long name, CA · ", "muted", False, None), ("198.51.100.10", "link", False, lambda: None)]
    row = Row("13:03", "neg", "Office 365", [], pieces, on_title=lambda: None)
    feed.set([Day("Today"), row])
    root.update()
    second = feed.canvas.find_withtag(f"{row.tag}&&second")
    shown = "".join(feed.canvas.itemcget(i, "text") for i in second)
    assert shown.endswith(ELLIPSIS) and shown != row.second()
    assert second and all(feed.tips.whole[i] == row.second() for i in second)     # anywhere on the line: the whole line
    point_at(feed.canvas, second[0], root)
    assert note_of(feed.tips, root) == row.second()
    host.geometry("1400x300")
    root.update()
    second = feed.canvas.find_withtag(f"{row.tag}&&second")
    assert "".join(feed.canvas.itemcget(i, "text") for i in second) == row.second() and not any(i in feed.tips.whole for i in second)


def test_what_is_cut_in_the_search_results_can_be_read_by_pointing_at_it(root, history):  # noqa: F811
    theme.set_animations(False)
    usual(history)
    long_app = "An application with a remarkably long name that goes on and on " * 3
    history.add([make_signin(10, **HOME, app=long_app.strip(), id="long", device_name="ALICE-LAPTOP-WITH-A-LONG-NAME")])
    top, app, p = page(root, history)
    try:
        p.text.set("remarkably")
        p.run(wait=True)
        root.update()
        line = next(w for row, _f in p.rows for w in row.parts if getattr(w, "whole", "").startswith("alice@contoso.com"))
        assert line.cut and line.hint._text_of() == line.whole and long_app.strip() in line.whole     # a hit that is cut: all of it
        short = next(w for row, _f in p.rows for w in row.parts if getattr(w, "whole", "") and not w.cut)
        assert short.hint._text_of() == ""                                                              # one that is not: no note
        # ... and in the table of all sign-ins, cell by cell
        p.filters.choose("signin")
        root.update()
        cut = {what: whole for what, whole in p.table_tips.whole.items()}
        assert any(str(what).startswith("open") and long_app.strip() in whole for what, whole in cut.items())
        table = p.table.get("1.0", "end")
        assert ELLIPSIS in table and long_app.strip() not in table
    finally:
        theme.set_animations(True)
        top.destroy()


def test_a_reason_is_not_cut_where_it_is_made():
    """What a failed sign-in failed with is shortened where it is shown (and can be read whole there) - never before."""
    from radar import search

    reason = "The user or administrator has not consented to use the application with ID and name given here, " * 2
    assert search._why_failed(make_signin(0, error_code=65001, failure_reason=reason)) == reason.strip().rstrip(".")
