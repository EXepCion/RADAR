"""The right-click menu in the app's own look: groups, rows, keyboard, closing, staying on the screen."""
import tkinter as tk

from test_ui import root  # noqa: F401  (the Tk fixture)

from radar.ui import theme
from radar.ui.menu import ContextMenu, icon_for


def groups(ran):
    return [("203.0.113.77", [("IP reputation (AbuseIPDB)", lambda: ran.append("abuse")),
                               ("Copy  203.0.113.77", lambda: ran.append("copy"))]),
            ("This row", [("View sign-in log entry", lambda: ran.append("view"))])]


def test_menu_shows_groups_and_runs_an_action_after_closing(root):  # noqa: F811
    ran = []
    menu = ContextMenu(root, groups(ran), 200, 200)
    root.update()
    assert menu.exists() and menu.top.overrideredirect()          # a borderless window of our own, not a Tk menu
    assert menu.labels == ["IP reputation (AbuseIPDB)", "Copy  203.0.113.77", "View sign-in log entry"]
    assert menu.titles == ["203.0.113.77", "This row"]
    assert str(menu.top.cget("background")) == theme.color("border")
    # one canvas draws it all: no widget per row that could flicker or vanish while the mouse moves
    assert [w.winfo_class() for w in menu.top.winfo_children()] == ["Canvas"] and not menu.canvas.winfo_children()
    assert menu.active == -1 and menu.highlight_box() is None
    spans = menu._spans
    assert len(spans) == 3 and all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))   # rows below each other, no overlap
    drawn = len(menu.canvas.find_all())
    for y_row, expected in ((spans[0][0] + 3, 0), (spans[1][0] + 3, 1), (spans[2][0] + 3, 2), (spans[1][1] - 1, 1), (spans[0][0] + 3, 0)):
        menu._highlight(menu.row_at(y_row))                         # what the mouse moving onto that row does
        root.update()
        assert menu.active == expected
        box = menu.highlight_box()
        assert box[1] <= spans[expected][0] + 1 and box[3] >= spans[expected][1] - 1   # the highlight is behind that row
        assert len(menu.canvas.find_all()) == drawn                 # nothing is created or removed while hovering
        assert [menu.canvas.itemcget(i, "state") for i in menu.canvas.find_all()].count("hidden") == 0
    menu._highlight(menu.row_at(spans[1][1] + 3))                 # on the line between the groups: no row
    root.update()
    assert menu.active == -1 and menu.highlight_box() is None
    menu._move(1)                                                 # arrow down: the first row
    menu._move(1)                                                 # ... the second
    assert menu.active == 1
    menu._run(menu._active)                                       # Enter
    assert not menu.exists() and ran == []                        # closed first ...
    root.update()
    root.after(5, lambda: None)
    for _ in range(5):
        root.update()
    assert ran == ["copy"]                                        # ... then the action runs
    menu.close()                                                  # closing twice does nothing


def test_one_group_has_no_title_and_escape_closes(root):  # noqa: F811
    ran = []
    menu = ContextMenu(root, [("only", [("Copy  x", lambda: ran.append(1))])], 100, 100)
    root.update()
    assert menu.titles == [] and menu.labels == ["Copy  x"]
    menu.top.event_generate("<Escape>")
    root.update()
    assert not menu.exists() and ran == []
    assert icon_for("Copy  x") == "copy" and icon_for("View sign-in log entry") == "open"


def test_menu_stays_on_the_screen(root):  # noqa: F811
    w, h = root.winfo_screenwidth(), root.winfo_screenheight()
    menu = ContextMenu(root, groups([]), w - 5, h - 5)            # asked for in the bottom right corner
    root.update()
    try:
        x, y = menu.top.winfo_rootx(), menu.top.winfo_rooty()
        assert x + menu.top.winfo_width() <= w and y + menu.top.winfo_height() <= h and x >= 0 and y >= 0
    finally:
        menu.close()


def test_links_open_the_new_menu(root):  # noqa: F811
    from types import SimpleNamespace

    from radar.ui.richtext import LinkHandler

    ran = []
    holder = tk.Frame(root)
    handler = LinkHandler(SimpleNamespace(), holder, SimpleNamespace(show=lambda *a, **k: None))
    event = SimpleNamespace(x_root=150, y_root=150)
    assert handler.popup(event, [("x", [])]) is None              # nothing to offer: no menu
    first = handler.popup(event, [("x", [("Copy  x", lambda: ran.append(1))])])
    assert isinstance(first, ContextMenu) and first.exists()
    second = handler.popup(event, [("y", [("Copy  y", lambda: ran.append(2))])])
    assert not first.exists() and second.exists()                 # one menu at a time
    second.invoke("Copy  y")
    for _ in range(5):
        root.update()
    assert ran == [2]
    holder.destroy()
