"""The card table: rows drawn on a card, with the part of the Treeview interface the pages use."""
from datetime import datetime

from test_ui import root  # noqa: F401  (the Tk fixture)

from radar.ui import theme
from radar.ui.cardtable import CardTable, friendly_time
from radar.ui.tables import make_sortable


def settle(root, n=6):  # noqa: F811
    for _ in range(n):
        root.update()


def test_times_are_written_the_way_one_reads_them():
    now = datetime(2026, 11, 12, 18, 0)
    assert friendly_time("2026-11-12 13:48", now) == "Today 13:48"
    assert friendly_time("2026-11-11 09:20", now) == "Yesterday 09:20"
    assert friendly_time("2026-11-03 07:05", now) == "03.11. 07:05"
    assert friendly_time("2025-12-31 23:59", now) == "31.12.2025 23:59"
    assert friendly_time("", now) == "" and friendly_time("never", now) == "never"   # what is no time stays as it is


def test_rows_selection_and_sorting_work_like_the_table_it_replaces(root):  # noqa: F811
    cols = ["When", "Severity", "State", "Count"]
    table = CardTable(root, cols, selectmode="extended", height=3)
    table.pack(fill="both", expand=True)
    for c in cols:
        table.heading(c, text=c, anchor="w")
        table.column(c, width=theme.px(120), stretch=c == "Count", anchor="w")
    table.pill("Severity")
    table.cell_role("State", lambda value, _tags: "error" if value == "open" else "muted")
    table.show_as("When")
    told = []
    table.bind("<<TreeviewSelect>>", lambda _e: told.append(table.selection()))
    for i, (when, sev, state, n) in enumerate([("2026-11-10 10:00", "High", "open", 12), ("2026-11-09 08:00", "Low", "dismissed", 3),
                                               ("2026-11-11 07:30", "Medium", "open", 101)]):
        table.insert("", "end", iid=f"r{i}", values=[when, sev, state, n], tags=(state,))
    settle(root)
    assert table.get_children("") == ("r0", "r1", "r2") and table["columns"] == tuple(cols)
    assert table.set("r1", "Severity") == "Low" and table.item("r2", "values")[3] == "101" and table.item("r0", "tags") == ("open",)
    assert table.set("r0", "When") == "2026-11-10 10:00" and table.shown_text("r0", "When") == "10.11. 10:00"

    # sorting by a column works on the values, numbers as numbers; the arrow goes into the heading
    sort = make_sortable(table, cols)
    sort("Count")
    assert table.get_children("") == ("r1", "r0", "r2") and table.heading("Count", "text") == "Count ▲"
    sort("Count")
    assert table.get_children("") == ("r2", "r0", "r1")

    # selection: set, tell once (afterwards, never in the middle), see, and rows that go take their selection along
    table.selection_set("r0")
    table.selection_set(["r0", "r1"])
    assert told == []
    settle(root)
    assert told == [("r0", "r1")] and table.selection() == ("r0", "r1")
    table.see("r1")
    table.delete("r1")
    settle(root)
    assert table.selection() == ("r0",) and not table.exists("r1") and told[-1] == ("r0",)

    # where the pointer is: rows from top to bottom, columns as "#n"; a click selects, Ctrl adds
    settle(root)
    row_h = table._row_h
    assert table.identify_row(2) == "r2" and table.identify_row(row_h + 2) == "r0" and table.identify_row(10 * row_h) == ""
    assert table.identify_column(theme.px(130)) == "#2"
    from types import SimpleNamespace

    table._click(SimpleNamespace(x=5, y=2, state=0))
    settle(root)
    assert table.selection() == ("r2",)
    table._click(SimpleNamespace(x=5, y=row_h + 2, state=0x4))
    settle(root)
    assert table.selection() == ("r2", "r0")

    # colours given for tags follow a switch between light and dark
    table.tag_configure("dismissed", foreground=theme.LIGHT["muted"])
    table.recolor_colors(theme.color_map(theme.LIGHT, theme.DARK))
    assert table.tag_configure("dismissed", "foreground") == theme.DARK["muted"]

    # "browse": one row at a time
    single = CardTable(root, ["A"], selectmode="browse")
    single.insert("", "end", iid="x", values=["1"])
    single.insert("", "end", iid="y", values=["2"])
    single.selection_set(["x", "y"])
    assert single.selection() == ("x",)
    single.destroy()
    table.destroy()


def test_the_pointer_over_the_heading_finds_the_column_edges(root):  # noqa: F811
    table = CardTable(root, ["A", "B"], height=2)
    table.column("A", width=100)
    assert table._column_edge(100) == "A" and not table._column_edge(50)  # (dragging there changes the width)
