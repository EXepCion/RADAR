"""Click-to-sort for ttk.Treeview tables (click a header; click again to reverse)."""
from __future__ import annotations

import re
from tkinter import ttk
from typing import Callable

ASC, DESC = " ▲", " ▼"
_NUMBER = re.compile(r"[-+]?\d+(?:\.\d+)?")


def sort_key(value: str) -> tuple:
    """Numbers sort numerically and before text; everything else case-insensitively (ISO dates sort correctly)."""
    text = (value or "").strip()
    compact = text.replace("'", "").replace(",", "").replace(" ", "")
    if _NUMBER.fullmatch(compact):
        return (0, float(compact), "")
    return (1, 0.0, text.lower())


def make_sortable(tree: ttk.Treeview, columns: list[str], labels: dict[str, str] | None = None) -> Callable[[str], None]:
    """Make every column header sortable. Returns the sort function (column -> None), e.g. for tests."""
    labels = labels or {}
    state = {"col": None, "desc": False}

    def sort(col: str) -> None:
        desc = state["col"] == col and not state["desc"]
        items = [(tree.set(iid, col), iid) for iid in tree.get_children("")]
        items.sort(key=lambda x: sort_key(x[0]), reverse=desc)
        for index, (_, iid) in enumerate(items):
            tree.move(iid, "", index)
        state.update(col=col, desc=desc)
        for c in columns:
            arrow = (DESC if desc else ASC) if c == col else ""
            tree.heading(c, text=labels.get(c, c) + arrow)

    def reapply() -> None:
        """Sort again by the column the user chose (after the rows were reloaded)."""
        if state["col"] is not None:
            state["desc"] = not state["desc"]  # sort() toggles the direction of the current column
            sort(state["col"])

    sort.reapply = reapply  # type: ignore[attr-defined]
    for c in columns:
        tree.heading(c, command=lambda c=c: sort(c))
    return sort
