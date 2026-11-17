"""A table drawn on a card: a line under every row, cells that can have their own colour or be a pill.

ttk.Treeview colours whole rows only and cannot draw a pill or a line between rows. This table draws its rows itself
(only the ones that are visible, so thousands of rows cost nothing) and offers the part of the Treeview interface the
pages use - insert, delete, set, item, selection, see, heading, column, tag_configure, identify_row - so sorting
(tables.make_sortable) and the right-click menu work with it unchanged. It tells a change of selection the same way:
``<<TreeviewSelect>>``.
"""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timedelta
from tkinter import ttk
from typing import Any, Callable

from .. import timefmt
from . import theme
from .rounded import Rounded, rounded_image
from .theme import px

ROW, HEAD, PAD = 36, 36, 12
ELLIPSIS = "…"


def friendly_time(value: str, now: datetime | None = None) -> str:
    """'2026-11-12 17:28 UTC+1' (timefmt.sortable) as one reads it: 'Today 17:28 UTC+1', 'Yesterday 17:28 UTC+1',
    '10.11. 17:28 UTC+1' ('10.11.2025 17:28 UTC+1'). A value without its zone gets the local one of that day."""
    try:
        when = datetime.strptime(str(value)[:16], timefmt.SORTABLE)
    except (TypeError, ValueError):
        return value
    zone = str(value)[16:].strip() or timefmt.zone(when.astimezone())
    today = (now or datetime.now()).date()
    clock = f"{when.hour:02d}:{when.minute:02d} {zone}"
    if when.date() == today:
        return f"Today {clock}"
    if when.date() == today - timedelta(days=1):
        return f"Yesterday {clock}"
    return f"{when.day:02d}.{when.month:02d}." + (" " if when.year == today.year else f"{when.year} ") + clock


def severity_pill(value: str) -> tuple[str, str] | None:
    """Palette roles (background, text) of a severity shown as a pill."""
    return theme.severity_roles(value) if value else None


class CardTable(Rounded):
    def __init__(self, parent: tk.Misc, columns: list[str], selectmode: str = "browse", height: int = 0,
                 xscroll: bool = False, border: bool = True, row_height: int = ROW):
        c = theme.color
        super().__init__(parent, rounded=border)  # (without a border it is part of a card that has the round corners)
        self._images: dict[str, Callable[[str], Any]] = {}
        self._action: tuple[str, Callable[[str], None]] | None = None
        self.columns = list(columns)
        self._cols: dict[str, dict[str, Any]] = {
            name: {"text": name, "width": px(120), "stretch": False, "anchor": "w", "command": None} for name in columns}
        self._rows: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._sel: list[str] = []
        self._focus, self._anchor, self._hover = "", "", ""
        self._tags: dict[str, dict[str, str]] = {}
        self._roles: dict[str, Callable[[str, tuple], str | None]] = {}
        self._pills: dict[str, Callable[[str], tuple[str, str] | None]] = {}
        self._shows: dict[str, Callable[[str], str]] = {}
        self._mode = selectmode
        self._row_h, self._head_h, self._pad = px(row_height), px(HEAD), px(PAD)
        self._notes: dict[str, Callable[[str], str]] = {}  # column -> a second, smaller line under its text
        self._drawn: Callable[[], None] | None = None      # told whenever the rows were drawn (scrolled, selected ...)
        self._tip: tk.Toplevel | None = None               # the whole text of a shortened cell, under the pointer
        self._tip_job: str | None = None
        self._tip_cell: tuple[str, str] = ("", "")
        self._x = self._y = 0          # how far the rows are scrolled, in pixels
        self._auto = 0                 # ids given to rows inserted without one
        self._backs: dict[str, int] = {}   # visible row -> its background rectangle
        self._cut: dict[tuple, str] = {}   # (text, width, bold) -> text shortened to fit
        self._draw_job: str | None = None
        self._tell_job: str | None = None
        self._drag: tuple[str, int, int] | None = None  # column being resized: (name, pointer x at start, width at start)
        self._font = tkfont.nametofont(theme.FONT_TABLE, root=self)
        self._bold = tkfont.nametofont(theme.FONT_TABLE_BOLD, root=self)
        self._plain = tkfont.nametofont(theme.FONT, root=self)  # the font of buttons
        self._over_action = ""  # the row whose button the pointer is on

        self.head = tk.Canvas(self, height=self._head_h, background=c("card"), highlightthickness=0, bd=0)
        self.body = tk.Canvas(self, background=c("card"), highlightthickness=0, bd=0, takefocus=1,
                              height=(height or 4) * self._row_h, width=px(200))
        self.ybar = ttk.Scrollbar(self, orient="vertical", command=self.yview)
        self.head.grid(row=0, column=0, sticky="ew")
        self.body.grid(row=1, column=0, sticky="nsew", pady=(0, px(5)))
        self.ybar.grid(row=1, column=1, sticky="ns", padx=(px(2), px(3)), pady=(px(4), px(6)))
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, minsize=self.ybar.winfo_reqwidth() + px(5))  # its place is kept: the columns never move
        self.rowconfigure(1, weight=1)
        self.xbar: ttk.Scrollbar | None = None
        if xscroll:
            self.xbar = ttk.Scrollbar(self, orient="horizontal", command=self.xview)
            self.xbar.grid(row=2, column=0, sticky="ew")
            self.rowconfigure(2, minsize=self.xbar.winfo_reqheight())

        body, head = self.body, self.head
        body.bind("<Configure>", lambda _e=None: self._redraw())
        body.bind("<Button-1>", self._click)
        body.bind("<Motion>", self._motion)
        body.bind("<Leave>", lambda _e=None: (self._set_hover(""), self._leave_action(), self._hide_tip()))
        body.bind("<ButtonPress>", lambda _e=None: self._hide_tip(), add="+")
        body.bind("<MouseWheel>", lambda e: self.yview("scroll", -1 if e.delta > 0 else 1, "wheel"))
        body.bind("<Shift-MouseWheel>", lambda e: self.xview("scroll", -1 if e.delta > 0 else 1, "wheel"))
        for key, step in (("<Up>", -1), ("<Down>", 1), ("<Prior>", -10), ("<Next>", 10), ("<Home>", -10 ** 9),
                          ("<End>", 10 ** 9)):
            body.bind(key, lambda _e, s=step: self._key(s))
        body.bind("<Control-a>", lambda _e=None: self._select_all())
        head.bind("<Button-1>", self._head_press)
        head.bind("<B1-Motion>", self._head_drag)
        head.bind("<ButtonRelease-1>", self._head_release)
        head.bind("<Motion>", lambda e: head.configure(cursor="sb_h_double_arrow" if self._column_edge(e.x) else ""))
        super().bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._redraw), add="+")

    # ------------------------------------------------- what callers bind goes to where the events happen
    def bind(self, sequence: str | None = None, func: Any = None, add: Any = None) -> Any:  # type: ignore[override]
        if sequence and sequence.startswith("<<"):
            return super().bind(sequence, func, add)
        return self.body.bind(sequence, func, add)

    def event_generate(self, sequence: str, **kw: Any) -> None:
        (super() if sequence.startswith("<<") else self.body).event_generate(sequence, **kw)

    def focus_set(self) -> None:
        self.body.focus_set()

    def __getitem__(self, key: str) -> Any:
        if key == "columns":
            return tuple(self.columns)
        return super().__getitem__(key)

    # ----------------------------------------------------------------- columns
    def heading(self, column: str, option: str | None = None, **kw: Any) -> Any:
        col = self._cols[column]
        if option is not None:
            return col.get(option, "")
        for key in ("text", "command"):
            if key in kw:
                col[key] = kw[key]
        self._schedule()
        return None

    def column(self, column: str, option: str | None = None, **kw: Any) -> Any:
        col = self._cols[column]
        if option is not None:
            return col.get(option, "")
        for key in ("width", "stretch", "anchor"):
            if key in kw:
                col[key] = kw[key]
        self._schedule()
        return None

    def cell_role(self, column: str, role_of: Callable[[str, tuple], str | None]) -> None:
        """Colour of a column's text: ``role_of(value, row tags)`` gives a palette role, or None for the row's colour."""
        self._roles[column] = role_of

    def pill(self, column: str, roles_of: Callable[[str], tuple[str, str] | None] = severity_pill) -> None:
        """Show a column's value as a pill: ``roles_of(value)`` gives the palette roles (background, text)."""
        self._pills[column] = roles_of

    def on_drawn(self, callback: Callable[[], None]) -> None:
        """``callback()`` after every time the rows were drawn: something beside the table that follows a row."""
        self._drawn = callback

    def row_middle(self, iid: str) -> int | None:
        """Where the middle of a row is on the screen (root y) - kept inside the visible rows when the row is
        scrolled out of view. None when there is no such row."""
        if str(iid) not in self._order:
            return None
        top = self.body.winfo_rooty()
        y = self._order.index(str(iid)) * self._row_h - self._y + self._row_h // 2
        return top + max(self._row_h // 2, min(max(self._height(), self._row_h) - self._row_h // 2, y))

    def note_of(self, column: str, note: Callable[[str], str]) -> None:
        """A second, smaller line under the text of a column: ``note(iid)``. (Give the table a ``row_height`` that
        has room for two lines.)"""
        self._notes[column] = note
        self._schedule()

    def image_of(self, column: str, image: Callable[[str], Any]) -> None:
        """A small picture in front of a column's text: ``image(row id)`` gives it (or None)."""
        self._images[column] = image

    def action(self, text: str, command: Callable[[str], None]) -> None:
        """A button at the right end of every row: ``command(row id)`` when it is clicked."""
        self._action = (text, command)
        self._schedule()

    def _action_width(self) -> int:
        return self._plain.measure(self._action[0]) + px(26) + 2 * self._pad if self._action else 0

    TIP_DELAY = 600  # ms the pointer rests on a shortened cell before its whole text appears

    def cut_text(self, iid: str, column: str) -> str:
        """The whole text of a cell when the table shows it shortened (with an ellipsis), else ''."""
        if iid not in self._rows or column not in self._cols or column in self._pills:
            return ""
        text = self.shown_text(iid, column)
        width = next((w for name, _left, w in self._spans() if name == column), 0)
        bold = any(self._tags.get(t, {}).get("font") for t in self._rows[iid]["tags"])
        return text if text and self._fit(text, width - 2 * self._pad, bold) != text else ""

    def _hide_tip(self) -> None:
        try:
            if self._tip_job is not None:
                self.after_cancel(self._tip_job)
            if self._tip is not None:
                self._tip.destroy()
        except tk.TclError:
            pass
        self._tip_job = self._tip = None
        self._tip_cell = ("", "")

    def _show_tip(self, text: str) -> None:
        self._tip_job = None
        try:
            tip = self._tip = tk.Toplevel(self)
            tip.withdraw()
            tip.overrideredirect(True)
            tip.attributes("-topmost", True)
            tip.configure(background=theme.color("border"))
            tk.Label(tip, text=text, font=theme.FONT_CAPTION, background=theme.color("card"), foreground=theme.color("text"),
                     padx=px(8), pady=px(4), bd=0, justify="left", wraplength=px(460)).pack(padx=1, pady=1)
            tip.update_idletasks()
            x = min(self.winfo_pointerx() + px(12), self.winfo_vrootx() + self.winfo_vrootwidth() - tip.winfo_reqwidth())
            tip.geometry(f"+{max(0, x)}+{self.winfo_pointery() + px(18)}")
            tip.deiconify()
        except tk.TclError:
            self._tip = None

    def _motion(self, event: tk.Event) -> None:
        iid = self.identify_row(event.y)
        self._set_hover(iid)
        cell = (iid, self.identify_column(event.x) if iid else "")
        if cell != self._tip_cell:  # another cell: what was shown goes, and the wait starts anew
            self._hide_tip()
            self._tip_cell = cell
            column = self.columns[int(cell[1][1:]) - 1] if cell[1].startswith("#") and cell[1][1:].isdigit() else cell[1]
            whole = self.cut_text(iid, column) if iid and column in self._cols else ""
            if whole:
                self._tip_job = self.after(self.TIP_DELAY, lambda: self._show_tip(whole))
        over = bool(iid and self._action and event.x >= self.body.winfo_width() - self._action_width())
        on = iid if over else ""
        if on != self._over_action:  # the button under the pointer is tinted, like any button
            self._over_action = on
            self._schedule()

    def _leave_action(self) -> None:
        if self._over_action:
            self._over_action = ""
            self._schedule()

    def show_as(self, column: str, text_of: Callable[[str], str] = friendly_time) -> None:
        """How a column's value is written out (the value itself, which is sorted and read back, stays)."""
        self._shows[column] = text_of

    def tag_configure(self, tag: str, option: str | None = None, **kw: Any) -> Any:
        style = self._tags.setdefault(tag, {})
        if option is not None:
            return style.get(option, "")
        style.update({k: str(v) for k, v in kw.items()})
        self._schedule()
        return None

    def recolor_colors(self, mapping: dict[str, str]) -> None:
        """A switch between light and dark: the colours given for tags follow (theme.recolor calls this)."""
        for style in self._tags.values():
            for key, value in list(style.items()):
                style[key] = mapping.get(value.lower(), value)
        self._schedule()

    # -------------------------------------------------------------------- rows
    def insert(self, parent: str = "", index: Any = "end", iid: str | None = None, values: Any = (), tags: Any = (),
               **_kw: Any) -> str:
        if iid is None:
            self._auto += 1
            iid = f"I{self._auto:03d}"
        iid = str(iid)
        if iid in self._rows:
            raise tk.TclError(f"Item {iid} already exists")
        self._rows[iid] = {"values": [str(v) for v in values], "tags": (tags,) if isinstance(tags, str) else tuple(tags)}
        if index == "end" or not isinstance(index, int) or index >= len(self._order):
            self._order.append(iid)
        else:
            self._order.insert(max(0, index), iid)
        self._schedule()
        return iid

    def delete(self, *items: str) -> None:
        gone = {str(i) for i in items}
        if not gone:
            return
        for iid in gone:
            self._rows.pop(iid, None)
        self._order = [i for i in self._order if i not in gone]
        if self._focus in gone:
            self._focus = ""
        if self._anchor in gone:
            self._anchor = ""
        if any(i in gone for i in self._sel):
            self._sel = [i for i in self._sel if i not in gone]
            self._tell()
        self._schedule()

    def get_children(self, _item: str = "") -> tuple[str, ...]:
        return tuple(self._order)

    def exists(self, iid: str) -> bool:
        return str(iid) in self._rows

    def move(self, iid: str, _parent: str, index: int) -> None:
        self._order.remove(iid)
        self._order.insert(index, iid)
        self._schedule()

    def set(self, iid: str, column: str | None = None, value: Any = None) -> Any:
        row = self._rows[str(iid)]["values"]
        if column is None:
            return {c: (row[i] if i < len(row) else "") for i, c in enumerate(self.columns)}
        i = self.columns.index(column)
        if value is None:
            return row[i] if i < len(row) else ""
        row.extend([""] * (i + 1 - len(row)))
        row[i] = str(value)
        self._schedule()
        return None

    def item(self, iid: str, option: str | None = None, **kw: Any) -> Any:
        row = self._rows[str(iid)]
        if "values" in kw:
            row["values"] = [str(v) for v in kw["values"]]
        if "tags" in kw:
            row["tags"] = (kw["tags"],) if isinstance(kw["tags"], str) else tuple(kw["tags"])
        if kw:
            self._schedule()
            return None
        if option == "values":
            return tuple(row["values"])
        if option == "tags":
            return tuple(row["tags"])
        return {"values": tuple(row["values"]), "tags": tuple(row["tags"])}

    # --------------------------------------------------------------- selection
    def selection(self) -> tuple[str, ...]:
        return tuple(self._sel)

    def selection_set(self, *items: Any) -> None:
        if len(items) == 1 and isinstance(items[0], (list, tuple)):
            items = tuple(items[0])
        wanted = [str(i) for i in items if str(i) in self._rows]
        if self._mode == "browse":
            wanted = wanted[:1]
        if wanted != self._sel:
            self._sel = wanted
            self._tell()
            self._schedule()

    def selection_add(self, *items: Any) -> None:
        self.selection_set(list(self._sel) + [str(i) for i in items if str(i) not in self._sel])

    def selection_remove(self, *items: Any) -> None:
        gone = {str(i) for i in items}
        self.selection_set([i for i in self._sel if i not in gone])

    def focus(self, iid: str | None = None) -> str:  # type: ignore[override]
        if iid is not None and str(iid) in self._rows:
            self._focus = str(iid)
        return self._focus

    def see(self, iid: str) -> None:
        if str(iid) not in self._rows:
            return
        top = self._order.index(str(iid)) * self._row_h
        height = max(self._height(), self._row_h)
        if top < self._y:
            self._y = top
        elif top + self._row_h > self._y + height:
            self._y = top + self._row_h - height
        self._schedule()

    def _tell(self) -> None:
        """Say that the selection changed - once, when the caller is done (like Treeview: never in the middle)."""
        if self._tell_job is None:
            def tell() -> None:
                self._tell_job = None
                try:
                    tk.Frame.event_generate(self, "<<TreeviewSelect>>")  # type: ignore[arg-type]
                except tk.TclError:
                    pass
            try:
                self._tell_job = self.after_idle(tell)
            except tk.TclError:
                pass

    def _click(self, event: tk.Event) -> None:
        self.body.focus_set()
        iid = self.identify_row(event.y)
        if not iid:
            return
        if self._action and event.x >= self.body.winfo_width() - self._action_width():
            self._action[1](iid)  # the row's button
            return
        state = int(event.state) if isinstance(event.state, int) else 0
        if self._mode == "extended" and state & 0x4:      # Ctrl: add or take away
            chosen = [i for i in self._sel if i != iid] if iid in self._sel else self._sel + [iid]
            self._anchor = iid
        elif self._mode == "extended" and state & 0x1 and self._anchor in self._rows:  # Shift: everything in between
            a, b = sorted((self._order.index(self._anchor), self._order.index(iid)))
            chosen = self._order[a:b + 1]
        else:
            chosen, self._anchor = [iid], iid
        self._focus = iid
        self.selection_set(chosen)

    def _key(self, step: int) -> str:
        if not self._order:
            return "break"
        at = self._order.index(self._focus) if self._focus in self._rows else (-1 if step > 0 else len(self._order))
        iid = self._order[max(0, min(len(self._order) - 1, at + step))]
        self._focus = self._anchor = iid
        self.selection_set([iid])
        self.see(iid)
        return "break"

    def _select_all(self) -> str:
        if self._mode == "extended":
            self.selection_set(list(self._order))
        return "break"

    # ------------------------------------------------------------ where things are
    def _spans(self) -> list[tuple[str, int, int]]:
        """(column, left edge, width) for every column; the stretching one takes the room that is left."""
        room = max(self.body.winfo_width() - self._action_width(), 1)
        widths = {c: int(self._cols[c]["width"]) for c in self.columns}
        spare = room - sum(widths.values())
        stretch = [c for c in self.columns if self._cols[c]["stretch"]]
        if spare > 0 and stretch:
            widths[stretch[-1]] += spare
        elif spare < 0 and stretch and self.xbar is None:
            # too narrow for the widths asked for (and nothing to scroll sideways): the stretching column gives way,
            # its text ends in an ellipsis - it never runs under the row's button or out of the card
            widths[stretch[-1]] = max(px(60), widths[stretch[-1]] + spare)
        spans, x = [], 0
        for c in self.columns:
            spans.append((c, x, widths[c]))
            x += widths[c]
        return spans

    def identify_row(self, y: int) -> str:
        index = (int(y) + self._y) // self._row_h
        return self._order[index] if y >= 0 and 0 <= index < len(self._order) else ""

    def identify_column(self, x: int) -> str:
        at = int(x) + self._x
        for i, (_c, left, width) in enumerate(self._spans()):
            if left <= at < left + width:
                return f"#{i + 1}"
        return ""

    def _column_edge(self, x: int) -> str:
        """The column whose right edge is under the pointer (to drag it wider or narrower)."""
        at = x + self._x
        for c, left, width in self._spans():
            if abs(left + width - at) <= px(4):
                return c
        return ""

    def _head_press(self, event: tk.Event) -> None:
        edge = self._column_edge(event.x)
        if edge:
            self._drag = (edge, event.x, int(self._cols[edge]["width"]))
            return
        col = self.identify_column(event.x)
        if col:
            command = self._cols[self.columns[int(col[1:]) - 1]]["command"]
            if command:
                command()

    def _head_drag(self, event: tk.Event) -> None:
        if self._drag:
            name, start, width = self._drag
            self._cols[name]["width"] = max(px(40), width + event.x - start)
            self._cut.clear()
            self._schedule()

    def _head_release(self, _event: tk.Event) -> None:
        self._drag = None

    # ------------------------------------------------------------------ scrolling
    def _height(self) -> int:
        """The height the rows have (before the table is on the screen: the height it asked for)."""
        height = self.body.winfo_height()
        return height if height > 1 else max(self.body.winfo_reqheight(), 1)

    def yview(self, *args: Any) -> Any:
        height, total = self._height(), len(self._order) * self._row_h
        if not args:
            return (self._y / total, min(1.0, (self._y + height) / total)) if total else (0.0, 1.0)
        if args[0] == "moveto":
            self._y = int(float(args[1]) * total)
        elif args[0] == "scroll":
            unit = height - self._row_h if args[2] == "pages" else self._row_h * (3 if args[2] == "wheel" else 1)
            self._y += int(args[1]) * unit
        self._redraw()
        return None

    def xview(self, *args: Any) -> Any:
        width, total = max(self.body.winfo_width(), 1), sum(int(self._cols[c]["width"]) for c in self.columns)
        if not args:
            return (self._x / total, min(1.0, (self._x + width) / total)) if total else (0.0, 1.0)
        if args[0] == "moveto":
            self._x = int(float(args[1]) * total)
        elif args[0] == "scroll":
            self._x += int(args[1]) * (width // 2 if args[2] == "pages" else px(60))
        self._redraw()
        return None

    # -------------------------------------------------------------------- drawing
    def _schedule(self) -> None:
        if self._draw_job is None:
            try:
                self._draw_job = self.after_idle(self._redraw)
            except tk.TclError:
                pass

    def _fit(self, text: str, width: int, bold: bool = False) -> str:
        key = (text, width, bold)
        hit = self._cut.get(key)
        if hit is not None:
            return hit
        font = self._bold if bold else self._font
        out = text
        if width <= 0:
            out = ""
        elif font.measure(text) > width:
            lo, hi = 0, len(text)
            while lo < hi:  # the longest beginning that fits together with the ellipsis
                mid = (lo + hi + 1) // 2
                if font.measure(text[:mid] + ELLIPSIS) <= width:
                    lo = mid
                else:
                    hi = mid - 1
            out = timefmt.keep_whole(text[:lo].rstrip() + ELLIPSIS) if lo else ""  # (never a time without its zone)
        if len(self._cut) > 20000:
            self._cut.clear()
        self._cut[key] = out
        return out

    def _fit_small(self, text: str, width: int) -> str:
        """A note, shortened with an ellipsis to the width of its column."""
        small = tkfont.nametofont(theme.FONT_CAPTION, root=self)
        if small.measure(text) <= width:
            return text
        while text and small.measure(text + "\u2026") > width:
            text = text[:-1]
        return timefmt.keep_whole(text.rstrip() + "\u2026")

    def _back(self, iid: str) -> str:
        if iid in self._sel:
            return theme.color("row_select")
        tinted = next((self._tags[t]["background"] for t in self._rows[iid]["tags"]
                       if self._tags.get(t, {}).get("background")), "") if iid in self._rows else ""
        return tinted or theme.color("heading_bg" if iid == self._hover else "card")

    def _set_hover(self, iid: str) -> None:
        if iid == self._hover:
            return
        previous, self._hover = self._hover, iid
        for i in (previous, iid):
            if i in self._backs:
                try:
                    self.body.itemconfigure(self._backs[i], fill=self._back(i))
                except tk.TclError:
                    pass

    def _redraw(self) -> None:
        self._draw_job = None
        try:
            if not self.winfo_exists():
                return
            self._draw()
        except tk.TclError:
            pass

    def _draw(self) -> None:
        c, body, head = theme.color, self.body, self.head
        width, height = max(body.winfo_width(), 1), self._height()
        spans = self._spans()
        total_w, total_h = (spans[-1][1] + spans[-1][2] if spans else 0), len(self._order) * self._row_h
        self._x = max(0, min(self._x, total_w - width))
        self._y = max(0, min(self._y, total_h - height))
        body.delete("all")
        head.delete("all")
        self._backs = {}
        pad, row_h = self._pad, self._row_h
        for name, left, w in spans:
            col = self._cols[name]
            x0 = left - self._x
            if x0 > width or x0 + w < 0:
                continue
            east = col["anchor"] == "e"
            head.create_text(x0 + (w - pad if east else pad), self._head_h // 2, anchor="e" if east else "w",
                             text=self._fit(str(col["text"]), w - 2 * pad, True), font=theme.FONT_TABLE_BOLD, fill=c("muted"))
        head.create_line(0, self._head_h - 1, width + 1, self._head_h - 1, fill=c("border"))
        first = self._y // row_h
        for index in range(first, min(len(self._order), (self._y + height) // row_h + 1)):
            iid = self._order[index]
            row = self._rows[iid]
            y0 = index * row_h - self._y
            self._backs[iid] = body.create_rectangle(0, y0, width + 1, y0 + row_h - 1, outline="", fill=self._back(iid))
            if y0 + row_h < height - px(2):  # (a row that ends at the lower edge gets no line: the card's edge follows)
                body.create_line(0, y0 + row_h - 1, width + 1, y0 + row_h - 1, fill=c("border"))
            colour = next((self._tags[t]["foreground"] for t in row["tags"] if self._tags.get(t, {}).get("foreground")),
                          c("text"))
            mid = y0 + row_h // 2
            bold = any(self._tags.get(t, {}).get("font") for t in row["tags"])  # (a tag with a font: its rows are bold)
            font = theme.FONT_TABLE_BOLD if bold else theme.FONT_TABLE
            if self._action:
                label, aw = self._action[0], self._action_width()
                x2, bh = width - pad, px(30)  # (the look of the standard button: height, corners, font, hover)
                body.create_image(x2, mid, anchor="e", image=rounded_image(
                    body, aw - 2 * pad, bh, px(4), "heading_bg" if iid == self._over_action else "card", "track"))
                body.create_text(x2 - (aw - 2 * pad) // 2, mid, text=label, font=theme.FONT, fill=c("text"))
            for i, (name, left, w) in enumerate(spans):
                x0 = left - self._x
                if x0 > width or x0 + w < 0:
                    continue
                value = row["values"][i] if i < len(row["values"]) else ""
                text = self._shows[name](value) if name in self._shows else value
                if not text:
                    continue
                pill = self._pills[name](value) if name in self._pills else None
                if pill:  # a tag may give its rows' pills other colours (tag_configure(tag, pill="background|text"))
                    other = next((self._tags[t]["pill"] for t in row["tags"] if self._tags.get(t, {}).get("pill")), "")
                    if "|" in other:
                        pill = tuple(other.split("|", 1))
                if pill:
                    label = self._fit(text, w - 2 * pad - px(16), True)
                    tw, ph = self._bold.measure(label) + px(16), px(22)
                    x1, y1, r = x0 + pad - px(4), mid - ph // 2, ph // 2
                    body.create_image(x1, y1, anchor="nw", image=rounded_image(body, tw, ph, r, pill[0]))
                    body.create_text(x1 + tw // 2, mid, text=label, font=theme.FONT_TABLE_BOLD, fill=c(pill[1]))
                    continue
                role = self._roles[name](value, row["tags"]) if name in self._roles else None
                east = self._cols[name]["anchor"] == "e"
                shift = 0
                picture = self._images[name](iid) if name in self._images else None
                if picture is not None and not east:
                    body.create_image(x0 + pad, mid, image=picture, anchor="w")
                    shift = picture.width() + px(8)
                note = self._notes[name](iid) if name in self._notes else ""
                at = mid - px(10) if note else mid
                body.create_text(x0 + (w - pad if east else pad + shift), at, anchor="e" if east else "w",
                                 text=self._fit(text, w - 2 * pad - shift, bold), font=font, fill=c(role) if role else colour)
                if note:
                    body.create_text(x0 + (w - pad if east else pad + shift), mid + px(10), anchor="e" if east else "w",
                                     text=self._fit_small(note, w - 2 * pad - shift), font=theme.FONT_CAPTION, fill=c("muted"))
        first_f, last_f = self.yview()
        if first_f <= 0.0 and last_f >= 1.0:
            self.ybar.grid_remove()
        else:
            self.ybar.grid()
        self.ybar.set(first_f, last_f)
        if self.xbar is not None:  # (its row is kept, so nothing moves when it comes and goes)
            first_x, last_x = self.xview()
            if first_x <= 0.0 and last_x >= 1.0:
                self.xbar.grid_remove()
            else:
                self.xbar.grid()
            self.xbar.set(first_x, last_x)
        if self._drawn is not None:
            self._drawn()

    def shown_text(self, iid: str, column: str) -> str:
        """What a cell says on the screen (after ``show_as``)."""
        value = self.set(iid, column)
        return self._shows[column](value) if column in self._shows else value
