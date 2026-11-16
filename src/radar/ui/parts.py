"""Small building blocks the pages of the main window share: a card, figure tiles, filter pills, tabs."""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from typing import Any, Callable

from . import theme
from .rounded import Rounded, background_of, rounded_image
from .theme import px


def card(parent: tk.Misc, **kw: Any) -> Rounded:
    """A white area with round corners and a hairline edge; what belongs together sits on one."""
    return Rounded(parent, **kw)


def on_card(parent: tk.Misc, **kw: Any) -> tk.Frame:
    """A frame inside a card (same colour, no border)."""
    return tk.Frame(parent, background=theme.color("card"), bd=0, highlightthickness=0, **kw)


def line(parent: tk.Misc) -> tk.Frame:
    """A hairline across a card."""
    return tk.Frame(parent, height=1, background=theme.color("border"), bd=0, highlightthickness=0)


class Hint:
    """A small note that appears under the pointer when it rests on one of the widgets (for text too long to show)."""

    DELAY = 500  # ms the pointer rests before the note appears

    def __init__(self, widgets: Any, text_of: Callable[[], str], wrap: int = 0) -> None:
        self._text_of, self._tip, self._due, self._owner, self._wrap = text_of, None, None, None, wrap
        for widget in widgets:
            widget.bind("<Enter>", lambda _e=None, w=widget: self._wait(w), add="+")
            widget.bind("<Leave>", lambda _e=None: self.hide(), add="+")
            widget.bind("<ButtonPress>", lambda _e=None: self.hide(), add="+")

    def _wait(self, widget: tk.Misc) -> None:
        self.hide()
        self._owner = widget
        self._due = widget.after(self.DELAY, self.show)

    def show(self) -> None:
        widget, self._due = self._owner, None
        text = self._text_of()
        if widget is None or not text:
            return
        try:
            tip = self._tip = tk.Toplevel(widget)
            tip.withdraw()
            tip.overrideredirect(True)
            tip.attributes("-topmost", True)
            tip.configure(background=theme.color("border"))
            tk.Label(tip, text=text, font=theme.FONT_CAPTION, background=theme.color("card"),
                     foreground=theme.color("text"), padx=px(8), pady=px(4), bd=0, justify="left",
                     wraplength=self._wrap or px(420)).pack(padx=1, pady=1)
            tip.update_idletasks()
            x = min(widget.winfo_pointerx() + px(12), widget.winfo_vrootx() + widget.winfo_vrootwidth() - tip.winfo_reqwidth())
            tip.geometry(f"+{x}+{widget.winfo_pointery() + px(18)}")
            tip.deiconify()
        except tk.TclError:
            self._tip = None

    def hide(self) -> None:
        try:
            if self._due is not None and self._owner is not None:
                self._owner.after_cancel(self._due)
            if self._tip is not None:
                self._tip.destroy()
        except tk.TclError:
            pass
        self._due = self._tip = None


class Tiles(ttk.Frame):
    """Figures side by side, each on its own card: a caption and a number. Same size whatever the numbers are."""

    EMPTY = "‒"  # a dash as wide as a digit

    def __init__(self, parent: tk.Misc, names: list[str], **kw: Any):
        super().__init__(parent, **kw)
        self.values: list[tk.Label] = []
        for i, name in enumerate(names):
            self.columnconfigure(i, weight=1, uniform="tiles")
            cell = card(self)
            cell.grid(row=0, column=i, sticky="nsew", padx=(0, px(10) if i < len(names) - 1 else 0))
            inner = on_card(cell, padx=px(14), pady=px(8))
            inner.pack(fill="both", expand=True)
            tk.Label(inner, text=name, font=theme.FONT_CAPTION, anchor="w", bd=0, padx=0, pady=0,
                     background=theme.color("card"), foreground=theme.color("muted")).pack(fill="x")
            value = tk.Label(inner, text=self.EMPTY, font=theme.FONT_FIGURE, anchor="w", bd=0, padx=0, pady=0,
                             background=theme.color("card"), foreground=theme.color("text"))
            value.pack(fill="x")
            self.values.append(value)

    def set(self, index: int, value: Any = None, role: str = "text") -> None:
        self.values[index].configure(text=self.EMPTY if value is None else str(value), foreground=theme.color(role))

    def text(self, index: int) -> str:
        return str(self.values[index].cget("text"))


class Segments(tk.Canvas):
    """A few pills of which one is chosen (a filter): the chosen one is filled with the accent colour.

    Every pill has the same, fixed width (``width`` characters), so a changing count never moves them."""

    def __init__(self, parent: tk.Misc, choices: list[tuple[str, str]], on_choose: Callable[[str], None],
                 width: int = 10, **kw: Any):
        self._on_choose = on_choose
        self._texts = dict(choices)
        self._order = [key for key, _text in choices]
        self.chosen, self._hover = "", ""
        font = tkfont.nametofont(theme.FONT_BOLD, root=parent)
        self._pill_w, self._pill_h, self._gap = font.measure("0" * width) + px(24), px(32), px(6)
        super().__init__(parent, highlightthickness=0, bd=0, background=background_of(parent), height=self._pill_h,
                         width=len(choices) * (self._pill_w + self._gap) - self._gap, **kw)
        self._shapes: dict[str, tuple[int, int]] = {}
        for i, key in enumerate(self._order):
            x = i * (self._pill_w + self._gap)
            shape = self.create_image(x, 0, anchor="nw")
            label = self.create_text(x + self._pill_w // 2, self._pill_h // 2, text=self._texts[key], font=theme.FONT)
            self._shapes[key] = (shape, label)
        self.bind("<Button-1>", lambda e: self.choose(self._key_at(e.x)))
        self.bind("<Motion>", lambda e: self._set_hover(self._key_at(e.x)))
        self.bind("<Leave>", lambda _e=None: self._set_hover(""))
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")
        self._paint()

    def _key_at(self, x: int) -> str:
        index, rest = divmod(max(0, x), self._pill_w + self._gap)
        return self._order[index] if index < len(self._order) and rest <= self._pill_w else ""

    def _set_hover(self, key: str) -> None:
        if key != self._hover:
            self._hover = key
            self._paint()
            self.configure(cursor="hand2" if key else "")

    def _paint(self) -> None:
        try:
            for key, (shape, label) in self._shapes.items():
                on = key == self.chosen
                self.itemconfigure(shape, image=rounded_image(
                    self, self._pill_w, self._pill_h, self._pill_h // 2,
                    "link" if on else "heading_bg" if key == self._hover else "card", "link" if on else "border"))
                self.itemconfigure(label, text=self._texts[key], font=theme.FONT_BOLD if on else theme.FONT,
                                   fill=theme.role_color("on_accent") if on else theme.color("text"))
        except tk.TclError:
            pass

    def choose(self, key: str, tell: bool = True) -> None:
        if key not in self._shapes:
            return
        self.chosen = key
        self._paint()
        if tell:
            self._on_choose(key)

    def set_text(self, key: str, text: str) -> None:
        self._texts[key] = text
        self._paint()

    def text(self, key: str) -> str:
        return self._texts[key]


class UnderlineTabs(Rounded):
    """Tabs on a card: the names in a row, the chosen one underlined in the accent colour, its page below.

    The pages stay where they are, one over the other, and choosing a tab only raises its page - nothing is unmapped,
    so tables do not flash. Create pages with ``.stack`` as parent and add them with ``add_page``. Tells a change with
    ``<<NotebookTabChanged>>``."""

    def __init__(self, parent: tk.Misc, **kw: Any):
        super().__init__(parent, **kw)
        c = theme.color
        self._texts: list[str] = []
        self._spans: list[tuple[int, int]] = []
        self._current, self._hover = 0, -1
        self.pages: list[tk.Misc] = []
        self._bold = tkfont.nametofont(theme.FONT_BOLD, root=self)
        self.strip = tk.Canvas(self, height=px(40), background=c("card"), highlightthickness=0, bd=0)
        self.strip.pack(fill="x")
        line(self).pack(fill="x")
        self.stack = tk.Frame(self, background=c("card"), bd=0, highlightthickness=0)
        self.stack.pack(fill="both", expand=True)
        self.stack.rowconfigure(0, weight=1)
        self.stack.columnconfigure(0, weight=1)
        self.strip.bind("<Button-1>", lambda e: self.select(self._tab_at(e.x)) if self._tab_at(e.x) >= 0 else None)
        self.strip.bind("<Motion>", lambda e: self._set_hover(self._tab_at(e.x)))
        self.strip.bind("<Leave>", lambda _e=None: self._set_hover(-1))
        self.strip.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")

    def add_page(self, page: tk.Misc, text: str) -> None:
        self.pages.append(page)
        self._texts.append(text)
        page.grid(row=0, column=0, sticky="nsew")
        self.pages[self._current].tkraise()
        self._paint()

    def current(self) -> int:
        return self._current

    def index(self, _what: Any = None) -> int:
        return self._current

    def select(self, index: int | None = None) -> Any:
        if index is None:
            return self._current
        index = int(index)
        if not 0 <= index < len(self.pages) or index == self._current:
            return None
        self._current = index
        self.pages[index].tkraise()
        self._paint()
        self.event_generate("<<NotebookTabChanged>>")
        return None

    def tab(self, index: int, option: str | None = None, **kw: Any) -> Any:
        if option == "text":
            return self._texts[index]
        if "text" in kw and kw["text"] != self._texts[index]:
            self._texts[index] = kw["text"]
            self._paint()
        return None

    def fit(self) -> None:
        """(Nothing to do: the pages fill the stack by themselves. Kept for callers of the notebook this replaces.)"""

    def _tab_at(self, x: int) -> int:
        return next((i for i, (left, right) in enumerate(self._spans) if left <= x < right), -1)

    def _set_hover(self, index: int) -> None:
        if index != self._hover:
            self._hover = index
            self._paint()

    def _paint(self) -> None:
        c, strip = theme.color, self.strip
        try:
            strip.delete("all")
            self._spans = []
            x, mid, pad = px(8), px(40) // 2, px(12)
            for i, text in enumerate(self._texts):
                width = self._bold.measure(text) + 2 * pad  # (measured bold: choosing a tab never moves the others)
                on = i == self._current
                strip.create_text(x + pad, mid, anchor="w", text=text, font=theme.FONT_BOLD if on else theme.FONT,
                                  fill=c("text") if on or i == self._hover else c("muted"))
                if on:
                    strip.create_rectangle(x + pad, px(40) - px(3), x + width - pad, px(40), outline="", fill=c("link"))
                self._spans.append((x, x + width))
                x += width
        except tk.TclError:
            pass


class Badge(tk.Label):
    """A pill with a word in it, outside a table: a severity next to a title. ``set(text, (background, text))``
    with palette roles; its place is kept when it is empty."""

    def __init__(self, parent: tk.Misc, template: str = "Medium \u00b7 100", background: str = "card"):
        self._font = tkfont.nametofont(theme.FONT_TABLE_BOLD, root=parent)
        self._size = (self._font.measure(template) + px(20), px(24))
        self._now: tuple[str, tuple[str, str]] = ("", ("card", "card"))
        self._back = background
        super().__init__(parent, bd=0, padx=0, pady=0, highlightthickness=0, background=theme.color(background),
                         font=theme.FONT_TABLE_BOLD, compound="center", anchor="w", width=self._size[0], height=self._size[1])
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._show), add="+")
        self._show()

    def set(self, text: str, roles: tuple[str, str] = ("card", "card")) -> None:
        self._now = (text, roles)
        self._show()

    def recolor_colors(self, _mapping: dict[str, str]) -> None:
        self._show()

    def _show(self) -> None:
        text, (bg, fg) = self._now
        try:
            width = self._font.measure(text) + px(20) if text else 2
            self._image = rounded_image(self, width, self._size[1], self._size[1] // 2, bg if text else self._back)
            self.configure(image=self._image, text=text, foreground=theme.color(fg), background=theme.color(self._back))
        except tk.TclError:
            pass


class StageTrack(tk.Canvas):
    """How far something got, as a row of named stops on a line: the stops reached are filled, a stop that was
    skipped on the way is a ring, what lies ahead is grey. Under each stop reached, a note (when it was reached).
    A stop that was reached but is settled (nothing of it is open any more) is filled grey.

    ``set(reached, role, settled)``: ``reached`` maps the number of a stop (1 ...) to its note, ``role`` is the
    palette role the open part is drawn in, ``settled`` the stops among them that are over. The height never changes."""

    def __init__(self, parent: tk.Misc, names: list[str], background: str = "card"):
        self._names, self._back = list(names), background
        self._reached: dict[int, str] = {}
        self._settled: set[int] = set()
        self._role = "link"
        self._small = tkfont.nametofont(theme.FONT_CAPTION, root=parent)
        line = self._small.metrics("linespace")
        self._dot = px(14)
        super().__init__(parent, height=self._dot + px(8) + 2 * line + px(2), background=theme.color(background),
                         highlightthickness=0, bd=0)
        self._images: list[Any] = []
        self.bind("<Configure>", lambda _e=None: self._draw(), add="+")
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._draw), add="+")

    def set(self, reached: dict[int, str], role: str = "link", settled: Any = ()) -> None:
        self._reached, self._role, self._settled = dict(reached), role, set(settled)
        self._draw()

    def recolor_colors(self, _mapping: dict[str, str]) -> None:
        self._draw()

    def texts(self) -> list[tuple[str, str, str]]:
        """(name, note, 'reached' | 'settled' | 'skipped' | 'ahead') of every stop - what the track shows."""
        furthest = max(self._reached, default=0)
        return [(name, self._reached.get(i, ""),
                 ("settled" if i in self._settled else "reached") if i in self._reached else "skipped" if i < furthest else "ahead")
                for i, name in enumerate(self._names, 1)]

    def _draw(self) -> None:
        try:
            c, width = theme.color, self.winfo_width()
            if width < 2:
                return
            self.configure(background=c(self._back))
            self.delete("all")
            self._images = []
            n, dot = len(self._names), self._dot
            slot = width / n
            y = dot // 2 + px(1)
            furthest = max(self._reached, default=0)
            still = max((i for i in self._reached if i not in self._settled), default=0)  # as far as it is open
            xs = [int(slot * (i + 0.5)) for i in range(n)]  # every stop in the middle of its slot, its text under it
            for i in range(n - 1):  # the line: coloured as far as it is open, grey-dark as far as it once got
                self.create_line(xs[i] + dot // 2, y, xs[i + 1] - dot // 2, y, width=px(2),
                                 fill=c(self._role) if i + 2 <= still else c("muted") if i + 2 <= furthest else c("border"))
            line = self._small.metrics("linespace")
            for i, (name, note, state) in enumerate(self.texts()):
                beyond = i + 1 > still  # (past what is still open: drawn in grey)
                fill, edge = ((self._role, None) if state == "reached" else ("muted", None) if state == "settled"
                              else ("card", "muted" if beyond else self._role) if state == "skipped" else ("card", "track"))
                image = rounded_image(self, dot, dot, dot // 2, fill, edge)
                self._images.append(image)
                self.create_image(xs[i], y, image=image)
                self.create_text(xs[i], dot + px(8), anchor="n", text=name, font=theme.FONT_CAPTION,
                                 fill=c("text") if state in ("reached", "settled") else c("muted"))
                if note:
                    self.create_text(xs[i], dot + px(8) + line, anchor="n", text=note, font=theme.FONT_CAPTION, fill=c("muted"))
        except tk.TclError:
            pass


class Pointer(tk.Canvas):
    """A small arrowhead in the gap between a list and what is shown for the selected row of it: it sits at the
    height of that row and points at it, so that one sees - without a word - what the panel beside belongs to.
    ``at(y)``: the height (root y) to point from; None hides it."""

    def __init__(self, parent: tk.Misc, role: str = "link", background: str = "window"):
        self._role, self._back, self._y = role, background, None
        self._image: Any = None
        super().__init__(parent, width=px(11), highlightthickness=0, bd=0, background=theme.color(background))
        self.bind("<Configure>", lambda _e=None: self._draw(), add="+")
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._draw), add="+")

    def at(self, root_y: int | None) -> None:
        if root_y != self._y:
            self._y = root_y
            self._draw()

    def recolor_colors(self, _mapping: dict[str, str]) -> None:
        self._draw()

    @property
    def shown_at(self) -> int | None:
        """The y inside the pointer's own strip it points from (None: hidden)."""
        try:
            return None if self._y is None else int(self._y - self.winfo_rooty())
        except tk.TclError:
            return None

    def _draw(self) -> None:
        from PIL import Image, ImageDraw, ImageTk

        try:
            self.configure(background=theme.color(self._back))
            self.delete("all")
            y = self.shown_at
            if y is None:
                return
            w, h, k = max(2, self.winfo_width()), px(18), 4
            big = Image.new("RGBA", (w * k, h * k), (0, 0, 0, 0))  # drawn large and scaled down: smooth edges
            ImageDraw.Draw(big).polygon([(0, h * k // 2), (w * k, 0), (w * k, h * k)], fill=theme.color(self._role))
            self._image = ImageTk.PhotoImage(big.resize((w, h), Image.LANCZOS), master=self)
            self.create_image(0, y, anchor="w", image=self._image)
        except tk.TclError:
            pass
