"""A timeline, drawn: days and under each its rows - when, a dot of its kind, what happened (with what is unusual
about it as small outlined tags), under it what kind of thing it is and where it came from, at its end an arrow.

A row is one shape with round corners - tinted where it is an alert, lit up softly under the pointer - and it unfolds
where it stands (a rounded block under its second line).

Everything is drawn on one canvas, and only what is near the part in view: a timeline can have thousands of rows.
Put together from widgets, every row would be windows for the system to create, lay out, move with every step of
scrolling and take down again; drawn, scrolling moves one picture, and a list of nine thousand rows is as light as
one of twenty. Rows are laid out as they are reached - the list goes on as it is scrolled.
"""
from __future__ import annotations

import bisect
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from typing import Any, Callable, Sequence

from . import theme
from .bits import LIT, Glide, fit_text, stepped
from .parts import Tips
from .richtext import autoscroll
from .rounded import rounded_image
from .theme import px

Piece = tuple[str, str, bool, Callable[[], None] | None]   # text, palette role, bold, what a click on it does (a link)

TIME, DOT, TEXT = 8, 58, 78     # where a row's time, its dot and its text begin
RADIUS = 8
GOES_ON = "The list goes on as you scroll"


class Day:
    """The heading of a day: its name and date, and the zone its times are in."""

    def __init__(self, text: str):
        self.text, self.tag, self.feed = text, "", None  # type: ignore[var-annotated]

    def draw(self, y: int) -> int:
        feed = self.feed
        feed.canvas.create_text(px(8), y + px(10), text=self.text, anchor="nw", font=theme.FONT_CAPTION_BOLD, fill=feed.plain_ink("muted"),
                                tags=(self.tag, "plain-muted"))
        return tkfont.nametofont(theme.FONT_CAPTION_BOLD, root=feed.canvas).metrics("linespace") + px(13)

    def erase(self) -> None:
        self.feed.canvas.delete(self.tag)

    def written(self) -> list[str]:
        return [self.text]


class Row:
    """One line of the timeline. It lives as long as the list (it remembers whether it is unfolded); what is drawn
    of it comes and goes with the part of the list in view."""

    def __init__(self, when: str, dot: str, what: str, marks: Sequence[str], pieces: Sequence[Piece], base: str = "card",
                 on_title: Callable[[], None] | None = None, on_arrow: Callable[[], None] | None = None, line: Any = None):
        self.when, self.dot, self.what, self.marks, self.pieces, self.base = when, dot, what, list(marks), list(pieces), base
        self.on_title, self.on_arrow, self.line = on_title, on_arrow, line
        self.detail: list[tuple[str, str]] | None = None   # what it is unfolded into (None: folded)
        self.tag, self.feed = "", None  # type: ignore[var-annotated]
        self.lit, self.new = 0.0, 1.0                      # under the pointer (0..1); what it unfolded into coming out of its ground
        self._glide: Glide | None = None
        self._fresh: Glide | None = None
        self._inks: list[tuple[int, str, str]] = []        # (item, palette role, what it stands on: "row" | "box")
        self._pills: list[tuple[int, int, int]] = []       # (item, width, height) of each small tag's outline
        self._shown: list[Any] = []                        # the images in use (whoever shows one holds it)

    # ------------------------------------------------------------------ colours
    def ground(self) -> str:
        """What the row is filled with now: its own colour, a touch toward the text colour while the pointer is on it."""
        t = stepped(self.lit)
        return theme.color(self.base) if t <= 0 else theme.mix(theme.color(self.base), theme.color("text"), LIT * t)

    def _ink(self, role: str, on: str) -> str:
        colour = theme.mix(theme.color("muted"), theme.color("text"), max(0.0, min(1.0, self.lit))) if role == "arrow" else theme.color(role)
        seen = self.feed.seen
        under = theme.color("heading_bg") if on == "box" else self.ground()
        there = min(seen, self.new) if on == "box" else seen
        return colour if there >= 1 else theme.mix(under, colour, max(0.0, there))

    def _fill(self) -> str:
        """The row's fill for a shape: its palette role where it rests on one (such shapes follow a theme switch)."""
        return self.base if stepped(self.lit) <= 0 else self.ground()

    def recolour(self) -> None:
        """Hover, appearing: only colours change - nothing is drawn anew, nothing moves."""
        c = self.feed.canvas
        try:
            fill, r = self._fill(), px(RADIUS)
            self._shown = [rounded_image(c, 2 * r, 2 * r, r, fill)]
            for item in c.find_withtag(f"{self.tag}&&corner"):
                c.itemconfigure(item, image=self._shown[0])
            for item in c.find_withtag(f"{self.tag}&&fill"):
                c.itemconfigure(item, fill=self.ground())
            edge = self._ink("warn", "row")
            for item, w, h in self._pills:
                self._shown.append(rounded_image(c, w, h, h // 2, fill, edge if self.feed.seen < 1 else "warn"))
                c.itemconfigure(item, image=self._shown[-1])
            for item, role, on in self._inks:
                c.itemconfigure(item, fill=self._ink(role, on))
        except tk.TclError:
            pass

    def light(self, on: bool) -> None:
        if self._glide is None:
            self._glide = Glide(self.feed.canvas, self._lit)
        self._glide.to(1 if on else 0)

    def _lit(self, t: float) -> None:
        self.lit = t
        self.recolour()

    def _came(self, t: float) -> None:
        self.new = t
        self.recolour()

    # ------------------------------------------------------------------ drawing
    def _text(self, x: int, y: int, text: str, role: str, font: str, on: str = "row", tags: tuple = (), **kw: Any) -> int:
        item = self.feed.canvas.create_text(x, y, text=text, font=font, fill=self._ink(role, on), tags=(self.tag,) + tags, **kw)
        self._inks.append((item, role, on))
        return item

    def _shape(self, x0: int, y0: int, x1: int, y1: int, r: int, role: str, corner: str, fill: str) -> None:
        """A rectangle with round corners: a smooth quarter in each corner (an image), the colour between them."""
        c = self.feed.canvas
        image = rounded_image(c, 2 * r, 2 * r, r, role)
        self._shown.append(image)
        for x, y in ((x0, y0), (x1 - 2 * r, y0), (x0, y1 - 2 * r), (x1 - 2 * r, y1 - 2 * r)):
            c.create_image(x, y, anchor="nw", image=image, tags=(self.tag, corner))
        colour = role if role.startswith("#") else theme.color(role)
        c.create_rectangle(x0 + r, y0, x1 - r, y1, outline="", fill=colour, tags=(self.tag, fill))
        c.create_rectangle(x0, y0 + r, x1, y1 - r, outline="", fill=colour, tags=(self.tag, fill))

    def _link(self, item: int, go: Callable[[], None], font: str = "") -> None:
        """What can be clicked: a hand over it - and, where it leads somewhere else (``font``), underlined."""
        c, feed = self.feed.canvas, self.feed

        def over(on: bool) -> None:
            try:
                c.configure(cursor="hand2" if on else "")
                if font:
                    c.itemconfigure(item, font=feed.lined(font) if on else font)
            except tk.TclError:
                pass

        c.tag_bind(item, "<Button-1>", lambda _e: go())
        c.tag_bind(item, "<Enter>", lambda _e: over(True))
        c.tag_bind(item, "<Leave>", lambda _e: over(False))

    def erase(self) -> None:
        self.feed.canvas.delete(self.tag)
        self._inks, self._pills, self._shown = [], [], []

    def draw(self, top: int) -> int:
        """Draw the row with its upper edge at ``top`` for the list's width - the text wraps under its own beginning -
        and tell how high it is."""
        c, width = self.feed.canvas, self.feed.width
        self.erase()
        body = tkfont.nametofont(theme.FONT, root=c)
        small = tkfont.nametofont(theme.FONT_CAPTION, root=c)
        strong = tkfont.nametofont(theme.FONT_CAPTION_BOLD, root=c)
        right = width - px(6)                      # where the row's shape ends (the scroll bar's side keeps a little air)
        arrow_x = right - px(16)
        x0, y0 = px(TEXT), top + px(7)
        room = max(px(120), arrow_x - px(14) - x0)
        mid = y0 + body.metrics("linespace") // 2
        self._text(px(TIME), mid, self.when, "muted", theme.FONT_CAPTION, anchor="w")
        self._text(px(DOT), mid, "●", self.dot, theme.FONT_CAPTION, anchor="w")
        # what happened - and what is unusual about it, as small outlined tags after it
        tags_wide = sum(strong.measure(m) + px(14) + px(8) for m in self.marks)
        title = self._text(x0, y0, self.what, "text", theme.FONT, anchor="nw", width=max(px(120), room - tags_wide), tags=("title",))
        if self.on_title is not None:
            self._link(title, self.on_title)
        box = c.bbox(title)
        x = box[2] + px(8)
        for mark in self.marks:
            w, h = strong.measure(mark) + px(14), strong.metrics("linespace") + px(2)
            image = rounded_image(c, w, h, h // 2, self._fill(), "warn")
            self._shown.append(image)
            self._pills.append((c.create_image(x, mid - h // 2, anchor="nw", image=image, tags=(self.tag,)), w, h))
            self._text(x + w // 2, mid, mark, "warn", theme.FONT_CAPTION_BOLD, anchor="center")
            x += w + px(8)
        # what kind of thing it is, whose, from where, with what
        y, x = box[3] + px(1), x0
        second, cut = [], False
        for text, role, bold, go in self.pieces:
            font = theme.FONT_CAPTION_BOLD if bold else theme.FONT_CAPTION
            left = arrow_x - px(10) - x
            shown = fit_text(text, left, font, c) if left > 0 else ""
            cut = cut or shown != text
            if not shown.strip() and text.strip():
                break
            item = self._text(x, y, shown, role, font, anchor="nw", tags=("second",))
            second.append(item)
            if go is not None:
                self._link(item, go, font)
            x += (strong if bold else small).measure(shown)
        if cut:   # what does not fit ends in an ellipsis: the whole line can be read by pointing at it
            for item in second:
                self.feed.tips.add(item, self.second())
        y += small.metrics("linespace")
        # what it is unfolded into: a rounded block under it
        if self.detail is not None:
            box_top = y + px(6)
            yy = box_top + px(6)
            for name, value in self.detail:
                self._text(x0 + px(12), yy, name, "muted", theme.FONT_CAPTION, "box", anchor="nw", tags=("detail",))
                item = self._text(x0 + px(90), yy, value, "text", theme.FONT_CAPTION, "box", anchor="nw", width=max(px(120), room - px(120)),
                                  tags=("detail", "value"))
                yy = c.bbox(item)[3] + px(3)
            y = yy + px(4)
            self._shape(x0, box_top, arrow_x - px(12), y, px(6), "heading_bg", "boxcorner", "boxfill")
            c.tag_raise(f"{self.tag}&&detail")
        bottom = y + px(7)
        if self.on_arrow is not None:
            arrow = self._text(arrow_x, mid, "⌄" if self.detail is not None else "›", "arrow", theme.FONT, anchor="center", tags=("arrow",))
            self._link(arrow, self.on_arrow)
        self._shape(0, top + px(1), right, bottom, px(RADIUS), self._fill(), "corner", "fill")
        c.tag_lower(f"{self.tag}&&fill")     # (the corners lie under the fill: a quarter's soft rim would show as a ring on it)
        c.tag_lower(f"{self.tag}&&corner")
        return bottom - top

    # ------------------------------------------------------------------ what it says (for whoever asks)
    def second(self) -> str:
        return "".join(text for text, _role, _bold, _go in self.pieces)

    def written(self) -> list[str]:
        return ([f"{self.when}\t{self.what}" + "".join(f"  [{mark}]" for mark in self.marks), self.second()]
                + [f"{name}\t{value}" for name, value in self.detail or []])

    def colour_of(self, part: str) -> str:
        """The colour something of the row is drawn in now ("title", "arrow", "value", "fill")."""
        c = self.feed.canvas
        return str(c.itemcget(c.find_withtag(f"{self.tag}&&{part}")[-1], "fill"))

    def arrow(self) -> str:
        c = self.feed.canvas
        return str(c.itemcget(c.find_withtag(f"{self.tag}&&arrow")[-1], "text"))

    def spot(self, text: str | None = None) -> tuple[int, int]:
        """Where on the canvas' window the row is (or, of it, what shows ``text``): a point to move the pointer to."""
        c = self.feed.canvas
        items = c.find_withtag(self.tag)
        if text is not None:
            items = tuple(i for i in items if c.type(i) == "text" and c.itemcget(i, "text") == text)
            if not items:
                raise LookupError(text)
            x0, y0, x1, y1 = c.bbox(items[0])
        else:
            x0, y0, x1, y1 = c.bbox(self.tag)
        return (x0 + x1) // 2, int((y0 + y1) // 2 - c.canvasy(0))

    def click(self, text: str) -> None:
        """Click what shows ``text`` (a link of the second line, the title, the arrow)."""
        c = self.feed.canvas
        x, y = self.spot(text)
        for event in ("<Motion>", "<Button-1>", "<ButtonRelease-1>"):
            c.event_generate(event, x=x, y=y)


class Feed(ttk.Frame):
    """The list: days and rows on one canvas, with its scroll bar (there only while the list does not fit)."""

    NOTCH = 100      # how far one notch of the wheel goes
    SCROLL_MS = 110  # ... and how long the way there takes (at once with animations off)

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, style="Card.TFrame")
        canvas = self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, background=theme.color("card"))
        bar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        shown = autoscroll(bar)

        def scrolled(first: str, last: str) -> None:
            shown(first, last)
            self._sync()

        canvas.configure(yscrollcommand=scrolled)
        canvas.grid(row=0, column=0, sticky="nsew")
        bar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, minsize=bar.winfo_reqwidth())   # its place is kept: the rows never change width
        self.items: list[Any] = []       # Day and Row, in order
        self.tops: list[int] = []        # where each item that has been laid out begins ...
        self.heights: list[int] = []     # ... and how high it is
        self.end = 0                     # where the next one will begin
        self.drawn: set[int] = set()     # the items drawn now (those near the part in view)
        self.width, self.seen = 0, 1.0
        self.end_note, self.end_go = "", None  # type: ignore[var-annotated]
        self._busy, self._hot, self._going, self._run = False, None, None, 0  # type: ignore[var-annotated]
        self.tips = Tips(canvas)   # the whole of whatever is shortened, under the pointer
        canvas.bind("<Configure>", self._sized, add="+")
        canvas.bind("<Motion>", lambda e: self._point(e.y), add="+")
        canvas.bind("<Leave>", lambda _e: self._point(None), add="+")
        canvas.bind("<MouseWheel>", self._wheel)
        canvas.bind("<<ThemeChanged>>", lambda _e=None: canvas.after_idle(self.redraw), add="+")

    # ------------------------------------------------------------------ what it holds
    def set(self, items: Sequence[Any], end_note: str = "", end_go: Callable[[], None] | None = None) -> None:
        """Another list: from its beginning. ``end_note``: what stands under its last row (``end_go``: a link)."""
        self.canvas.delete("all")
        self.tips.clear()
        self.items = list(items)
        for n, item in enumerate(self.items):
            item.tag, item.feed = f"i{n}", self
        self.tops, self.heights, self.end, self.drawn, self._hot, self._going = [], [], 0, set(), None, None
        self.end_note, self.end_go = end_note, end_go
        self.canvas.configure(scrollregion=(0, 0, 1, 1))
        self.canvas.yview_moveto(0)
        self._sync()

    @property
    def rows(self) -> list[Row]:
        """The rows drawn now, from the top."""
        return [self.items[i] for i in sorted(self.drawn) if isinstance(self.items[i], Row)]

    def row_of(self, ref: Any) -> Row | None:
        return next((item for item in self.items if isinstance(item, Row) and item.line is not None and item.line.ref == ref), None)

    def written(self) -> str:
        """What is drawn of the list, as text - and what stands under it."""
        out: list[str] = []
        for i in sorted(self.drawn):
            out += self.items[i].written()
        note = self.canvas.find_withtag("note")
        if note:
            out.append(str(self.canvas.itemcget(note[0], "text")))
        return "\n".join(out) + "\n"

    def lined(self, font: str) -> tkfont.Font:
        return theme.underlined(self.canvas, font)   # (exactly as large as the font itself: see there)

    def plain_ink(self, role: str) -> str:
        colour = theme.color(role)
        return colour if self.seen >= 1 else theme.mix(theme.color("card"), colour, max(0.0, self.seen))

    # ------------------------------------------------------------------ laying out and drawing what is in view
    def _sized(self, event: tk.Event) -> None:
        if event.width > 1 and event.width != self.width:
            self.width = event.width
            self.redraw()
        else:
            self._sync()

    def redraw(self) -> None:
        """Everything that is drawn, anew (another width, another theme)."""
        self.canvas.configure(background=theme.color("card"))
        self._place(sorted(self.drawn))
        self._sync()

    def _place(self, indices: Sequence[int]) -> None:
        """Draw these items (in order) where they belong. One that turns out higher or lower than it was moves all
        that comes after it - and, where that is above the part in view, the view with it: the reader stays put."""
        if not indices:
            return
        c, first = self.canvas, indices[0]
        view_top = c.canvasy(0)
        wanted, moved, above = set(indices), 0, 0
        for i in range(first, len(self.tops)):
            if not moved and i > indices[-1]:
                break
            if moved:
                self.tops[i] += moved
                if i in self.drawn and i not in wanted:
                    c.move(self.items[i].tag, 0, moved)
            if i in wanted:
                high = self.items[i].draw(self.tops[i])
                self.drawn.add(i)
                if high != self.heights[i]:
                    if self.tops[i] + self.heights[i] <= view_top:
                        above += high - self.heights[i]
                    moved += high - self.heights[i]
                    self.heights[i] = high
        self.end += moved
        if moved:
            self._region()
        if above:
            c.yview_moveto((view_top + above) / max(1, self._total()))

    def _total(self) -> int:
        return self.end + px(44 if self._note_text()[0] else 10)

    def _note_text(self) -> tuple[str, Callable[[], None] | None]:
        return (GOES_ON, None) if len(self.tops) < len(self.items) else (self.end_note, self.end_go)

    def _region(self) -> None:
        """How far the list reaches, and what stands under its last row."""
        c = self.canvas
        c.delete("note")
        text, go = self._note_text()
        if text:
            role = "link" if go else "muted"
            item = c.create_text(px(8), self.end + px(12), text=text, anchor="nw", font=theme.FONT_CAPTION, fill=self.plain_ink(role),
                                 tags=("note", f"plain-{role}"))
            if go:
                c.tag_bind(item, "<Button-1>", lambda _e: go())
                c.tag_bind(item, "<Enter>", lambda _e: (c.configure(cursor="hand2"), c.itemconfigure(item, font=self.lined(theme.FONT_CAPTION))))
                c.tag_bind(item, "<Leave>", lambda _e: (c.configure(cursor=""), c.itemconfigure(item, font=theme.FONT_CAPTION)))
        c.configure(scrollregion=(0, 0, max(1, self.width), self._total()))

    def _sync(self) -> None:
        """Have drawn what is in and near the part in view - laying the list out further where its end comes near -
        and nothing that is far from it."""
        if self._busy or self.width <= 1:
            return
        self._busy = True
        try:
            c = self.canvas
            top, high = c.canvasy(0), max(1, c.winfo_height())
            lo, hi = top - high, top + 2 * high
            grew = False
            while self.end < hi and len(self.tops) < len(self.items):   # the list goes on
                i = len(self.tops)
                self.tops.append(self.end)
                self.heights.append(self.items[i].draw(self.end))
                self.drawn.add(i)
                self.end += self.heights[i]
                grew = True
            first = max(0, bisect.bisect_right(self.tops, lo) - 1)
            last = bisect.bisect_left(self.tops, hi)
            self._place([i for i in range(first, min(last, len(self.tops))) if i not in self.drawn])
            for i in [i for i in self.drawn if self.tops[i] + self.heights[i] < top - 3 * high or self.tops[i] > top + 4 * high]:
                self.items[i].erase()
                self.drawn.discard(i)
            if grew or not c.find_withtag("note") and self._note_text()[0]:
                self._region()
        except tk.TclError:
            pass
        finally:
            self._busy = False

    def refresh(self, row: Row, fresh: bool = False) -> None:
        """A row has changed (it was unfolded, or folded again): draw it anew where it stands; what is under it makes
        room. ``fresh``: what it unfolded into comes out of its ground."""
        index = self.items.index(row)
        if index >= len(self.tops):
            return
        if fresh and theme.animations():
            row.new = 0.0
        self._place([index])
        self._region()
        self._sync()
        if fresh:
            if row._fresh is None:
                row._fresh = Glide(self.canvas, row._came, ms=220, back=1)
            row._fresh.at, row._fresh.goal = row.new, row.new
            row._fresh.to(1)

    # ------------------------------------------------------------------ appearing
    def appear(self, t: float) -> None:
        """How far what is written has come out of its ground (0: not to be seen, 1: there)."""
        self.seen = max(0.0, min(1.0, t))
        try:
            for i in self.drawn:
                if isinstance(self.items[i], Row):
                    self.items[i].recolour()
            for role in ("muted", "link"):
                for item in self.canvas.find_withtag(f"plain-{role}"):
                    self.canvas.itemconfigure(item, fill=self.plain_ink(role))
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ the pointer, the wheel
    def _point(self, y: int | None) -> None:
        """The pointer is at ``y`` of the window (None: gone): the row under it lights up, the one before lets go."""
        row = None
        if y is not None and self.tops:
            at = self.canvas.canvasy(y)
            i = bisect.bisect_right(self.tops, at) - 1
            if 0 <= i < len(self.tops) and i in self.drawn and at < self.tops[i] + self.heights[i] and isinstance(self.items[i], Row):
                row = self.items[i]
        if row is not self._hot:
            if self._hot is not None and self._hot.feed is self:
                self._hot.light(False)
            self._hot = row
            if row is not None:
                row.light(True)

    def _wheel(self, event: tk.Event) -> str:
        start = self._going if self._going is not None else self.canvas.canvasy(0)
        self.scroll_to(start + (-1 if event.delta > 0 else 1) * px(self.NOTCH))
        return "break"

    def scroll_to(self, top: float) -> None:
        """Move softly until ``top`` is at the upper edge - as far as the list goes."""
        c = self.canvas
        try:
            total, high = self._total(), c.winfo_height()
            if total <= high:
                return
            goal = max(0.0, min(float(total - high), float(top)))
            begin = float(c.canvasy(0))
            self._going = goal
            self._run = run = self._run + 1
        except tk.TclError:
            return

        def step(t: float) -> None:
            if run != self._run:
                return
            c.yview_moveto((begin + (goal - begin) * t) / max(1, self._total()))
            if t >= 1.0:
                self._going = None

        theme.animate(c, self.SCROLL_MS, step)
