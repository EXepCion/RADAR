"""Where an account's devices were, drawn to scale (the Movement card): time across, a lane for every device, and in
it a bar for every stay at one place, in the colour of the place - the place's name on the bar where it has room.

Twenty-four hours fill the chart's width, whatever that is; what came before is reached by moving the chart sideways:
dragging it (let go while it moves and it rolls on, slowing down by itself, until a click, the wheel or another drag
stops it), the mouse wheel, the arrow keys, its scroll bar. The card's "Now" brings it back to the end. The names of
the devices stay where they are, and so does a dotted line near the right edge with the time it stands at: the chart
moves under it.

A line every three hours, a time every six, the day's name at midnight. Under the chart the places and their colours.

A device's name is a link to the device's page (the name of what is not one device - the unregistered devices of a
system, the sign-ins that name none - is not). Taking hold of the chart is done on the chart, never on the names: a
click on a name takes no hold of it, and letting go of the chart over a name is no click on it.

It is drawn on a canvas, and only what is near the part in view: seven days of a busy phone are many bars.
"""
from __future__ import annotations

import math
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timedelta
from tkinter import ttk
from typing import Any, Callable

from .. import timefmt
from . import theme
from .bits import fit_text, stepped
from .parts import Tips
from .rounded import rounded_image
from .theme import px

NAMES, NAMES_NARROW, NARROW = 140, 100, 420   # the column of the devices' names - narrower in a narrow chart
GAP = 8              # between the names and the chart
TOP = 24             # the band of the times, above the lanes
LANE, BAR, RADIUS = 40, 18, 5
LEAST = 3            # a bar is at least this wide: a stay of minutes is seen too
ROOM = 18            # after now: the dotted line stands clear of the edge
VIEW = 24            # hours in view
NOTCH, KEY = 100, 40     # how far a notch of the wheel and an arrow key move the chart ...
SCROLL_MS, END_MS = 110, 420   # ... and how long that takes; and the way back to now
DECAY = 0.996        # what a roll keeps of its speed every millisecond
PUSH, REST = 0.1, 0.02   # px a ms (at 100 %): let go slower than PUSH is no push; slower than REST a roll is over
STILL_MS = 80        # held still this long before letting go: no push
PLACES = ("place1", "place2", "place3", "place4", "place5")
OTHER = "place_other"
SWATCH = (14, 8)


class Lanes(tk.Frame):
    """The chart of a ``search.Movement``. ``on_view(said, at_end)`` is told what is in view whenever that changes:
    the heading's words for it - the whole ("the last 24 hours · times in UTC+1"), then ever shorter forms for less
    room, each with its zone - and whether it is the end (now). ``on_device(device id, name)``: a device's name was
    clicked (without it the names are no links)."""

    def __init__(self, parent: tk.Misc, movement: Any, on_view: Callable[[tuple[str, ...], bool], None] | None = None,
                 background: str = "card", on_device: Callable[[str, str], None] | None = None):
        super().__init__(parent, background=theme.color(background), bd=0, highlightthickness=0)
        self.moves, self.on_view, self.on_device, self._back = movement, on_view, on_device, background
        self.now: datetime = movement.now
        self.lanes = list(movement.lanes)
        self.places = list(movement.places)
        self.role = {p.key: PLACES[i] if i < len(PLACES) else OTHER for i, p in enumerate(self.places)}
        self.place = {p.key: p for p in self.places}
        earliest = min((run.begin for lane in self.lanes for run in lane.runs), default=self.now)
        self.first = max(movement.since, earliest - timedelta(hours=1))   # where the chart begins: a little before the first stay
        self.scrolls = self.now - self.first > timedelta(hours=VIEW)
        self.seen = 1.0                       # how far it has come out of its ground (see appear)
        self.offset, self.most, self.total = 0, 0, 1   # px: the part in view begins at offset, of a chart total px wide
        self.at_end, self.right = True, None  # in view: the end (now) - or else the time at the right edge (kept through a resize)
        self.wide, self.names, self.stage_x, self.stage, self.per_hour = 0, 0, 0, 1, 1.0
        self.t0 = self.first
        self.said = ""
        self._window = (0.0, 0.0)             # the part of the chart drawn (px, around the part in view)
        self._run, self._going, self._grab, self._speed = 0, None, None, 0.0
        self._inks: list[tuple[tk.Canvas, int, str]] = []        # what is drawn, with its palette role ...
        self._pics: list[tuple] = []          # ... and its pictures: (canvas, item, width, height, radius, role)
        self._track_inks: list[tuple[tk.Canvas, int, str]] = []  # (of the part that moves, drawn anew as it moves)
        self._track_pics: list[tuple] = []
        self._shown: dict[tuple[tk.Canvas, int], Any] = {}   # the picture each item shows (whoever shows one holds it)
        self._bar_text: dict[str, str] = {}   # what a bar stands for (its tag -> what pointing at it says) ...
        self._bar_role: dict[str, str] = {}   # ... and its colour
        self._cursor = ""
        self._pointer_x = -1                  # where the pointer was last seen on the chart (px from its left edge) ...
        self._hover: int | None = None        # ... and the device's name under it (its item), if one is

        c = self.chart = tk.Canvas(self, highlightthickness=0, bd=0, background=theme.color(background), height=self._high(), takefocus=1)
        c.pack(fill="x")
        self.bar = ttk.Scrollbar(self, orient="horizontal", command=self.xview)
        if self.scrolls:
            self.bar.pack(fill="x", padx=(px(NAMES) + px(GAP), 0), pady=(px(2), 0))
        self.legend = tk.Canvas(self, highlightthickness=0, bd=0, background=theme.color(background), height=1)
        self.legend.pack(fill="x", pady=(px(10), 0))
        self.tips, self.legend_tips = Tips(c), Tips(self.legend)   # the whole of whatever is shortened - and a bar's place and times
        c.bind("<Configure>", lambda e: self.draw(e.width) if e.width != self.wide else None)
        self.legend.bind("<Configure>", lambda _e: self._legend())
        for widget in (c, self.legend):
            widget.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self.draw), add="+")
        c.bind("<ButtonPress-1>", self._press)
        c.bind("<B1-Motion>", self._drag)
        c.bind("<ButtonRelease-1>", self._release)
        c.bind("<Motion>", self._point, add="+")
        c.bind("<MouseWheel>", self._wheel)
        c.bind("<Shift-MouseWheel>", self._wheel)
        c.bind("<Left>", lambda _e: self._key(-1))
        c.bind("<Right>", lambda _e: self._key(+1))
        c.tag_bind("bar", "<Enter>", self._over_bar)
        c.tag_bind("bar", "<Leave>", lambda _e: self.tips.hint.hide())

    def _high(self) -> int:
        return px(TOP) + len(self.lanes) * px(LANE) + px(4)

    # ------------------------------------------------------------------ time and place on the chart
    def _x(self, t: datetime) -> int:
        """Where a time is on the whole chart (px from its beginning)."""
        return round((t - self.t0).total_seconds() / 3600 * self.per_hour)

    def _time(self, x: float) -> datetime:
        return self.t0 + timedelta(hours=x / self.per_hour)

    # ------------------------------------------------------------------ colours, and appearing
    def _colour(self, role: str) -> str:
        if role == "mark":   # (the dotted line: the text colour, half way to the card's)
            return theme.mix(theme.color(self._back), theme.color("text"), 0.5)
        return theme.role_color("on_accent") if role == "on_bar" else theme.color(role)

    def _ink(self, role: str) -> str:
        colour = self._colour(role)
        return colour if self.seen >= 1 else theme.mix(theme.color(self._back), colour, max(0.0, self.seen))

    def _picture(self, canvas: tk.Canvas, width: int, high: int, radius: int, role: str) -> Any:
        return rounded_image(canvas, width, high, radius, role if self.seen >= 1 else self._ink(role))

    def _image(self, canvas: tk.Canvas, x: float, y: float, width: int, high: int, radius: int, role: str, track: bool = False, **kw: Any) -> int:
        image = self._picture(canvas, width, high, radius, role)
        item = canvas.create_image(x, y, anchor="nw", image=image, **kw)
        self._shown[(canvas, item)] = image
        (self._track_pics if track else self._pics).append((canvas, item, width, high, radius, role))
        return item

    def appear(self, t: float) -> None:
        """How far what is drawn has come out of its ground (0: not to be seen, 1: there)."""
        self.seen = stepped(max(0.0, min(1.0, t)))
        try:
            for canvas, item, role in self._inks + self._track_inks:
                canvas.itemconfigure(item, fill=self._ink(role))
            for canvas, item, width, high, radius, role in self._pics + self._track_pics:
                self._shown[(canvas, item)] = self._picture(canvas, width, high, radius, role)
                canvas.itemconfigure(item, image=self._shown[(canvas, item)])
        except tk.TclError:
            pass

    def _text(self, canvas: tk.Canvas, x: float, y: float, text: str, role: str, font: str, track: bool = False, **kw: Any) -> int:
        item = canvas.create_text(x, y, text=text, font=font, fill=self._ink(role), **kw)
        (self._track_inks if track else self._inks).append((canvas, item, role))
        return item

    def _rect(self, canvas: tk.Canvas, x0: float, y0: float, x1: float, y1: float, role: str, track: bool = False, **kw: Any) -> int:
        item = canvas.create_rectangle(x0, y0, x1, y1, outline="", fill=self._ink(role), **kw)
        (self._track_inks if track else self._inks).append((canvas, item, role))
        return item

    def _round(self, canvas: tk.Canvas, x0: int, y0: int, width: int, high: int, r: int, role: str, track: bool = False, **kw: Any) -> None:
        """A rectangle with round corners, smooth (pictures - a canvas draws its own curves in steps) and in as few
        parts as can be: every part is drawn anew whenever the chart moves. A narrow one is one picture of its own
        width (there are a few such widths only); a wider one an end at either side - one picture for all bars - and
        the colour between them."""
        r = max(1, min(r, width // 2, high // 2))
        ends = ((x0, width),) if width <= 2 * r + 2 else ((x0, 2 * r), (x0 + width - 2 * r, 2 * r))
        for x, wide in ends:
            self._image(canvas, x, y0, wide, high, r, role, track, **kw)
        if len(ends) == 2:   # (the colour between them goes on top: the ends' inner corners are under it)
            self._rect(canvas, x0 + r, y0, x0 + width - r, y0 + high, role, track, **kw)

    # ------------------------------------------------------------------ drawing
    def draw(self, width: int | None = None) -> None:
        """Everything anew, for the width it has: what was in view stays in view (the end stays the end)."""
        c = self.chart
        try:
            width = width or c.winfo_width()
            if width <= 1:
                return
            self._stop()   # (what was moving it measured in the pixels of before)
            keep = None if self.at_end else self.right
            self.wide = width
            self.names = px(NAMES_NARROW) if width < px(NARROW) else px(NAMES)
            self.stage_x = self.names + px(GAP)
            self.stage = max(px(40), width - self.stage_x)
            self.per_hour = self.stage / VIEW
            self.t0 = min(self.first, self.now - timedelta(hours=VIEW - px(ROOM) / self.per_hour))
            self.total = self._x(self.now) + px(ROOM)
            self.most = max(0, self.total - self.stage)
            self.offset = self.most if keep is None else max(0, min(self.most, self._x(keep) - self.stage))
            if self.scrolls and self.bar.winfo_manager():
                self.bar.pack_configure(padx=(self.stage_x, 0))
            c.delete("all")
            self.tips.clear()
            self._inks, self._pics, self._track_inks, self._track_pics = [], [], [], []
            self._shown = {key: image for key, image in self._shown.items() if key[0] is not c}
            high = self._high()
            if int(c.cget("height")) != high:
                c.configure(height=high)
            c.configure(background=theme.color(self._back))
            # the middle line of every lane (under the bars)
            for i in range(len(self.lanes)):
                y = px(TOP) + i * px(LANE) + px(LANE) // 2
                item = c.create_line(self.stage_x, y, width, y, fill=self._ink("grid"), tags=("lane",))
                self._inks.append((c, item, "grid"))
            self._track()
            # the names, over what moves under them - a device's name a link to its page
            self._rect(c, 0, 0, self.stage_x, high, self._back, tags=("cover",))
            self._hover = None   # (what was under the pointer is drawn anew: the chart finds what is under it now)
            bold, small = tkfont.nametofont(theme.FONT_TABLE_BOLD, root=c), tkfont.nametofont(theme.FONT_CAPTION, root=c)
            for i, lane in enumerate(self.lanes):
                mid = px(TOP) + i * px(LANE) + px(LANE) // 2
                top = mid - (bold.metrics("linespace") + small.metrics("linespace")) // 2
                device = self.on_device is not None and bool(lane.key) and not lane.key.startswith("os:")
                for n, (text, font, role, y) in enumerate(((lane.name, theme.FONT_TABLE_BOLD, "text", top),
                                                           (lane.kind, theme.FONT_CAPTION, "muted", top + bold.metrics("linespace")))):
                    shown = fit_text(text, self.names, font, c)
                    link = device and n == 0   # (the name; not the line under it)
                    item = self._text(c, 0, y, shown, role, font, anchor="nw", tags=("name", "link") if link else ("name",))
                    if link:
                        self._link(item, lane.key, lane.name)
                    if shown != text:   # (after the link's bindings: the note adds to them)
                        self.tips.add(item, text)
            # the line that stands still while the chart moves under it, and the time it stands at
            x = width - px(ROOM)
            step, dot = px(4), max(1, px(2))
            for y in range(px(18), high, step):
                self._rect(c, x - dot // 2, y, x - dot // 2 + dot, min(high, y + dot), "mark", tags=("mark", "dots"))
            self._rect(c, 0, 0, 0, 0, self._back, tags=("mark", "at_ground"))
            self._text(c, width - px(12) - px(5), px(8), "", "text", theme.FONT_CAPTION_BOLD, anchor="e", tags=("mark", "at"))
            self._legend()
            self._view()
            self._show_cursor()
        except tk.TclError:
            pass

    def _link(self, item: int, device_id: str, name: str) -> None:
        """A device's name: a click on it opens the device's page; under the pointer a hand, and the name underlined -
        in a font exactly as large as its own (theme.underlined): a name that grew or shrank under the pointer could
        leave it and come back under it without end."""
        c = self.chart

        def over(on: bool) -> None:
            if on or self._hover == item:
                self._hover = item if on else None
            try:
                c.itemconfigure(item, font=theme.underlined(c, theme.FONT_TABLE_BOLD) if on else theme.FONT_TABLE_BOLD)
            except tk.TclError:
                return
            self._show_cursor()

        c.tag_bind(item, "<Button-1>", lambda _e: self.on_device(device_id, name) if self.on_device is not None else None)
        c.tag_bind(item, "<Enter>", lambda _e: over(True))
        c.tag_bind(item, "<Leave>", lambda _e: over(False))

    def _track(self) -> None:
        """What moves: the lines and times of the hours and days, and the bars - those near the part in view."""
        c = self.chart
        for _canvas, item, *_rest in self._track_pics:
            self._shown.pop((c, item), None)
        c.delete("track")
        self._track_inks, self._track_pics, self._bar_text, self._bar_role = [], [], {}, {}
        lo, hi = self.offset - self.stage, self.offset + 2 * self.stage
        self._window = (lo, hi)
        high, top = self._high(), px(TOP)

        def at(x: int) -> int:
            return self.stage_x + x - self.offset

        # a line every three hours, a time every six, a stronger line and the day's name at midnight (local time)
        day = self._time(max(0, lo)).astimezone().date() - timedelta(days=1)
        last = min(self.now, self._time(hi)).astimezone().date()
        while day <= last:
            for hour in range(0, 24, 3):
                t = datetime(day.year, day.month, day.day, hour).astimezone()
                x = self._x(t)
                if t < self.t0 or t > self.now or not lo <= x <= hi:
                    continue
                midnight = hour == 0
                item = c.create_line(at(x), px(4) if midnight else top - px(6), at(x), high, fill=self._ink("grid_strong" if midnight else "grid"),
                                     tags=("track", "hours"))
                self._track_inks.append((c, item, "grid_strong" if midnight else "grid"))
                if midnight:
                    self._text(c, at(x) + px(5), px(10), t.strftime("%a"), "text", theme.FONT_CAPTION_BOLD, True, anchor="w", tags=("track", "day"))
                elif hour % 6 == 0:
                    self._text(c, at(x) + px(4), px(10), timefmt.clock_bare(t), "muted", theme.FONT_CAPTION, True, anchor="w", tags=("track", "hour"))
            day += timedelta(days=1)
        # the bars: a stay at a place, as long as it lasted (at least LEAST), in the place's colour - and its name where it fits
        bold = tkfont.nametofont(theme.FONT_CAPTION_BOLD, root=c)
        for i, lane in enumerate(self.lanes):
            y = px(TOP) + i * px(LANE) + (px(LANE) - px(BAR)) // 2
            for n, run in enumerate(lane.runs):
                a = self._x(run.begin)
                b = max(a + px(LEAST), self._x(run.end))
                if b < lo or a > hi:
                    continue
                tag, place = f"b{i}.{n}", self.place[run.place]
                self._round(c, at(a), y, b - a, px(BAR), px(RADIUS), self.role[run.place], True, tags=("track", "bar", tag))
                if b - a >= bold.measure(place.short) + px(14):
                    self._text(c, at(a) + px(7), y + px(BAR) // 2, place.short, "on_bar", theme.FONT_CAPTION_BOLD, True, anchor="w",
                               tags=("track", "bar", tag, "barname"))
                self._bar_text[tag] = " · ".join(p for p in (lane.name, place.label, timefmt.span(run.begin, run.end), run.network) if p)
                self._bar_role[tag] = self.role[run.place]
        for layer in ("cover", "name", "mark"):
            c.tag_raise(layer)

    def _legend(self) -> None:
        """The places and their colours, in as many rows as they need - the places beyond the colours as one entry."""
        g = self.legend
        try:
            width = g.winfo_width() if g.winfo_width() > 1 else self.wide
            if width <= 1:
                return
            g.delete("all")
            self.legend_tips.clear()
            g.configure(background=theme.color(self._back))
            self._inks = [x for x in self._inks if x[0] is not g]
            self._pics = [x for x in self._pics if x[0] is not g]
            self._shown = {key: image for key, image in self._shown.items() if key[0] is not g}
            font = tkfont.nametofont(theme.FONT_CAPTION, root=g)
            row = font.metrics("linespace") + px(4)
            sw, sh = px(SWATCH[0]), px(SWATCH[1])
            named, rest = self.places[:len(PLACES)], self.places[len(PLACES):]
            entries = [(self.role[p.key], p.label, "") for p in named]
            if rest:
                entries.append((OTHER, f"{len(rest)} other place{'s' if len(rest) > 1 else ''}", ", ".join(p.label for p in rest)))
            x = y = 0
            for role, text, more in entries:
                need = sw + px(6) + font.measure(text)
                if x and x + need > width:
                    x, y = 0, y + row
                shown = fit_text(text, max(px(20), width - x - sw - px(6)), theme.FONT_CAPTION, g)
                self._image(g, x, y + (row - px(4) - sh) // 2, sw, sh, sh // 2, role, tags=("swatch",))
                words = self._text(g, x + sw + px(6), y + (row - px(4)) // 2, shown, "muted", theme.FONT_CAPTION, anchor="w", tags=("place",))
                if shown != text or more:
                    self.legend_tips.add(words, more or text)
                x += sw + px(6) + font.measure(shown) + px(16)
            high = y + row - px(4)
            if int(g.cget("height")) != high:
                g.configure(height=high)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ what is in view
    def _view(self) -> None:
        """What is in view has changed: the time under the dotted line, the scroll bar, the heading's words."""
        c = self.chart
        self.at_end = self.offset >= self.most - px(2)
        self.right = None if self.at_end else self._time(self.offset + self.stage)
        at = self.now if self.at_end else min(self.now, self._time(self.offset + self.stage - px(ROOM)))
        try:
            c.itemconfigure("at", text=timefmt.weekday_bare(at))
            box = c.bbox("at")
            if box:
                c.coords("at_ground", box[0] - px(5), 0, self.wide - px(12), px(16))
        except tk.TclError:
            return
        if self.scrolls:
            self.bar.set(self.offset / self.total, min(1.0, (self.offset + self.stage) / self.total))
        if self.at_end:
            zone = timefmt.zone(self.now.astimezone())
            forms = (f"the last {VIEW} hours · times in {zone}", f"the last {VIEW} hours, {zone}", f"last {VIEW} h, {zone}", zone)
        else:
            a = self._time(self.offset)
            b = min(self.now, a + timedelta(hours=VIEW))
            za, zb = timefmt.zone(a.astimezone()), timefmt.zone(b.astimezone())
            first, last = timefmt.weekday_bare(a), timefmt.weekday_bare(b)
            forms = ((f"{first} – {last} · times in {zb}", f"{first} – {last} {zb}") if za == zb else (f"{first} {za} – {last} {zb}",)) + (
                f"from {first} {za}", zb)
        if forms[0] != self.said:
            self.said = forms[0]
            if self.on_view is not None:
                self.on_view(forms, self.at_end)

    def _go(self, offset: float) -> int:
        """Have the part from ``offset`` in view (as far as the chart goes); returns where it is now."""
        goal = round(max(0, min(self.most, offset)))
        moved = self.offset - goal
        if moved:
            self.offset = goal
            try:
                self.chart.move("track", moved, 0)
                lo, hi = self._window
                if goal < lo or goal + self.stage > hi:   # beyond what is drawn: draw what is near
                    self._track()
            except tk.TclError:
                return goal
            self._view()
        return goal

    def xview(self, *args: Any) -> Any:
        """(What the scroll bar calls)."""
        if not args:
            return self.offset / self.total, min(1.0, (self.offset + self.stage) / self.total)
        self._stop()
        if args[0] == "moveto":
            self._go(float(args[1]) * self.total)
        elif args[0] == "scroll":
            self._go(self.offset + int(args[1]) * (self.stage if args[2] == "pages" else px(KEY)))
        return None

    # ------------------------------------------------------------------ moving it
    def _stop(self) -> None:
        """Whatever is moving the chart stops where it is."""
        self._run += 1
        self._going = None

    def scroll_to(self, offset: float, ms: int = SCROLL_MS) -> None:
        """Move softly until the part from ``offset`` is in view (at once with animations off)."""
        goal = max(0, min(self.most, round(offset)))
        begin = self.offset
        self._stop()
        self._going, run = goal, self._run

        def step(t: float) -> None:
            if run != self._run:
                return
            self._go(begin + (goal - begin) * t)
            if t >= 1.0:
                self._going = None

        theme.animate(self.chart, ms, step)

    def to_end(self) -> None:
        """Back to now (the card's "Now")."""
        self.scroll_to(self.most, END_MS)

    def _wheel(self, event: tk.Event) -> str | None:
        """The wheel over the chart turns it sideways: towards earlier days up, towards now down."""
        if self.most <= 0:
            return None
        start = self._going if self._going is not None else self.offset
        self.scroll_to(start + (-1 if event.delta > 0 else 1) * px(NOTCH))
        return "break"

    def _key(self, way: int) -> str:
        if self.most > 0:
            start = self._going if self._going is not None else self.offset
            self.scroll_to(start + way * px(KEY))
        return "break"

    def _point(self, event: tk.Event) -> None:
        self._pointer_x = event.x
        self._show_cursor()

    def _show_cursor(self) -> None:
        """Over the chart, where it can be moved, the pointer says so - and over a device's name that it is a link. (What
        has been taken hold of is moved, whatever the pointer is over.)"""
        movable = self.most > 0 and self._pointer_x >= self.stage_x
        cursor = "fleur" if self._grab is not None else "hand2" if self._hover is not None else "fleur" if movable else ""
        if cursor != self._cursor:
            self._cursor = cursor
            try:
                self.chart.configure(cursor=cursor)
            except tk.TclError:
                pass

    def _press(self, event: tk.Event) -> None:
        """A click stops what moves and takes the note away (Tips' own <ButtonPress> is not called: this binding is the
        more particular one); on the chart it takes hold of it (on the names it does not: a name is a link)."""
        self._stop()
        self.tips.hint.hide()
        self.chart.focus_set()
        if self.most > 0 and event.x >= self.stage_x and self._hover is None:
            self._grab = dict(x=event.x, offset=self.offset, at=event.time, last=event.x)
            self._speed = 0.0

    def _drag(self, event: tk.Event) -> None:
        """The chart follows the pointer - and how fast it goes is kept (px a ms, smoothed) for when it is let go."""
        grab = self._grab
        if grab is None:
            return
        self._go(grab["offset"] - (event.x - grab["x"]))
        passed = event.time - grab["at"]
        if passed > 0:
            self._speed = 0.7 * (event.x - grab["last"]) / passed + 0.3 * self._speed
        grab["at"], grab["last"] = event.time, event.x

    def _release(self, event: tk.Event) -> None:
        """Let go while it moves: it rolls on. Held still before: it stays."""
        grab, self._grab = self._grab, None
        self._pointer_x = event.x
        self._show_cursor()   # (let go over a name: a hand again - it was no click on it)
        if grab is not None and event.time - grab["at"] <= STILL_MS:
            self._roll(self._speed)

    def _roll(self, speed: float) -> None:
        """Roll on like a wheel that was given a push (``speed`` px a ms; to the right: towards earlier), losing a
        little of its speed every moment, until it is too slow to see - or at an end. Not with animations off."""
        scale = px(100) / 100
        if not theme.animations() or abs(speed) < PUSH * scale:
            return
        ln = math.log(DECAY)
        ms = math.log(REST * scale / abs(speed)) / ln       # until it is too slow to see
        whole = 1 - DECAY ** ms
        far = speed * whole / -ln                            # ... and how far it goes till then
        start = self.offset
        self._stop()
        run = self._run

        def step(p: float) -> None:
            if run != self._run:
                return
            goal = start - far * p
            self._go(goal)
            if goal <= 0 or goal >= self.most:   # at an end: it stops there
                self._stop()

        theme.animate(self.chart, max(1, round(ms)), step, ease=lambda u: (1 - DECAY ** (u * ms)) / whole)

    def _over_bar(self, _event: tk.Event) -> None:
        current = self.chart.find_withtag("current")
        tag = next((t for t in self.chart.gettags(current[0]) if t in self._bar_text), None) if current else None
        if tag is not None:
            self.tips.show_for(self._bar_text[tag])

    # ------------------------------------------------------------------ what it shows (for whoever asks)
    def written(self, tag: str = "") -> list[str]:
        """The texts drawn on the chart ("name", "day", "hour", "barname", "at"), from the left."""
        c = self.chart
        items = [i for i in (c.find_withtag(tag) if tag else c.find_all()) if c.type(i) == "text"]
        return [str(c.itemcget(i, "text")) for i in sorted(items, key=lambda i: (c.coords(i)[0], c.coords(i)[1]))]

    def bars(self) -> list[tuple[str, int, int, str]]:
        """(what pointing at it says, left, right, colour) of every bar drawn, from the left - in canvas pixels."""
        c, out = self.chart, []
        for tag, text in self._bar_text.items():
            x0, _y0, x1, _y1 = c.bbox(tag)
            out.append((text, x0, x1, self._ink(self._bar_role[tag])))
        return sorted(out, key=lambda b: b[1])
