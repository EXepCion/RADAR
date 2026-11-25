"""Small pieces the Search page and the pages about one thing are drawn with: pill and round buttons, filter pills,
outlined tags, a badge for what a row is about (initials, an icon), a dot, the chart of sign-ins per day, a text that
flows - and what makes them answer to the pointer: a value that glides (hover, selection and focus fade instead of
jumping), rows of a text that light up, links that underline.

All of them are drawn from palette colours through images that follow a theme switch (see theme._themed). What
moves, moves in a few fixed steps between two palette colours and is at rest on a palette colour again; with
animations switched off (Settings > Appearance) everything changes at once.
"""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from typing import Any, Callable, Sequence

from . import theme
from .rounded import background_of, rounded_image, tone
from .theme import px

STEPS = 8            # the steps between two colours (every step of a drawn shape is an image)
HOVER_MS = 90        # how long it takes to answer to the pointer ...
RELEASE = 2.0        # ... and how many times as long to let go again: quick to answer, gentle to leave
SHORTEST = 40        # ms: no movement is shorter than this
LIT = 0.05           # how far a row under the pointer goes toward the text colour


def stepped(t: float) -> float:
    """``t`` on one of the fixed steps between 0 and 1 (and beyond, for values that glide further)."""
    return round(t * STEPS) / STEPS


def between(roles: Sequence[str], t: float) -> str:
    """The colour at ``t`` along palette roles (0 = the first, 1 = the second ...): the role itself where ``t`` rests
    on one, a colour between two of them on the way."""
    t = max(0.0, min(float(len(roles) - 1), stepped(t)))
    i = min(int(t), len(roles) - 2)
    part = t - i
    if part == 0:
        return roles[i]
    if part == 1:
        return roles[i + 1]
    return theme.mix(tone(roles[i]), tone(roles[i + 1]), part)


class Glide:
    """A number that moves to where it is sent instead of jumping there; ``paint(value)`` draws each step. With
    animations off it is there at once."""

    def __init__(self, widget: tk.Misc, paint: Callable[[float], None], ms: int = HOVER_MS, back: int | None = None):
        self.widget, self.paint, self.ms = widget, paint, ms
        self.back = round(ms * RELEASE) if back is None else back   # going down (letting go) takes longer than going up
        self.at, self.goal, self._run = 0.0, 0.0, 0

    def duration(self, goal: float) -> int:
        """How long the way from where it is to ``goal`` takes: a way half as far takes half as long (a pointer that
        comes back before the fade is over does not wait for a whole one)."""
        far = min(1.0, abs(goal - self.at))
        return max(SHORTEST, round((self.ms if goal > self.at else self.back) * far))

    def jump(self, value: float) -> None:
        self._run += 1
        self.at = self.goal = float(value)
        try:
            self.paint(self.at)
        except tk.TclError:
            pass

    def to(self, goal: float) -> None:
        goal = float(goal)
        if goal == self.goal:
            return
        if not theme.animations():
            self.jump(goal)
            return
        self.goal = goal
        self._run += 1
        run, start = self._run, self.at

        def step(t: float) -> None:
            if run == self._run:
                self.at = start + (goal - start) * t
                self.paint(self.at)

        theme.animate(self.widget, self.duration(goal), step)


def watch_hover(parts: Sequence[tk.Misc], change: Callable[[bool], None]) -> None:
    """``change(True)`` when the pointer comes onto one of ``parts``, ``change(False)`` when it has left them all.
    (Going from one part to the next is no leaving: Tk reports a Leave for it, which would make the row blink.)"""
    parts, state = list(parts), {"on": False}

    def enter() -> None:
        if not state["on"]:
            state["on"] = True
            change(True)

    def check() -> None:
        try:
            first = parts[0]
            under = first.winfo_containing(*first.winfo_pointerxy())
        except (tk.TclError, KeyError, IndexError):
            under = None
        if state["on"] and under not in parts:
            state["on"] = False
            try:
                change(False)
            except tk.TclError:
                pass

    def leave(widget: tk.Misc) -> None:
        try:
            widget.after(1, check)
        except tk.TclError:
            pass

    for w in parts:
        w.bind("<Enter>", lambda _e: enter(), add="+")
        w.bind("<Leave>", lambda _e, w=w: leave(w), add="+")


def underline_on_hover(label: tk.Misc) -> None:
    """A link made of a label: underlined while the pointer is on it, with a hand."""
    def show(on: bool) -> None:
        try:
            if on:
                label._plain = label.cget("font")                                         # type: ignore[attr-defined]
                name = str(label._plain)                                                  # type: ignore[attr-defined]
                if not name:   # (a ttk label that leaves its font to its style)
                    from tkinter import ttk

                    name = str(ttk.Style(label).lookup(str(label.cget("style")) or label.winfo_class(), "font")) or theme.FONT
                label._lined = theme.underlined(label, name)   # type: ignore[attr-defined]  # (exactly as large: see there)
                label.configure(font=label._lined)                                        # type: ignore[attr-defined]
            elif getattr(label, "_plain", None) is not None:
                label.configure(font=label._plain)                                        # type: ignore[attr-defined]
        except tk.TclError:
            pass

    label.configure(cursor="hand2")
    label.bind("<Enter>", lambda _e: show(True), add="+")
    label.bind("<Leave>", lambda _e: show(False), add="+")


class Pill(tk.Canvas):
    """A button with fully round ends: a hairline edge, a word (or an icon in a circle), a hand over it. It darkens
    softly under the pointer, and a little more for the moment it is pressed."""

    FILLS = ("card", "menu_hover", "track")   # at rest, under the pointer, pressed

    def __init__(self, parent: tk.Misc, text: str, command: Callable[[], None], height: int = 32, icon: str = "", round_: bool = False):
        font = tkfont.nametofont(theme.FONT, root=parent)
        self._ph = px(height)
        self._image = theme.icon(parent, icon, "text", 14) if icon else None
        self._pw = self._ph if round_ else font.measure(text) + px(28)
        super().__init__(parent, width=self._pw, height=self._ph, highlightthickness=0, bd=0, background=background_of(parent), cursor="hand2")
        self._text, self._command, self._over = text, command, False
        self._shape = self.create_image(0, 0, anchor="nw")
        if self._image is not None and round_:
            self.create_image(self._pw // 2, self._ph // 2, image=self._image)
        else:
            self._label = self.create_text(self._pw // 2, self._ph // 2, text=text, font=theme.FONT)
        self._glide = Glide(self, self._paint)
        self.bind("<Button-1>", lambda _e: self._press())
        self.bind("<Enter>", lambda _e: self._hover(True))
        self.bind("<Leave>", lambda _e: self._hover(False))
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(lambda: self._paint(self._glide.at)), add="+")
        self._paint(0)

    def _hover(self, over: bool) -> None:
        self._over = over
        self._glide.to(1 if over else 0)

    def _press(self) -> None:
        self._glide.jump(2)                       # pressed: at once ...
        self._glide.to(1 if self._over else 0)    # ... and back as softly as it came
        self.invoke()

    def _paint(self, t: float = 0) -> None:
        try:
            self.configure(background=background_of(self.master))
            self._shown = rounded_image(self, self._pw, self._ph, self._ph // 2, between(self.FILLS, t), "border")
            self.itemconfigure(self._shape, image=self._shown)
            if hasattr(self, "_label"):
                self.itemconfigure(self._label, fill=theme.color("text"))
        except tk.TclError:
            pass

    def invoke(self) -> None:
        self._command()

    def cget(self, key: str) -> Any:  # (a button is asked for its text)
        return self._text if key == "text" else super().cget(key)


class Chips(tk.Canvas):
    """Filters as small pills, each as wide as its words; the chosen one is filled dark. One with nothing behind it can
    be left out (``hide``). The fill moves from the one that was chosen to the one that is; a pill under the pointer
    darkens softly."""

    def __init__(self, parent: tk.Misc, choices: list[tuple[str, str]], on_choose: Callable[[str], None]):
        self._on_choose = on_choose
        self._texts = dict(choices)
        self._order = [key for key, _text in choices]
        self._hidden: set[str] = set()
        self._spans: list[tuple[str, int, int]] = []
        self.chosen, self._was, self._hover = "", "", ""
        self._ph, self._gap = px(26), px(6)
        super().__init__(parent, highlightthickness=0, bd=0, background=background_of(parent), height=self._ph, width=1)
        self._pick = Glide(self, lambda _t: self._paint(), ms=150)   # 0: still on the one that was chosen, 1: on the chosen one
        self._pick.at = self._pick.goal = 1.0
        self._hovers: dict[str, Glide] = {}
        self.bind("<Button-1>", lambda e: self.choose(self._key_at(e.x)))
        self.bind("<Motion>", lambda e: self._set_hover(self._key_at(e.x)))
        self.bind("<Leave>", lambda _e=None: self._set_hover(""))
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")
        self._paint()

    def _key_at(self, x: int) -> str:
        return next((key for key, x0, x1 in self._spans if x0 <= x < x1), "")

    def _set_hover(self, key: str) -> None:
        if key != self._hover:
            old, self._hover = self._hover, key
            for k, goal in ((old, 0), (key, 1)):
                if k:
                    self._hovers.setdefault(k, Glide(self, lambda _t: self._paint())).to(goal)
            self.configure(cursor="hand2" if key else "")

    def _paint(self) -> None:
        try:
            self.delete("all")
            self.configure(background=background_of(self.master))
            bold = tkfont.nametofont(theme.FONT_CAPTION_BOLD, root=self)
            pick = stepped(self._pick.at)
            x, self._spans, self._shown = 0, [], []
            for key in self._order:
                if key in self._hidden:
                    continue
                on = key == self.chosen
                w = bold.measure(self._texts[key]) + px(24)   # (as wide as its words in bold: choosing it moves nothing)
                rest = between(("card", "menu_hover"), self._hovers[key].at if key in self._hovers else 0)
                if on:      # the dark fill arrives
                    fill, ink = between((rest, "text"), pick), between(("text", "card"), pick)
                    edge = fill
                elif key == self._was and pick < 1:   # ... and leaves the one it was on
                    fill, ink, edge = between(("text", rest), pick), between(("card", "text"), pick), between(("text", "border"), pick)
                else:
                    fill, ink, edge = rest, "text", "border"
                self._shown.append(rounded_image(self, w, self._ph, self._ph // 2, fill, edge))
                self.create_image(x, 0, anchor="nw", image=self._shown[-1])
                self.create_text(x + w // 2, self._ph // 2, text=self._texts[key], font=theme.FONT_CAPTION_BOLD if on else theme.FONT_CAPTION,
                                 fill=tone(ink))
                self._spans.append((key, x, x + w))
                x += w + self._gap
            if int(self.cget("width")) != max(1, x - self._gap):   # (only when it changes: a fade asks for no new layout)
                self.configure(width=max(1, x - self._gap))
        except tk.TclError:
            pass

    def choose(self, key: str, tell: bool = True) -> None:
        if key not in self._texts:
            return
        if key != self.chosen:
            self._was, self.chosen = self.chosen, key
            self._hidden.discard(key)
            self._pick.jump(0)
            self._pick.to(1)
        self._paint()
        if tell:
            self._on_choose(key)

    def set_text(self, key: str, text: str) -> None:
        self._texts[key] = text
        self._paint()

    def hide(self, key: str, hidden: bool) -> None:
        (self._hidden.add if hidden and key != self.chosen else self._hidden.discard)(key)
        self._paint()

    def text(self, key: str) -> str:
        return self._texts[key]


class Tag(tk.Canvas):
    """A word in an outlined pill ("Enabled", "Hosting provider", "new", "blocked by policy")."""

    def __init__(self, parent: tk.Misc, text: str, role: str = "muted", bold: bool = False, small: bool = False, background: str | None = None):
        name = theme.FONT_CAPTION_BOLD if bold else theme.FONT_CAPTION
        font = tkfont.nametofont(name, root=parent)
        self._pw, self._ph = font.measure(text) + px(14 if small else 18), font.metrics("linespace") + px(2 if small else 4)
        self._fill, self._role, self.text = background or "card", role, text
        super().__init__(parent, width=self._pw, height=self._ph, highlightthickness=0, bd=0, background=tone(self._fill))
        self._shape = self.create_image(0, 0, anchor="nw")
        self._label = self.create_text(self._pw // 2, self._ph // 2, text=text, font=name)
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")
        self._paint()

    def set_background(self, fill: str) -> None:
        """What it stands on (a palette role, or a colour on the way between two)."""
        if fill != self._fill:
            self._fill = fill
            self._paint()

    def _paint(self) -> None:
        try:
            self.configure(background=tone(self._fill))
            edge, ink = "border" if self._role == "muted" else self._role, theme.color("text" if self._role == "muted" else self._role)
            seen = getattr(self, "_seen", 1.0)
            if seen < 1:   # (appearing: on its way out of what it stands on)
                ground = tone(self._fill)
                edge, ink = theme.mix(ground, tone(edge), seen), theme.mix(ground, ink, seen)
            self._shown = rounded_image(self, self._pw, self._ph, self._ph // 2, self._fill, edge)
            self.itemconfigure(self._shape, image=self._shown)
            self.itemconfigure(self._label, fill=ink)
        except tk.TclError:
            pass

    def appear(self, t: float) -> None:
        """How far it has come out of what it stands on (0: not to be seen, 1: there)."""
        self._seen = stepped(max(0.0, min(1.0, t)))
        self._paint()

    def cget(self, key: str) -> Any:
        return self.text if key == "text" else super().cget(key)


class Badge(tk.Canvas):
    """What a row or a page is about, as a picture: an account's initials in a circle, anything else as an icon in a
    rounded square, an alert or a sign-in as a dot."""

    ICON = {"device": "device", "address": "globe", "network": "network", "country": "pin", "application": "apps", "search": "history"}

    def __init__(self, parent: tk.Misc, kind: str, text: str = "", size: int = 34, role: str = "", background: str = "card"):
        self._size, self._kind, self._role, self._back = px(size), kind, role, background
        super().__init__(parent, width=self._size, height=self._size, highlightthickness=0, bd=0, background=tone(background))
        self._shape = self.create_image(0, 0, anchor="nw")
        self._mark = None
        self._glyph = None
        self.quiet = False   # an account's circle in grey (one of several in a list; the chosen one is in the accent colour)
        if kind == "account":
            words = [w for w in text.replace("(", " ").split() if w[:1].isalnum()]
            initials = "".join(w[0] for w in words[:2]).upper() or "?"
            self._mark = self.create_text(self._size // 2, self._size // 2, text=initials, font=theme.FONT_BOLD if size >= 40 else theme.FONT_CAPTION_BOLD)
        elif kind in self.ICON:
            image = theme.icon(self, self.ICON[kind], "text", round(size * 0.5))
            if image is not None:
                self._glyph = self.create_image(self._size // 2, self._size // 2, image=image)
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")
        self._paint()

    def set_background(self, role: str) -> None:
        """What it stands on (a palette role, or a colour on the way between two)."""
        if role != self._back:
            self._back = role
            try:
                self.configure(background=tone(role))   # (the picture itself does not change with what it stands on)
            except tk.TclError:
                pass

    def set_quiet(self, quiet: bool) -> None:
        if quiet != self.quiet:
            self.quiet = quiet
            self._paint()

    def appear(self, t: float) -> None:
        """How far it has come out of what it stands on (0: not to be seen, 1: there)."""
        self._seen = stepped(max(0.0, min(1.0, t)))
        self._paint()

    def _paint(self) -> None:
        try:
            ground = tone(self._back)
            self.configure(background=ground)
            s, seen = self._size, getattr(self, "_seen", 1.0)

            def shade(colour: str) -> str:   # a colour as it is - or, appearing, on its way out of the ground
                return colour if seen >= 1 else theme.mix(ground, tone(colour), seen)

            if self._kind == "account":
                self._shown = rounded_image(self, s, s, s // 2, shade("track" if self.quiet else "link"))
                ink = theme.color("text") if self.quiet else theme.role_color("on_accent")
                self.itemconfigure(self._mark, fill=ink if seen >= 1 else theme.mix(ground, ink, seen))
            elif self._kind in self.ICON:   # (a search is no thing: its picture is round)
                self._shown = rounded_image(self, s, s, s // 2 if self._kind == "search" else px(8), shade("track"))
                if self._glyph is not None:
                    self.itemconfigure(self._glyph, state="normal" if seen >= 0.5 else "hidden")
            else:  # a dot in the middle
                d = px(10)
                self.coords(self._shape, (s - d) // 2, (s - d) // 2)
                self._shown = rounded_image(self, d, d, d // 2, shade(self._role or "muted"))
            self.itemconfigure(self._shape, image=self._shown)
        except tk.TclError:
            pass


class DayBars(tk.Canvas):
    """Sign-ins per day as small bars, oldest left; today's bar stands out when it is the highest."""

    def __init__(self, parent: tk.Misc, values: Sequence[int], width: int = 300, height: int = 28):
        super().__init__(parent, width=px(width), height=px(height), highlightthickness=0, bd=0, background=background_of(parent))
        self.values, self.shown = list(values), 1.0
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")
        self._paint()

    def grow(self, t: float) -> None:
        """Draw the bars up to the fraction ``t`` of their height (they rise when the page appears)."""
        self.shown = max(0.0, min(1.0, t))
        self._paint()

    def _paint(self) -> None:
        try:
            self.delete("all")
            self.configure(background=background_of(self.master))
            w, h, n = int(self.cget("width")), int(self.cget("height")), max(1, len(self.values))
            top = max(self.values, default=0) or 1
            step = w / n
            for i, v in enumerate(self.values):
                bar = max(px(2), round(h * v / top * self.shown)) if v else px(2)
                last = i == n - 1 and v == top and n > 1
                self.create_rectangle(round(i * step), h - bar, round(i * step + step - px(3)), h, outline="",
                                      fill=theme.color("warn" if last else "select" if not theme.is_dark() else "track"))
        except tk.TclError:
            pass


class SplitBar(tk.Canvas):
    """How something divides, as one thin bar with round ends in as many parts as there are shares. ``grow(t)``
    draws it up to the fraction ``t`` of its length (it runs in when the page appears)."""

    def __init__(self, parent: tk.Misc, shares: Sequence[tuple[int, str]], height: int = 6, background: str = "card"):
        super().__init__(parent, height=px(height), highlightthickness=0, bd=0, background=theme.color(background))
        self.shares, self._back, self.shown = list(shares), background, 1.0   # (count, palette role) each
        self.bind("<Configure>", lambda _e: self._paint(), add="+")
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(self._paint), add="+")

    def grow(self, t: float) -> None:
        self.shown = max(0.0, min(1.0, t))
        self._paint()

    def _paint(self) -> None:
        try:
            self.delete("all")
            self.configure(background=theme.color(self._back))
            width, h, gap = self.winfo_width(), int(self.cget("height")), px(2)
            total = sum(n for n, _role in self.shares) or 1
            room = (width - gap * (len(self.shares) - 1)) * self.shown
            x = 0.0
            for n, role in self.shares:
                part = max(float(h), room * n / total) if self.shown > 0 else 0.0
                x0, x1 = round(x), round(min(width, x + part))
                if x1 - x0 >= h:   # round ends: a small circle at each end (smooth, an image), the colour between them
                    cap = rounded_image(self, h, h, h // 2, role)
                    self.create_image(x0, 0, anchor="nw", image=cap)
                    self.create_image(x1 - h, 0, anchor="nw", image=cap)
                    # (the colour between them goes on top: a circle's soft rim would show as a ring on it)
                    self.create_rectangle(x0 + h // 2, 0, x1 - h // 2, h, outline="", fill=theme.color(role))
                x += part + gap
        except tk.TclError:
            pass


class Flow(tk.Text):
    """Short entries one after the other, in as many rows as they need (the widget is as high as its rows). An entry
    is never torn apart: where the next one does not fit beside the last, it begins a new row.
    ``add(text, role, on_click)`` appends a piece to the entry, ``tag`` a small outlined word, ``gap`` ends the entry.

    It is a text only to lay the entries out: it does not scroll, select or take the keyboard (the mouse wheel over
    it turns what it stands in), and a piece that can be clicked is underlined under the pointer."""

    SPACE = chr(160)   # (a space the text does not break at)
    BETWEEN = "   "

    def __init__(self, parent: tk.Misc, background: str = "card"):
        super().__init__(parent, height=1, wrap="word", bd=0, relief="flat", highlightthickness=0, padx=0, pady=0, cursor="arrow",
                         background=theme.color(background), foreground=theme.color("text"), font=theme.FONT, spacing1=px(2), spacing3=px(2),
                         takefocus=0)
        self.bindtags(tuple(t for t in self.bindtags() if t != "Text"))
        self._n = 0
        self._widths = [0]   # how wide each entry is
        self.bind("<Configure>", lambda _e: self.after_idle(self.fit), add="+")

    def add(self, text: str, role: str = "text", on_click: Callable[[], None] | None = None, font: str | None = None) -> None:
        self._n += 1
        tag = f"p{self._n}"
        text = text.replace(" ", self.SPACE)
        self.configure(state="normal")
        self.insert("end", text, tag)
        self.tag_configure(tag, foreground=theme.color(role), font=font or theme.FONT)
        self._widths[-1] += tkfont.nametofont(font or theme.FONT, root=self).measure(text)
        if on_click:
            self.tag_bind(tag, "<Button-1>", lambda _e: on_click())
            self.tag_bind(tag, "<Enter>", lambda _e: (self.configure(cursor="hand2"), self.tag_configure(tag, underline=True)))
            self.tag_bind(tag, "<Leave>", lambda _e: (self.configure(cursor="arrow"), self.tag_configure(tag, underline=False)))
        self.configure(state="disabled")

    def tag(self, text: str, role: str = "warn") -> None:
        """A small outlined word after the piece before it ("new")."""
        self.configure(state="normal")
        self.insert("end", self.SPACE)
        mark = Tag(self, text, role, small=True)
        self.window_create("end", window=mark, align="center")
        self._widths[-1] += mark._pw + tkfont.nametofont(theme.FONT, root=self).measure(self.SPACE) + px(2)
        self.configure(state="disabled")

    def gap(self) -> None:
        """Between two entries: here - and only here - a row may end."""
        self.configure(state="normal")
        self.insert("end", self.BETWEEN, f"gap{len(self._widths)}")
        self._widths.append(0)
        self.configure(state="disabled")

    def fit(self) -> None:
        try:
            room = self.winfo_width()
            if room <= 1:
                return
            between_two = tkfont.nametofont(theme.FONT, root=self).measure(self.BETWEEN)
            self.configure(state="normal")
            x = self._widths[0]
            for k in range(1, len(self._widths)):
                first, last = self.tag_ranges(f"gap{k}")
                wraps = x + between_two + self._widths[k] > room
                want = "\n" if wraps else self.BETWEEN
                if self.get(first, last) != want:
                    self.replace(first, last, want, f"gap{k}")
                x = self._widths[k] if wraps else x + between_two + self._widths[k]
            self.configure(state="disabled")
            rows = self.count("1.0", "end", "displaylines")
            self.configure(height=max(1, int(rows[0] if isinstance(rows, tuple) else rows or 1)))
        except tk.TclError:
            pass

    def text(self) -> str:
        return " ".join(self.get("1.0", "end").replace(self.SPACE, " ").split())


class RowGlow:
    """Rows of a text (a timeline, a table) that light up softly under the pointer. A row is everything that carries
    the tag ``row<n>``; ``add(n, base, marks)`` says what it stands on and which small tags are set into it (they
    take the row's colour with it)."""

    def __init__(self, text: tk.Text):
        self.text = text
        self.rows: dict[int, tuple[str, list[Tag]]] = {}
        self.glides: dict[int, Glide] = {}
        self.at: int | None = None
        text.bind("<Motion>", self._moved, add="+")
        text.bind("<Leave>", lambda _e: self._later(), add="+")

    def clear(self) -> None:
        self.rows, self.glides, self.at = {}, {}, None

    def add(self, n: int, base: str = "card", marks: Sequence[Tag] = ()) -> None:
        self.rows[n] = (base, list(marks))
        for mark in marks:
            mark.bind("<Enter>", lambda _e, n=n: self.light(n), add="+")
            mark.bind("<Leave>", lambda _e: self._later(), add="+")

    def row_at(self, x: int, y: int) -> int | None:
        try:
            index = self.text.index(f"@{x},{y}")
            line = self.text.dlineinfo(index)
            if line is None or not line[1] <= y < line[1] + line[3]:
                return None   # (under the last line the nearest character is not what the pointer is on)
            return next((int(t[3:]) for t in self.text.tag_names(index) if t.startswith("row") and t[3:].isdigit()), None)
        except tk.TclError:
            return None

    def _moved(self, event: tk.Event) -> None:
        self.light(self.row_at(event.x, event.y))

    def _later(self) -> None:
        try:
            self.text.after(30, self._left)
        except tk.TclError:
            pass

    def _left(self) -> None:
        """The pointer left the text - unless it only went onto one of the small tags set into a row."""
        try:
            under = self.text.winfo_containing(*self.text.winfo_pointerxy())
        except (tk.TclError, KeyError):
            under = None
        if under is self.text or any(under in marks for _base, marks in self.rows.values()):
            return
        self.light(None)

    def light(self, n: int | None) -> None:
        if n == self.at:
            return
        old, self.at = self.at, n
        for k, goal in ((old, 0), (n, 1)):
            if k is not None and k in self.rows:
                if k not in self.glides:
                    self.glides[k] = Glide(self.text, lambda t, k=k: self._paint(k, t), ms=90)
                self.glides[k].to(goal)

    def _paint(self, k: int, t: float) -> None:
        if k not in self.rows:
            return
        base, marks = self.rows[k]
        t = stepped(t)
        colour = base if t == 0 else theme.mix(theme.color(base), theme.color("text"), LIT * t)
        self.text.tag_configure(f"row{k}", background="" if t == 0 else colour)
        # (the arrow at the row's end comes forward with it)
        self.text.tag_configure(f"arr{k}", foreground="" if t == 0 else theme.mix(theme.color("muted"), theme.color("text"), t))
        for mark in marks:
            mark.set_background(colour)


def fit_text(text: str, width: int, font: str, widget: tk.Misc) -> str:
    """``text``, cut with an ellipsis where it would be wider than ``width`` pixels."""
    f = tkfont.nametofont(font, root=widget)
    if f.measure(text) <= width:
        return text
    while text and f.measure(text + "…") > width:
        text = text[:-1]
    return text.rstrip() + "…"


class FieldBox(tk.Canvas):
    """The outline of a text field as a pill (fully round ends); what goes into the field is put on ``inner``.
    ``watch(entry)``: while that entry has the keyboard the outline is in the accent colour - and, with ``glow``, a
    soft ring lies around it; both fade in and out."""

    GLOW = 0.22   # how much of the accent colour the ring around a field with the keyboard has

    def __init__(self, parent: tk.Misc, height: int, edge: str = "border", width: int = 0, glow: bool = False):
        self._ph, self._edge = px(height), edge
        self._g = px(3) if glow else 0
        super().__init__(parent, height=self._ph + 2 * self._g, width=px(width) if width else 1, highlightthickness=0, bd=0,
                         background=background_of(parent))
        self._halo = self.create_image(0, 0, anchor="nw") if glow else None
        self._shape = self.create_image(self._g, self._g, anchor="nw")
        self.inner = tk.Frame(self, background=theme.color("card"), bd=0, highlightthickness=0)
        self._window = self.create_window(self._g + self._ph // 2, self._g + self._ph // 2, anchor="w", window=self.inner)
        self.focus_glide = Glide(self, lambda _t: self._paint(self.winfo_width()), ms=140, back=240)
        self._shown: list[Any] = []
        self.bind("<Configure>", lambda e: self._paint(e.width), add="+")
        self.bind("<<ThemeChanged>>", lambda _e=None: self.after_idle(lambda: self._paint(self.winfo_width())), add="+")

    def watch(self, entry: tk.Misc) -> None:
        entry.bind("<FocusIn>", lambda _e: self.focus_glide.to(1), add="+")
        entry.bind("<FocusOut>", lambda _e: self.focus_glide.to(0), add="+")

    def _paint(self, width: int) -> None:
        try:
            t = stepped(self.focus_glide.at)
            ground = background_of(self.master)
            self.configure(background=ground)
            self.inner.configure(background=theme.color("card"))
            w, h = max(width - 2 * self._g, self._ph), self._ph
            self._shown = [rounded_image(self, w, h, h // 2, "card", between((self._edge, "link"), t))]
            self.itemconfigure(self._shape, image=self._shown[0])
            if self._halo is not None:
                ring = ground if t == 0 else theme.mix(ground, theme.color("link"), self.GLOW * t)
                self._shown.append(rounded_image(self, max(width, h + 2 * self._g), h + 2 * self._g, h // 2 + self._g, ring))
                self.itemconfigure(self._halo, image=self._shown[1])
            self.itemconfigure(self._window, width=max(10, w - h), height=h - px(8))
        except tk.TclError:
            pass


def come_forward(ground: tk.Misc) -> Callable[[float], None]:
    """Everything written on ``ground`` - its labels, the lines of its texts, its tags and badges - as something that
    can appear: the function returned takes it to ``t`` of its way out of what it stands on (0: not to be seen,
    1: there, exactly as it was). What holds the writing (cards, their outlines) is not part of it: it stays put,
    its content arrives. With animations off there is nothing to do."""
    if not theme.animations():
        return lambda _t: None
    steps: list[Callable[[float], None]] = []

    def text_steps(text: tk.Text) -> None:
        back, ink = str(text.cget("background")), str(text.cget("foreground"))
        steps.append(lambda t: text.configure(foreground=ink if t >= 1 else theme.mix(back, ink, t)))
        for tag in text.tag_names():
            for option in ("foreground", "background"):
                colour = str(text.tag_cget(tag, option))
                if colour.startswith("#") and len(colour) == 7 and tag != "sel":
                    steps.append(lambda t, tag=tag, option=option, colour=colour: text.tag_configure(
                        tag, **{option: colour if t >= 1 else theme.mix(back, colour, t)}))

    def walk(widget: tk.Misc) -> None:
        for w in widget.winfo_children():
            if callable(getattr(w, "appear", None)):   # what is drawn (a tag, a badge, a row of a timeline) appears by itself
                steps.append(w.appear)
            elif isinstance(w, tk.Text):
                text_steps(w)
                walk(w)   # (the small tags set into its lines)
            elif isinstance(w, tk.Label):
                back, ink = str(w.cget("background")), str(w.cget("foreground"))
                if ink != back and ink.startswith("#") and back.startswith("#") and len(ink) == 7 and len(back) == 7:
                    steps.append(lambda t, w=w, back=back, ink=ink: w.configure(foreground=ink if t >= 1 else theme.mix(back, ink, t)))
            else:
                walk(w)

    walk(ground)

    def arrive(t: float) -> None:
        for step in steps:
            try:
                step(t)
            except tk.TclError:   # (gone meanwhile: a list that was written anew)
                pass

    return arrive
