"""How old the shown data is, and the button to refresh it - the same control in every window with live data.

A window opens at once with the data the app already has, refreshes it in the background (the button says
"Refreshing..." and is disabled meanwhile, its icon turns) and then shows the age of the data; the age keeps
counting while the window is open. A finished refresh is confirmed by a check mark on the button for a moment.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk
from typing import Any, Callable

from . import theme
from .theme import px

REFRESH, REFRESHING = "Refresh", "Refreshing..."
TICK_MS = 15_000
SPIN_FRAMES, SPIN_MS = 24, 40   # one turn of the icon in about a second
DONE_MS, POP_MS = 1400, 220     # how long the check mark stays / how fast it pops up
ICON_SIZE = 16
#: the longest text of the age label: its width is reserved, so nothing next to it moves
TEMPLATE = "Data from 8888-88-88 88:88 (88 min ago) - refresh failed: sign-in required"


def age_text(as_of: datetime | None, now: datetime | None = None) -> str:
    """'just now', '7 min ago', '5 h ago', '3 days ago' (rounded down: data is never shown younger than it is)."""
    if as_of is None:
        return "age unknown"
    now = now or datetime.now(timezone.utc)
    minutes = int(max(0.0, (now - as_of).total_seconds()) // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // 1440} days ago"


def stamp(as_of: datetime, now: datetime | None = None) -> str:
    """Local time of the data; with the date unless it is today."""
    local, today = as_of.astimezone(), (now or datetime.now(timezone.utc)).astimezone().date()
    return local.strftime("%H:%M" if local.date() == today else "%Y-%m-%d %H:%M")


def describe(as_of: datetime | None, busy: bool, error: str = "", now: datetime | None = None) -> str:
    """The label next to the button: the age of what is shown. That a refresh is running is said by the button
    alone (not repeated here)."""
    text = "No data yet" if as_of is None else f"Data from {stamp(as_of, now)} ({age_text(as_of, now)})"
    if error and not busy:
        return text + f" - refresh failed: {error}"
    return text


class DataAge(ttk.Frame):
    """[Refresh] Data from 16:52 (3 min ago)   - button and age label; ``button_side`` 'left' or 'right'."""

    def __init__(self, parent: tk.Misc, on_refresh: Callable[[], None], button_side: str = "left", **kw: Any):
        super().__init__(parent, **kw)
        self.as_of: datetime | None = None
        self.busy = False
        self.error = ""
        self.phase = "idle"  # idle | spinning (refresh running) | done (check mark after a successful refresh)
        self.frame = 0       # position of the turning icon
        self._frames: dict[tuple, Any] = {}
        self._photo = self._make_photo()
        self._anim_job: str | None = None
        self._tick_job: str | None = None
        # fixed width: "Refresh" and "Refreshing..." take the same room
        self._on_refresh = on_refresh
        self.button = ttk.Button(self, text=f" {REFRESH}" if self._photo else REFRESH, command=self._press,
                                 width=len(REFRESHING) + 1,
                                 **({"image": self._photo, "compound": "left"} if self._photo else {}))
        width = int(self.tk.call("font", "measure", theme.FONT, TEMPLATE)) + px(4)
        holder = tk.Frame(self, width=width, height=1, background=theme.color("window"), bd=0, highlightthickness=0)
        holder.pack_propagate(False)
        self.label = tk.Label(holder, font=theme.FONT, anchor="w" if button_side == "left" else "e", bd=0, padx=0,
                              pady=0, highlightthickness=0, background=theme.color("window"),
                              foreground=theme.color("muted"))
        self.label.pack(fill="both", expand=True)
        self.button.bind("<Leave>", lambda _e: self.button.configure(cursor=""), add="+")
        self.button.pack(side=button_side)
        holder.pack(side=button_side, fill="y", padx=(px(10), 0) if button_side == "left" else (0, px(10)))
        self.bind("<Destroy>", lambda e: self._stop() if e.widget is self else None, add="+")
        self.bind("<<ThemeChanged>>", lambda _e: self._draw_icon(), add="+")
        self._paint()
        self._tick()

    # ------------------------------------------------------------- state
    def set(self, as_of: datetime | None = None, busy: bool = False, error: str = "", keep_time: bool = False) -> None:
        """State of the data: its time, whether a refresh is running, and why the last refresh failed (if it did).
        ``keep_time``: leave the shown time as it is (e.g. a refresh has just started)."""
        was_busy = self.busy
        if not keep_time:
            self.as_of = as_of
        self.busy, self.error = busy, error
        if busy and not was_busy:
            self._start_spin()
        elif was_busy and not busy:
            self._end_spin(success=not error)
        self._paint()

    @property
    def pressable(self) -> bool:
        return not self.busy

    def _press(self) -> None:
        if not self.busy:
            self._on_refresh()

    @property
    def text(self) -> str:
        return describe(self.as_of, self.busy, self.error)

    def _paint(self) -> None:
        try:
            self.label.configure(text=self.text, foreground=theme.color("error" if self.error and not self.busy
                                                                        else "muted"))
            label = REFRESHING if self.busy else REFRESH
            self.button.configure(text=f" {label}" if self._photo else label,
                                  style="Busy.TButton" if self.busy else "TButton", takefocus=0 if self.busy else 1)
            # While busy the button cannot be pressed and does not react to the mouse. It is not put into the ttk
            # 'disabled' state: ttk draws the image of a disabled button dotted, which ruins the turning icon.
            tags = [t for t in self.button.bindtags() if t != "TButton"]
            if self.busy:
                self.button.state(["!active", "!pressed"])
                self.button.configure(cursor="")
            else:
                tags.insert(1, "TButton")
            self.button.bindtags(tuple(tags))
        except tk.TclError:
            pass

    def _tick(self) -> None:
        try:
            self._paint()  # the age keeps counting
            self._tick_job = self.after(TICK_MS, self._tick)
        except tk.TclError:
            self._tick_job = None

    # ---------------------------------------------------------- animation
    def _make_photo(self):
        return self._image("refresh", "text")

    def _image(self, name: str, role: str, angle: float = 0.0, scale: float = 1.0):
        """PhotoImage of the icon glyph in a palette colour, turned by ``angle`` degrees (clockwise) and scaled
        around its centre; cached per colour (so a theme switch gets new ones). None without the icon font."""
        from PIL import Image, ImageTk

        size = px(ICON_SIZE)
        if theme._icon_font(size * 4) is None:
            return None
        key = (name, theme.role_color(role), round(angle, 1), round(scale, 2))
        if key not in self._frames:
            big = theme._render_icon(name, role, size * 4)
            if angle:
                big = big.rotate(-angle, resample=Image.BICUBIC)
            if scale != 1.0:
                inner = max(1, int(size * 4 * scale))
                canvas = Image.new("RGBA", big.size, (0, 0, 0, 0))
                canvas.paste(big.resize((inner, inner), Image.LANCZOS), ((size * 4 - inner) // 2,) * 2)
                big = canvas
            self._frames[key] = ImageTk.PhotoImage(big.resize((size, size), Image.LANCZOS), master=self._root())
        return self._frames[key]

    def _draw_icon(self, scale: float = 1.0) -> None:
        if self._photo is None:
            return
        try:
            if self.phase == "spinning":
                image = self._image("refresh", "muted", 360.0 * (self.frame % SPIN_FRAMES) / SPIN_FRAMES)
            elif self.phase == "done":
                image = self._image("check", "link", scale=round(0.4 + 0.6 * scale, 1) if scale < 1.0 else 1.0)
            else:
                image = self._image("refresh", "text")
            self.button.configure(image=image)
        except tk.TclError:
            pass

    def _cancel_anim(self) -> None:
        if self._anim_job:
            try:
                self.after_cancel(self._anim_job)
            except tk.TclError:
                pass
            self._anim_job = None

    def _start_spin(self) -> None:
        """The refresh starts: the icon begins to turn (with animations off it just stays as it is)."""
        self._cancel_anim()
        self.frame = 0
        if not theme.animations() or self._photo is None:
            self.phase = "spinning" if self._photo is not None else "idle"
            self._draw_icon()
            return
        self.phase = "spinning"
        self._spin()

    def _spin(self) -> None:
        self._anim_job = None
        if self.phase != "spinning":
            return
        try:
            self._draw_icon()
            self.frame += 1
            self._anim_job = self.after(SPIN_MS, self._spin)
        except tk.TclError:
            pass

    def _end_spin(self, success: bool) -> None:
        """The refresh ended: a check mark pops up for a moment (success), then the normal icon is back."""
        self._cancel_anim()
        if not success or not theme.animations() or self._photo is None:
            self.phase = "idle"
            self._draw_icon()
            return
        self.phase = "done"
        theme.animate(self, POP_MS, lambda t: self._draw_icon(scale=t))
        try:
            self._anim_job = self.after(DONE_MS, self._back_to_idle)
        except tk.TclError:
            pass

    def _back_to_idle(self) -> None:
        self._anim_job = None
        if self.phase == "done":
            self.phase = "idle"
            self._draw_icon()

    def _stop(self) -> None:
        self._cancel_anim()
        if self._tick_job:
            try:
                self.after_cancel(self._tick_job)
            except tk.TclError:
                pass
            self._tick_job = None
