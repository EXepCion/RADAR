"""The right-click menu, drawn in the app's own look.

Tk's own menu is the classic Windows one (grey, square, system font) and ignores the theme. This is a small
borderless window in the card colour with rounded corners: group titles in the caption style, one row per action
with its icon, a highlight that follows the mouse or the arrow keys. It closes on a click anywhere else, on Escape
and when the app loses the focus; an action runs after the menu is gone.

Everything is drawn on ONE canvas. (A first version made each row of separate label widgets - on Windows every
widget is a window of its own, and recolouring several of them as the mouse moved made the menu flicker and rows
vanish.) The highlight is a single shape that is moved behind the row under the pointer; nothing else is redrawn.
"""
from __future__ import annotations

import ctypes
import logging
import tkinter as tk
import tkinter.font as tkfont
from typing import Callable

from .. import screens
from . import theme
from .theme import px

log = logging.getLogger(__name__)

Groups = list[tuple[str, list[tuple[str, Callable[[], None]]]]]
MIN_WIDTH, MAX_TEXT = 220, 460
PAD, ROW_PAD, ICON_BOX, GAP = 4, 7, 20, 8  # px (before scaling): outer padding, above/below a row's text, icon, icon-text
DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND = 33, 2


def icon_for(label: str) -> str:
    """Copying and opening look different at a glance."""
    return "copy" if label.lower().startswith("copy") else "open"


def _rounded(x1: int, y1: int, x2: int, y2: int, r: int) -> list[int]:
    """Points of a rounded rectangle for a smoothed canvas polygon."""
    return [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r,
            x1, y1 + r, x1, y1]


class ContextMenu:
    def __init__(self, parent: tk.Misc, groups: Groups, x: int, y: int):
        self.labels: list[str] = []
        self.titles: list[str] = []
        self._commands: list[Callable[[], None]] = []
        self._spans: list[tuple[int, int]] = []  # (top, bottom) of each row on the canvas
        self._images: list[object] = []          # kept alive with the menu
        self._active = -1
        self._closed = False
        self._parent = parent
        card, border = theme.color("card"), theme.color("border")
        top = self.top = tk.Toplevel(parent)
        top.withdraw()
        top.overrideredirect(True)
        top.configure(background=border)
        try:
            top.attributes("-topmost", True)
        except tk.TclError:
            pass
        canvas = self.canvas = tk.Canvas(top, background=card, highlightthickness=0, bd=0, cursor="hand2")
        canvas.pack(fill="both", expand=True, padx=1, pady=1)  # the 1 px that shows is the outline
        width, height = self._draw(groups)
        canvas.configure(width=width, height=height)
        canvas.bind("<Motion>", lambda e: self._highlight(self.row_at(e.y)))
        canvas.bind("<Leave>", lambda _e: self._highlight(-1))
        canvas.bind("<ButtonRelease-1>", lambda e: self._run(self.row_at(e.y)))
        top.bind("<Escape>", lambda _e: self.close())
        top.bind("<Up>", lambda _e: self._move(-1))
        top.bind("<Down>", lambda _e: self._move(1))
        top.bind("<Return>", lambda _e: self._run(self._active))
        top.bind("<FocusOut>", lambda _e: self.close())
        top.bind("<ButtonPress>", self._pressed, add="+")
        self._place(x, y, width + 2, height + 2)
        top.deiconify()
        self._round()
        top.lift()
        try:
            top.focus_force()
            top.grab_set()  # a click on another window of the app comes here first: it closes the menu
        except tk.TclError:
            pass

    # ------------------------------------------------------------------- draw
    def _draw(self, groups: Groups) -> tuple[int, int]:
        """Put everything on the canvas; returns the size it needs."""
        c = self.canvas
        body, caption = tkfont.nametofont(theme.FONT), tkfont.nametofont(theme.FONT_CAPTION)
        pad, row_pad, icon_box, gap = px(PAD), px(ROW_PAD), px(ICON_BOX), px(GAP)
        text_x = pad + px(8) + icon_box + gap
        several = len(groups) > 1
        longest = max([body.measure(label) for _t, items in groups for label, _f in items]
                      + [caption.measure(t) - icon_box - gap for t, _i in groups if several and t] + [0])
        text_width = min(px(MAX_TEXT), longest)
        width = max(px(MIN_WIDTH), text_x + text_width + px(16) + pad)
        # the one highlight shape, behind everything; parked out of sight until a row is under the pointer
        self._hover = c.create_polygon(_rounded(0, -100, 10, -90, 2), smooth=True, fill=theme.color("menu_hover"), outline="")
        y = pad
        for index, (title, items) in enumerate(groups):
            if index:
                y += px(4)
                c.create_line(pad + px(8), y, width - pad - px(8), y, fill=theme.color("border"))
                y += px(5)
            if title and several:
                self.titles.append(title)
                y += px(4)
                c.create_text(pad + px(10), y, text=title, anchor="nw", font=caption, fill=theme.color("muted"))
                y += caption.metrics("linespace") + px(2)
            for label, command in items:
                item = c.create_text(text_x, y + row_pad, text=label, anchor="nw", font=body, fill=theme.color("text"),
                                     width=text_width)
                bottom = c.bbox(item)[3] + row_pad
                image = theme.icon(c, icon_for(label), "muted")
                if image is not None:
                    self._images.append(image)
                    c.create_image(pad + px(8) + icon_box // 2, y + row_pad + body.metrics("linespace") // 2, image=image)
                self._spans.append((y, bottom))
                self.labels.append(label)
                self._commands.append(command)
                y = bottom
        self._width = width
        return width, y + pad

    def _place(self, x: int, y: int, width: int, height: int) -> None:
        """At the pointer, moved back onto the screen it is on when it would stick out."""
        area = None
        try:
            area = screens.area_at(x, y)
        except Exception:  # noqa: BLE001 - no monitor information: the whole screen then
            log.debug("monitor lookup failed", exc_info=True)
        left, upper, right, lower = (area if area is not None else
                                     (0, 0, self.top.winfo_screenwidth(), self.top.winfo_screenheight()))
        if x + width > right:
            x = max(left, x - width)        # opens to the left of the pointer instead
        if y + height > lower:
            y = max(upper, lower - height)
        self.top.geometry(f"{width}x{height}+{x}+{y}")

    def _round(self) -> None:
        """Rounded corners and the system's shadow (Windows 11; elsewhere it stays a plain rectangle)."""
        try:
            hwnd = int(self.top.wm_frame(), 16)
            value = ctypes.c_int(DWMWCP_ROUND)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(value),
                                                       ctypes.sizeof(value))
        except Exception:  # noqa: BLE001
            log.debug("rounded menu corners not available", exc_info=True)

    # ----------------------------------------------------------------- behave
    def row_at(self, y: int) -> int:
        """The row at this canvas height, -1 between rows (titles, lines, padding)."""
        for index, (top, bottom) in enumerate(self._spans):
            if top <= y < bottom:
                return index
        return -1

    @property
    def active(self) -> int:
        """The highlighted row (-1: none)."""
        return self._active

    def highlight_box(self) -> tuple[int, int, int, int] | None:
        """Where the highlight is drawn (None while no row is highlighted)."""
        if self._active < 0:
            return None
        x1, y1, x2, y2 = self.canvas.bbox(self._hover)
        return x1, y1, x2, y2

    def _highlight(self, index: int) -> None:
        if self._closed or index == self._active:
            return
        self._active = index
        if index < 0:
            self.canvas.coords(self._hover, *_rounded(0, -100, 10, -90, 2))
            return
        top, bottom = self._spans[index]
        self.canvas.coords(self._hover, *_rounded(px(PAD), top, self._width - px(PAD), bottom, px(4)))

    def _move(self, step: int) -> str:
        count = len(self._spans)
        if count:
            self._highlight((self._active + step) % count if self._active >= 0 else (0 if step > 0 else count - 1))
        return "break"

    def _pressed(self, event: tk.Event) -> None:
        inside = self.top.winfo_containing(event.x_root, event.y_root)
        if inside is None or not str(inside).startswith(str(self.top)):
            self.close()

    def _run(self, index: int) -> str:
        if self._closed or not 0 <= index < len(self._commands):
            return "break"
        command = self._commands[index]
        self.close()
        try:
            self._parent.after_idle(command)  # after the menu is gone: an action may open a window or a browser
        except tk.TclError:
            command()
        return "break"

    def invoke(self, label: str) -> None:
        """Run the action with this label (what a click on it does)."""
        self._run(self.labels.index(label))

    def exists(self) -> bool:
        try:
            return not self._closed and bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.top.grab_release()
            self.top.destroy()
        except tk.TclError:
            pass
