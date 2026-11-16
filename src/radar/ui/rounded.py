"""A frame with round corners.

Tk frames are rectangles. A round one is a canvas that draws the shape (fill and hairline edge) and holds the real
frame a little inside it, so the frame's square corners stay within the round outline. To whoever uses it, it is the
frame: children go into it, and pack / grid / destroy move the whole thing.
"""
from __future__ import annotations

import math
import tkinter as tk
from typing import Any

from . import theme
from .theme import px

RADIUS, INSET = 8, 3


def background_of(widget: tk.Misc) -> str:
    """The colour a widget is drawn on (ttk widgets do not say: they are on the window colour)."""
    try:
        return str(widget.cget("background"))
    except tk.TclError:
        return theme.color("window")


def round_points(x1: int, y1: int, x2: int, y2: int, r: int) -> list[float]:
    """The outline of a rectangle with round corners, as points for ``create_polygon``: real quarter circles (a
    radius of half the height makes a pill)."""
    r = max(0, min(r, (x2 - x1) // 2, (y2 - y1) // 2))
    if r == 0:
        return [x1, y1, x2, y1, x2, y2, x1, y2]
    steps = max(4, min(16, r))
    points: list[float] = []
    for cx, cy, start in ((x2 - r, y1 + r, -90), (x2 - r, y2 - r, 0), (x1 + r, y2 - r, 90), (x1 + r, y1 + r, 180)):
        for i in range(steps + 1):
            angle = math.radians(start + 90 * i / steps)
            points += [round(cx + r * math.cos(angle), 2), round(cy + r * math.sin(angle), 2)]
    return points


def _render(width: int, height: int, radius: int, fill: str, edge: str | None):
    from PIL import Image, ImageDraw

    scale = 4  # drawn four times as large and scaled down: that is what makes the curve smooth
    img = Image.new("RGBA", (width * scale, height * scale), (0, 0, 0, 0))
    rgb = lambda role: theme._rgb(theme.role_color(role)) + (255,)  # noqa: E731
    ImageDraw.Draw(img).rounded_rectangle(
        (0, 0, width * scale - 1, height * scale - 1), radius=radius * scale, fill=rgb(fill),
        outline=rgb(edge) if edge else None, width=scale if edge else 0)
    return img.resize((width, height), Image.LANCZOS)


def rounded_image(widget: tk.Misc, width: int, height: int, radius: int, fill: str, edge: str | None = None):
    """A smooth rounded rectangle in palette colours, as an image (a canvas draws its own shapes with visible steps).
    One image per size and colours; it is redrawn in place when the theme switches."""
    width, height = max(2, int(width)), max(2, int(height))
    radius = max(0, min(int(radius), width // 2, height // 2))
    return theme._themed(widget, ("round", width, height, radius, fill, edge),
                         lambda: _render(width, height, radius, fill, edge))


class Rounded(tk.Frame):
    """A frame in a palette colour with round corners and a hairline edge (``rounded=False``: a plain frame)."""

    def __init__(self, parent: tk.Misc, rounded: bool = True, fill: str = "card", edge: str = "border",
                 radius: int = RADIUS, **kw: Any):
        self._outer: tk.Canvas | None = None
        self._fill, self._edge, self._radius = fill, edge, px(radius)
        self._going = False
        options = dict(background=theme.color(fill), bd=0, highlightthickness=0)
        options.update(kw)
        if not rounded:
            super().__init__(parent, **options)
            return
        outer = self._outer = tk.Canvas(parent, highlightthickness=0, bd=0, background=background_of(parent),
                                        width=1, height=1)
        super().__init__(outer, **options)
        tk.Frame.pack(self, fill="both", expand=True, padx=px(INSET), pady=px(INSET))
        # the outline: a smooth corner piece in each corner, the area between them filled, a hairline along each side
        self._corners = [outer.create_image(0, 0, anchor="nw") for _ in range(4)]
        self._fills = [outer.create_rectangle(0, 0, 0, 0, outline="") for _ in range(2)]
        self._sides = [outer.create_line(0, 0, 0, 0) for _ in range(4)]
        outer.bind("<Configure>", lambda _e=None: self._outline(), add="+")
        outer.bind("<<ThemeChanged>>", lambda _e=None: outer.after_idle(self._outline), add="+")

    @property
    def outer(self) -> tk.Misc:
        """What sits in the parent (the widget to hand to a paned window, for instance)."""
        return self._outer if self._outer is not None else self

    def set_edge(self, role: str) -> None:
        """The colour of the outline (a palette role), e.g. the accent for the one that is chosen."""
        self._edge = role
        self._outline()

    def _outline(self) -> None:
        outer = self._outer
        if outer is None:
            return
        try:
            w, h = outer.winfo_width(), outer.winfo_height()
            r = max(1, min(self._radius, w // 2, h // 2))
            piece = rounded_image(outer, 2 * r, 2 * r, r, self._fill, self._edge)
            fill, edge = theme.color(self._fill), theme.color(self._edge)
            for item, (x, y) in zip(self._corners, ((0, 0), (w - 2 * r, 0), (0, h - 2 * r), (w - 2 * r, h - 2 * r))):
                outer.coords(item, x, y)
                outer.itemconfigure(item, image=piece)
            outer.coords(self._fills[0], r, 0, w - r, h)
            outer.coords(self._fills[1], 0, r, w, h - r)
            for item in self._fills:
                outer.itemconfigure(item, fill=fill)
            for item, coords in zip(self._sides, ((r, 0, w - r, 0), (r, h - 1, w - r, h - 1), (0, r, 0, h - r),
                                                  (w - 1, r, w - 1, h - r))):
                outer.coords(item, *coords)
                outer.itemconfigure(item, fill=edge)
        except tk.TclError:
            pass

    # ---- where it sits is where its outline sits
    def pack(self, *args: Any, **kw: Any) -> Any:  # type: ignore[override]
        return self._outer.pack(*args, **kw) if self._outer is not None else tk.Frame.pack(self, *args, **kw)

    pack_configure = pack  # type: ignore[assignment]

    def pack_forget(self) -> None:
        self._outer.pack_forget() if self._outer is not None else tk.Frame.pack_forget(self)

    def grid(self, *args: Any, **kw: Any) -> Any:  # type: ignore[override]
        return self._outer.grid(*args, **kw) if self._outer is not None else tk.Frame.grid(self, *args, **kw)

    grid_configure = grid  # type: ignore[assignment]

    def grid_remove(self) -> None:
        self._outer.grid_remove() if self._outer is not None else tk.Frame.grid_remove(self)

    def grid_forget(self) -> None:
        self._outer.grid_forget() if self._outer is not None else tk.Frame.grid_forget(self)

    def tkraise(self, above: Any = None) -> None:  # type: ignore[override]
        self._outer.tkraise(above) if self._outer is not None else tk.Frame.tkraise(self, above)

    lift = tkraise  # type: ignore[assignment]

    def destroy(self) -> None:
        if self._outer is not None and not self._going:
            self._going = True
            self._outer.destroy()  # (takes this frame along)
            return
        super().destroy()
