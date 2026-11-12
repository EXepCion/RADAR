"""Which screen is the mouse on? Windows open there - on the screen one is looking at, not on the primary one.

No Tk and no other imports of the app: used by the tray app's windows (ui.theme) and by the live map's launcher.
Everything degrades to "don't know" (None) off Windows or when the system calls fail; callers then leave the
window where the system puts it.
"""
from __future__ import annotations

import ctypes
import sys

Area = tuple[int, int, int, int]  # left, top, right, bottom of a screen's work area (without the taskbar)


class _Point(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class _Rect(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


class _MonitorInfo(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("rcMonitor", _Rect), ("rcWork", _Rect), ("dwFlags", ctypes.c_ulong)]


_NEAREST = 2  # MONITOR_DEFAULTTONEAREST


def pointer() -> tuple[int, int] | None:
    """Where the mouse is, in the coordinates of this process."""
    if sys.platform != "win32":
        return None
    try:
        pt = _Point()
        if not ctypes.windll.user32.GetCursorPos(ctypes.byref(pt)):
            return None
        return pt.x, pt.y
    except (AttributeError, OSError):
        return None


def area_at(x: int, y: int) -> Area | None:
    """The work area of the screen this point is on (the nearest one for a point outside all screens)."""
    if sys.platform != "win32":
        return None
    try:
        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.restype = ctypes.c_void_p
        user32.MonitorFromPoint.argtypes = [_Point, ctypes.c_ulong]
        user32.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_MonitorInfo)]
        monitor = user32.MonitorFromPoint(_Point(x, y), _NEAREST)
        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(_MonitorInfo)
        if not monitor or not user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            return None
        w = info.rcWork
        return (w.left, w.top, w.right, w.bottom) if w.right > w.left and w.bottom > w.top else None
    except (AttributeError, OSError):
        return None


def pointer_area() -> Area | None:
    """The work area of the screen the mouse is on right now."""
    at = pointer()
    return area_at(*at) if at else None


def place(width: int, height: int, area: Area, vertical: float = 0.5, margin: int = 8) -> tuple[int, int, int, int]:
    """Where a window of this size goes on that screen: centred (``vertical`` 0.33 = a third from the top), never
    larger than the screen and never over its edge. Returns x, y, width, height."""
    left, top, right, bottom = area
    room_w, room_h = max(1, right - left - 2 * margin), max(1, bottom - top - 2 * margin)
    width, height = min(width, room_w), min(height, room_h)
    x = left + margin + (room_w - width) // 2
    y = top + margin + int((room_h - height) * vertical)
    return x, y, width, height


def overlap(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> bool:
    """Do two windows (x, y, width, height) cover a common spot?"""
    return a[0] < b[0] + b[2] and b[0] < a[0] + a[2] and a[1] < b[1] + b[3] and b[1] < a[1] + a[3]


def beside(width: int, height: int, other: tuple[int, int, int, int], area: Area, gap: int = 12,
           margin: int = 8) -> tuple[int, int] | None:
    """A place for a window of this size next to another window (x, y, width, height) on that screen, without
    covering it: right of it, else left, else below, else above - lined up with its top (or left) edge as far as the
    screen allows. None when there is no such place."""
    left, top, right, bottom = area
    ox, oy, ow, oh = other
    lo_x, hi_x = left + margin, right - margin - width
    lo_y, hi_y = top + margin, bottom - margin - height
    if hi_x < lo_x or hi_y < lo_y:
        return None  # larger than the screen
    y = min(max(oy, lo_y), hi_y)
    x = min(max(ox, lo_x), hi_x)
    for spot in ((ox + ow + gap, y), (ox - gap - width, y), (x, oy + oh + gap), (x, oy - gap - height)):
        if lo_x <= spot[0] <= hi_x and lo_y <= spot[1] <= hi_y and not overlap((spot[0], spot[1], width, height), other):
            return spot
    return None


def same_screen(x: int, y: int, area: Area) -> bool:
    """Is this point (e.g. a window's middle) on that screen?"""
    here = area_at(x, y)
    return here == area if here else True
