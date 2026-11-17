"""Shared Tk styling: Windows 11 (Fluent) look via the Sun Valley ttk theme, light + dark palettes that can be
switched while windows are open, DPI-scaled fonts, small animations and the taskbar flash helper.
(Sound lives in radar.audio.)"""
from __future__ import annotations

import ctypes
import functools
import logging
import math
import os
import time
import tkinter as tk
from pathlib import Path
from ctypes import wintypes
from datetime import datetime, timezone
from tkinter import font as tkfont
from tkinter import ttk
from typing import Any, Callable

from .. import screens

log = logging.getLogger(__name__)

# Named fonts (created in init): body text, semibold, small caption, window title, big numbers, IDs, tables.
FONT, FONT_BOLD, FONT_CAPTION, FONT_CAPTION_BOLD = "AadBody", "AadStrong", "AadCaption", "AadCaptionStrong"
FONT_TITLE, FONT_DISPLAY, FONT_MONO = "AadTitle", "AadDisplay", "AadMono"
FONT_PAGE, FONT_FIGURE = "AadPage", "AadFigure"  # main window: the title of a page, the number on a tile
FONT_TABLE, FONT_TABLE_BOLD = "AadTable", "AadTableStrong"
FONT_PAD = "AadPad"    # empty lines that form the top/bottom padding of cards inside a text
CELL_PAD = 12          # px left/right inside table cells (headings line up with the cell text)
HEADING_TEXT_SHIFT = 4  # Tk draws cell text this much further in than heading text at the same padding

# Colour roles. Two roles may share a value only if they share it in BOTH palettes (switching the theme maps
# every colour of the old palette to the same role of the new one - see recolor()).
LIGHT = {
    "window": "#f3f3f3", "card": "#ffffff", "border": "#e5e5e5", "track": "#e6e6e6", "heading_bg": "#f9f9f9",
    "text": "#1a1a1a", "muted": "#5d5d5d", "link": "#005fb8", "select": "#cce4f7",
    "row_select": "#dcebf8", "new_row": "#eef5fc", "attention": "#fff4ce", "menu_hover": "#f0f0f0", "disabled": "#a3a3a3",
    "rail": "#eaeaeb", "rail_select": "#dcdcdd", "rail_hover": "#e3e3e4",
    "error": "#a4262c", "pos": "#a4262c", "neg": "#107c10", "warn": "#8a5300",
    "sev_high_bg": "#fde7e9", "sev_high_fg": "#a4262c", "sev_medium_bg": "#fdeadb", "sev_medium_fg": "#8a3b00",
    "sev_low_bg": "#fff4ce", "sev_low_fg": "#7a4600", "sev_info_bg": "#ebebeb", "sev_info_fg": "#5d5d5d",
    "diff_add": "#dff6dd",
}
DARK = {
    "window": "#202020", "card": "#2b2b2b", "border": "#3d3d3d", "track": "#454545", "heading_bg": "#323232",
    "text": "#f3f3f3", "muted": "#ababab", "link": "#60cdff", "select": "#264f78",
    "row_select": "#2e4a66", "new_row": "#26333f", "attention": "#4a3b10", "menu_hover": "#383838", "disabled": "#6f6f6f",
    "rail": "#1a1a1b", "rail_select": "#343435", "rail_hover": "#272728",
    "error": "#ff99a4", "pos": "#ff99a4", "neg": "#6ccb5f", "warn": "#fcb76a",
    "sev_high_bg": "#4a2327", "sev_high_fg": "#ff99a4", "sev_medium_bg": "#4a2f1a", "sev_medium_fg": "#ffb86b",
    "sev_low_bg": "#4a3b10", "sev_low_fg": "#f9e2a6", "sev_info_bg": "#3a3a3a", "sev_info_fg": "#ababab",
    "diff_add": "#1e3a22",
}
# light-palette constants kept for callers / tests that compare against them
MUTED, HEADER_BG, TEXT_BG, BORDER = LIGHT["muted"], LIGHT["window"], LIGHT["card"], LIGHT["border"]
LINK_FG, ERROR_FG = LIGHT["link"], LIGHT["error"]

_scale = 1.0
_per_monitor = False  # Windows was told that RADAR handles every screen's scaling itself
_rescale_listeners: list[Callable[[], None]] = []
_palette = LIGHT
_dark = False
_animations = True
_has_sv = False


def color(role: str) -> str:
    return _palette[role]


def severity_roles(severity) -> tuple[str, str]:
    """(background role, foreground role) of a severity pill."""
    name = getattr(severity, "name", str(severity)).lower()
    return (f"sev_{name}_bg", f"sev_{name}_fg") if f"sev_{name}_bg" in _palette else ("sev_info_bg", "sev_info_fg")


def severity_colors(severity) -> tuple[str, str]:
    """(background, foreground) of a severity pill in the current palette."""
    bg, fg = severity_roles(severity)
    return _palette[bg], _palette[fg]


def is_dark() -> bool:
    return _dark


def animations() -> bool:
    return _animations


def set_animations(enabled: bool) -> None:
    global _animations
    _animations = bool(enabled)


def set_dpi_awareness() -> None:
    """Tell Windows that RADAR draws every screen at that screen's own scaling.

    With less ("system aware") Windows takes what was drawn for the main screen and stretches the picture on a
    screen with another scaling - sharp on one monitor, blurry on the other. Tk does not follow a window from screen
    to screen by itself; ``adapt_to_monitor`` sets the scale for the screen a window opens on."""
    global _per_monitor
    try:
        user32 = ctypes.windll.user32
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetProcessDpiAwarenessContext.restype = ctypes.c_int
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):  # per monitor, version 2 (Windows 10 1703+)
            _per_monitor = True
            return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def pointer_scale() -> float | None:
    """The scaling of the screen the mouse is on (1.0 = 100 %, 1.5 = 150 %); None when Windows does not tell."""
    try:
        from ctypes import wintypes

        user32, shcore = ctypes.windll.user32, ctypes.windll.shcore
        point = wintypes.POINT()
        if not user32.GetCursorPos(ctypes.byref(point)):
            return None
        user32.MonitorFromPoint.argtypes, user32.MonitorFromPoint.restype = [wintypes.POINT, wintypes.DWORD], ctypes.c_void_p
        monitor = user32.MonitorFromPoint(point, 2)  # 2: the nearest screen
        dpi_x, dpi_y = ctypes.c_uint(), ctypes.c_uint()
        shcore.GetDpiForMonitor.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                                            ctypes.POINTER(ctypes.c_uint)]
        if shcore.GetDpiForMonitor(monitor, 0, ctypes.byref(dpi_x), ctypes.byref(dpi_y)) != 0 or not dpi_x.value:
            return None
        return max(1.0, dpi_x.value / 96.0)
    except Exception:
        return None


def on_rescale(callback: Callable[[], None]) -> None:
    """Call this after the scale changed: whoever keeps a window built in advance builds it again."""
    _rescale_listeners.append(callback)


def set_scale(root: tk.Misc, scale: float) -> bool:
    """Everything built from now on is drawn at this scale (fonts, sizes, icons). True when it changed."""
    global _scale
    scale = max(1.0, float(scale))
    if abs(scale - _scale) < 0.01:
        return False
    _scale = scale
    try:
        root.tk.call("tk", "scaling", scale * 96.0 / 72.0)
        _fonts(root)  # type: ignore[arg-type]
        if _has_sv:
            _scale_sv_fonts(root)  # type: ignore[arg-type]
        _style_ttk(root)
    except tk.TclError:
        log.debug("rescale incomplete", exc_info=True)
    for callback in list(_rescale_listeners):
        try:
            callback()
        except Exception:  # noqa: BLE001 - one window failing to rebuild must not stop the others
            log.exception("a window could not be rebuilt for the new scale")
    return True


def adapt_to_monitor(root: tk.Misc) -> bool:
    """Before a window opens: take over the scaling of the screen the mouse is on - where the window will appear.

    Only while no RADAR window is showing: what is on the screen keeps its size, and windows that belong together
    look the same. (A window dragged to a screen with another scaling stays sharp and keeps its size in pixels.)"""
    if not _per_monitor:
        return False
    try:
        for child in root._root().winfo_children():
            if isinstance(child, tk.Toplevel) and child.winfo_viewable():
                return False
    except tk.TclError:
        return False
    scale = pointer_scale()
    return set_scale(root._root(), scale) if scale else False


def px(value: float) -> int:
    return int(round(value * _scale))


# ------------------------------------------------------------------ setup
def init(root: tk.Tk, dark: bool = False, animations: bool = True) -> None:
    """Load the Fluent theme and fonts once per Tk root, then apply light or dark."""
    global _scale, _has_sv
    _scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
    set_animations(animations)
    _fonts(root)
    try:
        import sv_ttk  # noqa: F401 - Sun Valley: the Windows 11 look for ttk (MIT)

        style = ttk.Style(root)
        sv_ttk._load_theme(style)
        # sv-ttk's configure_colors also calls tk_setPalette, which forces its colours onto every widget still at
        # its default - ttk labels included, overriding our styles (muted text printed black, grey label boxes).
        # Keep its ttk part, skip the palette: our widgets set their colours explicitly (see recolor()).
        root.tk.eval("""
            auto_load tk_setPalette
            if {[info procs ::_aad_sv_configure_colors] eq ""} {
                rename ::configure_colors ::_aad_sv_configure_colors
                proc ::configure_colors {} {
                    rename ::tk_setPalette ::_aad_tk_setPalette
                    proc ::tk_setPalette {args} {}
                    catch {::_aad_sv_configure_colors}
                    rename ::tk_setPalette {}
                    rename ::_aad_tk_setPalette ::tk_setPalette
                }
            }
        """)
        _has_sv = True
        # sv-ttk recolours its own defaults on every theme change (idle time); ours must run after it
        root.bind_class(root.winfo_class(), "<<ThemeChanged>>", lambda _e: _after_theme(root), add="+")
    except Exception as exc:  # pragma: no cover - package missing: plain Windows theme, light only
        log.info("Fluent theme not available (%s), using the Windows theme", exc)
        _has_sv = False
    _apply(root, dark)


def _fonts(root: tk.Tk) -> None:
    families = set(tkfont.families(root))

    def pick(*names: str) -> str:
        return next((n for n in names if n in families), names[-1])

    # Tk draws text with GDI: the static Segoe UI faces are hinted for it and look crisper than the variable
    # Segoe UI Variable (uneven spacing at 12-14 px); only the large title/number use the variable Display face.
    body = pick("Segoe UI")
    strong = pick("Segoe UI Semibold", body)
    display = pick("Segoe UI Variable Display Semibold", strong)
    mono = pick("Cascadia Mono", "Consolas")
    existing = set(root.tk.splitlist(root.tk.call("font", "names")))
    for name, family, size in ((FONT, body, 14), (FONT_BOLD, strong, 14), (FONT_CAPTION, body, 12),
                               (FONT_CAPTION_BOLD, strong, 12), (FONT_TABLE, body, 13), (FONT_TABLE_BOLD, strong, 13),
                               (FONT_TITLE, display, 20), (FONT_DISPLAY, display, 40), (FONT_MONO, mono, 13),
                               (FONT_PAGE, display, 24), (FONT_FIGURE, display, 28),
                               (FONT_PAD, body, 9)):
        # created in Tcl directly: a tkinter Font object would delete its font when garbage-collected
        root.tk.call("font", "configure" if name in existing else "create", name, "-family", family,
                     "-size", -px(size))
    tkfont.nametofont("TkDefaultFont", root=root).configure(family=body, size=-px(14))


def _scale_sv_fonts(root: tk.Tk) -> None:
    """sv-ttk defines its fonts in pixels; scale them with the display like everything else."""
    for name, size in (("SunValleyCaptionFont", 12), ("SunValleyBodyFont", 14), ("SunValleyBodyStrongFont", 14),
                       ("SunValleyBodyLargeFont", 18), ("SunValleySubtitleFont", 20), ("SunValleyTitleFont", 28)):
        try:
            tkfont.nametofont(name, root=root).configure(size=-px(size))
        except tk.TclError:
            pass


def _apply(root: tk.Tk, dark: bool) -> None:
    global _palette, _dark
    _dark, _palette = bool(dark), (DARK if dark else LIGHT)
    if _has_sv:
        import sv_ttk

        sv_ttk.set_theme("dark" if _dark else "light", root)
        _scale_sv_fonts(root)
        try:  # what sv-ttk would do at idle time - now, before any window of the new mode is built
            root.tk.eval("configure_colors")
        except tk.TclError:
            pass
    else:
        style = ttk.Style(root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
    _after_theme(root)


def _after_theme(root: tk.Misc) -> None:
    """Our styles on top of what the theme just configured (runs after sv-ttk's own ThemeChanged handler)."""
    _style_ttk(root)
    if not root.__dict__.get("_aad_hand"):
        root.__dict__["_aad_hand"] = True
        _hand_over_buttons(root)


def _style_ttk(root: tk.Misc) -> None:
    """Our styles on top of the theme (re-applied after every theme change)."""
    c = _palette
    style = ttk.Style(root)
    style.configure(".", background=c["window"], foreground=c["text"], font=FONT)
    style.configure("TFrame", background=c["window"])
    style.configure("TLabel", background=c["window"], foreground=c["text"])
    style.configure("Muted.TLabel", background=c["window"], foreground=c["muted"], font=FONT_CAPTION)
    style.configure("Busy.TButton", foreground=c["muted"])  # a button that is working (see freshness.DataAge)
    style.configure("Title.TLabel", background=c["window"], foreground=c["text"], font=FONT_TITLE)
    style.configure("PageTitle.TLabel", background=c["window"], foreground=c["text"], font=FONT_PAGE)
    style.configure("Card.TFrame", background=c["card"])
    style.configure("Card.TCheckbutton", background=c["card"])
    style.configure("Card.Switch.TCheckbutton", background=c["card"])
    style.configure("Card.TRadiobutton", background=c["card"])  # a switch on a card (main window settings)
    style.configure("Card.TLabel", background=c["card"], foreground=c["text"])
    style.configure("CardMuted.TLabel", background=c["card"], foreground=c["muted"], font=FONT_CAPTION)
    style.configure("CardHeading.TLabel", background=c["card"], foreground=c["text"], font=FONT_BOLD)
    # Tables (Fluent list look): flat heading row in a light tint with muted semibold labels, no expander arrow
    # column (all our tables are flat lists), the same left padding for headings and cells so they line up.
    style.layout("Treeview.Heading", [
        ("Treeitem.row", {"sticky": "nswe"}),
        ("Treeheading.padding", {"sticky": "nswe", "children": [
            ("Treeheading.image", {"side": "right", "sticky": ""}), ("Treeheading.text", {"sticky": "we"})]})])
    style.layout("Treeview.Item", [
        ("Treeitem.padding", {"sticky": "nswe", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""}), ("Treeitem.text", {"sticky": "nswe"})]})])
    style.configure("Treeview", background=c["card"], fieldbackground=c["card"], foreground=c["text"],
                    rowheight=px(32), font=FONT_TABLE)
    style.map("Treeview", background=[("selected", c["row_select"])], foreground=[("selected", c["text"])])
    for heading in ("Heading", "Treeview.Heading"):
        style.configure(heading, background=c["heading_bg"], foreground=c["muted"], font=FONT_TABLE_BOLD, relief="flat",
                        padding=(px(CELL_PAD) + px(HEADING_TEXT_SHIFT), px(8), px(CELL_PAD), px(8)))
        style.map(heading, background=[("active", c["track"])], foreground=[("active", c["text"])])
    for part in ("Cell", "Treeview.Cell", "Item", "Treeview.Item"):
        style.configure(part, padding=(px(CELL_PAD), 0))
    style.configure("TNotebook", background=c["window"])
    style.configure("TPanedwindow", background=c["window"])
    style.configure("Card.TPanedwindow", background=c["card"])
    style.configure("Sash", sashthickness=px(6))
    try:
        root.configure(background=c["window"])
    except tk.TclError:
        pass


# ---------------------------------------------------------- theme switch
_COLOR_OPTIONS = ("background", "foreground", "highlightbackground", "highlightcolor", "selectbackground",
                  "selectforeground", "inactiveselectbackground", "insertbackground", "activebackground",
                  "activeforeground", "disabledforeground", "troughcolor")


def color_map(old: dict[str, str], new: dict[str, str]) -> dict[str, str]:
    return {old[k].lower(): new[k] for k in old}


def _descendants(widget: tk.Misc):
    yield widget
    for child in widget.winfo_children():
        yield from _descendants(child)


def recolor(widget: tk.Misc, mapping: dict[str, str]) -> int:
    """Swap palette colours on a widget tree: widget options, text tags, canvas items, treeview tags."""
    changed = 0

    def swap(get: Callable[[], object], put: Callable[[str], None]) -> None:
        nonlocal changed
        try:
            new = mapping.get(str(get()).lower())
            if new:
                put(new)
                changed += 1
        except (tk.TclError, ValueError, TypeError):
            pass

    for w in _descendants(widget):
        hook = getattr(w, "recolor_colors", None)  # a widget that keeps colours of its own (the card table's tags)
        if callable(hook):
            hook(mapping)
        for opt in _COLOR_OPTIONS:
            swap(lambda: w.cget(opt), lambda v: w.configure({opt: v}))
        if isinstance(w, tk.Text):
            for tag in w.tag_names():
                for opt in ("foreground", "background", "lmargincolor", "rmargincolor", "selectbackground",
                            "selectforeground"):
                    swap(lambda: w.tag_cget(tag, opt), lambda v: w.tag_configure(tag, {opt: v}))
        elif isinstance(w, tk.Canvas):
            for item in w.find_all():
                for opt in ("fill", "outline"):
                    swap(lambda: w.itemcget(item, opt), lambda v: w.itemconfigure(item, {opt: v}))
        elif isinstance(w, ttk.Treeview):
            try:
                tags = w.tk.splitlist(w.tk.call(w, "tag", "names"))
            except tk.TclError:
                tags = ()
            for tag in tags:
                for opt in ("foreground", "background"):
                    swap(lambda: w.tag_configure(tag, opt), lambda v: w.tag_configure(tag, **{opt: v}))
    return changed


def set_mode(root: tk.Tk, dark: bool) -> None:
    """Switch light/dark while windows are open (they recolour in place; a short fade when animations are on)."""
    if bool(dark) == _dark:
        return
    old = _palette
    _apply(root, dark)
    recolor(root, color_map(old, _palette))  # the root and every window (Toplevels are its children)
    _refresh_images(root)
    for top in (w for w in _descendants(root) if isinstance(w, tk.Toplevel)):
        title_bar(top)
        try:
            if top.winfo_viewable():
                fade(top, 0.75, 1.0, 220)
        except tk.TclError:
            pass


def title_bar(top: tk.Misc) -> None:
    """Dark or light Windows title bar to match the palette (Windows 10 2004+ / 11)."""
    try:
        top.update_idletasks()
        hwnd = int(top.wm_frame(), 16)
        value = ctypes.c_int(1 if _dark else 0)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (19 on older Windows 10 builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value),
                                                          ctypes.sizeof(value)) == 0:
                break
    except Exception:
        log.debug("title bar colour failed", exc_info=True)


# ------------------------------------------------- theme-aware images
#: Segoe Fluent Icons (Windows 11) / Segoe MDL2 Assets (Windows 10) code points
ICONS = {"open": "\ue8a7", "copy": "\ue8c8", "clock": "\ue823", "check": "\ue73e", "refresh": "\ue72c",
         # the main window's navigation
         "link": "\ue71b", "target": "\ue7ba", "history": "\ue81c", "document": "\ue8a5", "globe": "\ue774",
         "settings": "\ue713", "story": "\uf003", "aim": "\uf272", "report": "\uf000"}
#: glyphs only the Windows 11 icon font has, and what the older one (Windows 10) shows in their place
ICONS_OLD_FONT = {"story": "link", "aim": "target", "report": "document"}
ACCENT_FG = {False: "#ffffff", True: "#000000"}  # text on the accent button (sv-ttk: white on blue / black on cyan)


def _rgb(hex_color: str) -> tuple[int, int, int]:
    return tuple(int(hex_color[i:i + 2], 16) for i in (1, 3, 5))  # type: ignore[return-value]


def role_color(role: str) -> str:
    return ACCENT_FG[_dark] if role == "on_accent" else _palette[role]


@functools.lru_cache(maxsize=4)
def _icon_font(size: int):
    from PIL import ImageFont

    for name in ("SegoeIcons.ttf", "segmdl2.ttf"):
        path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / name
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return None


def _render_icon(name: str, role: str, size: int):
    from PIL import Image, ImageDraw

    font = _icon_font(size * 4)
    img = Image.new("RGBA", (size * 4, size * 4), (0, 0, 0, 0))
    if font is not None:
        if name in ICONS_OLD_FONT and "segmdl2" in str(getattr(font, "path", "")).lower():
            name = ICONS_OLD_FONT[name]
        ImageDraw.Draw(img).text((size * 2, size * 2), ICONS[name], font=font, fill=_rgb(role_color(role)) + (255,),
                                 anchor="mm")
    return img.resize((size, size), Image.LANCZOS)


def _render_pill(width: int, height: int, role: str):
    from PIL import Image, ImageDraw

    s = 4
    img = Image.new("RGBA", (width * s, height * s), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle([0, 0, width * s - 1, height * s - 1], radius=height * s // 2,
                                          fill=_rgb(_palette[role]) + (255,))
    return img.resize((width, height), Image.LANCZOS)


def _themed(widget: tk.Misc, key: tuple, render: Callable[[], object]):
    """A PhotoImage drawn from palette colours, cached per Tk root and redrawn in place on a theme switch."""
    from PIL import ImageTk

    root = widget._root()
    cache = root.__dict__.setdefault("_aad_images", {})
    if key not in cache:
        cache[key] = (ImageTk.PhotoImage(render(), master=root), render)
    return cache[key][0]


def _refresh_images(root: tk.Misc) -> None:
    for photo, render in root.__dict__.get("_aad_images", {}).values():
        try:
            photo.paste(render())
        except (tk.TclError, ValueError):
            pass


def icon(widget: tk.Misc, name: str, role: str = "text", size: int = 16):
    """A Fluent icon glyph in a palette colour (None when the icon font is missing)."""
    size = px(size)
    if name not in ICONS or _icon_font(size * 4) is None:
        return None
    return _themed(widget, ("icon", name, role, size), lambda: _render_icon(name, role, size))


def pill_image(widget: tk.Misc, width: int, height: int, role: str):
    return _themed(widget, ("pill", width, height, role), lambda: _render_pill(width, height, role))


def button_cursor(widget: tk.Misc) -> None:
    """Hand pointer over a button that can be pressed, the normal pointer over a disabled one."""
    try:
        widget.configure(cursor="hand2" if widget.instate(["!disabled"]) else "")
    except tk.TclError:
        pass


def _hand_over_buttons(root: tk.Misc) -> None:
    """All buttons of the app (class binding): the mouse pointer shows that they are clickable."""
    for cls in ("TButton", "TCheckbutton", "TRadiobutton", "TMenubutton"):
        root.bind_class(cls, "<Enter>", lambda e: button_cursor(e.widget), add="+")


REVEAL_DELAY_MS = 60  # time for the first paint of all widgets before a new window becomes visible


class Panel(ttk.Frame):
    """The content of a "window" hosted as a page inside another window (the main window's pages).

    The window classes build themselves into ``top``; given a Panel instead of a Toplevel they work unchanged: what
    only a real window has (title bar, size, icon, fading in) is accepted and does nothing here. ``close`` - what
    a Close / Cancel button or a finished save calls - tells the host (``on_close``) instead of destroying."""

    is_panel = True

    def __init__(self, parent: tk.Misc, on_close: Callable[[], None] | None = None):
        super().__init__(parent)
        self._title, self._on_close = "", on_close

    def title(self, text: str | None = None) -> str:
        if text is not None:
            self._title = text
        return self._title

    def geometry(self, *_a: Any) -> str:
        return ""

    def minsize(self, *_a: Any) -> None:
        return None

    def iconphoto(self, *_a: Any) -> None:
        return None

    def deiconify(self) -> None:
        return None

    def attributes(self, *_a: Any) -> str:
        return ""

    def resizable(self, *_a: Any) -> None:
        return None

    def protocol(self, *_a: Any) -> None:
        return None

    def close(self) -> None:
        if self._on_close is not None:
            self._on_close()


def is_panel(top: tk.Misc) -> bool:
    return bool(getattr(top, "is_panel", False))


def close(top: tk.Misc) -> None:
    """What Close, Cancel, Escape and a finished save do: a window goes away, a page tells its host."""
    try:
        if is_panel(top):
            top.close()  # type: ignore[attr-defined]
        else:
            top.destroy()
    except tk.TclError:
        pass


def new_window(root: tk.Misc, parent: tk.Misc | None = None, on_close: Callable[[], None] | None = None,
               **kw: Any) -> tk.Toplevel:
    """A window that is invisible from the very first moment; ``style_window`` reveals it when it is complete.

    A plain Toplevel shows up as soon as anything runs the idle tasks while it is being built (empty, wrong title
    bar colour, panes not split yet) - that is what flickers when a window opens.

    With ``parent`` the content becomes a page inside that widget instead (a Panel, see there)."""
    if parent is not None:
        return Panel(parent, on_close)  # type: ignore[return-value]
    adapt_to_monitor(root)
    top = tk.Toplevel(root, background=_palette["window"], **kw)
    _safe_alpha(top, 0.0)
    return top


def style_window(top: tk.Toplevel, fade_ms: int = 180, prepare: Callable[[], None] | None = None) -> None:
    """Common end of building a window: title bar matching the palette, final layout, then reveal (fade-in).

    Everything happens while the window is invisible; it appears once, complete and painted. ``prepare`` does
    layout that needs real widget sizes (pane splits)."""
    if is_panel(top):  # a page: its host shows it; only the layout that needs real sizes is done, once it has them
        if prepare is not None:
            def fit() -> None:
                try:
                    if top.winfo_exists():
                        prepare()
                except tk.TclError:
                    log.debug("page preparation failed", exc_info=True)
            top.after_idle(fit)
        return
    top.configure(background=_palette["window"])
    _safe_alpha(top, 0.0)  # (already so for windows from new_window)
    title_bar(top)
    if prepare is not None:
        try:
            top.update_idletasks()
            prepare()
        except tk.TclError:
            log.debug("window preparation failed", exc_info=True)
    reveal(top, fade_ms)


# The window that is always on top (the reminders). A window opened while it is showing must not end up behind
# it: it is put beside it where the screen has room, and otherwise raised above it.
_front: Callable[[], tk.Misc | None] | None = None
_raised: list[tk.Misc] = []
FRAME = (8, 32)  # roughly what the window frame adds: left/right border, title bar


def keep_clear_of(front: Callable[[], tk.Misc | None]) -> None:
    """``front()`` gives the always-on-top window while it is showing (else None)."""
    global _front
    _front = front


def _front_rect(top: tk.Misc) -> tuple[int, int, int, int] | None:
    """Where the always-on-top window is (with its frame) - None when it is not showing or is ``top`` itself."""
    try:
        front = _front() if _front else None
        if front is None or front is top or not front.winfo_exists() or not front.winfo_viewable():
            return None
        return (front.winfo_x(), front.winfo_y(), front.winfo_width() + 2 * FRAME[0], front.winfo_height() + FRAME[1] + FRAME[0])
    except tk.TclError:
        return None


def _rect(top: tk.Misc) -> tuple[int, int, int, int]:
    return (top.winfo_x(), top.winfo_y(), top.winfo_width() + 2 * FRAME[0], top.winfo_height() + FRAME[1] + FRAME[0])


def is_raised(top: tk.Misc) -> bool:
    """Was this window raised above the always-on-top window (and has to stay there while that one shows)?"""
    return top in _raised


def stay_in_front(top: tk.Misc) -> bool:
    """A window that lies (partly) under the always-on-top window is raised above it - and so is one that lies
    under a window that was raised that way: the window that opens last is never behind the one it was opened
    from. True when it was raised."""
    try:
        over = [r for r in [_front_rect(top)] if r is not None]
        over += [_rect(w) for w in _raised if w is not top and w.winfo_exists() and w.winfo_viewable()]
        if not over:
            return False
        mine = _rect(top)
        if not any(screens.overlap(mine, rect) for rect in over):
            return False
        top.attributes("-topmost", True)
        top.lift()
        if top not in _raised:
            _raised.append(top)
        return True
    except tk.TclError:
        return False


def release_raised() -> None:
    """The always-on-top window is gone: the windows raised above it are ordinary windows again."""
    while _raised:
        top = _raised.pop()
        try:
            if top.winfo_exists():
                top.attributes("-topmost", False)
        except tk.TclError:
            pass


def to_pointer_screen(top: tk.Misc, vertical: float = 0.5, only_if_elsewhere: bool = False) -> bool:
    """Put a window on the screen the mouse is on - where one is looking when it opens - centred there and never
    larger than that screen. ``only_if_elsewhere``: leave a window alone that already is on that screen (one the
    user has placed). False when the screen is not known; the window then stays where the system put it."""
    area = screens.pointer_area()
    if area is None:
        return False
    try:
        top.update_idletasks()
        w, h = max(top.winfo_width(), top.winfo_reqwidth()), max(top.winfo_height(), top.winfo_reqheight())
        size = top.geometry().split("+")[0].split("x")  # a size set before the window was laid out
        if len(size) == 2 and size[0].isdigit() and size[1].isdigit() and int(size[0]) > 1:
            w, h = max(w, int(size[0])) if top.winfo_width() <= 1 else w, max(h, int(size[1])) if top.winfo_height() <= 1 else h
        if only_if_elsewhere and screens.same_screen(top.winfo_x() + w // 2, top.winfo_y() + h // 2, area):
            return True
        x, y, fit_w, fit_h = screens.place(w, h, area, vertical)
        front = _front_rect(top)
        if front is not None:  # next to the always-on-top window, not under it (where the screen has the room)
            spot = screens.beside(fit_w + 2 * FRAME[0], fit_h + FRAME[1] + FRAME[0], front, area)
            if spot is not None:
                x, y = spot
        top.geometry(f"{fit_w}x{fit_h}+{x}+{y}" if (fit_w, fit_h) != (w, h) else f"+{x}+{y}")
        top.update_idletasks()
        return True
    except tk.TclError:
        log.debug("window not placed on the pointer's screen", exc_info=True)
        return False


def reveal(top: tk.Misc, fade_ms: int = 180) -> None:
    """Make an invisible window visible after its widgets had time to paint; it can never stay invisible.

    Just before it appears - still invisible - it is put on the screen the mouse is on. (Not earlier: while a new
    window is being built the system still reports where IT first put the window, and that report would undo the
    move.) A window whose place was set on purpose (``keep_place``) stays there."""
    def show() -> None:
        try:
            if top.winfo_exists() and float(top.attributes("-alpha")) < 1.0:
                if not getattr(top, "keep_place", False):
                    to_pointer_screen(top)
                stay_in_front(top)  # no room beside the always-on-top window: then above it, never behind
                fade_in(top, fade_ms)
        except tk.TclError:
            pass

    try:
        top.after(REVEAL_DELAY_MS, show)
        top.after(REVEAL_DELAY_MS + fade_ms + 600, lambda: _safe_alpha(top, 1.0))
    except tk.TclError:
        pass


# ------------------------------------------------------------- animation
def mix(a: str, b: str, t: float) -> str:
    """Colour between ``a`` (t=0) and ``b`` (t=1), both '#rrggbb'."""
    ca, cb = (int(a[i:i + 2], 16) for i in (1, 3, 5)), (int(b[i:i + 2], 16) for i in (1, 3, 5))
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


def ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


def animate(widget: tk.Misc, duration_ms: int, step: Callable[[float], None],
            done: Callable[[], None] | None = None, ease: Callable[[float], float] = ease_out) -> None:
    """Call ``step(progress)`` with 0..1 for ``duration_ms`` (~60 fps); instantly with animations off."""
    def finish() -> None:
        try:
            step(1.0)
            if done:
                done()
        except tk.TclError:
            pass

    if not _animations or duration_ms <= 0:
        finish()
        return
    start = time.monotonic()

    def tick() -> None:
        try:
            if not widget.winfo_exists():
                return
            t = min(1.0, (time.monotonic() - start) * 1000.0 / duration_ms)
            if t >= 1.0:
                finish()
                return
            step(ease(t))
            widget.after(16, tick)
        except tk.TclError:
            pass
        except Exception:
            log.debug("animation step failed", exc_info=True)
            finish()

    tick()


def fade(top: tk.Misc, start: float, end: float, duration_ms: int = 180) -> None:
    def set_alpha(t: float) -> None:
        top.attributes("-alpha", start + (end - start) * t)

    if _animations:
        try:
            top.attributes("-alpha", start)
            top.after(duration_ms + 400, lambda: _safe_alpha(top, end))  # never leave a window half visible
        except tk.TclError:
            return
    animate(top, duration_ms, set_alpha)


def _safe_alpha(top: tk.Misc, value: float) -> None:
    try:
        if top.winfo_exists():
            top.attributes("-alpha", value)
    except tk.TclError:
        pass


def fade_in(top: tk.Misc, duration_ms: int = 180) -> None:
    fade(top, 0.0, 1.0, duration_ms)


def slide_in(top: tk.Toplevel, distance: int = 24, duration_ms: int = 240) -> None:
    """Fade in while gliding up from ``distance`` px below its place (the reminder popup)."""
    if not _animations:
        return
    try:
        top.update_idletasks()
        x, y = top.winfo_x(), top.winfo_y()
    except tk.TclError:
        return
    fade_in(top, duration_ms)
    animate(top, duration_ms, lambda t: top.geometry(f"+{x}+{int(y + distance * (1 - t))}"))


def count_up(label: tk.Misc, value: int, duration_ms: int = 600, fmt: str = "{}") -> None:
    animate(label, duration_ms, lambda t: label.configure(text=fmt.format(int(math.floor(value * t + 0.5)))))


# ------------------------------------------------------------------ text
def humanize(dt: datetime | None, now: datetime | None = None) -> str:
    if dt is None:
        return ""
    now = now or datetime.now(timezone.utc)
    seconds = (now - dt).total_seconds()
    if seconds < 60:
        return "Now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = int(seconds // size)
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "Now"


UI_SWITCH_INTERVAL = 0.0005  # seconds


def keep_ui_responsive() -> None:
    """Let the windows answer at once while a scan is working in the background.

    Building a window is thousands of tiny calls into Tk, and Python hands the interpreter back to a busy
    background thread at each of them - by default for up to 5 ms every time. While a scan parses sign-ins, a
    window that opens in half a second would take many seconds (measured: 0.4 s idle, 16 s during a scan, 0.45 s
    with this). A shorter switch interval costs the scan a little and gives the user the window."""
    import sys

    if sys.getswitchinterval() > UI_SWITCH_INTERVAL:
        sys.setswitchinterval(UI_SWITCH_INTERVAL)


def local_time(dt: datetime | None, fmt: str | None = None) -> str:
    """A time in local time, written as ``fmt`` says (weekday, date and time without one), with its time zone
    (see radar.timefmt)."""
    from .. import timefmt

    return timefmt.stamp(dt, fmt or timefmt.LONG) if dt else "-"


# --------------------------------------------------------------- attention
class _FlashInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND), ("dwFlags", wintypes.DWORD),
                ("uCount", wintypes.UINT), ("dwTimeout", wintypes.DWORD)]


FLASHW_STOP, FLASHW_ALL, FLASHW_TIMER = 0x0, 0x3, 0x4


def flash(window: tk.Misc, stop: bool = False) -> None:
    """Flash title bar + taskbar button continuously (FLASHW_TIMER) until called again with stop=True."""
    try:
        hwnd = int(window.wm_frame(), 16)
        flags = FLASHW_STOP if stop else FLASHW_ALL | FLASHW_TIMER
        info = _FlashInfo(ctypes.sizeof(_FlashInfo), hwnd, flags, 0, 0)
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        log.debug("flash failed", exc_info=True)
