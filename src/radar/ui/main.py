"""The main window: incidents, ongoing attacks, alert history, reports and all settings in one place.

A navigation rail on the left, one page on the right. The pages for incidents, attacks, history, offices, virtual
desktops and the connection check are the same classes that used to be windows of their own, hosted here as pages
(theme.Panel). The reminders, the details of an alert and the live map stay windows of their own: the rail's
"Live map" entry and every "Open details" start them.

Pages are built the first time they are shown and then kept; changing page only raises another one - nothing is
rebuilt and nothing moves. On a first start (set-up not finished) the window opens on Settings > Account and
connection and the other sections are switched off until RADAR can read what it needs.
"""
from __future__ import annotations

from .. import timefmt
import logging
import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from PIL import ImageTk

from .. import APP_DISPLAY_NAME, audio, buildinfo, incidents, paths, startup
from .. import quiet as quiet_rules
from ..plugin_api import Severity
from . import icons, theme
from .cardtable import CardTable
from .reminder import SNOOZE_CHOICES
from .richtext import autoscroll, stable_label
from .tables import make_sortable
from .parts import Hint, card
from .rounded import round_points, rounded_image
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

log = logging.getLogger(__name__)

WIDTH, HEIGHT, RAIL, SUB = 1400, 820, 204, 186
SECTIONS = [("incidents", "Incidents", "story"), ("attacks", "Ongoing attacks", "aim"),
            ("history", "Alert history", "clock"), ("reports", "Reports", "report")]
SETTINGS, MAP = "settings", "map"
WELCOME = f"Welcome to {APP_DISPLAY_NAME}"
SETUP_DONE = ("RADAR is set up and working. It keeps running in the notification area and shows a reminder when it finds "
              "something. A good next step: Offices.")
SETUP_INTRO = ("Two steps: choose how RADAR signs in to your Microsoft Entra tenant, then let it check that it can read what "
               "it needs.")
SETTINGS_PAGES = [("detection", "Detection"), ("offices", "Offices"), ("hosts", "Virtual desktops"),
                  ("reminders", "Reminders and sound"), ("appearance", "Appearance and start"),
                  ("account", "Account and connection"), ("plugins", "Plugins"), ("advanced", "Advanced")]
SETUP_HINT = "Available as soon as RADAR is set up."
STATUS_TEMPLATE = "Sign-in threat detection, Directory audit\n" + "w" * 26  # the longest lines under the status
ATTACK_COUNT_EVERY = 300  # seconds between two counts for the "Ongoing attacks" badge
LEVELS = [("Info (everything)", "info"), ("Low", "low"), ("Medium", "medium"), ("High", "high")]
INTERVALS = [5, 10, 15, 30, 60, 120]


class NavList:
    """A list of entries to choose from (the rail, the settings list), drawn on one canvas.

    The chosen entry has a tinted, rounded background and an accent bar on its left; the entry under the pointer a
    lighter one; an entry can carry a count badge on the right. One canvas, so nothing flickers when the pointer
    moves: the only things that change are the colours of an entry's background shape and of its text."""

    def __init__(self, parent: tk.Misc, on_choose: Callable[[str], None], row: int = 40, width: int = 0,
                 roles: tuple[str, str, str] = ("window", "track", "heading_bg")):
        self._on_choose, self._row = on_choose, px(row)
        self._bg, self._sel, self._hov = roles  # palette roles: background, the chosen entry, under the pointer
        self.items: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self.selected, self._hover = "", ""
        self.canvas = tk.Canvas(parent, highlightthickness=0, bd=0, background=theme.color(self._bg),
                                width=px(width) if width else 1)
        self.canvas.bind("<Configure>", lambda _e: self._layout())
        self.canvas.bind("<Motion>", lambda e: self._set_hover(self.key_at(e.y)))
        self.canvas.bind("<Leave>", lambda _e: self._set_hover(""))
        self.canvas.bind("<Button-1>", lambda e: self.click(self.key_at(e.y)))

    def pack(self, **kw: Any) -> None:
        self.canvas.pack(**kw)

    def add(self, key: str, text: str, icon: str | None = None, bottom: bool = False, selectable: bool = True,
            trailing: str = "") -> None:
        c = self.canvas
        image = theme.icon(c, icon, "text") if icon else None
        item = {"text": text, "bottom": bottom, "selectable": selectable, "enabled": True, "image": image,
                "bg": c.create_polygon(0, 0, 0, 0, outline="", fill=theme.color(self._bg)),
                "bar": c.create_polygon(0, 0, 0, 0, outline="", fill=theme.color(self._bg)),
                "icon": c.create_image(0, 0, image=image, anchor="center") if image is not None else None,
                "label": c.create_text(0, 0, text=text, anchor="w", font=theme.FONT, fill=theme.color("text")),
                "trail": c.create_text(0, 0, text=trailing, anchor="e", font=theme.FONT_CAPTION, fill=theme.color("muted")),
                "pill": c.create_image(0, 0, anchor="e"),  # the badge: a smooth pill (an image), its count on it
                "count": c.create_text(0, 0, text="", anchor="center", font=theme.FONT_CAPTION_BOLD, fill=theme.color(self._bg)),
                "badge": "", "badge_role": "error", "top": 0}
        self.items[key] = item
        self._order.append(key)
        self._layout()

    @staticmethod
    def _rounded(x1: int, y1: int, x2: int, y2: int, r: int) -> list[int]:
        return round_points(x1, y1, x2, y2, r)

    def _layout(self) -> None:
        c = self.canvas
        try:
            width, height = max(c.winfo_width(), int(c.cget("width"))), c.winfo_height()
        except tk.TclError:
            return
        gap, y_top = px(2), 0
        bottoms = [k for k in self._order if self.items[k]["bottom"]]
        y_bottom = max(height, (len(self._order)) * (self._row + gap)) - len(bottoms) * (self._row + gap)
        for key in self._order:
            item = self.items[key]
            if item["bottom"]:
                top, y_bottom = y_bottom, y_bottom + self._row + gap
            else:
                top, y_top = y_top, y_top + self._row + gap
            item["top"] = top
            mid = top + self._row // 2
            c.coords(item["bg"], *self._rounded(0, top, width, top + self._row, px(5)))
            c.coords(item["bar"], *self._rounded(0, top + px(11), px(3), top + self._row - px(11), 1))
            x = px(14)
            if item["icon"] is not None:
                c.coords(item["icon"], x + px(9), mid)
                x += px(30)
            c.coords(item["label"], x, mid)
            c.coords(item["trail"], width - px(12), mid)
            self._place_badge(item, width, mid)
        self._paint_all()

    def _place_badge(self, item: dict[str, Any], width: int, mid: int) -> None:
        c = self.canvas
        if not item["badge"]:
            c.itemconfigure(item["pill"], image="")
            c.itemconfigure(item["count"], text="")
            return
        c.itemconfigure(item["count"], text=item["badge"])
        text_w = tkfont_measure(item["badge"])
        w, h = max(px(20), text_w + px(12)), px(18)
        x2 = width - px(10)
        bg, _fg = BADGE_ROLES.get(item["badge_role"], BADGE_ROLES["error"])
        c.coords(item["pill"], x2, mid)
        c.itemconfigure(item["pill"], image=rounded_image(c, w, h, h // 2, bg))
        c.coords(item["count"], x2 - w // 2, mid)

    def _paint(self, key: str) -> None:
        item = self.items.get(key)
        if item is None:
            return
        c = self.canvas
        chosen, hover, enabled = key == self.selected, key == self._hover, item["enabled"]
        try:
            back = self._sel if chosen else self._hov if hover and enabled else self._bg
            c.itemconfigure(item["bg"], fill=theme.color(back))
            c.itemconfigure(item["bar"], fill=theme.color("link" if chosen else back))
            c.itemconfigure(item["label"], fill=theme.color("text" if enabled else "disabled"),
                            font=theme.FONT_BOLD if chosen else theme.FONT)
            c.itemconfigure(item["trail"], fill=theme.color("muted" if enabled else "disabled"))
            if item["badge"]:
                bg, fg = BADGE_ROLES.get(item["badge_role"], BADGE_ROLES["error"])
                c.itemconfigure(item["count"], fill=theme.color(fg))
        except tk.TclError:
            pass

    def _paint_all(self) -> None:
        for key in self._order:
            self._paint(key)

    def key_at(self, y: int) -> str:
        for key in self._order:
            top = self.items[key]["top"]
            if top <= y < top + self._row:
                return key
        return ""

    def _set_hover(self, key: str) -> None:
        if key == self._hover:
            return
        previous, self._hover = self._hover, key
        for k in (previous, key):
            self._paint(k)
        try:
            self.canvas.configure(cursor="hand2" if key and self.items[key]["enabled"] else "")
        except tk.TclError:
            pass

    def click(self, key: str) -> None:
        """What a click on that entry does (nothing for one that is switched off)."""
        item = self.items.get(key)
        if item is None or not item["enabled"]:
            return
        if item["selectable"]:
            self.select(key)
        self._on_choose(key)

    def select(self, key: str) -> None:
        previous, self.selected = self.selected, key
        for k in (previous, key):
            self._paint(k)

    def set_enabled(self, key: str, enabled: bool) -> None:
        if key in self.items:
            self.items[key]["enabled"] = enabled
            self._paint(key)

    def enabled(self, key: str) -> bool:
        return bool(self.items.get(key, {}).get("enabled", True))

    def set_badge(self, key: str, count: int, role: str = "error") -> None:
        """A count on the right of an entry (0 = none)."""
        item = self.items.get(key)
        if item is None:
            return
        text = str(count) if count else ""
        if (text, role) != (item["badge"], item["badge_role"]):
            item["badge"], item["badge_role"] = text, role
            self._layout()

    def badge(self, key: str) -> str:
        return str(self.items.get(key, {}).get("badge", ""))

    def look(self, key: str) -> dict[str, str]:
        """How an entry is drawn right now (its colours), for whoever wants to check."""
        item, c = self.items[key], self.canvas
        return {"background": str(c.itemcget(item["bg"], "fill")), "bar": str(c.itemcget(item["bar"], "fill")),
                "text": str(c.itemcget(item["label"], "fill"))}


def tkfont_measure(text: str) -> int:
    import tkinter.font as tkfont

    try:
        return tkfont.nametofont(theme.FONT_CAPTION_BOLD).measure(text)
    except tk.TclError:
        return px(8) * len(text)


BADGE_ROLES = {"error": ("error", "card"), "warn": ("sev_medium_bg", "sev_medium_fg"), "news": ("link", "card")}
AUTO_CLOSE = [("Never", 0), ("After 3 days", 3), ("After 7 days", 7), ("After 14 days", 14), ("After 30 days", 30)]


class ScrollFrame(ttk.Frame):
    """A frame whose content scrolls vertically (rows of settings); the inner frame is ``body``."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent)
        canvas = self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, background=theme.color("window"))
        bar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=autoscroll(bar))  # (the bar is there only when the rows do not fit)
        canvas.grid(row=0, column=0, sticky="nsew")
        bar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, minsize=bar.winfo_reqwidth())  # its place is kept: the rows never change width
        self.body = ttk.Frame(canvas)
        self._window = canvas.create_window(0, 0, anchor="nw", window=self.body)
        self.body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(self._window, width=e.width))
        for widget in (canvas, self.body):
            widget.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", self._wheel), add="+")
            widget.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"), add="+")

    def _wheel(self, event: tk.Event) -> None:
        if self.canvas.winfo_exists() and self.body.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")


class Rows:
    """Rows of a settings page, grouped in white cards: a title, an explanation under it, the controls on the right."""

    def __init__(self, parent: tk.Misc):
        self.parent = parent
        self.card: tk.Misc | None = None
        self._rows_in_card = 0
        self._n = 0

    def group(self, text: str) -> None:
        """A new card for the rows that follow, with a caption as its first line."""
        c = theme.color
        self.card = card(self.parent)
        self.card.pack(fill="x", padx=(0, px(6)), pady=(px(10) if self._n else 0, 0))
        if text:
            strip = tk.Frame(self.card, background=c("heading_bg"), bd=0, highlightthickness=0, padx=px(16), pady=px(7))
            strip.pack(fill="x")
            tk.Label(strip, text=text, font=theme.FONT_CAPTION_BOLD, background=c("heading_bg"), foreground=c("muted"),
                     bd=0, padx=0, pady=0).pack(side="left")
            tk.Frame(self.card, background=c("border"), height=1, bd=0, highlightthickness=0).pack(fill="x")
        self._rows_in_card = 0
        self._n += 1

    def row(self, title: str, hint: str = "", hint_role: str = "muted") -> tuple[tk.Frame, ttk.Label, ttk.Label]:
        """(the place for controls on the right, the title label, the hint label)."""
        if self.card is None:
            self.group("")
        if self._rows_in_card:
            tk.Frame(self.card, background=theme.color("border"), height=1, bd=0).pack(fill="x")
        frame = tk.Frame(self.card, padx=px(16), pady=px(10), background=theme.color("card"), bd=0, highlightthickness=0)  # (sv-ttk draws its own Card.TFrame: not that one)
        frame.pack(fill="x")
        controls = tk.Frame(frame, background=theme.color("card"), bd=0, highlightthickness=0)
        controls.pack(side="right", padx=(px(12), 0))
        text = tk.Frame(frame, background=theme.color("card"), bd=0, highlightthickness=0)
        text.pack(side="left", fill="x", expand=True)
        name = ttk.Label(text, text=title, style="Card.TLabel", anchor="w", justify="left")
        name.pack(fill="x")
        note = ttk.Label(text, text=hint, style="CardMuted.TLabel", anchor="w", justify="left", wraplength=px(640))
        if hint_role != "muted":
            note.configure(foreground=theme.color(hint_role))
        if hint:
            note.pack(fill="x")
        self._rows_in_card += 1
        self._n += 1
        return controls, name, note

    def switch(self, title: str, hint: str, get: Callable[[], bool], toggle: Callable[[], None],
               hint_role: str = "muted") -> tk.BooleanVar:
        controls, _name, _note = self.row(title, hint, hint_role)
        var = tk.BooleanVar(value=bool(get()))

        def flipped() -> None:
            try:
                toggle()
            finally:
                var.set(bool(get()))  # what it is now, whatever the toggle did
        ttk.Checkbutton(controls, variable=var, style="Card.Switch.TCheckbutton", command=flipped).pack(side="right")
        return var

    def choice(self, title: str, hint: str, values: list[str], current: str, chosen: Callable[[str], None],
               width: int = 18) -> ttk.Combobox:
        controls, _name, _note = self.row(title, hint)
        var = tk.StringVar(value=current)
        box = ttk.Combobox(controls, textvariable=var, values=values, state="readonly", width=width)
        box.pack(side="right")
        box.bind("<<ComboboxSelected>>", lambda _e: chosen(var.get()))
        return box

    def button(self, controls: tk.Misc, text: str, command: Callable[[], None], accent: bool = False) -> ttk.Button:
        b = ttk.Button(controls, text=text, command=command, **({"style": "Accent.TButton"} if accent else {}))
        b.pack(side="right", padx=(px(6), 0))
        return b


class MainWindow:
    def __init__(self, root: tk.Tk, app: "App", page: str = "incidents", sub: str | None = None):
        self.app, self.root = app, root
        self._pages: dict[str, Any] = {}       # section -> the page object (it has .top or is a frame)
        self._frames: dict[str, tk.Misc] = {}  # section -> what is raised
        self._sub_frames: dict[str, tk.Misc] = {}
        self._sub_objects: dict[str, Any] = {}
        self._setup_mode = False
        top = self.top = theme.new_window(root)
        top.title(APP_DISPLAY_NAME)
        width = min(px(WIDTH), int(top.winfo_screenwidth() * 0.94))
        height = min(px(HEIGHT), int(top.winfo_screenheight() * 0.88))
        top.geometry(f"{width}x{height}")
        top.minsize(min(px(1290), top.winfo_screenwidth() - px(40)), min(px(700), top.winfo_screenheight() - px(80)))  # the embedded editors need their width
        self._icon = ImageTk.PhotoImage(icons.app_icon(32), master=root)
        top.iconphoto(False, self._icon)

        rail_bg = theme.color("rail")
        rail = tk.Frame(top, width=px(RAIL), background=rail_bg, bd=0, highlightthickness=0, padx=px(8), pady=px(10))
        rail.pack(side="left", fill="y")
        rail.pack_propagate(False)
        # at the bottom, on a card of its own: what RADAR is doing (a dot and a word, the times under it) and, under
        # a hairline, who it is signed in as. Every line has its fixed place: nothing moves when a scan starts.
        panel = card(rail, fill="window")
        panel.pack(side="bottom", fill="x")
        back = theme.color("window")
        flat = dict(bd=0, padx=0, pady=0, highlightthickness=0, background=back)
        self._status_width = px(RAIL - 16 - 6 - 24)  # the rail less its margins, the card's edge and its padding
        state = tk.Frame(panel, bd=0, highlightthickness=0, background=back, padx=px(12))
        state.pack(fill="x", pady=(px(9), px(8)))
        head = tk.Frame(state, bd=0, highlightthickness=0, background=back)
        head.pack(fill="x")
        self.status_dot = tk.Label(head, **flat)
        self.status_dot.pack(side="left", padx=(0, px(8)))
        self._dot_role = ""
        self.status = tk.Label(head, font=theme.FONT_BOLD, anchor="w", foreground=theme.color("text"), **flat)
        self.status.pack(side="left", fill="x", expand=True)
        self.status_detail = stable_label(state, STATUS_TEMPLATE, width=self._status_width, font=theme.FONT_CAPTION,
                                          min_lines=2, max_lines=2, background=back)
        self.status_detail.pack(fill="x", pady=(px(3), 0))
        tk.Frame(panel, height=1, background=theme.color("border"), bd=0, highlightthickness=0).pack(fill="x")
        who = self._account_area = tk.Frame(panel, bd=0, highlightthickness=0, background=back, padx=px(12), cursor="hand2")
        who.pack(fill="x", pady=(px(8), px(9)))
        caption = tk.Label(who, text="Signed in as", font=theme.FONT_CAPTION, anchor="w", foreground=theme.color("muted"), **flat)
        caption.pack(fill="x")
        self.status_account = tk.Label(who, font=theme.FONT, anchor="w", foreground=theme.color("text"), **flat)
        self.status_account.pack(fill="x", pady=(px(1), 0))
        self.status_app = tk.Label(who, font=theme.FONT_CAPTION, anchor="w", foreground=theme.color("muted"), **flat)
        self.status_app.pack(fill="x", pady=(px(1), 0))
        for widget in (who, caption, self.status_account, self.status_app):  # a click: the account page
            widget.bind("<Button-1>", lambda _e: self.show(SETTINGS, "account"))
        self.account_hint = Hint((caption, self.status_account), lambda: self.account_now()[1])  # the address
        self.app_hint = Hint((self.status_app,), lambda: self.app_now()[1])  # the application ID
        tk.Frame(rail, height=px(8), background=rail_bg, bd=0, highlightthickness=0).pack(side="bottom", fill="x")
        self.nav = NavList(rail, self._nav_chosen, roles=("rail", "rail_select", "rail_hover"))
        for key, label, icon in SECTIONS:
            self.nav.add(key, label, icon)
        self.nav.add(MAP, "Live map", "globe", selectable=False, trailing="\u2197")  # opens the map's own window
        self.nav.add(SETTINGS, "Settings", "settings", bottom=True)
        self.nav.pack(side="top", fill="both", expand=True, pady=(0, px(6)))

        tk.Frame(top, width=1, background=theme.color("border"), bd=0, highlightthickness=0).pack(side="left", fill="y")
        self.content = ttk.Frame(top)
        self.content.pack(side="left", fill="both", expand=True)
        self.content.rowconfigure(0, weight=1)
        self.content.columnconfigure(0, weight=1)

        top.bind("<Destroy>", self._destroyed, add="+")
        self.set_setup_mode(not app.setup_done)
        if self._setup_mode:
            page, sub = SETTINGS, "account"
        self.show(page, sub)
        self.refresh()
        theme.style_window(top)
        top.lift()
        top.focus_force()
        self._tick()

    # ------------------------------------------------------------------- rail
    def _nav_chosen(self, key: str) -> None:
        if key == MAP:
            self.app.show_map()
        else:
            self.show(key)

    @property
    def current(self) -> str:
        """The section that is shown."""
        return self.nav.selected

    @property
    def current_settings(self) -> str:
        """The settings page that is shown ('' before the settings were opened)."""
        return self.sub_nav.selected if getattr(self, "sub_nav", None) is not None else ""

    def set_setup_mode(self, on: bool) -> None:
        """Set-up not finished: only the settings are available; nothing else has anything to show yet."""
        self._setup_mode = on
        for key in self.nav.items:
            if key != SETTINGS:
                self.nav.set_enabled(key, not on)
        self._status()
        if getattr(self, "sub_nav", None) is not None:
            for key in self.sub_nav.items:
                if key != "account":
                    self.sub_nav.set_enabled(key, not on)
            self.settings_title.configure(text=WELCOME if on else "Settings")

    # ------------------------------------------------------------------ pages
    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        self.top.deiconify()
        self.top.lift()
        self.top.focus_force()

    def show(self, page: str, sub: str | None = None) -> None:
        """Bring a section to the front (and, for the settings, one of its pages); built on first use."""
        if page not in self.nav.items or page == MAP or (self._setup_mode and page != SETTINGS):
            page = SETTINGS if self._setup_mode else "incidents"
        came_from = self.current
        self.nav.select(page)
        if page not in self._frames:
            try:
                self._frames[page] = self._build(page)
            except Exception:
                log.exception("Page %s could not be built", page)
                return
            self._frames[page].grid(row=0, column=0, sticky="nsew")
        self._frames[page].tkraise()
        if page == SETTINGS:
            self.show_settings(sub or self.current_settings or "detection")
        elif page == "attacks":
            win = self._pages.get("attacks")
            if win is not None and not getattr(win, "_loaded_once", False):
                win._loaded_once = True
                win.load(then_refresh=True)  # at once what the app has, meanwhile fresh data in the background
            elif win is not None and came_from != "attacks":
                win.opened()
        elif page == "reports":
            self._pages["reports"].load()
            try:  # its figures have been looked at: the mark goes
                self.app.mark_reports_seen()
            except Exception:  # noqa: BLE001 - a badge must never be in the way
                log.debug("reports could not be marked as seen", exc_info=True)
            self.nav.set_badge("reports", 0, "news")

    def _build(self, page: str) -> tk.Misc:
        app, root, content = self.app, self.root, self.content
        if page == "incidents":
            from .incidents import IncidentsWindow
            win = app._incidents = self._pages[page] = IncidentsWindow(root, app, parent=content)
            return win.top
        if page == "attacks":
            from .attacks import AttacksWindow
            win = app._attacks_win = self._pages[page] = AttacksWindow(root, app, parent=content)
            return win.top
        if page == "history":
            from .history import HistoryWindow
            win = app._history = self._pages[page] = HistoryWindow(root, app, parent=content)
            return win.top
        if page == "reports":
            report = self._pages[page] = ReportsPage(content, app)
            return report.frame
        return self._build_settings()

    def page(self, name: str) -> Any:
        """The page object of a section, or None when it has not been shown yet."""
        return self._pages.get(name)

    # --------------------------------------------------------------- settings
    def _build_settings(self) -> tk.Misc:
        frame = ttk.Frame(self.content, padding=(px(20), px(16), px(20), px(12)))
        self.settings_title = ttk.Label(frame, text=WELCOME if self._setup_mode else "Settings", style="PageTitle.TLabel")
        self.settings_title.pack(fill="x")
        self.settings_intro = stable_label(frame, "w" * 110, width=px(WIDTH - RAIL - 60))
        self.settings_intro.pack(fill="x", pady=(px(4), px(8)))
        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        side = ttk.Frame(body, width=px(SUB))
        side.pack(side="left", fill="y", padx=(0, px(14)))
        side.pack_propagate(False)
        self.version_label = stable_label(side, f"{APP_DISPLAY_NAME} {buildinfo.full_version()}\nw", width=px(SUB - 20), min_lines=2)
        self.version_label.pack(side="bottom", fill="x", padx=px(12))
        self.sub_nav = NavList(side, self.show_settings, row=34)
        for key, label in SETTINGS_PAGES:
            self.sub_nav.add(key, label)
            if self._setup_mode and key != "account":
                self.sub_nav.set_enabled(key, False)
        self.sub_nav.pack(side="top", fill="both", expand=True)
        self.sub_content = ttk.Frame(body)
        self.sub_content.pack(side="left", fill="both", expand=True)
        self.sub_content.rowconfigure(0, weight=1)
        self.sub_content.columnconfigure(0, weight=1)
        return frame

    INTROS = {
        "detection": "Detection: what RADAR looks for. Changes apply at once.",
        "offices": "Offices: the public addresses your sites sign in from. Sign-ins from there count as \"in the office\".",
        "hosts": "Virtual desktops and shared hosts: a sign-in from one says where the machine is, not where the person is.",
        "reminders": "Reminders and sound: when a reminder pops up and how it gets your attention.",
        "appearance": "Appearance and start: how RADAR looks, and how it starts and stays up to date.",
        "account": "Account and connection: how RADAR signs in, and whether it can read everything it needs.",
        "plugins": "Plugins: the functions RADAR runs, how often, and checks of your own.",
        "advanced": "Advanced: the settings file, the log, and what RADAR keeps on this PC.",
    }

    def show_settings(self, sub: str) -> None:
        if sub not in dict(SETTINGS_PAGES) or (self._setup_mode and sub != "account"):
            sub = "account" if self._setup_mode else "detection"
        self.sub_nav.select(sub)
        # (which page it is, the list beside it says; the words are for the first set-up only)
        self.settings_intro.configure(text=SETUP_INTRO if self._setup_mode else "")
        if sub not in self._sub_frames:
            try:
                self._sub_frames[sub] = self._build_sub(sub)
            except Exception:
                log.exception("Settings page %s could not be built", sub)
                return
            self._sub_frames[sub].grid(row=0, column=0, sticky="nsew")
        self._sub_frames[sub].tkraise()
        self._update_version()

    def _rebuild_sub(self, sub: str) -> None:
        """Throw a settings page away and build it again (after Save / Discard in an embedded editor)."""
        old = self._sub_frames.pop(sub, None)
        self._sub_objects.pop(sub, None)
        if old is not None:
            try:
                tk.Frame.destroy(old)
            except tk.TclError:
                pass
        if self.exists() and self.current == SETTINGS and self.current_settings == sub:
            self.show_settings(sub)

    def _build_sub(self, sub: str) -> tk.Misc:
        app, parent = self.app, self.sub_content
        if sub == "offices":
            win = self._sub_objects[sub] = app.offices_editor(parent, lambda: self.root.after_idle(self._rebuild_sub, "offices"))
            return win.top
        if sub == "hosts":
            win = self._sub_objects[sub] = app.hosts_editor(parent, lambda: self.root.after_idle(self._rebuild_sub, "hosts"))
            return win.top
        if sub == "account":
            from .setup import SetupWindow
            win = app._setup = self._sub_objects[sub] = SetupWindow(self.root, app, run_now=False, parent=parent)
            return win.top
        scroll = ScrollFrame(parent)
        rows = Rows(scroll.body)
        getattr(self, f"_fill_{sub}")(rows)
        ttk.Frame(scroll.body, height=px(8)).pack(fill="x")
        return scroll

    def sub_object(self, sub: str) -> Any:
        return self._sub_objects.get(sub)

    # -- detection
    def _fill_detection(self, rows: Rows) -> None:
        app, pm = self.app, self.app.plugins
        for rt in pm.ordered():
            pid = rt.plugin.id
            rows.group("")  # one card per plugin: its name and state first, then its rules
            controls, name, _h = rows.row(rt.plugin.name, app.plugin_status_text(rt))
            name.configure(font=theme.FONT_BOLD)
            var = tk.BooleanVar(value=pm.is_enabled(pid))
            ttk.Checkbutton(controls, variable=var, style="Card.Switch.TCheckbutton",
                            command=lambda p=pid, v=var: (app.toggle_plugin(p), v.set(pm.is_enabled(p)))).pack(side="right")
            rows.button(controls, "Run now", lambda p=pid: app.scan_now(p))
            notes = getattr(rt.plugin, "rule_notes", None) or {}
            for rule in rt.plugin.rules:
                note = notes.get(rule.id)
                rows.switch(rule.name, f"{note[0].upper()}{note[1:]}." if note else (getattr(rule, "description", "") or ""),
                            lambda p=pid, r=rule.id: pm.rule_enabled(p, r), lambda p=pid, r=rule.id: app.toggle_rule(p, r),
                            hint_role="warn" if note else "muted")

    # -- reminders and sound
    def _fill_reminders(self, rows: Rows) -> None:
        app, cfg = self.app, self.app.cfg
        rows.group("Reminders")
        level = str(cfg.get("general", "notify_min_severity", default="low")).lower()
        labels = [label for label, _v in LEVELS]
        rows.choice("Remind me from", "Findings below this level are only logged; they stay in the alert history.", labels,
                    next((label for label, v in LEVELS if v == level), "Low"),
                    lambda label: cfg.set("general", "notify_min_severity", value=dict(LEVELS)[label]))
        rows.choice("Default snooze", "What the Snooze button offers first", [label for label, _m in SNOOZE_CHOICES],
                    str(cfg.get("general", "default_snooze", default="15 minutes")),
                    lambda label: cfg.set("general", "default_snooze", value=label), width=12)
        rows.switch("Flash the reminder window", "Until you touch it",
                    lambda: bool(cfg.get("general", "flash_window", default=True)),
                    lambda: cfg.set("general", "flash_window", value=not bool(cfg.get("general", "flash_window", default=True))))
        days = int(cfg.get("general", "auto_close_low_days", default=7) or 0)
        rows.choice("Close Low alerts by themselves", "Seen and unchanged for this long: they go to the alert history",
                    [label for label, _d in AUTO_CLOSE],
                    next((label for label, d in AUTO_CLOSE if d == days), f"After {days} days"),
                    lambda label: cfg.set("general", "auto_close_low_days", value=dict(AUTO_CLOSE).get(label, days)), width=14)
        rows.switch("Weekly MFA exposure report", "For Reports; a mark there tells when its figures have changed",
                    lambda: app.exposure_reminder, app.toggle_exposure_reminder)
        entries = app.quiet_entries() if hasattr(app, "quiet_entries") else []
        if entries:  # what "Don't remind again" in an alert switched off
            rows.group("Switched off")
            for q in entries:
                controls, _n, _h = rows.row(
                    f"{app.rule_name(q.rule_id)}: {quiet_rules.label(q.subject)}",
                    f"No reminders up to {Severity(q.severity).label} until {timefmt.stamp_year(q.until)}. Still judged "
                    f"and kept in the alert history.")
                rows.button(controls, "Remind me again", lambda q=q: (
                    app.unquiet(q.rule_id, q.subject), self.root.after_idle(self._rebuild_sub, "reminders")))
        rows.group("Sound")
        controls, _n, self.device_label = rows.row("Reminder sound", self._device_text())
        var = tk.BooleanVar(value=app.sound_enabled)
        ttk.Checkbutton(controls, variable=var, style="Card.Switch.TCheckbutton",
                        command=lambda: (app.toggle_sound(), var.set(app.sound_enabled))).pack(side="right")
        rows.button(controls, "Test", app.test_sound)
        rows.switch("Stay silent when Windows is muted", "No sound while the default playback device is muted or at volume 0",
                    lambda: app.respect_mute, app.toggle_respect_mute)

    @staticmethod
    def _device_text() -> str:
        try:
            return f"Plays on the default playback device: {audio.output_state().describe_device()}"
        except Exception:  # noqa: BLE001
            return "Plays on the default playback device"

    # -- appearance and start
    def _fill_appearance(self, rows: Rows) -> None:
        app, cfg = self.app, self.app.cfg
        rows.group("Appearance")
        rows.switch("Dark mode", "All windows and the right-click menu follow", lambda: app.dark_mode, app.toggle_dark_mode)
        rows.switch("Animations", "Fades, the risk bar, the reminder gliding in", lambda: app.animations, app.toggle_animations)
        rows.group("Start")
        rows.switch("Start with Windows", "RADAR starts in the notification area when you sign in to Windows",
                    startup.is_enabled, app.toggle_startup)
        rows.switch("Open this window at start", "Off: only the tray icon; the reminders come up when there is something new",
                    lambda: bool(cfg.get("general", "open_main_at_start", default=False)),
                    lambda: cfg.set("general", "open_main_at_start",
                                    value=not bool(cfg.get("general", "open_main_at_start", default=False))))
        rows.group("New versions")
        rows.switch("Check for new versions", "Once a day RADAR asks GitHub for the latest release. Nothing is downloaded or "
                    "installed by itself.", lambda: app.check_updates, app.toggle_check_updates)
        controls, _n, self.version_row = rows.row(f"{APP_DISPLAY_NAME} {buildinfo.full_version()}", self._version_text())
        rows.button(controls, "Open the releases page", app.open_update_page)
        rows.button(controls, "Look now", app.look_for_update)

    def _version_text(self) -> str:
        newer = getattr(self.app.updates, "available", None)
        return f"Version {newer.version} is available." if newer is not None else "No newer version is known."

    def _update_version(self) -> None:
        try:
            newer = getattr(self.app.updates, "available", None)
            self.version_label.configure(text=f"{APP_DISPLAY_NAME} {buildinfo.full_version()}"
                                         + (f"\n{newer.version} is available" if newer is not None else ""))
            if getattr(self, "version_row", None) is not None and self.version_row.winfo_exists():
                self.version_row.configure(text=self._version_text())
        except tk.TclError:
            pass

    # -- plugins
    def _fill_plugins(self, rows: Rows) -> None:
        app, pm, cfg = self.app, self.app.plugins, self.app.cfg
        rebuild = lambda: self.root.after_idle(self._rebuild_sub, "plugins")  # noqa: E731
        rows.group("Loaded")
        for rt in pm.ordered():
            pid = rt.plugin.id
            controls, _n, _h = rows.row(rt.plugin.name, ("built in" if rt.builtin else rt.source.replace("\\", "/").rsplit("/", 1)[-1])
                                        + " · " + app.plugin_status_text(rt))
            var = tk.BooleanVar(value=pm.is_enabled(pid))
            ttk.Checkbutton(controls, variable=var, style="Card.Switch.TCheckbutton",
                            command=lambda p=pid, v=var: (app.toggle_plugin(p), v.set(pm.is_enabled(p)))).pack(side="right")
            rows.button(controls, "Run now", lambda p=pid: app.scan_now(p))
            minutes = int(cfg.get("plugins", pid, "interval_minutes", default=rt.plugin.default_interval_minutes) or 15)
            choice = tk.StringVar(value=f"Every {minutes} min")
            box = ttk.Combobox(controls, textvariable=choice, state="readonly", width=13,
                               values=[f"Every {m} min" for m in sorted(set(INTERVALS + [minutes]))])
            box.pack(side="right", padx=(px(6), 0))
            box.bind("<<ComboboxSelected>>", lambda _e, p=pid, c=choice: cfg.set(
                "plugins", p, "interval_minutes", value=int(c.get().split()[1])))
        waiting, failed = list(getattr(pm, "unapproved", ())), list(pm.load_errors)
        if waiting or failed:
            rows.group("Not loaded")
        for name in waiting:
            controls, _n, _h = rows.row(name, "New in the plugins folder. A plugin is a program: it runs with your rights and RADAR's "
                                        "sign-in. Only allow a plugin you wrote or have read.", "warn")
            rows.button(controls, "Allow it to load", lambda n=name: (app.allow_user_plugin(n), self.root.after(1500, rebuild)), accent=True)
        for err in failed:
            rows.row(err.source.replace("\\", "/").rsplit("/", 1)[-1], f"Failed to load: {err.error}"[:200], "error")
        rows.group("Folder")
        controls, _n, _h = rows.row("Checks of your own", "Put a .py file into the plugins folder, then reload.")
        rows.button(controls, "Reload plugins", lambda: (app.reload_plugins(), rebuild()))
        rows.button(controls, "Open the plugins folder", app.open_plugins_dir)

    # -- advanced
    def _fill_advanced(self, rows: Rows) -> None:
        app, cfg = self.app, self.app.cfg
        rows.group("Files")
        controls, _n, _h = rows.row("Settings file", "Everything that has no switch here: thresholds, allowed countries, break-glass "
                                    "accounts, pinned accounts. Changes apply when the file is saved.")
        rows.button(controls, "Edit", app.open_config)
        controls, _n, _h = rows.row("Log file", "What RADAR did and when; names the signed-in account and its tenant")
        rows.button(controls, "Open", app.open_log)
        controls, _n, _h = rows.row("Data folder", str(paths.data_dir()))
        rows.button(controls, "Open", app.open_data_dir)
        rows.group("What is kept on this PC")
        settings = cfg.get("plugins", "signin_threats", "settings", default={}) or {}
        for title, hint, value in (
                ("Sign-ins made by hand", "who, when, from where, which device and app, result",
                 f"{int(float(settings.get('retention_days', 30)))} days"),
                ("Background sign-ins", "afterwards only which device was active from which address",
                 f"{float(settings.get('non_interactive_retention_hours', 3)):g} hours"),
                ("Alerts", "dismissed and logged-only ones are removed after this time",
                 f"{int(cfg.get('general', 'alert_retention_days', default=90))} days"),
                ("Known attacker addresses", "count against every sign-in from them",
                 f"{float((settings.get('hostile_indicators') or {}).get('days', 7)):g} days")):
            controls, _n, _h = rows.row(title, hint)
            ttk.Label(controls, text=value, style="CardMuted.TLabel", font=theme.FONT).pack(side="right")
        rows.group("Tenant")
        tenant = str(cfg.get("general", "data_tenant", default="") or "")
        rows.row(f"The stored data belongs to tenant {tenant}" if tenant else "No tenant yet: nothing has been read",
                 "One installation, one tenant. After a sign-in to another tenant RADAR reads nothing until you decide: sign in to "
                 "this one again, or start fresh (the data is archived, not deleted).")

    # ---------------------------------------------------------------- refresh
    def refresh(self) -> None:
        """Badges and the status block; the pages themselves follow the app's own refresh of open windows."""
        if not self.exists():
            return
        app = self.app
        try:
            now = datetime.now(timezone.utc)
            open_incidents = sum(1 for i in incidents.group(
                app.alerts.since(now - incidents.timedelta(days=incidents.LOOKBACK_DAYS + 1)), now) if i.open)
        except Exception:  # noqa: BLE001 - a badge must never be in the way
            open_incidents = 0
        self.nav.set_badge("incidents", open_incidents, "error")
        news = getattr(app, "report_news", None)  # the weekly report has other figures than last looked at
        self.nav.set_badge("reports", 0 if self.current == "reports" or news is None else news(), "news")
        self._attack_badge()
        self._status()

    def _attack_badge(self) -> None:
        """Accounts under attack, on the rail. Counted in the background (it reads the sign-in history), at most
        every few minutes; the Ongoing attacks page tells its own figure whenever it has loaded."""
        import time

        app = self.app
        if self._setup_mode or time.monotonic() - getattr(self, "_attacks_counted", -1e9) < ATTACK_COUNT_EVERY:
            return
        self._attacks_counted = time.monotonic()

        def work() -> None:
            try:
                count = app.count_attacked_accounts()
            except Exception:  # noqa: BLE001 - a badge must never be in the way
                log.debug("attack count failed", exc_info=True)
                return
            app.ui_call(self.set_attack_count, count)
        app._background(work, name="attack-count")

    def set_attack_count(self, count: int | None) -> None:
        if count is not None and self.exists():
            self.nav.set_badge("attacks", int(count), "warn")

    def status_now(self) -> tuple[str, str, str]:
        """What RADAR is doing: (colour role of the dot, one word or two, the small text under it)."""
        app = self.app
        if self._setup_mode:
            return "warn", "Set-up not finished", SETUP_HINT
        if app.paused:
            return "warn", "Paused", "No scans until you resume"
        if app._running:
            names = [app.plugins.get(p).plugin.name for p in app._running if app.plugins.get(p)]
            return "link", "Scanning", ", ".join(names)
        if app.auth.state == "required":
            return "error", "Sign-in required", "Settings > Account and connection"
        if app.last_error and getattr(app, "offline", False):
            return "warn", "No connection", "Microsoft is not reachable - trying again"
        if app.last_error:
            return "error", "Last scan failed", app.last_error[:60]
        if app.last_scan:
            scheduler = getattr(app, "scheduler", None)
            coming = scheduler.next_scan() if scheduler is not None and hasattr(scheduler, "next_scan") else None
            then = f"Next scan {timefmt.clock(coming)}" if coming else ""
            return "neg", "Monitoring", f"Last scan {timefmt.clock(app.last_scan)}" + (chr(10) + then if then else "")
        return "muted", "Waiting for first scan", ""

    def account_now(self) -> tuple[str, str]:
        """Who RADAR is signed in as: (the person's name, shown on one line; the address, for the hint).

        Where the sign-in did not tell the name, the part of the address before the @ stands for it."""
        account = "" if self._setup_mode else (self.app.auth.account or "")
        if not account:
            # (right after the start the sign-in is still on its way: that is not "nobody")
            checking = not self._setup_mode and getattr(self.app.auth, "state", "") == "unknown"
            return ("Checking..." if checking else "Nobody yet"), ""
        name = str(getattr(self.app.auth, "display_name", None) or "").strip()
        return name or account.partition("@")[0], account

    def app_now(self) -> tuple[str, str]:
        """The application RADAR signs in through: (its name, for the line under the person; its ID, for the hint).

        Where the sign-in did not tell the name, the kind of identity chosen in the settings stands for it."""
        from .. import identity

        if self._setup_mode or not self.app.auth.account:
            return "", ""
        auth = self.app.auth
        kind, client, _tenant = identity.current(self.app.cfg.get("auth", default={}) or {})
        name = str(getattr(auth, "app_name", None) or "").strip() or identity.LABELS.get(kind, "")
        app_id = str(getattr(auth, "app_id", None) or client or "").strip()
        return (f"via {name}" if name else ""), (f"Application ID {app_id}" if app_id else "")

    def _shorten(self, text: str, font: str) -> str:
        """The text, cut with an ellipsis where it would not fit the card."""
        import tkinter.font as tkfont

        measure = tkfont.nametofont(font, root=self.top).measure
        if measure(text) <= self._status_width:
            return text
        while text and measure(text + "\u2026") > self._status_width:
            text = text[:-1]
        return timefmt.keep_whole(text.rstrip() + "\u2026")

    def _status(self) -> None:
        try:
            role, word, detail = self.status_now()
            if role != self._dot_role:  # a round dot in the colour of the state (drawn smooth, as an image)
                self._dot_role = role
                self.status_dot.configure(image=theme.pill_image(self.status_dot, px(10), px(10), role))
            self.status.configure(text=word)
            self.status_detail.configure(text=detail)
            self.status_account.configure(text=self._shorten(self.account_now()[0], theme.FONT))
            self.status_app.configure(text=self._shorten(self.app_now()[0], theme.FONT_CAPTION))
        except tk.TclError:
            pass

    def _tick(self) -> None:
        if not self.exists():
            return
        self._status()
        self.top.after(3000, self._tick)

    def setup_finished(self) -> None:
        """RADAR can read what it needs: every section becomes available."""
        if self._setup_mode:
            self.set_setup_mode(False)
            if getattr(self, "settings_intro", None) is not None:
                self.settings_intro.configure(text=SETUP_DONE)  # until another settings page is chosen
        self.refresh()

    def _destroyed(self, event: tk.Event) -> None:
        if event.widget is not self.top:
            return
        app = self.app
        for name, page in (("_incidents", "incidents"), ("_attacks_win", "attacks"), ("_history", "history")):
            if getattr(app, name, None) is self._pages.get(page):
                setattr(app, name, None)
        if getattr(app, "_setup", None) is self._sub_objects.get("account"):
            app._setup = None


class ReportsPage:
    """Reports: the MFA exposure report - its figures and the accounts, with the age of the data."""

    COLS = ["Account", "Exposure", "Flags", "Last sign-in", "Password changed", "Excluded via"]
    WIDTHS = {"Account": 230, "Exposure": 150, "Flags": 200, "Last sign-in": 130, "Password changed": 160, "Excluded via": 220}
    SUMMARY = "MFA exposure: every account that can sign in without MFA, with clean-up candidates. " + "w" * 40

    def __init__(self, parent: tk.Misc, app: "App"):
        self.app = app
        self._busy = False
        frame = self.frame = ttk.Frame(parent, padding=(px(20), px(16), px(20), px(12)))
        head = ttk.Frame(frame)
        head.pack(fill="x", pady=(0, px(8)))
        tools = ttk.Frame(head)
        tools.pack(side="right", anchor="n", pady=(px(6), 0))
        self.open_btn = ttk.Button(tools, text="Open as a window", command=app.show_exposure_report)
        self.open_btn.pack(side="right")
        self.refresh_btn = ttk.Button(tools, text="Refresh", command=lambda: self.load(refresh=True))
        self.refresh_btn.pack(side="right", padx=(0, px(6)))
        ttk.Label(head, text="Reports", style="PageTitle.TLabel").pack(fill="x")
        self.summary = stable_label(head, self.SUMMARY, width=px(WIDTH - RAIL - 360), max_lines=2)
        self.summary.pack(fill="x", pady=(px(4), 0))
        self.figures = ttk.Frame(frame)
        self.figures.pack(fill="x", pady=(0, px(10)))
        self._figure_cells: list[Any] = []
        self._figure_labels: list[tuple[ttk.Label, ttk.Label]] = []
        for i in range(5):
            self.figures.columnconfigure(i, weight=1, uniform="figures")
            cell = card(self.figures)
            cell.grid(row=0, column=i, sticky="nsew", padx=(0, px(10) if i < 4 else 0))
            inner = tk.Frame(cell, padx=px(14), pady=px(10), background=theme.color("card"), bd=0, highlightthickness=0)
            inner.pack(fill="both", expand=True)
            caption = ttk.Label(inner, text=" ", style="CardMuted.TLabel")
            caption.pack(anchor="w")
            value = ttk.Label(inner, text=" ", style="Card.TLabel", font=theme.FONT_FIGURE)
            value.pack(anchor="w")
            self._figure_labels.append((value, caption))
            self._figure_cells.append(cell)
        self._set_figures([])
        table = ttk.Frame(frame)
        table.pack(fill="both", expand=True)
        tree = self.tree = CardTable(table, self.COLS, selectmode="browse")
        for c in self.COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(self.WIDTHS[c]), stretch=c == "Excluded via", anchor="w")
        tree.cell_role("Exposure", lambda value, _tags: "error" if value.upper().startswith("NO MFA") else None)
        make_sortable(tree, self.COLS)
        tree.grid(row=0, column=0, sticky="nsew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

    def _set_figures(self, figures: list[tuple[Any, Any]]) -> None:
        """The tiles above the table; the row keeps its height (the first tile always shows), unused tiles are gone."""
        figures = figures or [("Accounts without MFA", 0)]
        for k, (cell, (value, caption)) in enumerate(zip(self._figure_cells, self._figure_labels)):
            if k < len(figures):
                value.configure(text=str(figures[k][1]))
                caption.configure(text=str(figures[k][0]))
                cell.grid()
            else:
                cell.grid_remove()

    def load(self, refresh: bool = False) -> None:
        """Show what the app has (built in the background); ``refresh`` reads sign-ins and accounts again first."""
        if self._busy:
            return
        self._busy = True
        self.refresh_btn.configure(state="disabled")
        self.summary.configure(text="Reading accounts and MFA exclusions..." if refresh else "Building the report...")
        app = self.app

        def work() -> None:
            error = ""
            try:
                if refresh or app.threat_data_as_of() is None:
                    error = app.refresh_threat_data() or ""
                finding = app._build_exposure_report()
                as_of = app.threat_data_as_of()
            except Exception as exc:  # noqa: BLE001
                log.exception("Report could not be built")
                finding, as_of, error = None, None, str(exc)
            app.ui_call(self._show, finding, as_of, error)
        app._background(work, name="reports-page")

    def _show(self, finding: Any, as_of: Any, error: str) -> None:
        self._busy = False
        try:
            if not self.frame.winfo_exists():
                return
            self.refresh_btn.configure(state="normal")
            self.tree.delete(*self.tree.get_children(""))
            age = f" Accounts as of {timefmt.stamp(as_of)}." if as_of else ""
            if finding is None:
                self.summary.configure(text=(f"MFA exposure report: {error}" if error else getattr(
                    self.app, "NO_EXPOSURE", "No account can sign in without MFA.")) + age)
                self._set_figures([])
                return
            self.summary.configure(text="Accounts that can sign in without MFA." + age + (f" Not refreshed: {error}" if error else ""))
            figures = [(k, v) for k, v in finding.fields.items() if str(v).strip().isdigit()][:5]
            self._set_figures(figures)
            for i, row in enumerate(finding.evidence):
                self.tree.insert("", "end", iid=str(i), values=[row.get(c, "") for c in self.COLS])
        except tk.TclError:
            pass
