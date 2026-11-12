"""Outlook-style "Reminders" window listing all active security alerts."""
from __future__ import annotations

import logging
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk
from typing import TYPE_CHECKING

from PIL import ImageTk

from ..alerts import Alert
from ..plugin_api import Severity
from . import icons, theme
from .details import DetailsWindow
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

log = logging.getLogger(__name__)

SNOOZE_CHOICES: list[tuple[str, int]] = [
    ("5 minutes", 5), ("10 minutes", 10), ("15 minutes", 15), ("30 minutes", 30), ("1 hour", 60),
    ("2 hours", 120), ("4 hours", 240), ("8 hours", 480), ("1 day", 1440), ("2 days", 2880), ("1 week", 10080),
]


SUMMARY_LINES = 3
NEW_ROW_BG = theme.LIGHT["new_row"]  # unseen reminders: bold on light blue (like unread mail)
ATTENTION_BG = theme.LIGHT["attention"]  # header blink colour while waiting for the user (light palette)
FOCUS_GRACE_SECONDS = 1.5  # focus gained right after showing is not a user interaction
ELLIPSIS = "…"


def fit_lines(text: str, font: tkfont.Font, width: int, max_lines: int) -> str:
    """Word-wrap ``text`` to ``width`` pixels and cut it to ``max_lines`` lines, ending with '…' if shortened."""
    lines: list[str] = []
    words = (text or "").split()
    current = ""
    i = 0
    while i < len(words):
        word = words[i]
        candidate = f"{current} {word}" if current else word
        if font.measure(candidate) <= width:
            current, i = candidate, i + 1
            continue
        if not current:  # a single word wider than the line (IPv6, URL ...): hard-break it
            cut = len(word)
            while cut > 1 and font.measure(word[:cut]) > width:
                cut -= 1
            lines.append(word[:cut])
            words[i] = word[cut:]
        else:
            lines.append(current)
            current = ""
        if len(lines) == max_lines:
            break
    if current and len(lines) < max_lines:
        lines.append(current)
        current = ""
    truncated = i < len(words) or bool(current)
    if truncated and lines:
        last = lines[-1]
        while last and font.measure(last + ELLIPSIS) > width:
            last = last[:-1]
        lines[-1] = last.rstrip(" ,.;:") + ELLIPSIS
    return "\n".join(lines[:max_lines])


class ReminderWindow:
    def __init__(self, root: tk.Tk, app: "App"):
        self.root = root
        self.app = app
        self._images: dict[str, ImageTk.PhotoImage] = {}
        self._alerts: dict[str, Alert] = {}
        self._details: dict[int, DetailsWindow] = {}
        self._placed = False
        self._tick_job: str | None = None
        self._attention = False
        self._attention_since = 0.0
        self._blink_job: str | None = None

        top = self.top = tk.Toplevel(root, background=theme.color("window"))
        top.withdraw()
        top.title("Reminders")
        top.geometry(f"{px(680)}x{px(520)}")
        top.minsize(px(520), px(400))
        top.iconphoto(False, self._img("bell32", icons.bell(32)), self._img("bell16", icons.bell(16)))
        top.protocol("WM_DELETE_WINDOW", self.hide)
        top.bind("<Delete>", lambda _e: self.dismiss_selected())
        top.bind("<Return>", lambda _e: self.open_selected())
        top.bind("<Escape>", lambda _e: self.hide())
        theme.keep_clear_of(lambda: self.top)  # windows opened while this one shows go beside it or above it
        # any click / key / activation by the user ends the "attention" state (flashing, blinking header)
        top.bind("<ButtonPress>", lambda _e: self.stop_attention(), add="+")
        top.bind("<KeyPress>", lambda _e: self.stop_attention(), add="+")
        top.bind("<FocusIn>", lambda _e: self.stop_attention(from_focus=True), add="+")
        self._build()

    # --------------------------------------------------------------- build
    def _img(self, name: str, pil_image) -> ImageTk.PhotoImage:
        if name not in self._images:
            self._images[name] = ImageTk.PhotoImage(pil_image, master=self.root)
        return self._images[name]

    def _build(self) -> None:
        top = self.top
        self._f_title = tkfont.Font(root=self.root, font=theme.FONT_BOLD)
        self._f_body = tkfont.Font(root=self.root, font=theme.FONT)
        self._f_caption = tkfont.Font(root=self.root, font=theme.FONT_CAPTION)
        title_h, body_h = self._f_title.metrics("linespace"), self._f_body.metrics("linespace")
        caption_h = self._f_caption.metrics("linespace")
        # Fixed height: 1 title line + 1 info line + SUMMARY_LINES summary lines (the list must not jump).
        height = px(14) + title_h + caption_h + px(6) + SUMMARY_LINES * body_h + px(16)
        holder = ttk.Frame(top, padding=(px(12), px(12), px(12), 0))
        holder.pack(fill="x")
        card_bg = theme.color("card")
        header = self.header = tk.Frame(holder, background=card_bg, height=height, highlightthickness=0,
                                        highlightbackground=theme.color("border"), highlightcolor=theme.color("border"))
        header.pack(fill="x")
        header.grid_propagate(False)
        # created with its image so width/height are pixels (Tk uses characters for text-only labels)
        self.h_icon = tk.Label(header, background=card_bg, image=self._img("badge", icons.badge(Severity.INFO, px(36))),
                               width=px(36), height=px(36))
        self.h_icon.grid(row=0, column=0, rowspan=3, sticky="n", padx=(px(14), px(12)), pady=px(14))
        flat = dict(bd=0, padx=0, pady=0, highlightthickness=0, background=card_bg)  # measured text == drawn text
        self.h_title = tk.Label(header, font=self._f_title, foreground=theme.color("text"), anchor="w",
                                justify="left", **flat)
        self.h_title.grid(row=0, column=1, sticky="ew", pady=(px(14), 0), padx=(0, px(14)))
        self.h_when = tk.Label(header, foreground=theme.color("muted"), font=self._f_caption, anchor="w", **flat)
        self.h_when.grid(row=1, column=1, sticky="ew", padx=(0, px(14)))
        self.h_summary = tk.Label(header, font=self._f_body, foreground=theme.color("text"), anchor="nw",
                                  justify="left", **flat)
        self.h_summary.grid(row=2, column=1, sticky="new", pady=(px(6), 0), padx=(0, px(14)))
        header.columnconfigure(1, weight=1)
        self._text_width = px(520)
        self._header_text = ("", "", "")
        header.bind("<Configure>", self._on_header_resize)

        bottom = ttk.Frame(top, padding=(px(12), px(10), px(12), px(12)))
        bottom.pack(side="bottom", fill="x")
        row1 = ttk.Frame(bottom)
        row1.pack(fill="x")
        ttk.Button(row1, text="Dismiss all", command=self.dismiss_all).pack(side="left")
        ttk.Button(row1, text="Dismiss", style="Accent.TButton", command=self.dismiss_selected).pack(side="right")
        ttk.Button(row1, text="Open item", command=self.open_selected).pack(side="right", padx=(0, px(6)))
        row2 = ttk.Frame(bottom)
        row2.pack(fill="x", pady=(px(10), 0))
        ttk.Label(row2, text="Remind me again in", style="Muted.TLabel").pack(side="left", padx=(0, px(8)))
        default = str(self.app.cfg.get("general", "default_snooze", default="15 minutes"))
        labels = [c[0] for c in SNOOZE_CHOICES]
        self.snooze_var = tk.StringVar(value=default if default in labels else "15 minutes")
        ttk.Combobox(row2, textvariable=self.snooze_var, values=labels, state="readonly").pack(
            side="left", fill="x", expand=True)
        ttk.Button(row2, text="Snooze", command=self.snooze_selected).pack(side="right", padx=(px(8), 0))

        body = ttk.Frame(top, padding=(px(12), px(10), px(12), 0))
        body.pack(fill="both", expand=True)
        listing = tk.Frame(body, background=card_bg, highlightthickness=0, highlightbackground=theme.color("border"),
                           highlightcolor=theme.color("border"))
        listing.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(listing, columns=("severity", "occurred"), show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Subject", anchor="w")
        self.tree.heading("severity", text="Severity", anchor="w")
        self.tree.heading("occurred", text="Occurred", anchor="w")
        self.tree.column("#0", width=px(360), stretch=True)
        self.tree.column("severity", width=px(110), stretch=False)
        self.tree.column("occurred", width=px(130), stretch=False)
        vsb = ttk.Scrollbar(listing, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._f_bold = theme.FONT_TABLE_BOLD
        self.tree.tag_configure("new", font=self._f_bold, background=theme.color("new_row"))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_header())
        self.tree.bind("<Double-1>", lambda _e: self.open_selected())
        # only real user navigation marks a reminder as seen (programmatic selection on refresh does not)
        self.tree.bind("<ButtonRelease-1>", lambda _e: self.mark_selected_seen())
        for key in ("Up", "Down", "Prior", "Next", "Home", "End"):
            self.tree.bind(f"<KeyRelease-{key}>", lambda _e: self.mark_selected_seen())

    # -------------------------------------------------------------- state
    def _selected(self) -> list[Alert]:
        return [self._alerts[i] for i in self.tree.selection() if i in self._alerts]

    def _update_header(self) -> None:
        sel = self._selected()
        alert = sel[0] if sel else None
        if alert is None:
            self.h_icon.configure(image=self._img("badge", icons.badge(Severity.INFO, px(36))))
            self._set_header_text("No reminders", "", "")
            return
        sev = alert.severity
        self.h_icon.configure(image=self._img(f"badge-{sev.name}", icons.badge(sev, px(36))))
        origin = self.app.describe_origin(alert)
        score = f" · risk {alert.score}" if alert.factors else ""
        when = (f"{sev.label}{score}   ·   {origin}   ·   "
                f"{theme.local_time(alert.occurred_at or alert.first_seen, '%a %d.%m. %H:%M')}")
        summary = alert.summary
        if len(sel) > 1:
            summary = f"{len(sel)} reminders selected. " + summary
        self._set_header_text(alert.title, when, summary)

    def _set_header_text(self, title: str, when: str, summary: str) -> None:
        """Fit the texts into the fixed header: one line each for title/info, SUMMARY_LINES for the summary."""
        self._header_text = (title, when, summary)
        width = self._text_width
        self.h_title.configure(text=fit_lines(title, self._f_title, width, 1))
        self.h_when.configure(text=fit_lines(when, self._f_caption, width, 1))
        self.h_summary.configure(text=fit_lines(summary, self._f_body, width, SUMMARY_LINES))

    def _on_header_resize(self, event: tk.Event) -> None:
        width = max(px(150), event.width - px(14 + 12 + 36 + 14 + 8))  # icon column, paddings, safety margin
        if width != self._text_width:
            self._text_width = width
            self._set_header_text(*self._header_text)

    def refresh(self) -> None:
        alerts = self.app.alerts.active()
        previous = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        self._alerts = {}
        for a in alerts:
            iid = str(a.id)
            self._alerts[iid] = a
            self.tree.insert("", "end", iid=iid, text=f" {a.title}",
                             image=self._img(f"dot-{a.severity.name}", icons.severity_dot(a.severity, px(16))),
                             values=(f"{a.severity.label} · {a.score}" if a.score else a.severity.label,
                                     theme.humanize(a.occurred_at or a.first_seen)),
                             tags=() if a.seen else ("new",))
        keep = [i for i in previous if i in self._alerts] or ([str(alerts[0].id)] if alerts else [])
        if keep:
            self.tree.selection_set(keep)
            self.tree.focus(keep[0])
            self.tree.see(keep[0])
        self._update_title()
        self._update_header()
        if not alerts:
            self.hide()

    def _update_title(self) -> None:
        n = len(self._alerts)
        unseen = sum(1 for a in self._alerts.values() if not a.seen)
        self.top.title(f"{n} Reminder{'s' if n != 1 else ''}" + (f" ({unseen} new)" if unseen else ""))

    def mark_selected_seen(self) -> None:
        self.mark_seen(self._selected())

    def mark_seen(self, alerts: list[Alert]) -> None:
        unseen = [a for a in alerts if not a.seen]
        if not unseen:
            return
        self.app.alerts.mark_seen(a.id for a in unseen)
        for a in unseen:
            a.seen = True
            if self.tree.exists(str(a.id)):
                self.tree.item(str(a.id), tags=())
        self._update_title()
        self.app.on_alerts_changed()

    def show(self, attention: bool = False) -> bool:
        self.refresh()
        if not self._alerts:
            return False
        appearing = not self.top.winfo_viewable()
        if appearing:
            # It comes up on the screen the mouse is on. The first time in the upper middle; later it keeps the place
            # the user gave it - unless that is on another screen than the one they are looking at now.
            if not theme.to_pointer_screen(self.top, vertical=0.33, only_if_elsewhere=self._placed) and not self._placed:
                self.top.update_idletasks()
                w, h = self.top.winfo_width(), self.top.winfo_height()
                x = (self.top.winfo_screenwidth() - w) // 2
                y = (self.top.winfo_screenheight() - h) // 3
                self.top.geometry(f"+{max(0, x)}+{max(0, y)}")
            self._placed = True
        if appearing and theme.animations():
            self.top.attributes("-alpha", 0.0)  # appears only through the slide-in, not once before it
        self.top.deiconify()
        if appearing:
            theme.title_bar(self.top)
            theme.slide_in(self.top)  # glides up and fades in (instant with animations off)
        self.top.attributes("-topmost", True)
        self.top.lift()
        if attention:
            # put the (highest ranked) new reminder into the header; selecting it this way does not mark it seen
            first_new = next((iid for iid in self.tree.get_children() if not self._alerts[iid].seen), None)
            if first_new:
                self.tree.selection_set(first_new)
                self.tree.focus(first_new)
                self.tree.see(first_new)
                self._update_header()
            # do not steal keyboard focus from what the user is typing; flash until they interact instead
            self.start_attention()
            self.app.play_reminder_sound()
        else:
            try:
                self.top.focus_force()
            except tk.TclError:
                pass
        self._schedule_tick()
        return True

    # ---------------------------------------------------------- attention
    def start_attention(self) -> None:
        self._attention = True
        self._attention_since = time.monotonic()
        if self.app.cfg.get("general", "flash_window", default=True):
            theme.flash(self.top)  # title bar + taskbar button, continuously
        if self._blink_job is None:
            self._blink(0)

    def stop_attention(self, from_focus: bool = False) -> None:
        if not self._attention:
            return
        if from_focus and time.monotonic() - self._attention_since < FOCUS_GRACE_SECONDS:
            return  # Windows may activate the window itself right after it was shown
        self._attention = False
        theme.flash(self.top, stop=True)
        if self._blink_job:
            self.top.after_cancel(self._blink_job)
            self._blink_job = None
        self._paint_header(theme.color("card"))

    @property
    def attention(self) -> bool:
        return self._attention

    def _blink(self, step: int) -> None:
        """Header pulses while waiting: on at once, then fades back out (a hard blink with animations off)."""
        card, glow = theme.color("card"), theme.color("attention")
        if not self._attention:
            self._blink_job = None
            self._paint_header(card)
            return
        if step % 2 == 0:
            self._paint_header(glow)
        elif theme.animations():
            theme.animate(self.header, 560, lambda t: self._attention and self._paint_header(theme.mix(glow, card, t)))
        else:
            self._paint_header(card)
        self._blink_job = self.top.after(700, lambda: self._blink(step + 1))

    def _paint_header(self, color: str) -> None:
        for w in (self.header, self.h_icon, self.h_title, self.h_when, self.h_summary):
            w.configure(background=color)

    def hide(self) -> None:
        self.stop_attention()
        self.top.withdraw()
        theme.release_raised()  # windows that were raised above this one are ordinary windows again
        if self._tick_job:
            self.top.after_cancel(self._tick_job)
            self._tick_job = None

    @property
    def visible(self) -> bool:
        return self.top.winfo_viewable()

    def _schedule_tick(self) -> None:
        if self._tick_job:
            self.top.after_cancel(self._tick_job)
        self._tick_job = self.top.after(60_000, self._tick)

    def _tick(self) -> None:
        self._tick_job = None
        for iid, a in self._alerts.items():
            if self.tree.exists(iid):
                self.tree.set(iid, "occurred", theme.humanize(a.occurred_at or a.first_seen))
        if self.visible:
            self._schedule_tick()

    # ------------------------------------------------------------ actions
    def _after_change(self) -> None:
        self.refresh()
        self.app.on_alerts_changed()

    def dismiss_selected(self) -> None:
        self.stop_attention()
        sel = self._selected()
        if sel:
            self.app.alerts.dismiss(a.id for a in sel)
            self._after_change()

    def dismiss_all(self) -> None:
        self.stop_attention()
        self.app.alerts.dismiss_all()
        self._after_change()

    def snooze_selected(self) -> None:
        self.stop_attention()
        sel = self._selected()
        minutes = dict(SNOOZE_CHOICES).get(self.snooze_var.get(), 15)
        if sel:
            self.app.alerts.snooze((a.id for a in sel), minutes)
            self._after_change()

    def open_selected(self) -> None:
        self.stop_attention()
        self.mark_seen(self._selected()[:5])
        for alert in self._selected()[:5]:
            self.open_details(alert)

    def open_details(self, alert: Alert) -> None:
        win = self._details.get(alert.id)
        if win and win.exists():
            win.focus()
            return
        self._details[alert.id] = DetailsWindow(
            self.root, self.app, alert,
            on_dismiss=lambda a: (self.app.alerts.dismiss([a.id]), self._after_change()),
            on_snooze=lambda a: (self.app.alerts.snooze([a.id], self._snooze_minutes()), self._after_change()),
            snooze_label=self.snooze_var.get())

    def _snooze_minutes(self) -> int:
        return dict(SNOOZE_CHOICES).get(self.snooze_var.get(), 15)
