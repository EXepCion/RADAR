"""Outlook-style "Reminders" window listing all active security alerts."""
from __future__ import annotations

import logging
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from .. import timefmt
from ..alerts import Alert
from ..plugin_api import Severity
from . import icons, theme
from .details import DetailsWindow
from .cardtable import CardTable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

log = logging.getLogger(__name__)

SNOOZE_CHOICES: list[tuple[str, int]] = [
    ("5 minutes", 5), ("10 minutes", 10), ("15 minutes", 15), ("30 minutes", 30), ("1 hour", 60),
    ("2 hours", 120), ("4 hours", 240), ("8 hours", 480), ("1 day", 1440), ("2 days", 2880), ("1 week", 10080),
]


SUMMARY_LINES = 2  # (the rest is one click away: Open item)
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
        lines[-1] = timefmt.keep_whole(last.rstrip(" ,.;:") + ELLIPSIS)  # (never a time without its zone)
    return "\n".join(lines[:max_lines])


class ReminderWindow:
    def __init__(self, root: tk.Tk, app: "App"):
        self.root = root
        self.app = app
        self._images: dict[str, ImageTk.PhotoImage] = {}
        self._alerts: dict[str, Alert] = {}
        self._details: dict[int, DetailsWindow] = {}
        self._members: dict[str, list[Alert]] = {}   # row -> the open alerts it stands for (several: an incident)
        self._groups: dict[str, Any] = {}            # row -> its incident (rows that are one)
        self._row_of: dict[int, str] = {}            # alert -> its row
        self._when: dict[str, Any] = {}              # row -> the time it shows
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
        theme.on_rescale(self._rescaled)
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
        height = px(16) + title_h + px(2) + caption_h + px(10) + SUMMARY_LINES * body_h + px(18)
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
        self.h_icon.grid(row=0, column=0, rowspan=3, sticky="n", padx=(px(16), px(14)), pady=px(16))
        flat = dict(bd=0, padx=0, pady=0, highlightthickness=0, background=card_bg)  # measured text == drawn text
        self.h_title = tk.Label(header, font=self._f_title, foreground=theme.color("text"), anchor="w",
                                justify="left", **flat)
        self.h_title.grid(row=0, column=1, sticky="ew", pady=(px(16), px(2)), padx=(0, px(16)))
        self.h_when = tk.Label(header, foreground=theme.color("muted"), font=self._f_caption, anchor="w", **flat)
        self.h_when.grid(row=1, column=1, sticky="ew", padx=(0, px(16)))
        self.h_summary = tk.Label(header, font=self._f_body, foreground=theme.color("text"), anchor="nw",
                                  justify="left", **flat)
        self.h_summary.grid(row=2, column=1, sticky="new", pady=(px(10), 0), padx=(0, px(16)))
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
        self._dots: dict[str, ImageTk.PhotoImage] = {}  # row -> the dot in the colour of its severity
        self.tree = CardTable(body, ["subject", "severity", "occurred"], selectmode="extended")
        self.tree.heading("subject", text="Subject", anchor="w")
        self.tree.heading("severity", text="Severity", anchor="w")
        self.tree.heading("occurred", text="Occurred", anchor="w")
        self.tree.column("subject", width=px(360), stretch=True)
        self.tree.column("severity", width=px(120), stretch=False)
        self.tree.column("occurred", width=px(140), stretch=False)
        self.tree.image_of("subject", self._dots.get)
        self.tree.pack(fill="both", expand=True)
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
        """The open alerts of the selected rows (a row that is an incident stands for all of its open alerts)."""
        return [a for i in self.tree.selection() for a in self._members.get(i, ())]

    def _selected_rows(self) -> list[str]:
        return [i for i in self.tree.selection() if i in self._members]

    def _update_header(self) -> None:
        rows = self._selected_rows()
        sel = self._selected()
        alert = self._alerts.get(rows[0]) if rows else None
        if alert is None:
            self.h_icon.configure(image=self._img("badge", icons.badge(Severity.INFO, px(36))))
            self._set_header_text("No reminders", "", "")
            return
        inc = self._groups.get(rows[0])
        # The header says what the selected row does not: the whole title, the exact time, what happened. How bad
        # it is, how many alerts and how far it got stand in the row (and in the icon's colour) - not here again.
        if inc is not None:
            from .incidents import short_title

            members = self._members[rows[0]]
            sev = max(a.severity for a in members)
            self.h_icon.configure(image=self._img(f"badge-{sev.name}", icons.badge(sev, px(36))))
            when = f"{timefmt.stamp(inc.first)} \u2013 {timefmt.stamp(inc.last)}"
            strongest = inc.strongest
            reasons = ([str(text) for points, text in sorted(strongest.factors, key=lambda f: -int(f[0])) if int(points) > 0][:2]
                       if strongest is not None else [])
            summary = (f"{len(rows)} rows selected. " if len(rows) > 1 else "") + (
                f"Strongest finding: {strongest.title}" + (": " + "; ".join(reasons) if reasons else "")
                if strongest is not None else "")
            self._set_header_text(short_title(inc), when, summary)
            return
        sev = alert.severity
        self.h_icon.configure(image=self._img(f"badge-{sev.name}", icons.badge(sev, px(36))))
        when = theme.local_time(alert.occurred_at or alert.first_seen, "%a %d.%m. %H:%M")
        summary = alert.summary
        if len(rows) > 1:
            summary = f"{len(rows)} rows selected. " + summary
        self._set_header_text(alert.title, when, summary)

    def _set_header_text(self, title: str, when: str, summary: str) -> None:
        """Fit the texts into the fixed header: one line each for title/info, SUMMARY_LINES for the summary."""
        self._header_text = (title, when, summary)
        width = self._text_width
        self.h_title.configure(text=fit_lines(title, self._f_title, width, 1))
        self.h_when.configure(text=fit_lines(when, self._f_caption, width, 1))
        self.h_summary.configure(text=fit_lines(summary, self._f_body, width, SUMMARY_LINES))

    def _on_header_resize(self, event: tk.Event) -> None:
        width = max(px(150), event.width - px(16 + 14 + 36 + 16 + 8))  # icon column, paddings, safety margin
        if width != self._text_width:
            self._text_width = width
            self._set_header_text(*self._header_text)

    def _rows(self, alerts: list[Alert]) -> list[tuple[str, list[Alert], Any]]:
        """What the list shows: (row, the open alerts it stands for, its incident or None). Alerts that belong to
        one incident are one row - one thing to look at and to decide; every other alert is a row of its own.
        Most urgent first: by severity, then by risk score, then the latest."""
        from datetime import datetime, timedelta, timezone

        from .. import incidents

        rows: list[tuple[str, list[Alert], Any]] = []
        inside: set[int] = set()
        try:
            now = datetime.now(timezone.utc)
            found = incidents.group(self.app.alerts.since(now - timedelta(days=incidents.LOOKBACK_DAYS + 1)), now)
        except Exception:  # noqa: BLE001 - the reminders must come up whatever happens to the grouping
            log.exception("The reminders could not be grouped into incidents")
            found = []
        active = {a.id: a for a in alerts}
        for inc in found:
            members = [active[a.id] for a in inc.alerts if a.id in active and a.id not in inside]
            if members:
                inside.update(a.id for a in members)
                rows.append((f"incident:{inc.id}", members, inc))
        rows += [(str(a.id), [a], None) for a in alerts if a.id not in inside]
        rows.sort(key=lambda r: (-max(int(a.severity) for a in r[1]), -max(a.score for a in r[1]),
                                 -max(a.when.timestamp() for a in r[1])))
        return rows

    def refresh(self) -> None:
        from .incidents import who

        alerts = self.app.alerts.active()
        previous = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        self._alerts, self._members, self._groups, self._row_of, self._when = {}, {}, {}, {}, {}
        self._dots.clear()
        for iid, members, inc in self._rows(alerts):
            sev, score = max(a.severity for a in members), max(a.score for a in members)
            lead = max(members, key=lambda a: (int(a.severity), a.score))
            self._alerts[iid] = lead  # (the alert a row is shown by; for an incident its strongest open one)
            self._members[iid] = members
            self._when[iid] = max(a.occurred_at or a.first_seen for a in members)
            for a in members:
                self._row_of[a.id] = iid
            if inc is not None:
                self._groups[iid] = inc
                title = "  \u00b7  ".join(p for p in (
                    f"Incident: {who(inc)}", f"{len(members)} alert{'s' if len(members) != 1 else ''}", inc.stage_name) if p)
            else:
                title = lead.title
            self._dots[iid] = self._img(f"dot-{sev.name}", icons.severity_dot(sev, px(16)))
            self.tree.insert("", "end", iid=iid,
                             values=(title, f"{sev.label} · {score}" if score else sev.label, theme.humanize(self._when[iid])),
                             tags=() if all(a.seen for a in members) else ("new",))
        first = self.tree.get_children()
        keep = [i for i in previous if i in self._alerts] or (list(first[:1]) if first else [])
        if keep:
            self.tree.selection_set(keep)
            self.tree.focus(keep[0])
            self.tree.see(keep[0])
        self._update_title()
        self._update_header()
        if not alerts:
            self.hide()

    def _update_title(self) -> None:
        n = len(self._members)  # things to handle: an incident counts once
        unseen = sum(1 for members in self._members.values() if not all(a.seen for a in members))
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
            row = self._row_of.get(a.id, "")
            if self.tree.exists(row) and all(m.seen for m in self._members.get(row, ())):
                self.tree.item(row, tags=())
        self._update_title()
        self.app.on_alerts_changed()

    def _rescaled(self) -> None:
        """The scale changed (the next window opens on a screen with another scaling) while this window is hidden:
        it was built in advance, so it is built again."""
        try:
            if self.top.winfo_viewable():
                return
            for child in self.top.winfo_children():
                child.destroy()
            self._placed = False
            self.top.minsize(px(520), px(400))
            self.top.geometry(f"{px(680)}x{px(520)}")
            self._build()
        except tk.TclError:
            log.debug("reminder window not rebuilt", exc_info=True)

    def show(self, attention: bool = False) -> bool:
        if not self.top.winfo_viewable():
            theme.adapt_to_monitor(self.root)  # sharp on the screen it comes up on
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
            first_new = next((iid for iid in self.tree.get_children()
                              if not all(a.seen for a in self._members.get(iid, ()))), None)
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
        for iid, when in self._when.items():
            if self.tree.exists(iid):
                self.tree.set(iid, "occurred", theme.humanize(when))
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
            self.app.dismiss_alerts([a.id for a in sel], self.top)
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
        """The details of the selected rows: an alert's details, an incident's own window."""
        self.stop_attention()
        rows = self._selected_rows()[:5]
        self.mark_seen([a for row in rows for a in self._members[row]])
        opener = getattr(self.app, "open_incident", None)
        for row in rows:
            inc = self._groups.get(row)
            if inc is None or opener is None or not opener(inc.id):
                self.open_details(self._alerts[row])

    def open_details(self, alert: Alert) -> None:
        win = self._details.get(alert.id)
        if win and win.exists():
            win.focus()
            return
        self._details[alert.id] = DetailsWindow(
            self.root, self.app, alert,
            on_dismiss=lambda a: (self.app.dismiss_alerts([a.id], self.top), self._after_change()),
            on_snooze=lambda a: (self.app.alerts.snooze([a.id], self._snooze_minutes()), self._after_change()),
            snooze_label=self.snooze_var.get())

    def refresh_details(self) -> int:
        """Bring every open alert details window up to date with the stored alert (after a scan, a dismissal ...).
        Returns how many were redrawn; a window whose alert did not change is not touched."""
        redrawn = 0
        for alert_id, win in list(self._details.items()):
            if not win.exists():
                del self._details[alert_id]
                continue
            fresh = self.app.alerts.get(alert_id)
            if fresh is not None and win.update_alert(fresh):
                redrawn += 1
        return redrawn

    def _snooze_minutes(self) -> int:
        return dict(SNOOZE_CHOICES).get(self.snooze_var.get(), 15)
