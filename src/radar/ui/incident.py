"""One incident in a window of its own: everything about it in one place.

On top the same summary the Incidents page shows (name, severity, how far it got and when, accounts, attacker
addresses, what was done). Under it what there is no room for on the page: the whole advice, and for each of its
alerts why it is rated as it is. An alert's evidence and links are one double-click away, in that alert's details.
The open reminders of the incident are dismissed or snoozed together from here.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk
from typing import TYPE_CHECKING

from PIL import ImageTk

from .. import incidents
from ..alerts import ACTIVE, SNOOZED, Alert
from . import icons, theme
from .cardtable import CardTable
from .incidents import STEP_COLS, STEP_WIDTHS, Summary, clamp, short_title, state_line, state_role, step_rows
from .parts import Hint, Pointer, card, on_card
from .rounded import Rounded
from .richtext import LinkHandler, StatusLine, scrolled_text, stable_label
from .riskcard import RiskCard
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH, HEIGHT, MARGIN = 1280, 900, 20
HINT = ""  # (the line at the bottom says what was done; the arrowhead shows what belongs to what)
GONE = "These alerts no longer make an incident. The window shows how it was."


def window_title(incident: incidents.Incident) -> str:
    """What the window's title bar says: how bad, open or closed, and the incident's name."""
    level = f"{incident.severity.label} {incident.risk}" if incident.risk else incident.severity.label
    return f"Incident  \u00b7  {level}  \u00b7  {state_line(incident)}  \u00b7  {short_title(incident)}"[:160]


class IncidentWindow:
    def __init__(self, root: tk.Tk, app: "App", incident: incidents.Incident, snooze_minutes: int = 15,
                 snooze_label: str = "15 minutes"):
        self.app, self.incident = app, incident
        self._snooze_minutes = snooze_minutes
        self._steps: dict[str, Alert] = {}
        top = self.top = theme.new_window(root)
        top.title(window_title(incident))
        top.geometry(f"{theme.fit_width(top, px(WIDTH))}x{min(px(HEIGHT), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(1040), px(700))
        top.bind("<Escape>", lambda _e: theme.close(top))
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)
        inner = px(WIDTH - 2 * MARGIN)
        white = theme.color("card")

        footer = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), px(12)))
        footer.pack(side="bottom", fill="x")
        ttk.Button(footer, text="Close", command=top.destroy).pack(side="right", padx=(px(8), 0))
        self.open_btn = ttk.Button(footer, text="Open alert details", style="Accent.TButton", command=self.open_selected)
        self.open_btn.pack(side="right")
        self.dismiss_btn = ttk.Button(footer, text="Dismiss its open reminders", command=self.dismiss)
        self.dismiss_btn.pack(side="right", padx=(px(8), px(8)))
        self.snooze_btn = ttk.Button(footer, text=f"Snooze {snooze_label}", command=self.snooze)
        self.snooze_btn.pack(side="right", padx=(px(12), 0))
        hint = stable_label(footer, GONE, width=inner - px(620), max_lines=1)
        hint.pack(fill="x")
        self.hint = StatusLine(hint, HINT)

        body = ttk.Frame(top, padding=(px(MARGIN), px(16), px(MARGIN), 0))
        body.pack(fill="both", expand=True)
        box = card(body)
        box.pack(fill="x")
        about = on_card(box, padx=px(16), pady=px(12))
        about.pack(fill="x")
        self.block = Summary(about, inner - px(2 * 16 + 6), header=False, lines=(2, 2))  # (name and state: in the title bar)
        self.block.pack(fill="x")

        lower = ttk.Frame(body)
        lower.pack(fill="both", expand=True, pady=(px(10), 0))
        lower.columnconfigure(0, weight=5, uniform="lower")
        lower.columnconfigure(2, weight=4, uniform="lower")
        lower.rowconfigure(0, weight=1)
        steps = self.steps = CardTable(lower, STEP_COLS, selectmode="extended")
        for c in STEP_COLS:
            steps.heading(c, text=c, anchor="w")
            steps.column(c, width=px(160 if c == "Alert" else STEP_WIDTHS[c]), stretch=c == "Alert", anchor="w")
        steps.pill("Severity")
        steps.cell_role("State", state_role)
        steps.show_as("Time")
        steps.grid(row=0, column=0, sticky="nsew")
        self.step_sort = make_sortable(steps, STEP_COLS)
        self.step_sort("Time")  # in the order it happened (the header says so); a click on a header sorts otherwise
        steps.bind("<<TreeviewSelect>>", lambda _e: self._step_selected())
        steps.bind("<Double-1>", lambda e: self.open_selected() if steps.identify_row(e.y) else None)
        top.bind("<Return>", lambda _e: self.open_selected())

        # Why the selected alert is rated as it is: the risk assessment card of its details, the very same. That it
        # belongs to the selected alert - not to the incident - is shown, not said: the panel is framed in the accent
        # colour, and an arrowhead on its edge points at the selected row and follows it.
        self.pointer = Pointer(lower)
        self.pointer.grid(row=0, column=1, sticky="ns", padx=(px(3), 0))
        frame = self.why_frame = Rounded(lower, fill="window", edge="link")
        frame.grid(row=0, column=2, sticky="nsew")
        right = tk.Frame(frame, background=theme.color("window"), bd=0, highlightthickness=0)
        right.pack(fill="both", expand=True, padx=px(10), pady=px(10))
        self.why_title = tk.Label(right, font=theme.FONT_BOLD, anchor="w", bd=0, padx=0, pady=0,
                                  background=theme.color("window"), foreground=theme.color("text"))
        self._why_full = ""  # (not shown: the arrowhead points at the alert the assessment is of)
        Hint((self.why_title,), lambda: self._why_full, wrap=px(520))  # (the whole title where it is shortened)
        self.why_title.bind("<Configure>", lambda _e=None: self._fit_title(), add="+")
        holder = tk.Frame(right, background=theme.color("window"), bd=0, highlightthickness=0)
        holder.pack(fill="both", expand=True)
        steps.on_drawn(self._point)
        lower.bind("<Configure>", lambda _e=None: self._point(), add="+")
        self.links = LinkHandler(self.app, top, self.hint)
        self.reasons = scrolled_text(holder, self.links, height=8, width=10)
        self._pad = self.reasons.card_blocks(padding=18)
        self.risk: RiskCard | None = None

        self.show(incident)
        theme.style_window(top)
        top.lift()
        top.focus_force()
        steps.focus_set()

    # ------------------------------------------------------------------ state
    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        self.top.deiconify()
        self.top.lift()
        self.top.focus_force()

    def refresh(self) -> None:
        """Group the alerts again and show the incident as it is now (after a scan, a dismissal ...)."""
        if not self.exists():
            return
        now = datetime.now(timezone.utc)
        found = incidents.group(self.app.alerts.since(now - incidents.timedelta(days=incidents.LOOKBACK_DAYS + 1)), now)
        mine = {a.id for a in self.incident.own_alerts}
        fresh = next((i for i in found if i.id == self.incident.id), None) or max(
            (i for i in found if mine & {a.id for a in i.alerts}), key=lambda i: len(mine & {a.id for a in i.alerts}), default=None)
        if fresh is None:
            self.hint.show(GONE, error=True)
            self.dismiss_btn.configure(state="disabled")
            self.snooze_btn.configure(state="disabled")
            return
        self.show(fresh)

    def show(self, incident: incidents.Incident) -> None:
        self.incident = incident
        self.top.title(window_title(incident))
        self.block.show(incident)
        chosen = [iid for iid in self.steps.selection()]
        self.steps.delete(*self.steps.get_children(""))
        self._steps = {}
        for a, values in step_rows(incident):
            iid = str(a.id)
            self._steps[iid] = a
            self.steps.insert("", "end", iid=iid, tags=(a.status,), values=values)
        self.step_sort.reapply()  # type: ignore[attr-defined]
        keep = [iid for iid in chosen if iid in self._steps]
        first = incident.strongest
        if keep:
            self.steps.selection_set(keep)
        elif first is not None and str(first.id) in self._steps:
            self.steps.selection_set(str(first.id))  # what weighs most, to begin with
        still = bool(incident.open_alerts)
        self.dismiss_btn.configure(state="normal" if still else "disabled")
        self.snooze_btn.configure(state="normal" if any(a.status == ACTIVE for a in incident.open_alerts) else "disabled")
        self._step_selected()

    def _selected(self) -> list[Alert]:
        return [self._steps[iid] for iid in self.steps.selection() if iid in self._steps]

    def _step_selected(self) -> None:
        chosen = self._selected()
        a = chosen[0] if chosen else None
        self.open_btn.configure(state="normal" if chosen else "disabled")
        self._why_full = a.title if a else ""
        self._fit_title()
        self._point()
        self.reasons.clear()
        self.risk = None
        if a is None:
            return
        self.links.alert = a
        if a.factors:
            self.risk = RiskCard(self.reasons, a, self._pad)
        else:  # (a record of something that was done, or a finding without a score)
            self.reasons.begin_card("Risk assessment", first=True)
            self.reasons.write((a.summary or "No reasons are on record for this alert; its details say what it is about.") + "\n",
                               "card")
            self.reasons.end_card()

    def _fit_title(self) -> None:
        """The selected alert's title on one line (what does not fit ends in an ellipsis; the pointer shows all)."""
        try:
            width = max(px(120), self.why_title.winfo_width())
            self.why_title.configure(text=clamp(self._why_full, theme.FONT_BOLD, width, 1, self.top)
                                     if self._why_full else "No alert selected")
        except tk.TclError:
            pass

    def _point(self) -> None:
        """The arrowhead at the height of the selected alert (the first one, with several selected)."""
        try:
            chosen = [iid for iid in self.steps.selection() if iid in self._steps]
            self.pointer.at(self.steps.row_middle(chosen[0]) if chosen else None)
        except tk.TclError:
            pass

    # ---------------------------------------------------------------- actions
    def open_selected(self) -> None:
        for alert in self._selected()[:5]:
            fresh = self.app.alerts.get(alert.id)
            if fresh is not None:
                self.app.open_alert(fresh)

    def _open_ids(self, only_active: bool = False) -> list[int]:
        return [a.id for a in self.incident.open_alerts if a.status == ACTIVE or (not only_active and a.status == SNOOZED)]

    def dismiss(self) -> None:
        ids = self._open_ids()
        if not ids:
            return
        self.app.alerts.dismiss(ids)  # (all of it: nothing that goes with it is left to ask about)
        self.app.on_alerts_dismissed()
        self.refresh()
        self.hint.show(f"{len(ids)} reminder{'s' if len(ids) != 1 else ''} dismissed.")

    def snooze(self) -> None:
        ids = self._open_ids(only_active=True)
        if not ids:
            return
        self.app.alerts.snooze(ids, self._snooze_minutes)
        self.app.on_alerts_dismissed()
        self.refresh()
        self.hint.show(f"{len(ids)} reminder{'s' if len(ids) != 1 else ''} snoozed.")
