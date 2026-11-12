"""'Incidents' window: alerts that belong to one story, as one line each - with the story as a timeline below.

An incident is two or more alerts about the same account or the same known attacker address within a few days
(radar.incidents). Select one to see its alerts in order; they can be opened, and the open ones dismissed together
once the incident is dealt with.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from .. import incidents
from ..alerts import ACTIVE, DISMISSED, MUTED, SNOOZED, Alert
from . import icons, theme
from .richtext import StatusLine, stable_label
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH, MARGIN = 1180, 20
COLS = ["Last activity", "Severity", "State", "Reached", "Alerts", "Accounts", "Incident"]
WIDTHS = {"Last activity": 150, "Severity": 90, "State": 180, "Reached": 150, "Alerts": 60, "Accounts": 220, "Incident": 290}
STEP_COLS = ["Time", "Severity", "State", "Stage", "Account", "Alert"]
STEP_WIDTHS = {"Time": 150, "Severity": 90, "State": 110, "Stage": 150, "Account": 220, "Alert": 420}
STATE = {ACTIVE: "open", SNOOZED: "snoozed", DISMISSED: "dismissed", MUTED: "logged only"}
STATE_ROLE = {ACTIVE: "error", SNOOZED: "warn", DISMISSED: "muted", MUTED: "muted"}
ROWS = 7  # incidents visible without scrolling: the timeline below keeps its place
HINT = ("An incident is open while at least one of its alerts is still a reminder, and closed once all of them were "
        "dismissed. Select an incident to see its alerts in order; double-click an alert for its details.")
SUMMARY_TEMPLATE = "000 incidents in the last 00 days: 000 open (with reminders left), 000 closed (all dismissed). Data as of 00:00."
ABOUT_TEMPLATE = ("Closed: all 000 alerts were dismissed, the last on 00.00. 00:00. Nothing in it is a reminder any more; it opens "
                  "again by itself if one of them gets worse or a new alert joins. · "
                  "Accounts: aaaaaaaa@contoso.com, bbbbbbbb@contoso.com, cccccccc@contoso.com, dddddddd@contoso.com +00 · "
                  "Attacker addresses: 000.000.000.000, 000.000.000.000, 000.000.000.000 +00 · 00.00. 00:00 - 00.00. 00:00 · "
                  "Done so far: Sessions revoked, Password reset, Account disabled")


def _t(when: Any) -> str:
    return when.astimezone().strftime("%Y-%m-%d %H:%M") if when else ""


def _short(values: list[str], limit: int) -> str:
    return ", ".join(values[:limit]) + (f" +{len(values) - limit}" if len(values) > limit else "")


def about(incident: incidents.Incident) -> str:
    """One line on what holds the incident together and what was done about it."""
    parts = [incident.state_text, f"Accounts: {_short(incident.accounts, 4)}" if incident.accounts else ""]
    if incident.addresses:
        parts.append(f"Attacker addresses: {_short(incident.addresses, 3)}")
    parts.append(f"{incident.first.astimezone():%d.%m. %H:%M} - {incident.last.astimezone():%d.%m. %H:%M}")
    if incident.responses:
        parts.append(f"Done so far: {', '.join(incident.responses)}")
    return " · ".join(p for p in parts if p)


class IncidentsWindow:
    def __init__(self, root: tk.Tk, app: "App"):
        self.app = app
        self._incidents: dict[str, incidents.Incident] = {}
        self._steps: dict[str, Alert] = {}
        top = self.top = theme.new_window(root)
        top.title("Incidents")
        top.geometry(f"{px(WIDTH)}x{min(px(760), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(760), px(520))
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)
        inner = px(WIDTH - 2 * MARGIN)

        header = ttk.Frame(top, padding=(px(MARGIN), px(16), px(MARGIN), px(6)))
        header.pack(fill="x")
        ttk.Label(header, text="Incidents", style="Title.TLabel").pack(fill="x")
        self.summary = stable_label(header, SUMMARY_TEMPLATE, width=inner)
        self.summary.pack(fill="x", pady=(px(4), 0))

        footer = ttk.Frame(top, padding=(px(MARGIN), px(4), px(MARGIN), px(12)))
        footer.pack(side="bottom", fill="x")
        hint = stable_label(footer, HINT, width=inner)
        hint.pack(fill="x", pady=(0, px(6)))
        self.hint = StatusLine(hint, HINT)
        buttons = ttk.Frame(footer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Close", command=top.destroy).pack(side="right")
        self.open_btn = ttk.Button(buttons, text="Open details", style="Accent.TButton", command=self.open_selected, state="disabled")
        self.open_btn.pack(side="left")
        self.dismiss_btn = ttk.Button(buttons, text="Dismiss the incident's open reminders", command=self.dismiss_incident,
                                      state="disabled")
        self.dismiss_btn.pack(side="left", padx=(px(8), 0))

        upper = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), 0))
        upper.pack(fill="x")
        tree = self.tree = ttk.Treeview(upper, columns=COLS, show="headings", selectmode="browse", height=ROWS)
        for c in COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(WIDTHS[c]), stretch=c == "Incident", anchor="w")
        tree.tag_configure("open", foreground=theme.color("error"))
        tree.tag_configure("closed", foreground=theme.color("muted"))
        self.sort = make_sortable(tree, COLS)
        ys = ttk.Scrollbar(upper, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        upper.columnconfigure(0, weight=1)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._incident_selected())

        middle = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), 0))
        middle.pack(fill="x")
        self.about = stable_label(middle, ABOUT_TEMPLATE, width=inner)  # fixed height: the timeline does not move
        self.about.pack(fill="x")

        lower = ttk.Frame(top, padding=(px(MARGIN), px(6), px(MARGIN), 0))
        lower.pack(fill="both", expand=True)
        steps = self.steps = ttk.Treeview(lower, columns=STEP_COLS, show="headings", selectmode="extended")
        for c in STEP_COLS:
            steps.heading(c, text=c, anchor="w")
            steps.column(c, width=px(STEP_WIDTHS[c]), stretch=c == "Alert", anchor="w")
        for status, role in STATE_ROLE.items():
            steps.tag_configure(status, foreground=theme.color(role))
        ys2 = ttk.Scrollbar(lower, orient="vertical", command=steps.yview)
        steps.configure(yscrollcommand=ys2.set)
        steps.grid(row=0, column=0, sticky="nsew")
        ys2.grid(row=0, column=1, sticky="ns")
        lower.rowconfigure(0, weight=1)
        lower.columnconfigure(0, weight=1)
        steps.bind("<<TreeviewSelect>>", lambda _e: self._buttons())
        steps.bind("<Double-1>", lambda e: self.open_selected() if steps.identify_row(e.y) else None)
        top.bind("<Return>", lambda _e: self.open_selected())

        self.refresh()
        theme.style_window(top)
        top.lift()
        top.focus_force()
        tree.focus_set()

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
        """Group the alerts again; the selected incident and the sort order stay."""
        if not self.exists():
            return
        now = datetime.now(timezone.utc)
        found = incidents.group(self.app.alerts.since(now - incidents.timedelta(days=incidents.LOOKBACK_DAYS + 1)), now)
        selected = (self.tree.selection() or [""])[0]
        self.tree.delete(*self.tree.get_children(""))
        self._incidents = {}
        for inc in found:
            self._incidents[inc.id] = inc
            self.tree.insert("", "end", iid=inc.id, tags=("open" if inc.open else "closed",), values=[
                _t(inc.last), inc.severity.name.capitalize(), inc.state,
                inc.stage_name or "-", str(inc.own), _short(inc.accounts, 2), inc.title])
        self.sort.reapply()  # type: ignore[attr-defined]
        open_count = sum(1 for i in found if i.open)
        self.summary.configure(text=(
            f"{len(found)} incident{'s' if len(found) != 1 else ''} in the last {incidents.LOOKBACK_DAYS} days: "
            f"{open_count} open (with reminders left), {len(found) - open_count} closed (all dismissed). "
            f"Data as of {now.astimezone():%H:%M}."
            if found else f"No incidents in the last {incidents.LOOKBACK_DAYS} days: no two alerts belong together. "
                          f"Data as of {now.astimezone():%H:%M}."))
        if selected in self._incidents:
            self.tree.selection_set(selected)
        elif found:
            self.tree.selection_set(found[0].id)
        self._incident_selected()

    def select(self, incident_id: str) -> bool:
        """Show this incident (asked for from an alert's details)."""
        if incident_id not in self._incidents:
            self.hint.show("That incident is no longer there: its alerts are older than the window shows, or no "
                           "longer belong together.", error=True)
            return False
        self.tree.selection_set(incident_id)
        self.tree.see(incident_id)
        self._incident_selected()
        return True

    def _incident(self) -> incidents.Incident | None:
        return self._incidents.get((self.tree.selection() or [""])[0])

    def _incident_selected(self) -> None:
        inc = self._incident()
        chosen = set(self.steps.selection())
        self.steps.delete(*self.steps.get_children(""))
        self._steps = {}
        self.about.configure(text=about(inc) if inc else "")
        for a in (inc.alerts if inc else []):
            iid = str(a.id)
            self._steps[iid] = a
            stage = incidents.stage_of(a)
            kind = ("chain" if a.plugin_id == incidents.chains.CHAIN_PLUGIN else
                    "response" if a.signal in incidents.chains.NOT_LINKS else
                    f"{stage} {incidents.chains.STAGE_NAMES[stage]}" if stage else "-")
            self.steps.insert("", "end", iid=iid, tags=(a.status,), values=[
                _t(a.when), a.severity.name.capitalize(), STATE.get(a.status, a.status), kind,
                _short([s for s in a.subjects if "@" in s], 2), a.title])
        keep = [iid for iid in chosen if iid in self._steps]
        if keep:
            self.steps.selection_set(keep)
        self._buttons()

    def _buttons(self) -> None:
        inc = self._incident()
        self.open_btn.configure(state="normal" if self.steps.selection() else "disabled")
        self.dismiss_btn.configure(state="normal" if inc and inc.open_alerts else "disabled")

    # ---------------------------------------------------------------- actions
    def open_selected(self) -> None:
        for iid in list(self.steps.selection())[:5]:
            fresh = self.app.alerts.get(self._steps[iid].id) if iid in self._steps else None
            if fresh is not None:
                self.app.open_alert(fresh)

    def dismiss_incident(self) -> None:
        inc = self._incident()
        ids = [a.id for a in inc.open_alerts] if inc else []
        if not ids:
            return
        self.app.alerts.dismiss(ids)
        self.app.on_alerts_dismissed()
        self.refresh()
        self.hint.show(f"{len(ids)} reminder{'s' if len(ids) != 1 else ''} of the incident dismissed. They come back by "
                       f"themselves if something gets worse, and stay in the alert history.")
