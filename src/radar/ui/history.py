"""'Alert history' window: every alert the app still keeps - open, snoozed, dismissed, logged only - with a way back.

A reminder dismissed by accident is found here and reactivated: it returns to the reminders as a new one.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from ..alerts import ACTIVE, DISMISSED, MUTED, SNOOZED, Alert
from ..plugin_api import Severity
from . import icons, theme
from .richtext import StatusLine, stable_label
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH, MARGIN = 1180, 20
COLS = ["Last seen", "First seen", "Severity", "State", "Source", "Alert"]
WIDTHS = {"Last seen": 165, "First seen": 165, "Severity": 96, "State": 118, "Source": 210, "Alert": 400}
STATE = {ACTIVE: "open", SNOOZED: "snoozed", DISMISSED: "dismissed", MUTED: "logged only"}
STATE_ROLE = {ACTIVE: "error", SNOOZED: "warn", DISMISSED: "muted", MUTED: "muted"}  # palette roles
SHOW = [("All alerts", None), ("Dismissed", {DISMISSED}), ("Open and snoozed", {ACTIVE, SNOOZED}), ("Logged only", {MUTED})]
LEVELS = [("Any severity", Severity.INFO), ("Low and above", Severity.LOW), ("Medium and above", Severity.MEDIUM),
          ("High and above", Severity.HIGH)]
HINT = "Double-click an alert for its details. Reactivate puts a dismissed or logged-only alert back among the reminders."
SUMMARY_TEMPLATE = "0000 alerts kept (0000 shown): 000 open, 000 snoozed, 0000 dismissed, 0000 logged only. Alerts are kept for 00 days."
LIMIT = 5000


def _t(when: Any) -> str:
    return when.astimezone().strftime("%Y-%m-%d %H:%M") if when else ""


def matches(alert: Alert, states: set[str] | None, level: Severity, words: list[str]) -> bool:
    """Does the alert pass the three filters? ``words``: all must occur in title, summary, rule or subjects."""
    if states is not None and alert.status not in states:
        return False
    if alert.severity < level:
        return False
    if words:
        text = " ".join([alert.title, alert.summary, alert.rule_id, alert.plugin_id, " ".join(alert.subjects)]).lower()
        return all(w in text for w in words)
    return True


def can_reactivate(alert: Alert) -> bool:
    return alert.status in (DISMISSED, MUTED, SNOOZED)


class HistoryWindow:
    def __init__(self, root: tk.Tk, app: "App"):
        self.app = app
        self._alerts: dict[str, Alert] = {}
        top = self.top = theme.new_window(root)
        top.title("Alert history")
        top.geometry(f"{px(WIDTH)}x{min(px(700), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(760), px(380))
        top.bind("<Escape>", lambda _e: top.destroy())
        top.bind("<Return>", lambda _e: self.open_selected())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(px(MARGIN), px(16), px(MARGIN), px(6)))
        header.pack(fill="x")
        ttk.Label(header, text="Alert history", style="Title.TLabel").pack(fill="x")
        inner = px(WIDTH - 2 * MARGIN)
        self.summary = stable_label(header, SUMMARY_TEMPLATE, width=inner)  # fixed height: the table does not move
        self.summary.pack(fill="x", pady=(px(4), 0))

        bar = ttk.Frame(top, padding=(px(MARGIN), px(8), px(MARGIN), 0))
        bar.pack(fill="x")
        ttk.Label(bar, text="Show").pack(side="left")
        self.show_var = tk.StringVar(value=SHOW[0][0])
        show = ttk.Combobox(bar, textvariable=self.show_var, values=[n for n, _ in SHOW], state="readonly", width=18)
        show.pack(side="left", padx=(px(8), px(14)))
        self.level_var = tk.StringVar(value=LEVELS[0][0])
        level = ttk.Combobox(bar, textvariable=self.level_var, values=[n for n, _ in LEVELS], state="readonly", width=18)
        level.pack(side="left", padx=(0, px(14)))
        ttk.Label(bar, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        search = ttk.Entry(bar, textvariable=self.search_var, width=34)
        search.pack(side="left", padx=(px(8), 0))
        for box in (show, level):
            box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        self.search_var.trace_add("write", lambda *_a: self.refresh())

        footer = ttk.Frame(top, padding=(px(MARGIN), px(4), px(MARGIN), px(12)))
        footer.pack(side="bottom", fill="x")
        hint = stable_label(footer, HINT, width=inner)
        hint.pack(fill="x", pady=(0, px(6)))
        self.hint = StatusLine(hint, HINT)
        buttons = ttk.Frame(footer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Close", command=top.destroy).pack(side="right")
        self.reactivate_btn = ttk.Button(buttons, text="Reactivate", style="Accent.TButton", command=self.reactivate_selected,
                                         state="disabled")
        self.reactivate_btn.pack(side="left")
        self.open_btn = ttk.Button(buttons, text="Open details", command=self.open_selected, state="disabled")
        self.open_btn.pack(side="left", padx=(px(8), 0))

        frame = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), 0))
        frame.pack(fill="both", expand=True)
        tree = self.tree = ttk.Treeview(frame, columns=COLS, show="headings", selectmode="extended")
        for c in COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(WIDTHS[c]), stretch=c == "Alert", anchor="w")
        for status, role in STATE_ROLE.items():
            tree.tag_configure(status, foreground=theme.color(role))
        self.sort = make_sortable(tree, COLS)
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._selection_changed())
        tree.bind("<Double-1>", lambda e: self.open_selected() if tree.identify_row(e.y) else None)

        self.refresh()
        theme.style_window(top)
        top.lift()
        top.focus_force()
        search.focus_set()

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

    def _filters(self) -> tuple[set[str] | None, Severity, list[str]]:
        return (dict(SHOW).get(self.show_var.get()), dict(LEVELS).get(self.level_var.get(), Severity.INFO),
                self.search_var.get().lower().split())

    def refresh(self) -> None:
        """Read the alerts again and show the ones that pass the filters; selection and sort order stay."""
        if not self.exists():
            return
        everything = self.app.alerts.recent(LIMIT)
        states, level, words = self._filters()
        shown = [a for a in everything if matches(a, states, level, words)]
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children(""))
        self._alerts = {}
        for a in shown:
            iid = str(a.id)
            self._alerts[iid] = a
            self.tree.insert("", "end", iid=iid, tags=(a.status,), values=[
                _t(a.last_seen), _t(a.first_seen), a.severity.name.capitalize(), STATE.get(a.status, a.status),
                self.app.describe_origin(a), a.title])
        self.sort.reapply()  # type: ignore[attr-defined]
        keep = [iid for iid in selected if iid in self._alerts]
        if keep:
            self.tree.selection_set(keep)
        count = {s: sum(1 for a in everything if a.status == s) for s in STATE}
        days = self.app.cfg.get("general", "alert_retention_days", default=90)
        self.summary.configure(text=(
            f"{len(everything)} alerts kept ({len(shown)} shown): {count[ACTIVE]} open, {count[SNOOZED]} snoozed, "
            f"{count[DISMISSED]} dismissed, {count[MUTED]} logged only. Alerts are kept for {days} days."))
        self._selection_changed()

    def _selected(self) -> list[Alert]:
        return [self._alerts[iid] for iid in self.tree.selection() if iid in self._alerts]

    def _selection_changed(self) -> None:
        chosen = self._selected()
        self.open_btn.configure(state="normal" if chosen else "disabled")
        self.reactivate_btn.configure(state="normal" if any(can_reactivate(a) for a in chosen) else "disabled")

    # ---------------------------------------------------------------- actions
    def open_selected(self) -> None:
        for alert in self._selected()[:5]:
            fresh = self.app.alerts.get(alert.id)  # as it is now (it may have been updated since the list was read)
            if fresh is not None:
                self.app.open_alert(fresh)

    def reactivate_selected(self) -> None:
        ids = [a.id for a in self._selected() if can_reactivate(a)]
        if not ids:
            return
        self.app.alerts.reactivate(ids)
        self.app.on_alerts_reactivated()
        self.refresh()
        self.hint.show(f"{len(ids)} alert{'s' if len(ids) != 1 else ''} reactivated: back among the reminders, marked as new.")
