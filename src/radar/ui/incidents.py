"""'Incidents' page: alerts that belong to one story, taken together - which one first, what happened, what to do.

An incident is two or more alerts about the same account or the same known attacker address within a few days
(radar.incidents). The page answers, in this order, what somebody on watch asks:

* Which one first?   The list on the left: severity and risk, who it is about, how far it got, when it last moved.
* What happened?     The chosen incident on the right: how far along an attack it is (the stage track, with the
                     time each stage was reached), who and which attacker addresses, since when, what was done.
* How sure is that, and what now?   Its strongest finding with the reasons that weigh most, and the advice.
* The evidence.      Its alerts in order; each opens with all its details. The open ones can be dismissed together.

Everything has its fixed place: choosing another incident changes the texts, never the layout.
"""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime, timezone
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from .. import incidents
from ..alerts import ACTIVE, DISMISSED, MUTED, SNOOZED, Alert
from ..plugin_api import Severity
from . import icons, theme
from .cardtable import CardTable
from .parts import Badge, Hint, Segments, StageTrack, card, on_card
from .richtext import StatusLine, stable_label
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH, MARGIN = 1180, 20
LIST = 440  # the width of the list of incidents; the chosen incident takes the rest
COLS = ["Severity", "Incident", "Last activity"]
WIDTHS = {"Severity": 128, "Incident": 180, "Last activity": 106}
STEP_COLS = ["Time", "Severity", "Stage", "State", "Alert"]
STEP_WIDTHS = {"Time": 110, "Severity": 90, "Stage": 132, "State": 86, "Alert": 250}
STATE = {ACTIVE: "open", SNOOZED: "snoozed", DISMISSED: "dismissed", MUTED: "logged only"}
ROLE = {Severity.HIGH: "error", Severity.MEDIUM: "warn"}  # the colour an incident's progress is drawn in (else blue)
HINT = ("An incident is open while one of its alerts is still a reminder; it opens again by itself when one gets worse "
        "or a new alert joins. Double-click an incident or one of its alerts for all the details.")
SUMMARY_TEMPLATE = ("000 incidents in the last 00 days: 000 open, 000 closed. 000 more open alerts are not part of an "
                    "incident (000 High): see the reminders. Data as of 00:00.")
NOTHING = "No incident selected"
FACTS = ("Accounts", "Attacker addresses", "From - to", "Done so far")


def _t(when: Any) -> str:
    return when.astimezone().strftime("%Y-%m-%d %H:%M") if when else ""


def _short(values: list[str], limit: int) -> str:
    return ", ".join(values[:limit]) + (f" +{len(values) - limit}" if len(values) > limit else "")


def state_role(value: str, _tags: tuple = ()) -> str:
    """The colour of a state: what still needs a look stands out, what is over steps back."""
    return "error" if value.startswith("open") else "warn" if value.startswith("snoozed") else "muted"


def who(incident: incidents.Incident) -> str:
    """Whom an incident is about, short: its accounts (the first two), else that it hangs on an attacker address."""
    names = [a.split("@")[0] for a in incident.accounts]
    if names:
        return _short(names, 2)
    apps = sorted({str(a.fields.get("App")) for a in incident.own_alerts if a.fields.get("App")})
    return _short(apps, 1) if apps else "One attacker address"


def short_title(incident: incidents.Incident) -> str:
    """The incident's name without the stages in brackets a chain's title ends with: the track shows those."""
    title = incident.title
    return title[:title.rindex(" (")] if title.endswith(")") and " -> " in title.rsplit(" (", 1)[-1] else title


def progress(incident: incidents.Incident) -> str:
    """The small line under an incident in the list: how far it got, and how much of it is still open."""
    total, still = len(incident.reminders), len(incident.open_alerts)
    return " · ".join(p for p in (
        incident.stage_name or "No attack stage",
        f"{still}/{total} open" if still else "closed") if p)


def state_line(incident: incidents.Incident) -> str:
    """Open or closed, in a few words: how many of its alerts are open, or when the last one was dismissed."""
    total, still = len(incident.reminders), incident.open_alerts
    if still:
        snoozed = sum(1 for a in still if a.status == SNOOZED)
        return f"Open \u00b7 {len(still)} of {total} alerts" + (f", {snoozed} snoozed" if snoozed else "")
    times = [a.dismissed_at for a in incident.reminders if a.dismissed_at]
    return "Closed" + (f" \u00b7 last alert dismissed {max(times).astimezone():%d.%m. %H:%M}" if times else "")


def facts(incident: incidents.Incident) -> dict[str, str]:
    """What holds the incident together and what was done about it (the captions are FACTS)."""
    days = (incident.last - incident.first).days
    return {
        "Accounts": ", ".join(incident.accounts) or "-",
        "Attacker addresses": ", ".join(incident.addresses) or "None known",
        "From - to": (f"{incident.first.astimezone():%d.%m. %H:%M} - {incident.last.astimezone():%d.%m. %H:%M}"
                      + (f" ({days} days)" if days > 1 else "")),
        "Done so far": ", ".join(incident.responses) or "Nothing on record",
    }


def clamp(text: str, font: str, width: int, lines: int, widget: tk.Misc) -> str:
    """``text`` as it fits ``lines`` lines of ``width`` pixels; what does not fit ends in an ellipsis."""
    measure = tkfont.nametofont(font, root=widget).measure
    out: list[str] = []
    words = " ".join(str(text).split()).split(" ")
    line = ""
    for k, word in enumerate(words):
        trial = f"{line} {word}".strip()
        if measure(trial) <= width or not line:
            line = trial
            continue
        if len(out) == lines - 1:  # the last line: the rest does not fit
            while line and measure(line + "…") > width:
                line = line[:-1]
            return "\n".join(out + [line.rstrip(" ,;:") + "…"])
        out.append(line)
        line = word
    return "\n".join(out + [line])


class Summary(tk.Frame):
    """What an incident is, at a glance - the same block wherever an incident is shown (the page, its own window):
    its name, how bad and whether open, how far along an attack it is and when each stage was reached, whom and
    which attacker addresses it is about, since when, what was done. Every part has its fixed place."""

    def __init__(self, parent: tk.Misc, text_width: int):
        white = theme.color("card")
        super().__init__(parent, background=white, bd=0, highlightthickness=0)
        self._text_width = text_width
        self.full: dict[str, str] = {}  # the facts, unshortened
        self._title = ""
        self.title_label = tk.Label(self, font=theme.FONT_BOLD, anchor="w", bd=0, padx=0, pady=0, background=white,
                                    foreground=theme.color("text"))
        self.title_label.pack(fill="x")
        Hint((self.title_label,), lambda: self._title, wrap=px(520))
        line = on_card(self)
        line.pack(fill="x", pady=(px(6), 0))
        self.badge = Badge(line)
        self.badge.pack(side="left")
        self.state_label = tk.Label(line, font=theme.FONT, anchor="w", bd=0, padx=0, pady=0, background=white,
                                    foreground=theme.color("muted"))
        self.state_label.pack(side="left", fill="x", expand=True, padx=(px(10), 0))
        self.track = StageTrack(self, [incidents.chains.STAGE_NAMES[k] for k in sorted(incidents.chains.STAGE_NAMES)])
        self.track.pack(fill="x", pady=(px(14), px(8)))
        grid = on_card(self)
        grid.pack(fill="x")
        self._fact_width = (text_width - 3 * px(16)) // 4
        self.fact_labels: dict[str, tk.Label] = {}
        for k, name in enumerate(FACTS):
            grid.columnconfigure(k, weight=1, uniform="facts")
            cell = on_card(grid)
            cell.grid(row=0, column=k, sticky="nsew", padx=(0, px(16) if k < len(FACTS) - 1 else 0))
            tk.Label(cell, text=name, font=theme.FONT_CAPTION, anchor="w", bd=0, padx=0, pady=0, background=white,
                     foreground=theme.color("muted")).pack(fill="x")
            value = self.fact_labels[name] = tk.Label(cell, font=theme.FONT, anchor="nw", justify="left", bd=0, padx=0, pady=0,
                                                      height=2, background=white, foreground=theme.color("text"))
            value.pack(fill="x", pady=(px(1), 0))
            Hint((cell, value), lambda n=name: self.full.get(n, ""))  # the whole text where it is shortened

    def show(self, inc: incidents.Incident | None) -> None:
        self._title = short_title(inc) if inc else ""
        self.title_label.configure(text=clamp(self._title, theme.FONT_BOLD, self._text_width, 1, self) if inc else NOTHING)
        if inc:
            self.badge.set(f"{inc.severity.label} \u00b7 {inc.risk}" if inc.risk else inc.severity.label,
                           theme.severity_roles(inc.severity))
            self.state_label.configure(text=state_line(inc), foreground=theme.color("error" if inc.open else "muted"))
            stages = inc.stages
            self.track.set({stage: f"{when.astimezone():%d.%m. %H:%M}" + ("" if still else ", dismissed")
                            for stage, (when, still) in stages.items()},
                           ROLE.get(inc.severity, "link"), settled=[k for k, (_when, still) in stages.items() if not still])
        else:
            self.badge.set("")
            self.state_label.configure(text="")
            self.track.set({})
        self.full = facts(inc) if inc else {}
        for name, label in self.fact_labels.items():
            label.configure(text=clamp(self.full.get(name, ""), theme.FONT, self._fact_width, 2, self))


def step_rows(inc: incidents.Incident | None) -> list[tuple[Alert, list[str]]]:
    """The alerts of an incident as table rows (STEP_COLS), in order."""
    rows = []
    for a in (inc.alerts if inc else []):
        stage = incidents.stage_of(a)
        kind = ("Summary" if a.plugin_id == incidents.chains.CHAIN_PLUGIN else
                "Response" if a.signal in incidents.chains.NOT_LINKS else
                incidents.chains.STAGE_NAMES[stage] if stage else "-")
        rows.append((a, [_t(a.when), "" if kind == "Response" else a.severity.label, kind, STATE.get(a.status, a.status), a.title]))
    return rows


class IncidentsWindow:
    def __init__(self, root: tk.Tk, app: "App", parent: tk.Misc | None = None, on_close=None):
        self.app = app
        self._incidents: dict[str, incidents.Incident] = {}
        self._steps: dict[str, Alert] = {}
        top = self.top = theme.new_window(root, parent=parent, on_close=on_close)
        top.title("Incidents")
        top.geometry(f"{px(WIDTH)}x{min(px(780), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(1000), px(680))
        top.bind("<Escape>", lambda _e: theme.close(top))
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)
        inner = px(WIDTH - 2 * MARGIN)
        self._all: list[incidents.Incident] = []
        self._filter = ""  # until the first look: the open ones when there are any, otherwise all
        white = theme.color("card")

        header = ttk.Frame(top, padding=(px(MARGIN), px(16), px(MARGIN), px(6)))
        header.pack(fill="x")
        self.filter = Segments(header, [("open", "Open"), ("closed", "Closed"), ("all", "All")], self._filter_chosen, width=9)
        self.filter.pack(side="right", anchor="n", pady=(px(6), 0))
        ttk.Label(header, text="Incidents", style="PageTitle.TLabel").pack(fill="x")
        self.summary = stable_label(header, SUMMARY_TEMPLATE, width=inner - px(340))
        self.summary.pack(fill="x", pady=(px(4), 0))

        # at the bottom: what can be done with the chosen incident, and a line that explains or reports
        footer = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), px(12)))
        footer.pack(side="bottom", fill="x")
        if not theme.is_panel(top):
            ttk.Button(footer, text="Close", command=top.destroy).pack(side="right", padx=(px(8), 0))
        self.open_btn = ttk.Button(footer, text="Open details", style="Accent.TButton", command=self.open_selected, state="disabled")
        self.open_btn.pack(side="right")
        self.dismiss_btn = ttk.Button(footer, text="Dismiss its open reminders", command=self.dismiss_incident, state="disabled")
        self.dismiss_btn.pack(side="right", padx=(px(12), px(8)))
        hint = stable_label(footer, HINT, width=inner - px(380), max_lines=2)
        hint.pack(fill="x")
        self.hint = StatusLine(hint, HINT)

        body = ttk.Frame(top, padding=(px(MARGIN), px(6), px(MARGIN), 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, minsize=px(LIST))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # ---- which one first: the incidents, two lines each
        tree = self.tree = CardTable(body, COLS, selectmode="browse", row_height=54)
        for c in COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(WIDTHS[c]), stretch=c == "Incident", anchor="w")
        tree.pill("Severity", lambda value: theme.severity_roles(value.split(" ")[0]) if value else None)  # with the risk
        tree.note_of("Incident", lambda iid: progress(self._incidents[iid]) if iid in self._incidents else "")
        tree.cell_role("Incident", lambda _value, tags: "muted" if "closed" in tags else None)
        tree.show_as("Last activity")               # "Today 13:48"
        self.sort = make_sortable(tree, COLS)
        tree.grid(row=0, column=0, sticky="nsew")
        tree.bind("<<TreeviewSelect>>", lambda _e: self._incident_selected())
        tree.bind("<Double-1>", lambda e: self.open_incident() if tree.identify_row(e.y) else None)

        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(px(12), 0))
        text_w = inner - px(LIST + 12 + 2 * 16 + 6)

        # ---- what happened: the chosen incident
        box = card(right)
        box.pack(fill="x")
        about = on_card(box, padx=px(16), pady=px(12))
        about.pack(fill="x")
        self.block = Summary(about, text_w)
        self.block.pack(fill="x")
        self.title_label, self.badge, self.state_label = self.block.title_label, self.block.badge, self.block.state_label
        self.track, self.fact_labels = self.block.track, self.block.fact_labels

        # ---- how sure, and what now
        box = card(right)
        box.pack(fill="x", pady=(px(10), 0))
        advice = on_card(box, padx=px(16), pady=px(10))
        advice.pack(fill="x")
        self._text_width = text_w
        self._full: dict[str, str] = {}
        self.why_label = self._passage(advice, "Strongest finding", "why", 0)
        self.advice_label = self._passage(advice, "What to do", "advice", px(8))

        # ---- the evidence: its alerts in order
        steps = self.steps = CardTable(right, STEP_COLS, selectmode="extended")
        for c in STEP_COLS:
            steps.heading(c, text=c, anchor="w")
            steps.column(c, width=px(STEP_WIDTHS[c]), stretch=c == "Alert", anchor="w")
        steps.pill("Severity")
        steps.cell_role("State", state_role)
        steps.show_as("Time")
        steps.pack(fill="both", expand=True, pady=(px(10), 0))
        self.step_sort = make_sortable(steps, STEP_COLS)
        self.step_sort("Time")  # in the order it happened (the header says so); a click on a header sorts otherwise
        steps.bind("<<TreeviewSelect>>", lambda _e: self._buttons())
        steps.bind("<Double-1>", lambda e: self.open_selected() if steps.identify_row(e.y) else None)
        top.bind("<Return>", lambda _e: self.open_selected())

        self.refresh()
        theme.style_window(top)
        top.lift()
        top.focus_force()
        tree.focus_set()

    def _passage(self, parent: tk.Misc, caption: str, key: str, gap: int) -> tk.Label:
        """A caption with two lines of text under it (longer text ends in an ellipsis; the pointer shows all)."""
        white = theme.color("card")
        head = tk.Label(parent, text=caption, font=theme.FONT_CAPTION, anchor="w", bd=0, padx=0, pady=0, background=white,
                        foreground=theme.color("muted"))
        head.pack(fill="x", pady=(gap, 0))
        label = tk.Label(parent, font=theme.FONT, anchor="nw", justify="left", bd=0, padx=0, pady=0, height=2,
                         background=white, foreground=theme.color("text"))
        label.pack(fill="x", pady=(px(1), 0))
        Hint((head, label), lambda: self._full.get(key, ""), wrap=px(520))
        return label

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
        self._all = found
        open_count = sum(1 for i in found if i.open)
        if not self._filter:
            self._filter = "open" if open_count else "all"
            self.filter.choose(self._filter, tell=False)
        self.filter.set_text("open", f"Open {open_count}")
        self.filter.set_text("closed", f"Closed {len(found) - open_count}")
        shown = [i for i in found if self._filter == "all" or i.open == (self._filter == "open")]
        selected = (self.tree.selection() or [""])[0]
        self.tree.delete(*self.tree.get_children(""))
        self._incidents = {}
        for inc in shown:
            self._incidents[inc.id] = inc
            self.tree.insert("", "end", iid=inc.id, tags=("open" if inc.open else "closed",), values=[
                f"{inc.severity.label} · {inc.risk}" if inc.risk else inc.severity.label, who(inc), _t(inc.last)])
        self.sort.reapply()  # type: ignore[attr-defined]
        self.summary.configure(text=(
            f"{len(found)} incident{'s' if len(found) != 1 else ''} in the last {incidents.LOOKBACK_DAYS} days: "
            f"{open_count} open, {len(found) - open_count} closed."
            if found else f"No incidents in the last {incidents.LOOKBACK_DAYS} days: no two alerts belong together.")
            + self._alone(found) + f" Data as of {now.astimezone():%H:%M}.")
        if selected in self._incidents:
            self.tree.selection_set(selected)
        elif shown:
            self.tree.selection_set(shown[0].id)
        self._incident_selected()

    def _alone(self, found: list[incidents.Incident]) -> str:
        """What is open beside the incidents: single alerts, which are in the reminders (this page shows stories)."""
        try:
            inside = {a.id for i in found for a in i.alerts}
            alone = [a for a in self.app.alerts.active() if a.id not in inside and not a.is_system]
        except Exception:  # noqa: BLE001 - a count must never be in the way
            return ""
        if not alone:
            return ""
        high = sum(1 for a in alone if a.severity >= Severity.HIGH)
        return (f" {len(alone)} more open alert{'s are' if len(alone) != 1 else ' is'} not part of an incident"
                + (f" ({high} High)" if high else "") + ": see the reminders.")

    def _filter_chosen(self, key: str) -> None:
        self._filter = key
        self.refresh()

    def show_filter(self, key: str) -> None:
        """Show the open, the closed or all incidents."""
        self.filter.choose(key)

    def select(self, incident_id: str) -> bool:
        """Show this incident (asked for from an alert's details)."""
        if incident_id not in self._incidents and any(i.id == incident_id for i in self._all):
            self.filter.choose("all")  # it is there, only not among the ones shown
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
        self.block.show(inc)
        self._fact_full = self.block.full
        self._full = {"why": inc.why, "advice": inc.advice} if inc else {}
        self.why_label.configure(text=clamp(self._full.get("why", ""), theme.FONT, self._text_width, 2, self.top))
        self.advice_label.configure(text=clamp(self._full.get("advice", ""), theme.FONT, self._text_width, 2, self.top))
        for a, values in step_rows(inc):
            iid = str(a.id)
            self._steps[iid] = a
            self.steps.insert("", "end", iid=iid, tags=(a.status,), values=values)
        self.step_sort.reapply()  # type: ignore[attr-defined]
        keep = [iid for iid in chosen if iid in self._steps]
        if keep:
            self.steps.selection_set(keep)
        self._buttons()

    def _buttons(self) -> None:
        inc = self._incident()
        self.open_btn.configure(state="normal" if inc else "disabled")
        self.dismiss_btn.configure(state="normal" if inc and inc.open_alerts else "disabled")

    # ---------------------------------------------------------------- actions
    def open_selected(self) -> None:
        """The details of the selected alerts - with none selected, the incident in its own window."""
        chosen = [self._steps[iid] for iid in list(self.steps.selection())[:5] if iid in self._steps]
        if not chosen:
            self.open_incident()
        for alert in chosen:
            fresh = self.app.alerts.get(alert.id)
            if fresh is not None:
                self.app.open_alert(fresh)

    def open_incident(self) -> None:
        """The chosen incident in a window of its own, with everything about it (a double-click on it in the list)."""
        inc = self._incident()
        if inc is not None:
            self.app.open_incident(inc.id)

    def dismiss_incident(self) -> None:
        inc = self._incident()
        ids = [a.id for a in inc.open_alerts] if inc else []
        if not ids:
            return
        ids = self.app.dismiss_alerts(ids, self.top)
        self.app.on_alerts_dismissed()
        self.refresh()
        self.hint.show(f"{len(ids)} reminder{'s' if len(ids) != 1 else ''} of the incident dismissed. They come back by "
                       f"themselves if something gets worse, and stay in the alert history.")
