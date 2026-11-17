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

from .. import timefmt
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
from .parts import Badge, Hint, Pointer, Segments, StageTrack, card, on_card
from .rounded import Rounded
from .richtext import StatusLine, stable_label
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH, MARGIN = 1180, 20
LIST = 440  # the width of the list of incidents; the chosen incident takes the rest
COLS = ["Severity", "Incident", "Last activity"]
WIDTHS = {"Severity": 122, "Incident": 190, "Last activity": 100}
STEP_COLS = ["Time", "Severity", "Stage", "State", "Alert"]
STEP_WIDTHS = {"Time": 166, "Severity": 98, "Stage": 128, "State": 82, "Alert": 190}  # (the time with its zone)
STATE = {ACTIVE: "open", SNOOZED: "snoozed", DISMISSED: "dismissed", MUTED: "logged only"}
ROLE = {Severity.HIGH: "error", Severity.MEDIUM: "warn"}  # the colour an incident's progress is drawn in (else blue)
HINT = ""  # (the line at the bottom says what was done; how to use the page needs no words)
SUMMARY_TEMPLATE = ("Last 00 days. 000 more open alerts are not part of an incident (000 High): see the reminders. "
                    "Data as of 00:00 UTC+00:00.")
NOTHING = "No incident selected"
TRACK_LEGEND = ("Filled: the incident has an open alert of this stage.   Grey: its alerts of this stage were dismissed.   "
                "Ring: no alert of this stage - the attack was not seen there, the line only passes through.")
FACTS = ("Accounts", "Attacker addresses", "Period", "Done so far")
TEXTS = ("Strongest finding", "What to do")  # longer: several lines each
NO_ADVICE = "Look at its alerts in order and decide for each whether it was the person themselves."


def _t(when: Any) -> str:
    return timefmt.sortable(when) if when else ""


def _short(values: list[str], limit: int) -> str:
    return ", ".join(values[:limit]) + (f" +{len(values) - limit}" if len(values) > limit else "")


def ago(value: str) -> str:
    """How long ago a time of a table was (timefmt.sortable): 'Now', '3 hours ago', '2 days ago'."""
    try:
        when = datetime.strptime(str(value)[:16], timefmt.SORTABLE).astimezone()
    except (TypeError, ValueError):
        return value
    return theme.humanize(when)


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
    times = [a.dismissed_at for a in incident.reminders if a.dismissed_at]
    closed = "closed" + (f" {max(times).astimezone():%d.%m.}" if times else "")  # (a date: needs no time zone)
    return " · ".join(p for p in (
        incident.stage_name or "No attack stage",
        f"{still}/{total} open" if still else closed) if p)


def state_line(incident: incidents.Incident) -> str:
    """Open or closed, in a few words: how many of its alerts are open, or when the last one was dismissed."""
    total, still = len(incident.reminders), incident.open_alerts
    if still:
        snoozed = sum(1 for a in still if a.status == SNOOZED)
        return f"Open \u00b7 {len(still)} of {total} alerts" + (f", {snoozed} snoozed" if snoozed else "")
    times = [a.dismissed_at for a in incident.reminders if a.dismissed_at]
    return "Closed" + (f" \u00b7 last alert dismissed {timefmt.stamp(max(times))}" if times else "")


def facts(incident: incidents.Incident) -> dict[str, str]:
    """What holds the incident together and what was done about it (the captions are FACTS)."""
    days = (incident.last - incident.first).days
    times = [a.dismissed_at for a in incident.reminders if a.dismissed_at] if not incident.open else []
    closed = f"  \u00b7  closed {timefmt.stamp(max(times))}" if times else ""
    return {
        "Accounts": ", ".join(incident.accounts) or "-",
        "Attacker addresses": ", ".join(incident.addresses) or "None known",
        "Period": (f"{timefmt.stamp(incident.first)} \u2013 {timefmt.stamp(incident.last)}"
                   + (f"  \u00b7  {days} days" if days > 1 else "") + closed),
        "Done so far": ", ".join(incident.responses) or "Nothing on record",
    }


def clamp(text: str, font: str, width: int, lines: int, widget: tk.Misc) -> str:
    """``text`` as it fits ``lines`` lines of ``width`` pixels; what does not fit ends in an ellipsis."""
    measure = tkfont.nametofont(font, root=widget).measure
    out: list[str] = []
    words: list[str] = []
    for word in " ".join(str(text).split()).split(" "):
        if words and word.startswith("UTC"):  # a time and its zone are one word: never on two lines
            words[-1] += " " + word
        else:
            words.append(word)
    line = ""
    for k, word in enumerate(words):
        trial = f"{line} {word}".strip()
        if measure(trial) <= width or not line:
            line = trial
            continue
        if len(out) == lines - 1:  # the last line: the rest does not fit - as much of the next word as there is room for
            line = trial
            while line and measure(line + "…") > width:
                line = line[:-1]
            return "\n".join(out + [timefmt.keep_whole(line.rstrip(" ,;:") + "…")])
        out.append(line)
        line = word
    return "\n".join(out + [line])


class Summary(tk.Frame):
    """What an incident is, at a glance - the same block wherever an incident is shown (the page, its own window):
    its name, how bad and whether open, how far along an attack it is and when each stage was reached, whom and
    which attacker addresses it is about, since when, what was done. Every part has its fixed place."""

    def __init__(self, parent: tk.Misc, text_width: int, header: bool = True, lines: tuple[int, int] = (1, 2)):
        """``header=False``: without the name, the severity and the open/closed line - where the list beside it
        already says all three for the incident that is selected (the Incidents page). ``lines``: how many lines the
        strongest finding and the advice get (what does not fit ends in an ellipsis; the pointer shows all)."""
        self._lines = dict(zip(TEXTS, lines))
        white = theme.color("card")
        super().__init__(parent, background=white, bd=0, highlightthickness=0)
        self._text_width = text_width
        self.full: dict[str, str] = {}  # the facts, unshortened
        self._title = ""
        self.title_label = tk.Label(self, font=theme.FONT_BOLD, anchor="w", bd=0, padx=0, pady=0, background=white,
                                    foreground=theme.color("text"))
        Hint((self.title_label,), lambda: self._title, wrap=px(520))
        line = on_card(self)
        if header:
            self.title_label.pack(fill="x")
            line.pack(fill="x", pady=(px(6), 0))
        self.badge = Badge(line)
        self.badge.pack(side="left")
        self.state_label = tk.Label(line, font=theme.FONT, anchor="w", bd=0, padx=0, pady=0, background=white,
                                    foreground=theme.color("muted"))
        self.state_label.pack(side="left", fill="x", expand=True, padx=(px(10), 0))
        self.track = StageTrack(self, [incidents.chains.STAGE_NAMES[k] for k in sorted(incidents.chains.STAGE_NAMES)])
        self.track.pack(fill="x", pady=(px(14) if header else px(4), px(8)))
        Hint((self.track,), lambda: TRACK_LEGEND, wrap=px(460))  # what the three kinds of points mean
        # The facts as a list: the names in one column, the values beside them, one line each over the whole width.
        # A value that still does not fit ends in an ellipsis; the pointer shows all of it.
        tk.Frame(self, height=1, background=theme.color("border"), bd=0, highlightthickness=0).pack(fill="x", pady=(px(2), px(8)))
        grid = on_card(self)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        self.fact_labels: dict[str, tk.Label] = {}
        for row, name in enumerate(FACTS + TEXTS):
            tall = name in TEXTS  # (several lines: its name stands at the top of them)
            caption = tk.Label(grid, text=name, font=theme.FONT, anchor="nw", bd=0, padx=0, pady=0, background=white,
                               foreground=theme.color("muted"))
            caption.grid(row=row, column=0, sticky="nw", padx=(0, px(20)), pady=(px(6) if name == TEXTS[0] else px(2), px(2)))
            value = self.fact_labels[name] = tk.Label(grid, font=theme.FONT, anchor="nw", justify="left", bd=0, padx=0, pady=0,
                                                      height=self._lines.get(name, 1), background=white,
                                                      foreground=theme.color("text"))
            value.grid(row=row, column=1, sticky="ew", pady=(px(6) if name == TEXTS[0] else px(2), px(2)))
            value.bind("<Configure>", lambda _e=None, n=name: self._fit_fact(n), add="+")
            Hint((caption, value), lambda n=name: self.full.get(n, ""))  # the whole text where it is shortened

    def _fit_fact(self, name: str) -> None:
        """A fact on its one line, as wide as its place is (what does not fit ends in an ellipsis)."""
        try:
            label = self.fact_labels[name]
            width = label.winfo_width()
            text = self.full.get(name, "")
            lines = self._lines.get(name, 1)
            label.configure(text=clamp(text, theme.FONT, width, lines, self) if width > px(40) else text)
        except tk.TclError:
            pass

    def show(self, inc: incidents.Incident | None) -> None:
        self._title = short_title(inc) if inc else ""
        self.title_label.configure(text=clamp(self._title, theme.FONT_BOLD, self._text_width, 1, self) if inc else NOTHING)
        if inc:
            self.badge.set(f"{inc.severity.label} \u00b7 {inc.risk}" if inc.risk else inc.severity.label,
                           theme.severity_roles(inc.severity))
            self.state_label.configure(text=state_line(inc), foreground=theme.color("error" if inc.open else "muted"))
            stages = inc.stages
            self.track.set({stage: f"{timefmt.stamp(when)}" + ("" if still else ", dismissed")
                            for stage, (when, still) in stages.items()},
                           ROLE.get(inc.severity, "link"), settled=[k for k, (_when, still) in stages.items() if not still])
        else:
            self.badge.set("")
            self.state_label.configure(text="")
            self.track.set({})
        self.full = {**facts(inc), TEXTS[0]: inc.why, TEXTS[1]: inc.advice or NO_ADVICE} if inc else {}
        for name in self.fact_labels:
            self._fit_fact(name)


def step_rows(inc: incidents.Incident | None) -> list[tuple[Alert, list[str]]]:
    """The alerts of an incident as table rows (STEP_COLS), in order."""
    rows = []
    counted = {a.id for a in inc.own_alerts} if inc else set()
    for a in (inc.alerts if inc else []):
        stage = incidents.stage_of(a)
        # what was only logged is context: it is no stop on the line above, so it does not carry a stop's name
        kind = ("Summary" if a.plugin_id == incidents.chains.CHAIN_PLUGIN else
                "Response" if a.signal in incidents.chains.NOT_LINKS else
                "Context" if a.id not in counted else
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
        top.geometry(f"{theme.fit_width(top, px(WIDTH))}x{min(px(780), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(theme.fit_width(top, px(1000)), px(680))
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
        hint = stable_label(footer, "w" * 60, width=inner - px(380), max_lines=1)
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
        tree.show_as("Last activity", ago)          # "3 hours ago": what matters for which one first
        self.sort = make_sortable(tree, COLS)
        tree.grid(row=0, column=0, sticky="nsew")
        tree.bind("<<TreeviewSelect>>", lambda _e: self._incident_selected())
        tree.bind("<Double-1>", lambda e: self.open_incident() if tree.identify_row(e.y) else None)
        tree.tag_configure("closed", pill="sev_info_bg|sev_info_fg")  # colour only where something needs a look

        # in the place of the list when it is empty (same size, same card): nothing open is good news, said plainly
        empty = self.empty = card(body)
        empty.grid(row=0, column=0, sticky="nsew")
        middle = on_card(empty)
        middle.place(relx=0.5, rely=0.4, anchor="center")
        white = theme.color("card")
        self._empty_images = {True: theme.icon(empty, "check", "neg", 28), False: None}
        self.empty_icon = tk.Label(middle, background=white, bd=0, highlightthickness=0)
        self.empty_icon.pack(pady=(0, px(8)))
        self.empty_title = tk.Label(middle, font=theme.FONT_BOLD, background=white, foreground=theme.color("text"), bd=0)
        self.empty_title.pack()
        self.empty_link = tk.Label(middle, font=theme.FONT, background=white, foreground=theme.color("link"), bd=0)
        self.empty_link.pack(pady=(px(6), 0))
        self.empty_link.bind("<Button-1>", lambda _e=None: self.show_filter("closed") if self.empty_link.cget("text") else None)
        self.empty_note = tk.Label(middle, font=theme.FONT_CAPTION, background=white, foreground=theme.color("muted"), bd=0,
                                   wraplength=px(LIST - 60), justify="center")
        self.empty_note.pack(pady=(px(14), 0))
        tk.Misc.lower(empty.outer, tree.outer)

        # The chosen incident, on the right. Whose it is, is shown, not said again (the list says who, how bad and how
        # much of it is open): the right side is framed in the accent colour and an arrowhead on its edge points at
        # the selected incident and follows it.
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=1)
        self.pointer = Pointer(body)
        self.pointer.grid(row=0, column=1, sticky="ns", padx=(px(3), 0))
        frame = self.frame = Rounded(body, fill="window", edge="link")
        frame.grid(row=0, column=2, sticky="nsew")
        right = self._right = tk.Frame(frame, background=theme.color("window"), bd=0, highlightthickness=0)
        right.pack(fill="both", expand=True, padx=px(8), pady=px(8))
        text_w = inner - px(LIST + 14 + 2 * 11 + 2 * 16 + 6)
        tree.on_drawn(self._point)
        body.bind("<Configure>", lambda _e=None: self._point(), add="+")

        # ---- what happened: the chosen incident
        box = card(right)
        box.pack(fill="x")
        about = on_card(box, padx=px(16), pady=px(12))
        about.pack(fill="x")
        self.block = Summary(about, text_w, header=False)
        self.block.pack(fill="x")
        self.title_label, self.badge, self.state_label = self.block.title_label, self.block.badge, self.block.state_label
        self.track, self.fact_labels = self.block.track, self.block.fact_labels

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
        if not self._filter:  # it opens on what is open - also when that is nothing (then it says so, plainly)
            self._filter = "open"
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
        self.summary.configure(text=(  # (how many are open and closed: on the buttons beside it)
            f"Last {incidents.LOOKBACK_DAYS} days." if found else f"No incidents in the last {incidents.LOOKBACK_DAYS} days.")
            + self._alone(found) + f" Data as of {timefmt.clock(now)}.")
        if selected in self._incidents:
            self.tree.selection_set(selected)
        elif shown:
            self.tree.selection_set(shown[0].id)
        self._show_empty(found, shown)
        self._incident_selected()

    def _show_empty(self, found: list[incidents.Incident], shown: list[incidents.Incident]) -> None:
        """In the place of the list when it has nothing to show: what that means, and where the rest is."""
        closed = sum(1 for i in found if not i.open)
        if shown:
            tk.Misc.lower(self.empty.outer, self.tree.outer)  # (a canvas: its own lower() is for its items)
            return
        if self._filter == "open":
            title, done = "No open incidents", True
            link = (f"{closed} closed in the last {incidents.LOOKBACK_DAYS} days" if closed else "")
        else:
            title, done = ("No closed incidents" if self._filter == "closed" else "No incidents"), False
            link = ""
        self.empty_title.configure(text=title)
        self.empty_icon.configure(image=self._empty_images[done] or "")
        self.empty_link.configure(text=link, cursor="hand2" if link else "")
        self.empty_note.configure(text=self._alone(found).strip())  # single alerts may still be open: not "all clear"
        tk.Misc.lift(self.empty.outer, self.tree.outer)

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
            self.hint.show("That incident is no longer there.", error=True)
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
        self._point()
        self._fact_full = self.block.full
        for a, values in step_rows(inc):
            iid = str(a.id)
            self._steps[iid] = a
            self.steps.insert("", "end", iid=iid, tags=(a.status,), values=values)
        self.step_sort.reapply()  # type: ignore[attr-defined]
        keep = [iid for iid in chosen if iid in self._steps]
        if keep:
            self.steps.selection_set(keep)
        self._buttons()

    def _point(self) -> None:
        """The arrowhead at the height of the selected incident."""
        try:
            chosen = (self.tree.selection() or [""])[0]
            self.pointer.at(self.tree.row_middle(chosen) if chosen in self._incidents else None)
            mine = chosen in self._incidents
            self.frame.set_edge("link" if mine else "window")  # framed when it is somebody's ...
            if mine and not self._right.winfo_manager():
                self._right.pack(fill="both", expand=True, padx=px(8), pady=px(8))
            elif not mine and self._right.winfo_manager():
                self._right.pack_forget()  # ... and empty, not a form without values, when no incident is selected
        except tk.TclError:
            pass

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
        self.hint.show(f"{len(ids)} reminder{'s' if len(ids) != 1 else ''} dismissed.")
