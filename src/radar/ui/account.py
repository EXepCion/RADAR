"""Everything RADAR has stored about one account - or one device, IP address, network, country or application -, on
one page of the main window.

Two panes. Left, in a fixed width and scrolling by itself: what it is, what is open, its habits, what stands out.
Right, always in view whatever the window's height: where the account's devices were in the last days, and the
timeline of sign-ins, changes and alerts. A card with nothing in it is one line - no room is kept for rows that are not there.

The timeline is a list of rows, each a shape with round corners: an alert's row is tinted, the row under the pointer
lights up, a sign-in's row unfolds where it stands. It is drawn (see feed), and only what is near the part in view -
the list goes on as it is scrolled.
"""
from __future__ import annotations

import threading
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from .. import search as finder
from .. import timefmt
from . import theme
from .bits import (Badge, Chips, DayBars, FieldBox, Flow, Glide, Pill, SplitBar, Tag, between, come_forward, fit_text, underline_on_hover,
                   watch_hover)
from .parts import Hint, ScrollFrame, card, on_card
from .feed import Day, Feed, Piece, Row
from .lanes import Lanes
from .rounded import tone
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

LEFT = 440          # the summary's width
FACTS_SHOWN = 4     # facts in the head before "more"
CHART_FROM = 900    # the timeline pane is at least this wide: the sign-ins per day are drawn beside the filters
FILTERS = [("all", "Everything"), ("Sign-in", "Sign-ins"), ("Failed", "Failed"), ("Change", "Changes"), ("Alert", "Alerts")]
SHADES = ("link", "select", "track", "track")  # the parts of a habits bar: first, second, the rest
DOT = {"Sign-in": "neg", "Failed": "error", "Change": "link", "Alert": "warn"}
LEVEL_ROLE = {"high": "error", "medium": "warn"}
TIME_COLUMN = 52    # where a line's text begins, after its time


class AccountPage:
    def __init__(self, root: tk.Tk, app: "App", parent: tk.Misc, user_id: str, on_back: Callable[[], None],
                 on_search: Callable[[str], None], background: bool = True, kind: str = "account"):
        self.app, self.root, self.user_id, self.kind = app, root, user_id, kind   # (``user_id``: the key of whatever kind it is)
        self.background = background   # read off the UI thread (False: at once, here - for tests)
        self.view: finder.AccountView | None = None
        self.only: finder.Worth | None = None    # the "Worth a look" entry whose sign-ins alone are shown (None: no such filter)
        self.unfolded: set[Any] = set()
        self.all_facts = False
        self._grown = 1.0              # how far what runs in when the page appears has come
        self.lanes: Lanes | None = None    # the Movement card's chart, when there is movement to show
        self.now_button: Pill | None = None
        c = theme.color
        top = self.top = theme.new_window(root, parent=parent)
        pad = px(20)

        # ---- the bar: back, a search field, the way that led here; how old the data is; what else can be done
        bar = self.bar = ttk.Frame(top, padding=(pad, px(14), pad, px(10)))
        bar.pack(fill="x")
        self.back = Pill(bar, "Back", on_back, height=36, icon="back", round_=True)
        self.back.pack(side="left")
        box = FieldBox(bar, 36, "border", width=250)
        box.pack(side="left", padx=(px(12), px(12)))
        inner = box.inner
        glass = theme.icon(inner, "search", "muted", 14)
        if glass is not None:
            tk.Label(inner, image=glass, background=c("card"), bd=0).pack(side="left", padx=(0, px(8)))
        self.find = tk.StringVar()
        self.entry = tk.Entry(inner, textvariable=self.find, width=24, bd=0, relief="flat", highlightthickness=0, font=theme.FONT,
                              background=c("card"), foreground=c("text"), insertbackground=c("link"))
        self.entry.pack(side="left")
        self.entry_hint = tk.Label(inner, text="Search", font=theme.FONT, background=c("card"), foreground=c("muted"), bd=0, padx=0, pady=0)
        self.entry_hint.place(in_=self.entry, x=px(2), rely=0.5, anchor="w")
        self.entry_hint.bind("<Button-1>", lambda _e: self.entry.focus_set())
        self.find.trace_add("write", lambda *_a: self.entry_hint.place_forget() if self.find.get() else self.entry_hint.place(
            in_=self.entry, x=px(2), rely=0.5, anchor="w"))
        self.entry.bind("<Return>", lambda _e: on_search(self.find.get()))
        box.watch(self.entry)   # (its outline turns to the accent colour while it has the keyboard)
        self.refresh = Pill(bar, "Read again", self.load, height=36, icon="refresh", round_=True)
        self.refresh.pack(side="right")
        if kind == "account":
            self.entra = Pill(bar, "Open in Entra", lambda: app.open_account_in_entra(user_id))
            self.entra.pack(side="right", padx=(0, px(8)))
        self.map = Pill(bar, "Live map", app.show_map)
        self.map.pack(side="right", padx=(0, px(8)))
        self.age = ttk.Label(bar, text="", style="Muted.TLabel")
        self.age.pack(side="right", padx=px(12))

        # Nothing of the page's content is shown before all of it is there: a page that fills in piece by piece -
        # cards arriving one after the other, one pushing the next down - is restless to look at. Until then: one line.
        self.ready = self.failed = False
        self._waiting: list[Callable[[], None]] = []
        self.wait_note = ttk.Label(top, text="Reading what is stored …", style="Muted.TLabel")
        self.wait_note.pack(anchor="w", padx=pad, pady=px(8))
        panes = self.panes = ttk.Frame(top, padding=(pad, 0, pad, px(14)))
        left = ttk.Frame(panes, width=px(LEFT))
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self.summary = ScrollFrame(left)
        self.summary.pack(fill="both", expand=True)
        self.right = ttk.Frame(panes)
        self.right.pack(side="left", fill="both", expand=True, padx=(px(8), 0))
        self.moves = ttk.Frame(self.right)        # the Movement card, when there is movement to show
        self.moves.pack(fill="x")
        timeline = card(self.right)
        timeline.pack(fill="both", expand=True)
        head = self.head = on_card(timeline, padx=px(16), pady=px(12))
        head.pack(fill="x")
        tk.Label(head, text="Timeline", font=theme.FONT_BOLD, background=c("card"), foreground=c("text"), bd=0).pack(side="left", padx=(0, px(14)))
        self.filters = Chips(head, FILTERS, lambda _k: self._filter())
        self.filters.pack(side="left")
        self.filters.choose("all", tell=False)
        self.chart: tk.Misc | None = None
        body = on_card(timeline, padx=px(8), pady=0)
        body.pack(fill="both", expand=True, pady=(0, px(8)))
        self.feed = Feed(body)
        self.feed.pack(fill="both", expand=True)
        self.feed.canvas.bind("<Configure>", lambda e: self._width(e.width), add="+")
        self.splits: list[SplitBar] = []
        theme.style_window(top)
        self.load()

    def _width(self, _width: int) -> None:
        """The sign-ins per day are drawn beside the filters where there is room for them. (The rows of the timeline
        lay themselves out for the width they are given.)"""
        if self.chart is not None:
            wide = self.right.winfo_width() >= px(CHART_FROM)
            if wide and not self.chart.winfo_manager():
                self.chart.pack(side="right")
            elif not wide and self.chart.winfo_manager():
                self.chart.pack_forget()

    # ------------------------------------------------------------------ data
    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def load(self, wait: bool = False) -> None:
        """Read it again (off the UI thread; ``wait``: here and now - for tests)."""
        wait = wait or not self.background

        def work() -> None:
            try:
                view = self.app.account_view(self.user_id) if self.kind == "account" else self.app.thing_view(self.kind, self.user_id)
            except Exception:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).exception("The page could not be read")
                self._failed() if wait else self.app.ui_call(self._failed)
                return
            if wait:
                self._show_or_say(view)
            else:
                self.app.ui_call(self._show_or_say, view)

        if wait:
            work()
        else:
            threading.Thread(target=work, name="account", daemon=True).start()

    def _show_or_say(self, view: finder.AccountView) -> None:
        """What was read is drawn - and if that fails, the page says so instead of waiting forever."""
        try:
            self.show(view)
        except Exception:  # noqa: BLE001
            import logging
            logging.getLogger(__name__).exception("The page could not be drawn")
            self._failed()

    def show(self, view: finder.AccountView) -> None:
        if not self.exists():
            return
        self.view = view
        first = not self.ready
        if first:   # what runs in when the page appears (the bars, the ways between places) begins at nothing
            self._grown = 0.0 if theme.animations() else 1.0
        self.age.configure(text=self.app.search_age())
        self._summary()
        self._movement()
        for key, label in FILTERS:
            n = sum(view.counts.values()) if key == "all" else view.counts.get(key, 0)
            self.filters.set_text(key, f"{label} {n:,}" if n and key != "all" else label)
        if self.chart is not None:
            self.chart.destroy()
            self.chart = None
        if any(view.per_day):
            self.chart = on_card(self.head)
            tk.Label(self.chart, text="sign-ins per day", font=theme.FONT_CAPTION, background=theme.color("card"), foreground=theme.color("muted"),
                     bd=0).pack(side="right", padx=(px(10), 0))
            self.bars = DayBars(self.chart, view.per_day)
            self.bars.grow(self._grown)
            self.bars.pack(side="right")
            self._width(self.feed.canvas.winfo_width())
        self._timeline()
        self._grow(self._grown)
        if first:
            # everything is written: lay it out while it is still out of sight, then show it - whole, once
            self.wait_note.pack_forget()
            self.panes.pack(fill="both", expand=True)
            try:
                self.top.update_idletasks()
                for flow in self.flows:
                    flow.fit()
                self.top.update_idletasks()
            except tk.TclError:
                return
            arrive = come_forward(self.panes)   # the cards are there; what is written on them comes out of its ground
            arrive(self._grown)
            self.ready = True
            waiting, self._waiting = self._waiting, []
            for tell in waiting:
                tell()
            theme.animate(self.top, 300, lambda t: (self._grow(t), arrive(t)))   # (at once with animations off)

    def _failed(self) -> None:
        """The reading failed: the page says so (instead of reading forever) and comes forward - it has a way back."""
        if not self.exists() or self.ready:
            return
        self.failed = True
        self.wait_note.configure(text="This could not be read – the log says why.")
        waiting, self._waiting = self._waiting, []
        for tell in waiting:
            tell()

    def when_ready(self, tell: Callable[[], None]) -> None:
        """``tell()`` as soon as the page is complete and laid out (at once if it is already)."""
        if self.ready or self.failed:
            tell()
        else:
            self._waiting.append(tell)

    # ------------------------------------------------------------------ the summary
    def _card(self, title: str, sub: str = "", quiet: bool = False) -> tk.Frame:
        """A card of the summary with its heading; returns the frame for its rows."""
        c = theme.color
        box = card(self.summary.body)
        box.pack(fill="x", padx=(0, px(6)), pady=(0, px(10)))
        inner = on_card(box, padx=px(16), pady=px(12))
        inner.pack(fill="x")
        head = on_card(inner)
        head.pack(fill="x")
        tk.Label(head, text=title, font=theme.FONT_BOLD, background=c("card"), foreground=c("text"), bd=0).pack(side="left")
        if sub:
            tk.Label(head, text=sub, font=theme.FONT_CAPTION_BOLD if quiet else theme.FONT_CAPTION, background=c("card"),
                     foreground=c("neg" if quiet else "muted"), bd=0).pack(side="left", padx=(px(10), 0))
        return inner

    def _row(self, parent: tk.Misc, title: str, line: str, note: str, role: str, on_click: Callable[[], None] | None, bold: bool = False,
             dot: str = "", arrow: bool = False) -> tk.Frame:
        c = theme.color
        row = tk.Frame(parent, background=c("card"), bd=0, highlightthickness=0, cursor="hand2" if on_click else "")
        row.pack(fill="x", pady=(px(8), 0))
        parts: list[tk.Misc] = [row]
        if dot:
            parts.append(Badge(row, "dot", size=18, role=dot))
            parts[-1].pack(side="left", padx=(0, px(8)))
        if arrow:
            parts.append(tk.Label(row, text="›", font=theme.FONT, background=c("card"), foreground=c("muted"), bd=0))
            parts[-1].pack(side="right", padx=(px(8), 0))
        if note:
            parts.append(tk.Label(row, text=note, font=theme.FONT_CAPTION_BOLD, background=c("card"), foreground=c(role), bd=0))
            parts[-1].pack(side="right", padx=(px(10), 0))
        text = on_card(row)
        text.pack(side="left", fill="x", expand=True)
        parts += [text, tk.Label(text, text=title, font=theme.FONT_BOLD if bold else theme.FONT, background=c("card"), foreground=c("text"),
                                 bd=0, anchor="w", justify="left", wraplength=px(LEFT - 170))]
        parts[-1].pack(fill="x")
        if line:
            parts.append(tk.Label(text, text=line, font=theme.FONT_CAPTION, background=c("card"), foreground=c("muted"), bd=0, anchor="w"))
            parts[-1].pack(fill="x")
        if on_click:   # what can be clicked answers to the pointer: its text and its arrow turn to the link colour
            words, tip = parts[-2 if line else -1], next((w for w in parts if isinstance(w, tk.Label) and w.cget("text") == "›"), None)

            def paint(t: float) -> None:
                words.configure(foreground=tone(between(("text", "link"), t)))
                if tip is not None:
                    tip.configure(foreground=tone(between(("muted", "link"), t)))

            glide = Glide(row, paint)
            watch_hover(parts, lambda on: glide.to(1 if on else 0))
            for w in parts:
                w.bind("<Button-1>", lambda _e: on_click())
        return row

    def _summary(self) -> None:
        view, c, app = self.view, theme.color, self.app
        assert view is not None
        for child in self.summary.body.winfo_children():
            child.destroy()

        # ---- what it is
        box = card(self.summary.body)
        box.pack(fill="x", padx=(0, px(6)), pady=(0, px(10)))
        inner = on_card(box, padx=px(16), pady=px(14))
        inner.pack(fill="x")
        top = on_card(inner)
        top.pack(fill="x")
        Badge(top, view.kind, view.title, size=44).pack(side="left", padx=(0, px(12)))
        risk = on_card(top)
        risk.pack(side="right", anchor="n")
        tk.Label(risk, text="Highest open risk", font=theme.FONT_CAPTION, background=c("card"), foreground=c("muted"), bd=0).pack(anchor="e")
        open_risk = view.risk is not None
        role = LEVEL_ROLE.get(view.risk_level.lower(), "muted") if open_risk else "neg"
        figure = on_card(risk)
        figure.pack(anchor="e")
        self.risk = tk.Label(figure, text=str(view.risk) if open_risk else "Nothing open", font=theme.FONT_TITLE if open_risk else theme.FONT_BOLD,
                             background=c("card"), foreground=c(role), bd=0)
        self.risk.pack(side="left")
        self.risk_level = tk.Label(figure, text=view.risk_level if open_risk else "", font=theme.FONT_CAPTION_BOLD, background=c("card"),
                                   foreground=c(role), bd=0)
        self.risk_level.pack(side="left", padx=(px(6), 0), anchor="s", pady=(0, px(4)))
        names = on_card(top)
        names.pack(side="left", fill="x", expand=True)
        self.title = tk.Label(names, text=view.title, font=theme.FONT_TITLE, background=c("card"), foreground=c("text"), bd=0, anchor="w",
                              justify="left", wraplength=px(LEFT - 240))
        self.title.pack(fill="x")
        if view.upn:
            tk.Label(names, text=view.upn, font=theme.FONT_CAPTION, background=c("card"), foreground=c("muted"), bd=0, anchor="w", justify="left",
                     wraplength=px(LEFT - 240)).pack(fill="x")
        tags = list(view.tags)
        if view.kind == "account":
            tags = [("Enabled" if view.enabled else "Disabled", "neg" if view.enabled else "error")] + ([(view.member.capitalize(), "muted")] if view.member else [])
        self.tags: list[Tag] = []
        if tags:
            line = on_card(inner)
            line.pack(fill="x", pady=(px(10), 0))
            for text, notice in tags:
                role = notice if isinstance(notice, str) else ("warn" if notice else "muted")
                self.tags.append(Tag(line, text, role, bold=role != "muted"))
                self.tags[-1].pack(side="left", padx=(0, px(6)))
        facts = view.facts if self.all_facts else view.facts[:FACTS_SHOWN]
        if facts:
            tk.Frame(inner, height=1, background=c("border"), bd=0, highlightthickness=0).pack(fill="x", pady=(px(12), px(4)))
            grid = on_card(inner)
            grid.pack(fill="x")
            for column in (0, 1):
                grid.columnconfigure(column, weight=1, uniform="fact")
            for i, fact in enumerate(facts):
                cell = on_card(grid)
                cell.grid(row=i // 2, column=i % 2, sticky="nw", pady=(px(8), 0))
                tk.Label(cell, text=fact.label, font=theme.FONT_CAPTION, background=c("card"), foreground=c("muted"), bd=0, anchor="w").pack(fill="x")
                tk.Label(cell, text=fact.value, font=theme.FONT_BOLD if fact.warn else theme.FONT, background=c("card"),
                         foreground=c("warn" if fact.warn else "text"), bd=0, anchor="w", justify="left", wraplength=px(LEFT // 2 - 40)).pack(fill="x")
            rest = len(view.facts) - FACTS_SHOWN
            if rest > 0:
                more = tk.Label(inner, text="Fewer facts" if self.all_facts else f"{rest} more facts", font=theme.FONT_CAPTION, background=c("card"),
                                foreground=c("link"), bd=0, cursor="hand2", anchor="w")
                more.pack(side="top", anchor="w", pady=(px(10), 0))
                more.bind("<Button-1>", lambda _e: self._toggle_facts())
                underline_on_hover(more)
                self.more_facts = more

        # ---- what is open: the incident first, then its alerts, each with a dot of its level
        open_n = len(view.incidents) + len(view.open_alerts)
        sub = " · ".join(p for p in (finder._plural(len(view.incidents), "incident") if view.incidents else "",
                                          finder._plural(len(view.open_alerts), "open alert") if view.open_alerts else "") if p)
        now_card = self._card("Right now", sub or "nothing open", quiet=not open_n)
        for incident in view.incidents:
            # (as the alert's window names it: its title - what weighs in it stands in the incident's own window)
            still, total = len(incident.open_alerts), len(incident.reminders)
            self._row(now_card, incident.title, f"Incident · {still} of {finder._plural(total, 'alert')} open",
                      "High" if incident.risk >= 70 else "Incident", "error", lambda i=incident: app.open_incident(i.id), bold=True, dot="error")
        for alert in view.open_alerts:
            role = LEVEL_ROLE.get(alert.severity.label.lower(), "muted")
            self._row(now_card, alert.title, "Alert · " + timefmt.stamp(alert.occurred_at or alert.last_seen),
                      f"{alert.severity.label} · {alert.score}", role, lambda a=alert: app.open_alert(a), dot=role)
        if view.earlier_alerts:
            earlier = tk.Label(now_card, text=f"Before: {finder._plural(view.earlier_alerts, 'alert')}, closed or logged only · show in the timeline",
                               font=theme.FONT_CAPTION, background=c("card"), foreground=c("link"), bd=0, cursor="hand2", anchor="w")
            earlier.pack(side="top", anchor="w", pady=(px(8), 0))
            earlier.bind("<Button-1>", lambda _e: self.filters.choose("Alert"))
            underline_on_hover(earlier)
        self.now_card = now_card

        # ---- habits: one row per kind; a bar shows how the kind divides, the entries under it name its parts
        self.flows: list[Flow] = []
        self.splits = []
        if view.habits:
            habits = self._card(view.habits_title, f"{finder.DAYS} days · {finder._plural(view.counts.get('Sign-in', 0), 'sign-in')}")
            for n, kind in enumerate(view.habits):
                if n:
                    tk.Frame(habits, height=1, background=c("border"), bd=0, highlightthickness=0).pack(fill="x", pady=(px(8), 0))
                row = on_card(habits)
                row.pack(fill="x", pady=(px(8), 0))
                tk.Label(row, text=kind.label, font=theme.FONT_CAPTION_BOLD, background=c("card"), foreground=c("muted"), bd=0, anchor="nw",
                         width=13, justify="left").pack(side="left", anchor="n")
                side = on_card(row)
                side.pack(side="left", fill="x", expand=True)
                bar = SplitBar(side, [(entry.count, self._shade(i, entry)) for i, entry in enumerate(kind.entries)])
                bar.pack(fill="x", pady=(px(5), px(4)))
                self.splits.append(bar)
                flow = Flow(side)
                flow.pack(fill="x")
                self.flows.append(flow)
                for i, entry in enumerate(kind.entries):
                    if i:
                        flow.gap()
                    flow.add("■ ", self._shade(i, entry), font=theme.FONT_CAPTION)
                    flow.add(entry.name, "link" if entry.ref else "text", (lambda e=entry: app.open_found(e.ref[0], e.ref[1], e.name)) if entry.ref else None)
                    flow.add(f" {entry.count:,}", "muted", font=theme.FONT_CAPTION)
                    if entry.new:
                        flow.tag("new")

        # ---- what stands out
        worth = self._card("Worth a look", f"{finder.DAYS} days · a click filters the timeline" if view.worth else f"nothing unusual in {finder.DAYS} days",
                           quiet=not view.worth)
        for item in view.worth:
            self._row(worth, item.label, "", f"{item.count:,}", "warn", (lambda w=item: self._only(w)) if item.ids else None, arrow=bool(item.ids))
        self.worth_card = worth

    @staticmethod
    def _shade(index: int, entry: finder.Entry) -> str:
        return "warn" if entry.new else SHADES[min(index, len(SHADES) - 1)]

    def _grow(self, t: float) -> None:
        """What runs in when the page appears, at ``t`` of its way: the bars of the habits, the sign-ins per day
        rising. (No number counts up: a risk that is 55 never reads 20, not even for a moment.)"""
        self._grown = t
        try:
            for bar in self.splits:
                bar.grow(t)
            if self.chart is not None:
                self.bars.grow(t)
        except tk.TclError:
            pass

    def _toggle_facts(self) -> None:
        self.all_facts = not self.all_facts
        self._summary()

    # ------------------------------------------------------------------ movement
    def _movement(self) -> None:
        """Where the account's devices were in the last days (see lanes.Lanes): a lane for every device, the colour
        of a bar its place, a device's name the way to its page; under the chart the places. The card is there only
        when the devices were seen at more than one place."""
        for child in self.moves.winfo_children():
            child.destroy()
        view, c = self.view, theme.color
        self.lanes, self.now_button = None, None
        if view is None or view.movement is None:
            self.moves.configure(height=1)
            return
        moves = view.movement
        box = card(self.moves)
        box.pack(fill="x", pady=(0, px(10)))
        inner = on_card(box, padx=px(16), pady=px(12))
        inner.pack(fill="x")
        head = on_card(inner)
        head.pack(fill="x")
        tk.Label(head, text="Movement", font=theme.FONT_BOLD, background=c("card"), foreground=c("text"), bd=0).pack(side="left")
        # "Now" is there only while an earlier time is in view - and its room is kept, so that nothing beside it moves
        room = on_card(head)
        room.pack(side="right")
        self.now_button = Pill(room, "Now", lambda: self.lanes.to_end() if self.lanes is not None else None, height=26)
        room.configure(width=self.now_button.winfo_reqwidth(), height=self.now_button.winfo_reqheight())
        room.pack_propagate(False)
        # which 24 hours are in view, in as much room as there is (all of it under the pointer, where it is cut)
        self.span = tk.Label(head, text="", width=1, font=theme.FONT_CAPTION, background=c("card"), foreground=c("muted"), bd=0, anchor="w")
        self.span.pack(side="left", fill="x", expand=True, padx=(px(10), px(10)))
        self._said: tuple[str, ...] = ("",)
        Hint([self.span], lambda: self._said[0] if self.span.cget("text") != self._said[0] else "")
        self.span.bind("<Configure>", lambda _e: self._say(), add="+")
        self.lanes = Lanes(inner, moves, on_view=self._in_view,
                           on_device=lambda device_id, name: self.app.open_found("device", device_id, name))
        self.lanes.pack(fill="x", pady=(px(10), 0))

    def _in_view(self, said: tuple[str, ...], at_end: bool) -> None:
        """The chart moved: the heading says which hours are in view, and "Now" is there unless they are the last."""
        self._said = said
        self._say()
        if self.now_button is not None:
            if at_end:
                self.now_button.place_forget()
            elif not self.now_button.winfo_manager():
                self.now_button.place(x=0, y=0)

    def _say(self) -> None:
        """The words for what is in view, in the room there is: the whole, or the first shorter form that fits - each
        with its zone. Shorter still, it is cut; a time whose zone would be cut goes with it (timefmt.keep_whole)."""
        try:
            room = self.span.winfo_width()
            font = tkfont.nametofont(theme.FONT_CAPTION, root=self.span)
            fits = next((form for form in self._said if room <= 1 or font.measure(form) <= room), None)
            self.span.configure(text=fits if fits is not None else timefmt.keep_whole(fit_text(self._said[-1], room, theme.FONT_CAPTION, self.span)))
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ the timeline
    def _only(self, worth: finder.Worth) -> None:
        self.only = worth
        self.filters.choose("all", tell=False)
        self._timeline()

    def _filter(self) -> None:
        self.only = None
        self._timeline()

    def visible_lines(self) -> list[finder.Line]:
        view = self.view
        if view is None:
            return []
        chosen = self.filters.chosen or "all"
        lines = [ln for ln in view.timeline if chosen == "all" or ln.kind == chosen]  # noqa: E501
        if self.only is not None:
            lines = [ln for ln in lines if finder.covers(ln, self.only)]
        return lines

    @property
    def rows(self) -> list[Row]:
        """The rows of the timeline that are drawn now (those in and near the part in view), from the top."""
        return self.feed.rows

    @property
    def marks(self) -> list[str]:
        """What is marked as unusual on them (the small tags)."""
        return [mark for row in self.feed.rows for mark in row.marks]

    def _timeline(self) -> None:
        """The timeline anew, from its beginning: the days and under each its rows."""
        lines = self.visible_lines()
        today, day, items = datetime.now().astimezone().date(), None, []
        for ln in lines:
            local = ln.when.astimezone()
            if local.date() != day:   # a day begins: its name, and - once per day - the zone its times are in
                day = local.date()
                name = "Today" if day == today else local.strftime("%A")
                items.append(Day(f"{name}, {local.strftime('%d.%m.%Y')} · times in {timefmt.zone(local)}"))
            items.append(self._row_of(ln))
        note, go = "", None
        if not lines:
            note = "Nothing of this kind in the stored days." if self.view and self.view.timeline else "Nothing is stored about this."
        elif self.only is not None:
            note, go = "Only what “Worth a look” picked · show everything", self._filter
        self.feed.set(items, note, go)

    def _row_of(self, ln: finder.Line) -> Row:
        """One line of the timeline as a row (see feed.Row): what stands in its second line, and what a click on its
        text, its links and its arrow does."""
        app = self.app
        alert, failed = ln.kind == "Alert", ln.kind == "Failed"
        pieces: list[Piece] = [(ln.kind + ("" if not alert or not ln.level else f" · {ln.level}"), "error" if failed else "muted", alert or failed, None)]
        if ln.account:
            pieces += [(" · ", "muted", False, None), (ln.account, "link", False, lambda: app.open_found("account", ln.user_id, ln.account))]
        # (a page does not repeat on every row what it is itself about)
        if (ln.place or ln.ip) and self.kind != "address":
            pieces.append((" · " + (ln.place + " · " if ln.place and ln.ip else ln.place), "muted", False, None))
            if ln.ip:
                pieces.append((ln.ip, "link", False, lambda: app.open_found("address", ln.ip, ln.ip)))
        if (ln.device or (ln.kind in ("Sign-in", "Failed") and ln.ip)) and self.kind != "device":
            known = bool(ln.device and ln.device_id)
            pieces += [(" · ", "muted", False, None),
                       (ln.device or "no device", "link" if known else "muted", False,
                        (lambda: app.open_found("device", ln.device_id, ln.device)) if known else None)]
        folds = bool(ln.ref) and ln.ref[0] == "signin"   # a sign-in unfolds where it stands; anything else opens what it is about
        low = alert and ln.level in ("low", "closed", "info")
        row = Row(timefmt.clock_bare(ln.when), "muted" if low else DOT[ln.kind], ln.what, ln.marks, pieces,
                  base="alert_bg" if alert else "card", on_title=(lambda: self._open(ln)) if ln.ref else None,
                  on_arrow=((lambda: self._fold(ln)) if folds else (lambda: self._open(ln))) if ln.ref else None, line=ln)
        if ln.ref in self.unfolded:
            row.detail = self._unfolded(ln)
            if row.detail is None:
                self.unfolded.discard(ln.ref)
        return row

    def _unfolded(self, line: finder.Line) -> list[tuple[str, str]] | None:
        """What the line unfolds into; None when the history cannot be read just now (the row stays folded)."""
        try:
            return self.app.unfold(line)
        except Exception:  # noqa: BLE001 - a row that cannot be unfolded must not break the page
            import logging
            logging.getLogger(__name__).exception("A timeline row could not be unfolded")
            return None

    def _fold(self, line: finder.Line) -> None:
        """Unfold a sign-in's row where it stands, or fold it again. Nothing else moves: the reader keeps their place."""
        row = self.feed.row_of(line.ref)
        if row is None:
            self.unfolded ^= {line.ref}
            return
        opening = row.detail is None
        detail = self._unfolded(line) if opening else None
        if opening and detail is None:
            return  # (nothing changes: a click later tries again)
        self.unfolded ^= {line.ref}
        row.detail = detail
        self.feed.refresh(row, fresh=opening)

    def _open(self, line: finder.Line) -> None:
        if line.ref:
            self.app.open_found(line.ref[0], line.ref[1], line.what)

    def written(self) -> str:
        """What the timeline shows, as text: the days, and for every row its time and what it says, its second line,
        and what it is unfolded into ("name<tab>value") - and what stands under the last row."""
        return self.feed.written()
