"""The Search page of the main window: one field, and beneath it what was found - or, before anything is typed, what
was opened last.

The field stands at the same place with and without results: nothing jumps when typing starts. Searching runs off
the UI thread (a search takes a moment on a large history) and only the answer to what is in the field now is shown.
A hit opens its page here - an account, a device, an address, a network, a country, an application - and its back
button leads the way back; alerts and sign-ins open in their own windows.
"""
from __future__ import annotations

import re
import threading
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from .. import search as finder
from .. import timefmt
from . import theme
from .bits import Badge, Chips, FieldBox, Glide, RowGlow, Tag, between, fit_text, stepped, underline_on_hover
from .parts import Hint, ScrollFrame, Tips, card, on_card
from .richtext import autoscroll
from .rounded import Rounded, tone
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

COLUMN = 800      # the field and what is under it
WIDE = 1110       # ... and the list of all sign-ins, which is a table
TOP = 96          # where the field stands (under the page's upper edge)
WAIT_MS = 180     # after the last key before the search starts
SHELL_MS = 400    # a page that takes longer than this to read is shown while it reads (saying so), not waited for in silence
PER_KIND = 5      # hits of a kind shown under "All"
LIMIT = 60        # hits of a kind fetched (shown when its filter is chosen)
PLACEHOLDER = "Account, device, IP address, application or ID"
LABELS = {"account": "Accounts", "device": "Devices", "address": "Addresses", "application": "Apps", "alert": "Alerts",
          "signin": "Sign-ins"}
FILTERS = [("all", "All")] + [(k, LABELS[k]) for k in finder.KINDS]
NOTE_ROLE = {"success": "neg", "failed": "error"}
LEVEL_ROLE = {"high": "error", "medium": "warn"}
TABLE = (("When", 22), ("What", 150), ("Account", 560), ("From", 730), ("Device", 950))   # the sign-in table's columns and where they begin


class SearchPage:
    def __init__(self, root: tk.Tk, app: "App", parent: tk.Misc, background: bool = True):
        self.app, self.root = app, root
        self.background = background   # read off the UI thread (False: at once, here - for tests)
        self.results: finder.Results | None = None
        self.rows: list[tuple[tk.Frame, Callable[[], None]]] = []   # what is listed now, with what a click on it does
        self.selected = -1
        self.path: list[tuple[str, Any, str]] = []                  # the pages opened one from the other: (kind, key, title)
        self.signins: list[finder.Line] = []
        self._seq, self._due, self._view = 0, None, None
        self._seen: Any = None   # the page that is on screen (``_view`` may be one that is still being read)
        c = theme.color
        top = self.top = theme.new_window(root, parent=parent)
        self.stack = ttk.Frame(top)
        self.stack.pack(fill="both", expand=True)
        self.stack.rowconfigure(0, weight=1)
        self.stack.columnconfigure(0, weight=1)
        find = self.find = ttk.Frame(self.stack)
        find.grid(row=0, column=0, sticky="nsew")
        column = self.column = ttk.Frame(find, width=px(COLUMN))
        column.pack(side="top", fill="y", expand=True, pady=(px(TOP), px(16)))
        column.pack_propagate(False)

        box = self.box = FieldBox(column, 56, "link", glow=True)   # the field: a pill, outlined in the accent colour; a soft ring
        # lies around it while it has the keyboard
        box.pack(fill="x")
        inner = box.inner
        glass = theme.icon(inner, "search", "muted", 18)
        if glass is not None:
            tk.Label(inner, image=glass, background=c("card"), bd=0).pack(side="left", padx=(0, px(12)))
        self.clear = tk.Label(inner, text="✕", font=theme.FONT, background=c("card"), foreground=c("muted"), bd=0, cursor="hand2")
        self.clear.bind("<Button-1>", lambda _e: (self.text.set(""), self.entry.focus_set()))
        self.clear.bind("<Enter>", lambda _e: self.clear.configure(foreground=theme.color("text")))
        self.clear.bind("<Leave>", lambda _e: self.clear.configure(foreground=theme.color("muted")))
        self.text = tk.StringVar()
        self.entry = tk.Entry(inner, textvariable=self.text, bd=0, relief="flat", highlightthickness=0, font=theme.FONT,
                              background=c("card"), foreground=c("text"), insertbackground=c("link"))
        self.entry.pack(side="left", fill="x", expand=True)
        box.watch(self.entry)
        self.hint = tk.Label(inner, text=PLACEHOLDER, font=theme.FONT, background=c("card"), foreground=c("muted"), bd=0, padx=0, pady=0)
        self.hint.place(in_=self.entry, x=px(6), rely=0.5, anchor="w")
        self.hint.bind("<Button-1>", lambda _e: self.entry.focus_set())
        self.text.trace_add("write", lambda *_a: self._typed())

        bar = ttk.Frame(column, height=px(32))   # (its room is kept while the pills are away: the list below never moves)
        bar.pack(fill="x", pady=(px(14), px(8)))
        bar.pack_propagate(False)
        self.age = ttk.Label(bar, text="", style="Muted.TLabel", anchor="e", font=theme.FONT_CAPTION)   # how old what is searched is
        self.age.pack(side="right", padx=(px(8), px(8)))
        self.filters = Chips(bar, FILTERS, self._filter_chosen)
        self.filters.choose("all", tell=False)
        self.scroll = ScrollFrame(column)
        self.scroll.pack(fill="both", expand=True)
        self.plain = ttk.Frame(self.scroll.body)   # what was opened last stands straight on the page ...
        self.listing = card(self.scroll.body, radius=12)   # ... what was found, on a card
        self.body = on_card(self.listing, padx=px(6), pady=px(6))
        self.body.pack(fill="x")
        self._into, self._ground = self.body, "card"   # where rows go now, and the colour they stand on
        self.table: tk.Text | None = None      # the list of all sign-ins (built when its filter is chosen)
        self.table_card: tk.Misc | None = None

        for key, step in (("<Down>", 1), ("<Up>", -1)):
            self.entry.bind(key, lambda _e, s=step: self._move(s) or "break")
        self.entry.bind("<Return>", lambda _e: self._open_selected())
        self.entry.bind("<Escape>", lambda _e: self.text.set(""))
        theme.style_window(top)
        self.show_last()
        self.entry.focus_set()

    # ------------------------------------------------------------------ what is typed
    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        """Back to the field, with what it found."""
        self.path = []
        if self._view is not None and self._view is not self._seen:   # a page still being read: nobody waits for it any more
            self._view.top.destroy()
            self._view = self._seen
        self.stack.configure(cursor="")
        self.find.tkraise()
        self.entry.focus_set()

    def _typed(self) -> None:
        text = self.text.get()
        if text:
            self.hint.place_forget()
            self.clear.pack(side="right", padx=(px(8), 0), before=self.entry)
        else:
            self.hint.place(in_=self.entry, x=px(6), rely=0.5, anchor="w")
            self.clear.pack_forget()
        if self._due is not None:
            self.root.after_cancel(self._due)
        self._due = self.root.after(WAIT_MS, self.run)

    def run(self, wait: bool = False) -> None:
        """Search for what is in the field (off the UI thread; ``wait``: here and now - for tests)."""
        if self._due is not None:
            self.root.after_cancel(self._due)
        self._due = None
        wait = wait or not self.background
        self._seq += 1
        seq, text = self._seq, self.text.get().strip()
        if len(text) < finder.MIN_LENGTH:
            self.results = None
            self.show_last()
            return

        def work() -> None:
            try:
                found = self.app.search(text, LIMIT)
                lines = self.app.search_signins(text)
            except Exception:  # noqa: BLE001 - a search that fails shows nothing; the log says why
                import logging
                logging.getLogger(__name__).exception("Search failed")
                found, lines = finder.Results(text), []
            if wait:
                self._arrived(seq, found, lines)
            else:
                self.app.ui_call(self._arrived, seq, found, lines)

        if wait:
            work()
        else:
            threading.Thread(target=work, name="search", daemon=True).start()

    def _arrived(self, seq: int, found: finder.Results, lines: list[finder.Line]) -> None:
        if seq != self._seq or not self.exists():
            return  # the field says something else by now
        self.results, self.signins = found, lines
        self.show_results()

    # ------------------------------------------------------------------ what is listed
    def _clear(self) -> None:
        for holder in (self.body, self.plain):
            for child in holder.winfo_children():
                child.destroy()
        self.rows, self.selected = [], -1
        self.links: list[tk.Label] = []
        self.scroll.canvas.yview_moveto(0)
        if self.table_card is not None:
            self.table_card.destroy()
            self.table, self.table_card = None, None
        self.column.configure(width=px(COLUMN))
        self.scroll.pack(fill="both", expand=True)

    def _use(self, plain: bool) -> None:
        """Where the rows go: straight onto the page (what was opened last) or onto the card (what was found)."""
        self._into, self._ground = (self.plain, "window") if plain else (self.body, "card")
        if plain:
            self.listing.pack_forget()
            self.plain.pack(fill="x", padx=(0, px(6)))
        else:
            self.plain.pack_forget()
            self.listing.pack(fill="x", padx=(0, px(6)))

    def _caption(self, text: str, action: tuple[str, Callable[[], None]] | None = None) -> None:
        c = theme.color
        head = tk.Frame(self._into, background=c(self._ground), bd=0, highlightthickness=0, padx=px(12))
        head.pack(fill="x", pady=(px(8), px(2)))
        tk.Label(head, text=text, font=theme.FONT_CAPTION, background=c(self._ground), foreground=c("muted"), bd=0).pack(side="left")
        if action:
            link = tk.Label(head, text=action[0], font=theme.FONT_CAPTION, background=c(self._ground), foreground=c("link"), bd=0, cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", lambda _e: action[1]())
            underline_on_hover(link)

    def _rule(self) -> None:
        """A hairline between two kinds of hits."""
        tk.Frame(self._into, height=1, background=theme.color("border"), bd=0, highlightthickness=0).pack(fill="x", padx=px(12), pady=(px(6), 0))

    def _link(self, text: str, go: Callable[[], None]) -> None:
        """Under the hits of a kind, where their text begins: where the rest of them is."""
        c = theme.color
        line = tk.Frame(self._into, background=c(self._ground), bd=0, highlightthickness=0, padx=px(58))
        line.pack(fill="x", pady=(px(2), px(6)))
        link = tk.Label(line, text=text, font=theme.FONT_CAPTION, background=c(self._ground), foreground=c("link"), bd=0, cursor="hand2")
        link.pack(side="left")
        link.bind("<Button-1>", lambda _e: go())
        underline_on_hover(link)
        self.links.append(link)

    def _title(self, parent: tk.Misc, title: str, typed: str, small: bool = False) -> list[tk.Misc]:
        """The title of a hit - or (``small``) its second line -, with what was typed in bold where it occurs."""
        c = theme.color
        fonts = (theme.FONT_CAPTION, theme.FONT_CAPTION_BOLD) if small else (theme.FONT, theme.FONT_BOLD)
        # The line is as high as its writing and as wide as the row lets it be - whatever is written on it. (If it
        # asked for the room its text needs, shortening the text would change the room, which would shorten the text ...)
        high = max(tkfont.nametofont(f, root=parent).metrics("linespace") for f in fonts)
        line = tk.Frame(parent, background=c(self._ground), bd=0, highlightthickness=0, height=high, width=1)
        line.pack(fill="x")
        line.pack_propagate(False)
        parts: list[tk.Misc] = [line]
        found = re.search(re.escape(typed), title, re.IGNORECASE) if typed else None
        pieces = [(title[:found.start()], False), (title[found.start():found.end()], True), (title[found.end():], False)] if found else [(title, False)]
        for text, bold in pieces:
            if text:
                parts.append(tk.Label(line, text=text, font=fonts[bold], background=c(self._ground), foreground=c("muted" if small else "text"),
                                      bd=0, padx=0, pady=0, anchor="w"))
                parts[-1].pack(side="left")
        labels = parts[1:]
        whole = [(str(w.cget("text")), str(w.cget("font"))) for w in labels]

        def fit(event: tk.Event) -> None:
            """A text longer than its room is shown from its beginning and ends in an ellipsis. (Left to itself a
            label that is too narrow shows the middle of its text: cut off at both ends.)"""
            room = event.width
            if room == getattr(line, "fitted", None):
                return
            line.fitted = room  # type: ignore[attr-defined]
            cut = False
            for label, (text, font) in zip(labels, whole):
                want = fit_text(text, room, font, label) if room > 0 else ""
                cut = cut or want != text
                if label.cget("text") != want:
                    label.configure(text=want)
                room -= tkfont.nametofont(font, root=label).measure(want)
            line.cut = cut  # type: ignore[attr-defined]

        line.bind("<Configure>", fit, add="+")
        line.whole, line.cut = "".join(text for text, _font in whole), False  # type: ignore[attr-defined]
        line.hint = Hint([line] + labels, lambda: line.whole if line.cut else "")  # type: ignore[attr-defined]  # (the whole of it, by pointing)
        return parts

    def _row(self, title: str, line: str, note: str, on_click: Callable[[], None], note_role: str = "muted", badge: tuple[str, str] = ("", ""),
             typed: str = "", note_tag: bool = False, arrow: bool = False, quiet: bool = False) -> None:
        c = theme.color
        # (a row has round corners: the tint of the chosen one is a rounded shape, not a band)
        row = Rounded(self._into, fill=self._ground, edge=self._ground, radius=8, padx=px(9), pady=px(4 if line else 0), cursor="hand2")
        row.pack(fill="x")
        widgets: list[tk.Misc] = [row]
        row.badge, row.arrow, row.quiet = None, None, quiet  # type: ignore[attr-defined]
        if badge[0]:
            row.badge = Badge(row, badge[0], title, role=badge[1], background=self._ground)  # type: ignore[attr-defined]
            row.badge.set_quiet(quiet)                                # type: ignore[attr-defined]
            row.badge.pack(side="left", padx=(0, px(12)))            # type: ignore[attr-defined]
            widgets.append(row.badge)                                 # type: ignore[attr-defined]
        if arrow:   # (always there, seen on the chosen row only: choosing a row moves nothing)
            row.arrow = tk.Label(row, text="›", font=theme.FONT, background=c(self._ground), foreground=c(self._ground), bd=0)  # type: ignore[attr-defined]
            row.arrow.pack(side="right", padx=(px(10), 0))            # type: ignore[attr-defined]
            widgets.append(row.arrow)                                 # type: ignore[attr-defined]
        if note:
            if note_tag:
                widgets.append(Tag(row, note, note_role, bold=note_role != "muted", background=self._ground))
            else:
                widgets.append(tk.Label(row, text=note, font=theme.FONT_CAPTION_BOLD if note_role != "muted" else theme.FONT_CAPTION,
                                        background=c(self._ground), foreground=c(note_role), bd=0))
            widgets[-1].pack(side="right", padx=(px(12), 0))
        text = tk.Frame(row, background=c(self._ground), bd=0, highlightthickness=0)
        text.pack(side="left", fill="x", expand=True)
        widgets.append(text)
        widgets += self._title(text, title, typed)
        if line:
            widgets += self._title(text, line, typed, small=True)
        index = len(self.rows)
        row.glide = Glide(row, lambda t, row=row, ground=self._ground: self._tint(row, ground, t))  # type: ignore[attr-defined]
        for w in widgets + [row.outer]:
            w.bind("<Button-1>", lambda _e: on_click())
            w.bind("<Motion>", lambda _e, i=index: self._select(i) if i != self.selected else None, add="+")  # (the mouse moved onto it:
            # a list that appears under a resting pointer keeps its best hit selected)
        row.parts = [w for w in widgets if not isinstance(w, (Badge, Tag))]  # type: ignore[attr-defined]
        row.tinted = [w for w in widgets if isinstance(w, (Badge, Tag))]     # type: ignore[attr-defined]
        self.rows.append((row, on_click))

    def _select(self, index: int, at_once: bool = False) -> None:
        """Choose a row: its tint fades in while that of the row chosen before fades out. (``at_once``: a list that
        appears has its best hit chosen already - nothing moves.)"""
        for i, (row, _f) in enumerate(self.rows):
            if row.quiet and row.badge is not None:  # type: ignore[attr-defined]
                row.badge.set_quiet(i != index)      # type: ignore[attr-defined]
            (row.glide.jump if at_once else row.glide.to)(1 if i == index else 0)  # type: ignore[attr-defined]
        self.selected = index

    def _tint(self, row: Any, ground: str, t: float) -> None:
        """A row between not chosen (0) and chosen (1): its ground, everything on it, and its arrow."""
        colour = between((ground, "new_row"), t)
        raw = tone(colour)
        row.set_fill(colour)
        for w in row.parts:
            if w is not row:
                w.configure(background=raw)
        if row.arrow is not None:
            row.arrow.configure(foreground=theme.mix(raw, theme.color("link"), max(0.0, min(1.0, stepped(t)))))
        for w in row.tinted:
            w.set_background(colour)

    def _move(self, step: int) -> None:
        if self.rows:
            self._select(max(0, min(len(self.rows) - 1, self.selected + step)))
            self.scroll.see(self.rows[self.selected][0].outer)   # (the keyboard never chooses a row that is out of view)

    def _open_selected(self) -> None:
        if self.rows:
            self.rows[max(self.selected, 0)][1]()

    def _filter_chosen(self, _key: str) -> None:
        if self.results is not None:
            self.show_results()

    def show_last(self) -> None:
        """Nothing is typed: what was opened last (nothing yet: the field stands alone)."""
        self._clear()
        self.filters.pack_forget()   # (filters are for results: nothing is typed, there is nothing to filter)
        self.age.configure(text="")
        last = list(self.app.opened_last())
        if not last:
            self.listing.pack_forget()
            self.plain.pack_forget()
            return
        self._use(True)
        self._caption("Opened last", ("Clear", lambda: (self.app.clear_opened(), self.show_last())))
        for item in last:
            self._row(item["title"], item.get("line", ""), item.get("when", ""),
                      lambda item=item: self.open(item["kind"], item["key"], item["title"], item.get("line", "")),
                      badge=(item["kind"] if item["kind"] in Badge.ICON or item["kind"] == "account" else "search", ""))

    def show_results(self) -> None:
        found = self.results
        if found is None:
            return
        self._clear()
        self._use(False)
        self.filters.pack(side="left")
        self.filters.set_text("all", f"All {found.total:,}")
        for kind in finder.KINDS:   # (a kind nothing was found of has no filter)
            self.filters.set_text(kind, f"{LABELS[kind]} {found.counts[kind]:,}" if found.counts[kind] else LABELS[kind])
            self.filters.hide(kind, not found.counts[kind])
        self._fit_age()
        chosen = self.filters.chosen or "all"
        if chosen == "signin" and self.signins:
            self._table()
            return
        kinds = finder.KINDS if chosen == "all" else (chosen,)
        shown = 0
        for kind in kinds:
            every = found.hits[kind]
            open_ = [h for h in every if kind == "alert" and h.note.endswith("open")]   # under "All": the alerts that are open, if any
            hits = (open_ or every)[:PER_KIND] if chosen == "all" else every[:LIMIT]
            if not hits:
                continue
            more = found.counts[kind] - len(hits)
            if shown:
                self._rule()
            self._caption(LABELS[kind])
            for hit in hits:
                line, note, role, tagged, badge = hit.line, hit.note, "muted", False, (kind, "")
                if kind == "account":
                    role, tagged = ("warn" if "open alert" in note else "muted"), bool(note)
                elif kind == "alert":
                    level = note.split(" ")[0].lower()
                    role = LEVEL_ROLE.get(level, "muted")
                    badge = ("dot", role if "open" in note else "")
                    line = " · ".join(p for p in (hit.line, timefmt.stamp(hit.when)) if p)
                elif kind == "signin":   # one line: the dot says how it ended, at the right stands when
                    badge, line, note = ("dot", NOTE_ROLE.get(note, "muted")), "", timefmt.stamp(hit.when)
                self._row(hit.title, line, note, lambda h=hit: self.open(h.kind, h.key, h.title, h.line), role, badge, found.text, tagged,
                          arrow=True, quiet=kind == "account")
                shown += 1
            if more > 0 and chosen != "all":
                self._caption(f"{more:,} more: type more to narrow it down")
            elif more > 0 and open_ and len(open_) == len(hits) and found.counts[kind] == len(every):
                self._link(f"{more:,} more, closed or logged only · in Alert history", lambda: self.app.show_main("history"))
            elif more > 0:
                self._link(f"All {found.counts[kind]:,} {LABELS[kind].lower()}", lambda k=kind: self.filters.choose(k))
        if not shown:
            self._caption(f"Nothing found for “{found.text}” in the stored {finder.DAYS} days.")
        elif self.rows:
            self._select(0, at_once=True)

    def _fit_age(self) -> None:
        """How old what is searched is, at the right of the filters - shorter where both would not fit."""
        text = self.app.search_age()
        self.age.configure(text=text)
        self.column.update_idletasks()
        room = self.column.winfo_width()
        if room > 1 and self.filters.winfo_reqwidth() + self.age.winfo_reqwidth() + px(24) > room and ", " in text:
            self.age.configure(text=text.split(", ", 1)[1])

    # ------------------------------------------------------------------ all sign-ins: a table
    def _table(self) -> None:
        """The sign-ins found, newest first, in columns: when, what (with what is unusual about it), whose, from where,
        with which device. The text of a line opens its record; blue opens that thing's page."""
        c = theme.color
        self.scroll.pack_forget()
        self.column.configure(width=px(WIDE))
        box = self.table_card = card(self.column, radius=12)
        box.pack(fill="both", expand=True)
        inner = on_card(box, padx=px(6), pady=px(6))
        inner.pack(fill="both", expand=True)
        inner.rowconfigure(0, weight=1)
        inner.columnconfigure(0, weight=1)
        text = self.table = tk.Text(inner, wrap="none", bd=0, relief="flat", highlightthickness=0, background=c("card"), foreground=c("text"),
                                    font=theme.FONT, cursor="arrow", spacing1=px(9), spacing3=px(9), padx=px(10), pady=0,
                                    tabs=tuple(px(x) for _n, x in TABLE))
        sb = ttk.Scrollbar(inner, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=autoscroll(sb))
        text.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        text.tag_configure("head", foreground=c("muted"), font=theme.FONT_CAPTION)
        text.tag_configure("muted", foreground=c("muted"), font=theme.FONT_CAPTION)
        text.tag_configure("link", foreground=c("link"))
        text.tag_configure("failed", foreground=c("error"), font=theme.FONT_BOLD)
        for kind, role in (("Sign-in", "neg"), ("Failed", "error")):
            text.tag_configure("dot" + kind, foreground=c(role))
        zone = timefmt.zone(datetime.now().astimezone())
        text.insert("end", "\t".join([""] + [f"When ({zone})" if name == "When" else name for name, _x in TABLE]) + "\n", "head")
        self.table_marks: list[Tag] = []
        widths = [px(TABLE[i + 1][1] - TABLE[i][1] - 16) for i in range(len(TABLE) - 1)]

        def hand(tag: str, go: Callable[[], None]) -> None:
            lined = not tag.startswith("open")   # (a link is underlined under the pointer; the line's own text is not)
            text.tag_bind(tag, "<Button-1>", lambda _e: go())
            text.tag_bind(tag, "<Enter>", lambda _e: (text.configure(cursor="hand2"), text.tag_configure(tag, underline=lined)))
            text.tag_bind(tag, "<Leave>", lambda _e: (text.configure(cursor="arrow"), text.tag_configure(tag, underline=False)))

        glow = self.table_glow = RowGlow(text)   # the row under the pointer lights up
        tips = self.table_tips = Tips(text)      # the whole of a cell that is shortened, under the pointer
        for n, ln in enumerate(self.signins[:LIMIT * 5]):
            begin, row_marks = text.index("end-1c"), []
            text.insert("end", "●", "dot" + ln.kind)
            text.insert("end", "\t" + timefmt.stamp_bare(ln.when), "muted")
            marks_room = sum(px(8) + 0 for _m in ln.marks)
            what = fit_text(ln.what, widths[1] - marks_room - sum(px(110) for _m in ln.marks), theme.FONT, text)
            text.insert("end", "\t")
            text.insert("end", what, (f"open{n}",) + (("failed",) if ln.kind == "Failed" and False else ()))
            hand(f"open{n}", lambda line=ln: self.app.open_found(line.ref[0], line.ref[1], line.what))
            if what != ln.what:
                tips.add(f"open{n}", ln.what)
            for mark in ln.marks:
                text.insert("end", "  ")
                self.table_marks.append(Tag(text, mark, "warn", bold=True, small=True))
                row_marks.append(self.table_marks[-1])
                text.window_create("end", window=self.table_marks[-1], align="center")
            text.insert("end", "\t")
            if ln.account:
                whose = fit_text(ln.account, widths[2], theme.FONT, text)
                text.insert("end", whose, ("link", f"acc{n}"))
                hand(f"acc{n}", lambda line=ln: self.open("account", line.user_id, line.account))
                if whose != ln.account:
                    tips.add(f"acc{n}", ln.account)
            text.insert("end", "\t")
            if ln.ip:
                where = fit_text(ln.place, widths[3] - px(110), theme.FONT, text)
                text.insert("end", where + (" · " if ln.place else ""), ("muted", f"plc{n}"))
                if where != ln.place:
                    tips.add(f"plc{n}", ln.place)
                text.insert("end", ln.ip, ("link", f"ip{n}"))
                hand(f"ip{n}", lambda line=ln: self.open("address", line.ip, line.ip))
            text.insert("end", "\t")
            if ln.device and ln.device_id:
                text.insert("end", ln.device, ("link", f"dev{n}"))
                hand(f"dev{n}", lambda line=ln: self.open("device", line.device_id, line.device))
            elif ln.ip:
                text.insert("end", "no device", "muted")
            text.insert("end", "\n")
            text.tag_add(f"row{n}", begin, "end-1c")
            glow.add(n, "card", row_marks)
        rest = (self.results.counts["signin"] if self.results else 0)
        text.insert("end", f"{len(self.signins):,} lines for {rest:,} sign-ins · a line that stands for several says how many\n", "head")
        text.configure(state="disabled")

    # ------------------------------------------------------------------ opening
    def open(self, kind: str, key: Any, title: str = "", line: str = "") -> None:
        """A click on a hit: an alert or a sign-in opens in its own window; everything else has a page here."""
        if kind in ("alert", "signin", "change"):
            self.app.open_found(kind, key)
        elif kind == "search":   # a search from "Opened last": typed again
            self.text.set(str(key))
            self.entry.icursor("end")
            self.run()
        else:
            if self.results is not None and not self.path:
                self.app.remember_opened("search", self.results.text, self.results.text, f"a search · {self.results.total:,} results")
            self.app.remember_opened(kind, key, title, line)
            self.show_thing(kind, key, title)

    def show_account(self, user_id: str) -> None:
        self.show_thing("account", user_id)

    def show_thing(self, kind: str, key: Any, title: str = "", push: bool = True) -> None:
        """The page about an account, a device, an address, a network, a country or an application. The way that led
        to it - the search, then each page opened from the one before - is remembered: its back button goes one step
        back at a time."""
        from .account import AccountPage

        if push:
            self.path.append((kind, key, title or str(key)))
        if self._view is not None and self._view is not self._seen:   # one that was still being read
            self._view.top.destroy()
        # The page is built out of sight - under what is on screen now - and comes forward when it is complete: what
        # is on screen (the hits, or the page this one was opened from) stays until then, and nothing fills in
        # piece by piece.
        view = self._view = AccountPage(self.root, self.app, self.stack, str(key), on_back=self._back, on_search=self._search_for,
                                        background=self.background, kind=kind)
        view.top.grid(row=0, column=0, sticky="nsew")
        view.top.lower()

        def reveal() -> None:
            try:
                if self._view is not view or self._seen is view or not view.exists():
                    return
                before, self._seen = self._seen, view
                view.top.tkraise()
                view.top.focus_set()   # (keys no longer go to the search field underneath)
                if before is not None and before.exists():
                    before.top.destroy()
                self.stack.configure(cursor="")
            except tk.TclError:
                pass

        self.stack.configure(cursor="watch")
        view.when_ready(reveal)
        self.root.after(SHELL_MS, reveal)

    def _back(self) -> None:
        """One step back: the page this one was opened from, or the search."""
        self._back_to(len(self.path) - 2)

    def _back_to(self, depth: int) -> None:
        if depth < 0:
            self.focus()
            return
        self.path = self.path[:depth + 1]
        kind, key, title = self.path[-1]
        self.show_thing(kind, key, title, push=False)

    def _search_for(self, text: str) -> None:
        """A search asked for from another page. What was found the last time is taken away before the search page
        comes back: it shows the new search - never, for a moment, the old one."""
        self.text.set(text)
        self.entry.icursor("end")
        self.results = None
        self._clear()
        self.listing.pack_forget()
        self.plain.pack_forget()
        self.filters.pack_forget()
        self.age.configure(text="")
        self.run()          # now, not after the pause that waits for more typing
        self.focus()

    def account_view(self) -> Any:
        return self._view
