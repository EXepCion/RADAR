"""'Ongoing attacks' page: what is being tried against the accounts right now, from the sign-in history - whatever
was dismissed among the reminders.

Laid out like the Incidents page, for the same questions in the same order:

* What kind, and how much?   The filter under the title: the four kinds of attack with their counts, the most
                             dangerous first (a password that is known, a stolen session, guessing, the addresses
                             it all comes from). It opens on the first kind there is something of.
* Which one first?           The list on the left: is it still going on, whom or which address, the two or three
                             facts that tell how bad, when it last happened.
* What exactly?              On the right everything about the selected row - framed, with an arrowhead that points
                             at the row it belongs to. Accounts and addresses are links.

Everything has its fixed place: data that arrives, or another row, changes the texts, never the layout.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from PIL import ImageTk

from .. import linkify, timefmt
from . import icons, theme
from .cardtable import CardTable, friendly_time
from .freshness import DataAge
from .parts import Hint, Pointer, Segments, card, on_card
from .richtext import LinkHandler, StatusLine, attach_table_menu, scrolled_text, stable_label
from .rounded import Rounded
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WINDOWS = [("Last 24 hours", 24), ("Last 72 hours", 72), ("Last 7 days", 168), ("Last 30 days", 720)]
# every fact of a row, in the order the panel on the right shows them
ACCOUNT_COLS = ["Status", "Account", "Risk", "MFA", "Got past password", "Reminder", "Last attempt", "Last 24 h",
                "Attempts", "IPs", "Networks", "Countries", "Type", "First attempt", "Also targets"]
IP_COLS = ["Status", "IP address", "Pattern", "Network", "Network type", "Country", "Accounts", "Attempts",
           "Last attempt", "First attempt", "Targeted accounts"]
KNOWN_COLS = ["Status", "Account", "Risk", "Password reset since", "MFA", "Pattern", "Days", "Events", "Reminder",
              "Last event", "First event", "Networks", "Clients"]
SESSION_COLS = ["Status", "Account", "Kind", "Risk", "Reminder", "Last use from there", "First seen", "Suspicious side",
                "Session ID"]
TIME_COLS = {"Last attempt", "First attempt", "Last event", "First event", "Last use from there", "First seen"}
KEY_COLS = ("Account", "Session ID", "IP address")  # what identifies a row across a refresh
# the kinds of attack, the most dangerous first: (key, name on the filter, the facts of a row, its name, its time)
SECTIONS = [("known", "Password known", KNOWN_COLS, "Account", "Last event"),
            ("sessions", "Stolen sessions", SESSION_COLS, "Account", "Last use from there"),
            ("guessing", "Password guessing", ACCOUNT_COLS, "Account", "Last attempt"),
            ("ips", "Attacking IPs", IP_COLS, "IP address", "Last attempt")]
SECTION_KEYS = [s[0] for s in SECTIONS]
LIST_COLS = ["Status", "Who", "Last"]
LIST_WIDTHS = {"Status": 96, "Who": 220, "Last": 104}
STATUS_PILL = {"Active": ("sev_high_bg", "sev_high_fg"), "Quiet": ("sev_medium_bg", "sev_medium_fg"),
               "Ended": ("sev_info_bg", "sev_info_fg")}  # still going on stands out; what is over steps back
HINT = ""  # (the line at the bottom says what happened: a look-up, an error)
WIDTH, MARGIN, LIST = 1180, 20, 460
DOT = " · "


def summary_text(sources: int, rotating: int) -> str:
    """What the list of addresses does not say by itself: how many of them tried only once or twice - rotating
    proxies, which blocking single addresses does not stop. (Shown with that list; '' when there is nothing to say.)"""
    if not rotating:
        return ""
    return f"{rotating} of {sources} tried only once or twice: rotating proxies, blocking them one by one does not help."


SUMMARY_TEMPLATE = "w" * 60  # one line: it always has its place


def _t(dt) -> str:
    return timefmt.sortable(dt) if dt else ""


def ago(value: str) -> str:
    """How long ago a time of a table was (timefmt.sortable): 'Now', '3 hours ago', '2 days ago'."""
    try:
        return theme.humanize(datetime.strptime(str(value)[:16], timefmt.SORTABLE).astimezone())
    except (TypeError, ValueError):
        return value


def clamp_line(text: str, label: tk.Misc) -> str:
    """A text on the one line its label has (what does not fit ends in an ellipsis)."""
    import tkinter.font as tkfont

    try:
        width, measure = max(px(120), label.winfo_width()), tkfont.nametofont(theme.FONT, root=label).measure
    except tk.TclError:
        return text
    if measure(text) <= width:
        return text
    while text and measure(text + timefmt.ELLIPSIS) > width:
        text = text[:-1]
    return timefmt.keep_whole(text.rstrip() + timefmt.ELLIPSIS)


def account_values(a: Any, reminder: str) -> list[str]:
    past = a.past_password or "-"
    return [a.status, a.account, "" if a.score is None else str(a.score), a.mfa, "YES" if past.startswith("Yes") else past,
            reminder, _t(a.last), str(a.last_24h), str(a.attempts), str(a.ips), str(a.networks), a.countries, a.kind,
            _t(a.first), a.also_targets]


def ip_values(s: Any, _reminder: str = "") -> list[str]:
    return [s.status, s.ip, s.pattern, s.network, s.network_type, s.country, str(s.accounts), str(s.attempts),
            _t(s.last), _t(s.first), s.targets]


def known_values(k: Any, reminder: str) -> list[str]:
    return [k.status, k.account, str(k.score), k.password_reset, k.mfa, k.kinds, str(k.days), str(k.events), reminder,
            _t(k.last), _t(k.first), k.networks, k.clients]


def session_values(s: Any, reminder: str) -> list[str]:
    return [s.status, s.account, s.kind, str(s.score), reminder, _t(s.last), _t(s.first), s.suspicious, s.session]


VALUES: dict[str, Callable[[Any, str], list[str]]] = {"known": known_values, "sessions": session_values,
                                                       "guessing": account_values, "ips": ip_values}


def note(section: str, row: dict[str, str]) -> str:
    """The small line under a row of the list: the two or three facts that tell how bad it is."""
    if section == "guessing":
        parts = ["Got past the password" if row["Got past password"] == "YES" else "",
                 f"{row['Attempts']} attempts", f"{row['IPs']} IPs", row["Countries"]]
    elif section == "known":
        parts = [row["Pattern"], f"{row['Events']} events in {row['Days']} day(s)"]
    elif section == "sessions":
        parts = [row["Kind"], row["Suspicious side"]]
    else:
        parts = [f"{row['Accounts']} account(s)", f"{row['Attempts']} attempts", row["Network"] or row["Country"]]
    return DOT.join(p for p in parts if p and p != "-")


class AttacksWindow:
    def __init__(self, root: tk.Tk, app: "App", parent: tk.Misc | None = None, on_close=None):
        self.app = app
        self.result = None
        top = self.top = theme.new_window(root, parent=parent, on_close=on_close)
        top.title("Ongoing attacks")
        top.geometry(f"{theme.fit_width(top, px(WIDTH))}x{min(px(720), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(theme.fit_width(top, px(1000)), px(520))
        top.bind("<Escape>", lambda _e: theme.close(top))
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)
        inner = px(WIDTH - 2 * MARGIN)
        self._chosen_by_user = False
        self._failed = False  # the line beside the filter shows why the analysis failed (until it works again)
        self._full: dict[str, dict[str, str]] = {}  # row of a list -> all its facts {name: text}
        self._rows: dict[str, Any] = {}             # row of a list -> the object behind it (accounts, sessions ...)

        header = ttk.Frame(top, padding=(px(MARGIN), px(16), px(MARGIN), px(4)))
        header.pack(fill="x")
        # on the right: how old the data is + Refresh (reads sign-ins and accounts again), and the period looked at
        tools = ttk.Frame(header)
        tools.pack(side="right", anchor="n", pady=(px(6), 0))
        self.period = tk.StringVar(value=WINDOWS[1][0])
        box = ttk.Combobox(tools, textvariable=self.period, values=[w for w, _ in WINDOWS], state="readonly", width=16)
        box.pack(side="right", padx=(px(10), 0))
        box.bind("<<ComboboxSelected>>", lambda _e: self.load())
        self.age = DataAge(tools, self.refresh, button_side="right")
        self.age.pack(side="right")
        self.refresh_btn = self.age.button
        ttk.Label(header, text="Ongoing attacks", style="PageTitle.TLabel").pack(fill="x")

        # the kinds of attack with their counts (the most dangerous first), and beside them where it all comes from
        under = ttk.Frame(top, padding=(px(MARGIN), px(6), px(MARGIN), 0))
        under.pack(fill="x")
        self.filter = Segments(under, [(key, name) for key, name, *_rest in SECTIONS], self._filter_chosen, width=19)
        self.filter.pack(side="left")
        self.status = stable_label(under, SUMMARY_TEMPLATE, width=inner - px(4 * 190 + 30), max_lines=1)
        self._status_whole = ""   # (the line is one line long: what does not fit can be read by pointing at it)
        Hint((self.status,), lambda: self._status_whole if str(self.status.cget("text")) != self._status_whole else "", wrap=px(520))
        self.status.pack(side="left", fill="x", expand=True, padx=(px(14), 0))

        footer = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), px(12)))
        footer.pack(side="bottom", fill="x")
        if not theme.is_panel(top):
            ttk.Button(footer, text="Close", command=top.destroy).pack(side="right", padx=(px(8), 0))
        self.open_btn = ttk.Button(footer, text="Open assessment", style="Accent.TButton", command=self.open_selected,
                                   state="disabled", width=18)
        self.open_btn.pack(side="right", padx=(px(12), 0))
        hint = stable_label(footer, "w" * 60, width=inner - px(220), max_lines=1)
        hint.pack(fill="x")
        self.hint = StatusLine(hint, HINT)
        self.links = LinkHandler(app, top, self.hint)

        body = self.body = ttk.Frame(top, padding=(px(MARGIN), px(10), px(MARGIN), 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, minsize=px(LIST))
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)

        # ---- which one first: a list for each kind, one of them shown (they are swapped, not rebuilt: no flash)
        self.lists: dict[str, CardTable] = {}
        self._sorts: dict[str, Any] = {}
        for key, _name, _cols, who, _when in SECTIONS:
            tree = self.lists[key] = CardTable(body, LIST_COLS, selectmode="browse", row_height=54)
            tree.heading("Status", text="Status", anchor="w")
            tree.heading("Who", text=who, anchor="w")
            tree.heading("Last", text="Last seen", anchor="w")
            for c in LIST_COLS:
                tree.column(c, width=px(LIST_WIDTHS[c]), stretch=c == "Who", anchor="w")
            tree.pill("Status", STATUS_PILL.get)
            tree.note_of("Who", lambda iid, k=key: note(k, self._full[iid]) if iid in self._full else "")
            tree.show_as("Last", ago)
            self._sorts[key] = make_sortable(tree, LIST_COLS, labels={"Who": who, "Last": "Last seen"})
            tree.grid(row=0, column=0, sticky="nsew")
            tree.bind("<<TreeviewSelect>>", lambda _e: self._selection_changed())
            tree.bind("<Double-1>", lambda e, t=tree: self.open_selected() if t.identify_row(e.y) else None)
            tree.on_drawn(self._point)
            attach_table_menu(tree, self.links, lambda iid: self._full.get(iid))
        self.known_tree, self.sessions_tree = self.lists["known"], self.lists["sessions"]
        self.accounts_tree, self.ips_tree = self.lists["guessing"], self.lists["ips"]
        self._trees = [self.lists[k] for k in SECTION_KEYS]

        # in the place of the list when the kind shown has nothing: said plainly (nothing is good news here)
        empty = self.empty = card(body)
        empty.grid(row=0, column=0, sticky="nsew")
        middle = on_card(empty)
        middle.place(relx=0.5, rely=0.4, anchor="center")
        white = theme.color("card")
        self._check = theme.icon(empty, "check", "neg", 28)
        self.empty_icon = tk.Label(middle, background=white, bd=0, highlightthickness=0)
        self.empty_icon.pack(pady=(0, px(8)))
        self.empty_title = tk.Label(middle, font=theme.FONT_BOLD, background=white, foreground=theme.color("text"), bd=0)
        self.empty_title.pack()

        # ---- what exactly: everything about the selected row, framed, an arrowhead pointing at the row
        self.pointer = Pointer(body)
        self.pointer.grid(row=0, column=1, sticky="ns", padx=(px(3), 0))
        frame = self.frame = Rounded(body, fill="window", edge="window")
        frame.grid(row=0, column=2, sticky="nsew")
        holder = self._right = tk.Frame(frame, background=theme.color("window"), bd=0, highlightthickness=0)
        holder.pack(fill="both", expand=True, padx=px(8), pady=px(8))
        self.row_text = scrolled_text(holder, self.links, height=8, width=10)
        self._pad = self.row_text.card_blocks(padding=18)
        # the values start at one place, whatever the row and the kind: wide enough for the longest name there is
        self.row_text.set_key_width([c for _k, _n, cols, _w, _t in SECTIONS for c in cols], indent=self._pad)
        body.bind("<Configure>", lambda _e=None: self._point(), add="+")

        self.filter.choose("guessing", tell=False)
        self._show_list()
        theme.style_window(top)
        top.lift()
        top.focus_force()

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

    @property
    def hours(self) -> int:
        return dict(WINDOWS).get(self.period.get(), 72)

    @property
    def section(self) -> str:
        return self.filter.chosen or "guessing"

    def _current_tree(self) -> CardTable:
        return self.lists[self.section]

    def show_filter(self, key: str) -> None:
        """Show one kind of attack (as a click on the filter does)."""
        self.filter.choose(key)

    def _filter_chosen(self, _key: str) -> None:
        self._chosen_by_user = True
        self._show_list()

    def _show_list(self) -> None:
        """The list of the chosen kind in front - or, when it has nothing, that this is so."""
        tree = self._current_tree()
        name = next(n for k, n, *_r in SECTIONS if k == self.section)
        if tree.get_children(""):
            tk.Misc.lift(tree.outer)
        else:
            waiting = self.result is None
            self.empty_title.configure(text="Reading the sign-in history..." if waiting else
                                       f"{name}: nothing in the {self.period.get().lower()}")
            self.empty_icon.configure(image="" if waiting else (self._check or ""))
            tk.Misc.lift(self.empty.outer)
        if self.result is not None and not self._failed:
            note_ = summary_text(len(self.result.sources), self.result.single_attempt_ips) if self.section == "ips" else ""
            self._status_whole = note_
            self.status.configure(text=clamp_line(note_, self.status), foreground=theme.color("muted"))
        self._selection_changed()

    @staticmethod
    def row_values(tree: Any, iid: str) -> dict[str, str] | None:
        """What a row of a list shows, as {column: text}."""
        if not iid or not tree.exists(iid):
            return None
        return {c: str(v) for c, v in zip(tree["columns"], tree.item(iid, "values"))}

    def facts(self, iid: str) -> dict[str, str] | None:
        """Every fact of a row {name: text} (the panel on the right, the right-click menu)."""
        return self._full.get(iid)

    def _selection_changed(self) -> None:
        tree = self._current_tree()
        sel = [i for i in tree.selection() if i in self._full]
        row = self._full[sel[0]] if sel else None
        self.row_text.clear()
        if row:
            key = next(w for k, _n, _c, w, _t2 in SECTIONS if k == self.section)
            shown = [c for c in row if c != key and row[c].strip() not in ("", "-", "?")]  # (what is not known is left out)
            self.row_text.begin_card(first=True)
            self.row_text.write_value(row[key] + "\n", key, row, tags=("card", "card_heading"))
            for c in shown:
                text = friendly_time(row[c]) if c in TIME_COLS else row[c]
                self.row_text.write_field(c, text, row, name_tag="muted", tags=("card",))
            self.row_text.end_card()
        self._update_button()
        self._point()

    def _point(self) -> None:
        """The arrowhead at the height of the selected row; the panel is framed when it is some row's, else empty."""
        try:
            tree = self._current_tree()
            sel = [i for i in tree.selection() if i in self._full]
            self.pointer.at(tree.row_middle(sel[0]) if sel else None)
            self.frame.set_edge("link" if sel else "window")
        except tk.TclError:
            pass

    def _update_button(self) -> None:
        """The one thing to do with the selected row: an account's assessment, or looking an address up."""
        on_ip = self.section == "ips"
        sel = [i for i in self._current_tree().selection() if i in self._full]
        self.open_btn.configure(text="Look up address" if on_ip else "Open assessment",
                                state="normal" if sel else "disabled")

    # ------------------------------------------------------------ content
    def load(self, then_refresh: bool = False) -> None:
        """Show the overview from the data the app already has (no waiting for Entra); with ``then_refresh`` the
        data is refreshed in the background afterwards and the overview shown again."""
        if self.result is None:
            self.status.configure(text="", foreground=theme.color("muted"))
            self._show_list()
        if then_refresh:
            self.age.set(busy=True, keep_time=True)
            self.app.load_attacks(self, self.hours, then_refresh=True)
        else:
            self.app.load_attacks(self, self.hours)

    def _most_dangerous(self) -> str:
        """The first kind, most dangerous first, there is something of ('guessing' when there is nothing at all)."""
        r = self.result
        data = {"known": r.password_known, "sessions": r.sessions, "guessing": r.accounts, "ips": r.sources} if r else {}
        return next((k for k in SECTION_KEYS if data.get(k)), "guessing")

    def opened(self) -> None:
        """The page comes into view again: it starts on the most dangerous kind there is something of. (The kind
        the user chose stays while the page is in view - through every refresh - and no longer than that.)"""
        self._chosen_by_user = False
        if self.result is not None and self.exists():
            self.filter.choose(self._most_dangerous(), tell=False)
            self._show_list()

    def refresh(self) -> None:
        """Read sign-ins and accounts from Entra again, then show the overview (the Refresh button)."""
        if self.age.busy:
            return
        self.age.set(busy=True, keep_time=True)
        self.app.load_attacks(self, self.hours, refresh=True)

    def show(self, result: Any, reminder: Any, as_of: Any = None, busy: bool = False, error: str = "") -> None:
        """``reminder(section, row) -> str`` gives the reminder state ('open', 'dismissed', ...) of a row.
        ``as_of``: moment the data is from; ``busy``: a refresh is still running; ``error``: why it failed."""
        if not self.exists():
            return
        self.result = result
        self.age.set(as_of or getattr(result, "generated", None), busy=busy, error=error)
        selected = {key: self._selected_key(key) for key in SECTION_KEYS}
        for tree in self._trees:
            tree.delete(*tree.get_children())
        self._rows.clear()
        self._full.clear()
        data = {"known": result.password_known, "sessions": result.sessions, "guessing": result.accounts, "ips": result.sources}
        for key, name, cols, who, when in SECTIONS:
            tree = self.lists[key]
            for i, row in enumerate(data[key]):
                iid = f"{key}{i}"
                values = dict(zip(cols, VALUES[key](row, "" if key == "ips" else reminder(key, row))))
                self._rows[iid], self._full[iid] = row, values
                tree.insert("", "end", iid=iid, values=[values["Status"], values[who], values[when]], tags=(row.status,))
            # the figure: what is going on NOW (the list also has what went quiet or ended, by its Status). The
            # figures of the three kinds about accounts add up to the one on the navigation.
            self.filter.set_text(key, f"{name} {sum(1 for row in data[key] if getattr(row, 'status', '') == 'Active')}")
        self._failed = False
        if not self._chosen_by_user:  # it opens on the most dangerous kind there is something of
            self.filter.choose(self._most_dangerous(), tell=False)
        # a refresh keeps what the user was looking at: sort order and selected row
        for key in SECTION_KEYS:
            self._sorts[key].reapply()
            self._select_key(key, selected[key])
        self._show_list()

    def _selected_key(self, section: str) -> tuple | None:
        sel = [i for i in self.lists[section].selection() if i in self._full]
        row = self._full[sel[0]] if sel else None
        return tuple(row.get(c, "") for c in KEY_COLS) if row else None

    def _select_key(self, section: str, key: tuple | None) -> None:
        tree = self.lists[section]
        rows = tree.get_children("")
        match = next((iid for iid in rows if key is not None and
                      tuple(self._full[iid].get(c, "") for c in KEY_COLS) == key), None)
        chosen = match or (rows[0] if rows else None)  # (something is always selected: the panel is never blank)
        if chosen:
            tree.selection_set(chosen)
            tree.focus(chosen)
            tree.see(chosen)

    def show_error(self, message: str) -> None:
        if self.exists():
            self.age.set(busy=False, error=message, keep_time=True)
            self._failed = True
            self._status_whole = f"Could not analyse the history: {message}"
            self.status.configure(text=clamp_line(self._status_whole, self.status),
                                  foreground=theme.color("error"))

    # ---------------------------------------------------------------- actions
    def selected_account(self) -> Any:
        """The account, known password or session behind the selected row (None on the list of addresses)."""
        if self.section == "ips":
            return None
        sel = self._current_tree().selection()
        return self._rows.get(sel[0]) if sel else None

    def _lookup_ip(self) -> None:
        sel = [i for i in self.ips_tree.selection() if i in self._full]
        row = self._full[sel[0]] if sel else None
        entity = linkify.row_entity(row)
        if entity:
            self.links.default(entity, row)

    def open_selected(self) -> None:
        if self.section == "ips":
            self._lookup_ip()
            return
        a = self.selected_account()
        if a:
            self.app.open_attack_details(a)
