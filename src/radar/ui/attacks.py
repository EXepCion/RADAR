"""'Ongoing attacks' window: live view of password attacks, independent of (dismissed) reminders."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from .. import linkify
from . import icons, theme
from .freshness import DataAge
from .richtext import LinkHandler, StackedNotebook, StatusLine, attach_table_menu, scrolled_text, stable_label
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WINDOWS = [("Last 24 hours", 24), ("Last 72 hours", 72), ("Last 7 days", 168), ("Last 30 days", 720)]
ACCOUNT_COLS = ["Status", "Account", "Risk", "MFA", "Got past password", "Reminder", "Last attempt", "Last 24 h",
                "Attempts", "IPs", "Networks", "Countries", "Type", "First attempt", "Also targets"]
IP_COLS = ["Status", "IP address", "Pattern", "Network", "Network type", "Country", "Accounts", "Attempts",
           "Last attempt", "First attempt", "Targeted accounts"]
KNOWN_COLS = ["Status", "Account", "Risk", "Password reset since", "MFA", "Pattern", "Days", "Events", "Reminder",
              "Last event", "First event", "Networks", "Clients"]
SESSION_COLS = ["Status", "Account", "Kind", "Risk", "Reminder", "Last use from there", "First seen", "Suspicious side",
                "Session ID"]
WIDTHS = {"Account": 270, "Countries": 190, "Got past password": 150, "Also targets": 420, "Network": 280,
          "Targeted accounts": 420, "Last attempt": 115, "First attempt": 115, "Type": 115, "Reminder": 85,
          "Risk": 50, "IPs": 50, "Status": 60, "Last 24 h": 70, "IP address": 250, "Pattern": 170, "Days": 50,
          "Password reset since": 170, "MFA": 100,
          "Last event": 115, "First event": 115, "Networks": 260, "Clients": 300, "Kind": 110,
          "Last use from there": 130, "First seen": 115, "Suspicious side": 420, "Session ID": 270,
          "Network type": 110}
WIDTH_SCALE, WIDTH_PAD = 1.08, 16  # the widths above were set for the 9 pt font; tables now use 13 px + cell padding
STATUS_ROLE = {"Active": "error", "Quiet": "warn", "Ended": "muted"}  # palette roles (follow dark mode)
TAB_NAMES = ["Password guessing", "Password known", "Stolen sessions", "Attacking IPs"]
KEY_COLS = ("Account", "Session ID", "IP address")  # what identifies a row across a refresh
FIGURE_SPACE, FIGURE_DASH = "\u2007", "\u2012"  # exactly as wide as a digit
HINT = ("Dismissed reminders do not hide anything here. Double-click an account for the full assessment. Text with the "
        "link icon is a link: click it to open it, right-click a row or link for more options (Entra, IP reputation, copy).")
WIDTH, MARGIN = 1180, 20


def tab_label(name: str, count: int | None = None) -> str:
    """Tab title with its count, padded to the same width for 'loading' and any count up to 999 (tabs stay put)."""
    shown = FIGURE_DASH if count is None else str(count)
    return f"{name} ({shown})" + FIGURE_SPACE * max(0, 3 - len(shown))


def summary_text(label: str, guess: int, known: int, sessions: int, active: int, sources: int,
                 rotating: int) -> str:
    parts = [f"{guess} account(s) under password guessing", f"{known} with the password apparently known",
             f"{sessions} stolen/replayed session(s)"]
    return (f"In the {label}: " + ", ".join(parts) + f" - {active} still active (within the last 6 hours). "
            f"{sources} attacking IP(s): {sources - rotating} tried several accounts or several times"
            + (f", {rotating} tried an account only once or twice (rotating proxies - blocking single IPs does "
               "not stop that)" if rotating else "") + ".")


#: the longest summary there can be: the status line always has room for it
SUMMARY_TEMPLATE = summary_text("last 72 hours", 8888, 8888, 8888, 8888, 88888, 8888)


def _t(dt) -> str:
    return dt.astimezone().strftime("%Y-%m-%d %H:%M") if dt else ""


def account_values(a: Any, reminder: str) -> list[str]:
    past = a.past_password or "-"
    return [a.status, a.account, "" if a.score is None else str(a.score), a.mfa, "YES" if past.startswith("Yes") else past,
            reminder, _t(a.last), str(a.last_24h), str(a.attempts), str(a.ips), str(a.networks), a.countries, a.kind,
            _t(a.first), a.also_targets]


def ip_values(s: Any) -> list[str]:
    return [s.status, s.ip, s.pattern, s.network, s.network_type, s.country, str(s.accounts), str(s.attempts),
            _t(s.last), _t(s.first), s.targets]


def known_values(k: Any, reminder: str) -> list[str]:
    return [k.status, k.account, str(k.score), k.password_reset, k.mfa, k.kinds, str(k.days), str(k.events), reminder,
            _t(k.last), _t(k.first), k.networks, k.clients]


def session_values(s: Any, reminder: str) -> list[str]:
    return [s.status, s.account, s.kind, str(s.score), reminder, _t(s.last), _t(s.first), s.suspicious, s.session]


class AttacksWindow:
    def __init__(self, root: tk.Tk, app: "App"):
        self.app = app
        self.result = None
        top = self.top = theme.new_window(root)
        top.title("Ongoing attacks")
        top.geometry(f"{px(WIDTH)}x{min(px(720), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(720), px(380))
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(6)))
        header.pack(fill="x")
        ttk.Label(header, text="Ongoing attacks", style="Title.TLabel").pack(fill="x")
        inner = px(WIDTH - 2 * MARGIN)
        self.status = stable_label(header, SUMMARY_TEMPLATE, width=inner)  # fixed height: the tables do not move
        self.status.pack(fill="x", pady=(px(4), 0))

        bar = ttk.Frame(top, padding=(px(20), px(8), px(20), 0))
        bar.pack(fill="x")
        ttk.Label(bar, text="Period").pack(side="left")
        self.period = tk.StringVar(value=WINDOWS[1][0])
        box = ttk.Combobox(bar, textvariable=self.period, values=[w for w, _ in WINDOWS], state="readonly", width=16)
        box.pack(side="left", padx=(px(8), px(10)))
        box.bind("<<ComboboxSelected>>", lambda _e: self.load())
        # how old the data is + Refresh (reads sign-ins and accounts again); disabled while a refresh is running
        self.age = DataAge(bar, self.refresh)
        self.age.pack(side="left")
        self.refresh_btn = self.age.button

        footer = ttk.Frame(top, padding=(px(20), px(4), px(20), px(12)))
        footer.pack(side="bottom", fill="x")
        hint = stable_label(footer, HINT, width=inner)
        hint.pack(fill="x", pady=(0, px(6)))
        self.hint = StatusLine(hint, HINT)
        self.links = LinkHandler(app, top, self.hint)
        buttons = ttk.Frame(footer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Close", command=top.destroy).pack(side="right")
        self.open_btn = ttk.Button(buttons, text="Open assessment", command=self.open_selected, state="disabled")
        self.open_btn.pack(side="left")

        body = self.body = ttk.PanedWindow(top, orient="vertical")
        body.pack(fill="both", expand=True, padx=px(20), pady=(px(10), 0))
        self.tabs = StackedNotebook(body)  # tables are swapped, not re-mapped: no flash
        body.add(self.tabs, weight=3)
        detail = ttk.Frame(body, padding=(0, px(8), 0, 0))
        body.add(detail, weight=1)
        self.row_text = scrolled_text(detail, self.links, height=8)
        self.accounts_tree, self.sort_accounts = self._table(ACCOUNT_COLS)
        self.known_tree, self.sort_known = self._table(KNOWN_COLS)
        self.sessions_tree, self.sort_sessions = self._table(SESSION_COLS)
        self.ips_tree, self.sort_ips = self._table(IP_COLS)
        self._trees = [self.accounts_tree, self.known_tree, self.sessions_tree, self.ips_tree]
        self._sorts = [self.sort_accounts, self.sort_known, self.sort_sessions, self.sort_ips]
        for tree, name in zip(self._trees, TAB_NAMES):
            self.tabs.add_page(tree.master, tab_label(name))
        self._rows: dict[str, Any] = {}  # tree item id -> row (accounts, password known, sessions)
        for tree in (self.accounts_tree, self.known_tree, self.sessions_tree):
            tree.bind("<Double-1>", lambda e, t=tree: self.open_selected() if t.identify_row(e.y) else None)
        for tree in (self.accounts_tree, self.known_tree, self.sessions_tree, self.ips_tree):
            tree.bind("<<TreeviewSelect>>", lambda _e: self._selection_changed())
            attach_table_menu(tree, self.links, lambda iid, t=tree: self.row_values(t, iid))
        self.ips_tree.bind("<Double-1>", lambda e: self._lookup_ip() if self.ips_tree.identify_row(e.y) else None)
        self.tabs.bind("<<NotebookTabChanged>>", lambda _e: self._selection_changed())
        theme.style_window(top, prepare=self._fit_panes)  # the split is set before the window is visible
        top.lift()
        top.focus_force()

    def _fit_panes(self) -> None:
        """The selected row in full below the table: about 9 lines, the rest for the table (resizable)."""
        try:
            self.top.update_idletasks()
            total = self.body.winfo_height()
            if total > px(300):
                self.body.sashpos(0, total - px(170))
                self.top.update_idletasks()
            self.tabs.fit()
        except tk.TclError:
            pass

    @staticmethod
    def row_values(tree: ttk.Treeview, iid: str) -> dict[str, str] | None:
        """A table row as {column: text} (for the full-row view and the right-click menu)."""
        if not iid or not tree.exists(iid):
            return None
        return {c: str(v) for c, v in zip(tree["columns"], tree.item(iid, "values"))}

    def _selection_changed(self) -> None:
        self._update_button()
        tree = self._current_tree()
        sel = tree.selection()
        row = self.row_values(tree, sel[0]) if sel else None
        self.row_text.clear()
        if row:
            shown = [c for c in tree["columns"] if row.get(c, "").strip()]
            self.row_text.set_key_width(shown)
            for c in shown:
                self.row_text.write_field(c, row[c], row, name_tag="muted")

    def _lookup_ip(self) -> None:
        sel = self.ips_tree.selection()
        row = self.row_values(self.ips_tree, sel[0]) if sel else None
        entity = linkify.row_entity(row)
        if entity:
            self.links.default(entity, row)

    def _current_tree(self) -> ttk.Treeview:
        return self._trees[self.tabs.current()]

    def _update_button(self) -> None:
        self.open_btn.configure(state="normal" if self.selected_account() else "disabled")

    def _table(self, cols: list[str]) -> tuple[ttk.Treeview, Any]:
        frame = ttk.Frame(self.tabs.stack, padding=px(6))
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(WIDTHS.get(c, 70 if len(c) < 9 else 90) * WIDTH_SCALE + WIDTH_PAD), stretch=False,
                        anchor="w")
        for status, role in STATUS_ROLE.items():
            tree.tag_configure(status, foreground=theme.color(role))
        sort = make_sortable(tree, cols)
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree, sort

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

    # ------------------------------------------------------------ content
    def load(self, then_refresh: bool = False) -> None:
        """Show the overview from the data the app already has (no waiting for Entra); with ``then_refresh`` the
        data is refreshed in the background afterwards and the overview shown again."""
        if self.result is None:
            self.status.configure(text="Analysing the sign-in history...", foreground=theme.color("muted"))
        if then_refresh:
            self.age.set(busy=True, keep_time=True)
            self.app.load_attacks(self, self.hours, then_refresh=True)
        else:
            self.app.load_attacks(self, self.hours)

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
        selected = [self._selected_key(tree) for tree in self._trees]
        for tree in self._trees:
            tree.delete(*tree.get_children())
        self._rows.clear()
        sections = [(self.accounts_tree, "guessing", result.accounts, account_values),
                    (self.known_tree, "known", result.password_known, known_values),
                    (self.sessions_tree, "sessions", result.sessions, session_values)]
        for tree, section, rows, values in sections:
            for i, row in enumerate(rows):
                iid = f"{section}{i}"
                self._rows[iid] = row
                tree.insert("", "end", iid=iid, values=values(row, reminder(section, row)), tags=(row.status,))
        for i, s in enumerate(result.sources):
            self.ips_tree.insert("", "end", iid=f"s{i}", values=ip_values(s), tags=(s.status,))
        label = next((w for w, h in WINDOWS if h == result.hours), f"{result.hours:g} h").lower()
        guess, known, sess = result.accounts, result.password_known, result.sessions
        active = result.active_all
        text = summary_text(label, len(guess), len(known), len(sess), active, len(result.sources),
                            result.single_attempt_ips)
        self.status.configure(text=text, foreground=theme.color("error" if active else "muted"))
        for i, n in enumerate((len(guess), len(known), len(sess), len(result.sources))):
            self.tabs.tab(i, text=tab_label(TAB_NAMES[i], n))
        # a refresh keeps what the user was looking at: sort order and selected row
        for tree, sort, key in zip(self._trees, self._sorts, selected):
            sort.reapply()
            self._select_key(tree, key)
        self._selection_changed()

    def _selected_key(self, tree: ttk.Treeview) -> tuple | None:
        sel = tree.selection()
        row = self.row_values(tree, sel[0]) if sel else None
        return tuple(row.get(c, "") for c in KEY_COLS) if row else None

    def _select_key(self, tree: ttk.Treeview, key: tuple | None) -> None:
        if key is None:
            return
        for iid in tree.get_children(""):
            row = self.row_values(tree, iid) or {}
            if tuple(row.get(c, "") for c in KEY_COLS) == key:
                tree.selection_set(iid)
                tree.focus(iid)
                tree.see(iid)
                return

    def show_error(self, message: str) -> None:
        if self.exists():
            self.age.set(busy=False, error=message, keep_time=True)
            self.status.configure(text=f"Could not analyse the history: {message}", foreground=theme.color("error"))

    def selected_account(self) -> Any:
        sel = self._current_tree().selection()
        return self._rows.get(sel[0]) if sel else None

    def open_selected(self) -> None:
        a = self.selected_account()
        if a:
            self.app.open_attack_details(a)
