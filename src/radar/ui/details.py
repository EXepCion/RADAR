"""Details ("Open Item") window in the Windows 11 style: header with severity badge, command bar, cards for what
happened / details / recommendation, risk assessment, quick links into Entra, and the evidence table.

Everything wraps and scrolls instead of being cut off; users, IPs, apps, groups, roles, permissions and log IDs
are links (click = most useful action, right-click = all actions + copy); the selected evidence row is shown
in full below the table, and double-clicking it opens the original log entry / the referenced alert.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Callable

from PIL import ImageTk

from .. import linkify
from ..alerts import Alert
from ..linkify import Entity
from . import icons, theme
from .richtext import (LinkHandler, StatusLine, attach_table_menu, card, card_label, fit_columns, pill,
                       stable_label,
                       scrolled_text)
from .tables import make_sortable
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

ENTRA_SIGNIN_LOGS = linkify.SIGNIN_LOGS_URL
DEFAULT_HINT = ("Text with the link icon is a link: click it to open it, right-click for more options. Text can be "
                "selected and copied.")
WIDTH, HEIGHT = 1120, 1040
WIDE_FROM = 1700      # from this window width the evidence stands beside the cards instead of below them
BODY_MARGIN = 20      # px left and right of the cards / evidence area
MIN_EVIDENCE = 260    # px the evidence keeps when the cards need more room than there is


def portal_hint(request_id: str, tab: str, date: str) -> str:
    return (f"Request ID {request_id} copied. In Entra choose the '{tab}' tab > Add filters > Request ID > paste, and "
            f"include {date} in the date range. Or double-click the row to see the full record here.")


LONGEST_HINT = portal_hint("8" * 36, "non-interactive", "8888-88-88")
#: entities offered in the "Open in Entra" card, with what their link says
QUICK_LINKS = {
    ("app", "app"): "enterprise app", ("app", "app_credentials"): "certificates & secrets",
    ("user", "user"): "user in Entra", ("group", "group"): "group", ("policy", "policy"): "Conditional Access policy",
    ("device", "device"): "device", ("partner", "xtenant"): "cross-tenant settings",
    ("tenant", "tenant"): "which organisation?", ("role", "role_docs"): "what the role can do",
    ("ip", "abuseipdb"): "IP reputation (AbuseIPDB)",
}
MAX_QUICK_LINKS, MAX_QUICK_USERS = 5, 2
#: apps only from the fields naming the acting / changed app - not sign-in targets (Microsoft's own apps)
QUICK_APP_FIELDS = {"initiated by", "app"}
#: context fields: what they name is not what the alert is about (e.g. the user's own IPs under "Not counted")
QUICK_SKIP_FIELDS = {"not counted", "account context", "re-assessed", "related signals", "correlated with",
                     "people on that ip then"}


def visible_columns(evidence: list[dict[str, str]]) -> list[str]:
    return [c for c in dict.fromkeys(k for row in evidence for k in row) if not c.startswith("_")]


def alert_as_text(alert: Alert, origin: str = "") -> str:
    lines = [alert.title, f"Severity: {alert.severity.label}" + (f" (risk score {alert.score}/100)" if alert.score else ""),
             f"Source: {origin}", f"Occurred: {theme.local_time(alert.occurred_at)}", "", alert.summary, ""]
    lines += [f"{k}: {v}" for k, v in alert.fields.items()]
    if alert.factors:
        lines += ["", "Risk assessment:"] + [f"  {p:+d}  {t}" for p, t in alert.factors]
    if alert.recommendation:
        lines += ["", f"Recommended action: {alert.recommendation}"]
    if alert.evidence:
        cols = visible_columns(alert.evidence)
        lines += ["", "Evidence:", "\t".join(cols)]
        lines += ["\t".join(str(row.get(c, "")) for c in cols) for row in alert.evidence]
    return "\n".join(lines)


def quick_links(alert: Alert) -> list[tuple[Entity, str, str]]:
    """(entity, action, link text) for the main objects named in the fields - the 'Open in Entra' card."""
    out: list[tuple[Entity, str, str]] = []
    seen: set[tuple[str, str]] = set()
    users = 0
    for field, value in alert.fields.items():
        if field.strip().lower() in QUICK_SKIP_FIELDS:
            continue
        for e in linkify.find_entities(str(value), field):
            key = (e.kind, e.value.lower())
            if key in seen or (e.kind == "app" and field.strip().lower() not in QUICK_APP_FIELDS):
                continue
            seen.add(key)
            if e.kind == "user":
                users += 1
                if users > MAX_QUICK_USERS:
                    continue
            for (kind, action), what in QUICK_LINKS.items():
                if kind == e.kind and len(out) < MAX_QUICK_LINKS:
                    out.append((e, action, f"{e.short} – {what}"))
    return out


class DetailsWindow:
    def __init__(self, root: tk.Tk, app: "App", alert: Alert, on_dismiss: Callable[[Alert], None],
                 on_snooze: Callable[[Alert], None] | None = None, snooze_label: str = "",
                 on_refresh: Callable[[], None] | None = None):
        """``on_refresh``: the window shows live data - it gets the data-age label and the Refresh button
        (``self.age``, a freshness.DataAge)."""
        self.app = app
        self._on_refresh = on_refresh
        self.age = None
        self.alert = alert
        self._on_dismiss = on_dismiss
        self._on_snooze = on_snooze
        self._snooze_label = snooze_label
        self.tree: ttk.Treeview | None = None
        self.body: ttk.Frame | None = None  # holds the cards and the evidence (only with evidence)
        self._paneds: dict[bool, ttk.PanedWindow] = {}  # wide? -> splitter (side by side / one above the other)
        self._wide: bool | None = None
        self._fitted: tuple[int, int] = (0, 0)
        self._top_size: tuple[int, int] = (0, 0)
        self._tall_pos = 0  # last split of the cards-above-evidence arrangement
        self._tall_detail = 0  # ... and the height of the row detail in it
        self._fit_job: str | None = None
        self.row_text = None
        self.side: ttk.Frame | None = None
        self._rows: dict[str, dict[str, str]] = {}
        top = self.top = theme.new_window(root)
        top.title(alert.title)
        height = min(px(HEIGHT), int(top.winfo_screenheight() * 0.9))
        top.geometry(f"{px(WIDTH)}x{height}")
        top.minsize(px(680), px(480))
        self._icon = ImageTk.PhotoImage(icons.badge(alert.severity, px(44)), master=root)
        self._small = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._small)
        top.bind("<Escape>", lambda _e: top.destroy())
        self._build()
        theme.style_window(top, prepare=self._fit_panes)  # panes are split before the window is visible
        top.attributes("-topmost", True)
        top.lift()
        top.focus_force()
        top.after(400, lambda: top.attributes("-topmost", False))
        top.after(120, self._animate_risk)

    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        self.top.deiconify()
        self.top.lift()
        self.top.focus_force()

    # --------------------------------------------------------------- build
    def _build(self) -> None:
        a, top = self.alert, self.top
        origin = self.app.describe_origin(a)

        header = ttk.Frame(top, padding=(px(24), px(16), px(24), px(6)))
        header.pack(fill="x")
        tk.Label(header, image=self._icon, background=theme.color("window"), bd=0).grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(0, px(16)), pady=(px(2), 0))
        title = ttk.Label(header, text=a.title, style="Title.TLabel", justify="left", wraplength=px(WIDTH - 110))
        title.grid(row=0, column=1, sticky="ew")
        meta = ttk.Frame(header)
        meta.grid(row=1, column=1, sticky="ew", pady=(px(6), 0))
        bg_role, fg_role = theme.severity_roles(a.severity)
        score = f" · risk {a.score} / 100" if a.factors else ""
        pill(meta, f"{a.severity.label}{score}", bg_role, fg_role).pack(side="left")
        ttk.Label(meta, text=f"{origin}   ·   {self._when()}", style="Muted.TLabel").pack(side="left", padx=(px(10), 0))
        header.columnconfigure(1, weight=1)
        header.bind("<Configure>", lambda e: title.configure(wraplength=max(px(200), e.width - px(110))))

        footer = ttk.Frame(top, padding=(px(24), px(2), px(24), px(10)))
        footer.pack(side="bottom", fill="x")
        hint = stable_label(footer, LONGEST_HINT, width=px(WIDTH - 48))  # fixed height: hovering moves nothing
        hint.pack(fill="x")
        self.status = StatusLine(hint, DEFAULT_HINT)
        self.hint = hint
        self.links = LinkHandler(self.app, top, self.status, alert=a)

        bar = ttk.Frame(top, padding=(px(18), px(6), px(20), px(10)))
        bar.pack(fill="x")

        def button(text: str, command: Callable[[], None], icon: str, role: str = "text", style: str = "TButton",
                   side: str = "right") -> None:
            image = theme.icon(top, icon, role)
            b = ttk.Button(bar, text=f" {text}" if image else text, command=command, style=style,
                           **({"image": image, "compound": "left"} if image else {}))
            b.pack(side=side, padx=(0, px(4)) if side == "left" else (px(6), 0))

        for label, url in a.links:
            cmd = self._open_signin_logs if url == ENTRA_SIGNIN_LOGS else (lambda u=url: self.app.open_link(u))
            button(label, cmd, "open", "link", "Toolbutton", "left")
        if a.status == "active":
            button("Dismiss", self._dismiss, "check", "on_accent", "Accent.TButton")
            if self._on_snooze:
                button(f"Snooze {self._snooze_label}".strip(), self._snooze, "clock")
        button("Copy details", self._copy, "copy")
        if self._on_refresh:
            from .freshness import DataAge

            self.age = DataAge(bar, self._on_refresh, button_side="right")
            self.age.pack(side="right", padx=(px(6), 0))

        if a.evidence:
            # Two splitters, one in use: cards above the evidence, or - in a wide window - beside it. The two panes
            # are children of ``body`` (not of a splitter) so that they can change over.
            body = self.body = ttk.Frame(top)
            body.pack(fill="both", expand=True, padx=px(BODY_MARGIN), pady=(0, px(6)))
            self._paneds = {False: ttk.PanedWindow(body, orient="vertical"),
                            True: ttk.PanedWindow(body, orient="horizontal")}
            info = self._info_pane = ttk.Frame(body)
            self._evidence_pane = self._evidence(body)
            self._arrange(False)
            top.bind("<Configure>", self._top_resized, add="+")
        else:
            info = ttk.Frame(top)
            info.pack(fill="both", expand=True, padx=px(20), pady=(0, px(6)))
        self._info(info)

    def _info(self, parent: ttk.Frame) -> None:
        a = self.alert
        quick = quick_links(a)
        if a.factors or quick:
            self._side_column(parent, quick)
        box = ttk.Frame(parent)
        box.pack(side="left", fill="both", expand=True)
        # one scrolling text drawn as separate cards (What happened / Details / Recommended action)
        text = self.info = scrolled_text(box, self.links, height=8)
        pad = text.card_blocks(padding=20)
        rows = list(a.fields.items())
        text.set_key_width([k for k, _ in rows] or ["Details"], cap=280, indent=pad)
        first = True
        if a.summary:
            text.begin_card("What happened", first=True)
            text.write_value(a.summary, tags=("card",))
            text.write("\n", "card")
            text.end_card()
            first = False
        if rows:
            text.begin_card("Details", first=first)
            for k, v in rows:
                text.write_field(k, v, name_tag="muted", tags=("card",))
            text.end_card()
            first = False
        if a.recommendation:
            text.begin_card("Recommended action", first=first)
            text.write_value(a.recommendation, tags=("card",))
            text.write("\n", "card")
            text.end_card()

    def _when(self) -> str:
        """'occurred Tue 10.11.2026 11:02 · detected 11:58 · updated 12:40' (dates only where they differ)."""
        a = self.alert
        occurred = a.occurred_at or a.first_seen

        def short(dt) -> str:
            same_day = dt.astimezone().date() == occurred.astimezone().date()
            return theme.local_time(dt, "%H:%M" if same_day else "%d.%m. %H:%M")

        parts = [f"occurred {theme.local_time(occurred, '%a %d.%m.%Y %H:%M')}", f"detected {short(a.first_seen)}"]
        if (a.last_seen - a.first_seen).total_seconds() >= 60:
            parts.append(f"updated {short(a.last_seen)}")
        return "   ·   ".join(parts)

    def _side_column(self, parent: ttk.Frame, quick: list[tuple[Entity, str, str]]) -> None:
        """Right column: Risk assessment and Open in Entra as cards in one scrolling text (never clipped)."""
        a = self.alert
        side = self.side = ttk.Frame(parent, width=px(360))
        side.pack(side="right", fill="y", padx=(px(12), 0))
        text = self.side_text = self.quick_text = scrolled_text(side, self.links, height=8, width=10)
        side.grid_propagate(False)  # fixed width: the text inside is grid-managed
        pad = text.card_blocks(padding=18)
        if a.factors:
            indent = pad + px(40)
            text.configure(tabs=(indent - px(8), "right", indent))
            text.tag_configure("score_num", font=theme.FONT_DISPLAY)
            text.tag_configure("bar_line", spacing1=px(2), spacing3=px(12))
            text.tag_configure("factor", lmargin2=indent, spacing3=px(8))
            text.tag_raise("factor", "card")
            text.begin_card("Risk assessment", first=True)
            text.write(str(a.score), "card", "score_num")
            text.write(f"  / 100 · {a.severity.label}\n", "card", "muted")
            bar = self.bar = tk.Canvas(text, height=px(6), width=px(300), highlightthickness=0, bd=0,
                                       background=theme.color("track"))
            self._bar_fill = bar.create_rectangle(0, 0, 0, px(6), width=0,
                                                  fill="#%02x%02x%02x" % icons.SEVERITY_RGB[a.severity])
            self._bar_progress = 1.0
            text.configure(state="normal")
            text.window_create("end-1c", window=bar)
            text.tag_add("card", "end-2c")
            text.configure(state="disabled")
            text.write("\n", "card", "bar_line")
            text.tag_add("bar_line", "end-3c linestart", "end-1c")

            def fit_bar(_e: tk.Event | None = None) -> None:
                try:
                    bar.configure(width=max(px(60), text.winfo_width() - 2 * pad))
                    self._draw_bar(self._bar_progress)
                except tk.TclError:
                    pass
            text.bind("<Configure>", fit_bar, add="+")
            for points, reason in a.factors:
                sign = "pos" if points > 0 else "neg" if points < 0 else "muted"
                text.write(f"\t{points:+d}" if points else "\t±0", "card", "factor", "bold", sign)
                text.write("\t", "card", "factor")
                text.write_value(reason, tags=("card", "factor"))
                text.write("\n", "card", "factor")
            text.end_card()
        if quick:
            text.begin_card("Open in Entra", first=not a.factors)
            text.tag_configure("quick", spacing3=px(6))
            for entity, action, label in quick:
                text.write_link(label, entity, tags=("card", "quick"), action=action)
                text.write("\n", "card", "quick")
            text.end_card()

    def score_text(self) -> str:
        try:
            return self.side_text.get("score_num.first", "score_num.last")
        except (tk.TclError, AttributeError):
            return ""

    def _set_score(self, value: int) -> None:
        t = self.side_text
        try:
            start = t.index("score_num.first")
            t.configure(state="normal")
            t.delete("score_num.first", "score_num.last")
            t.insert(start, str(value), ("card", "score_num"))
            t.configure(state="disabled")
        except tk.TclError:
            pass

    def _evidence(self, parent: tk.Misc) -> tk.Frame:
        a = self.alert
        cols = visible_columns(a.evidence)
        frame = card(parent, padding=14)
        head = tk.Frame(frame, background=theme.color("card"))
        head.pack(fill="x", pady=(0, px(8)))
        card_label(head, f"Evidence ({len(a.evidence)})", font=theme.FONT_BOLD).pack(side="left")
        card_label(head, "Double-click a row to open its log entry · right-click for more · click a header to sort",
                   role="muted", font=theme.FONT_CAPTION).pack(side="left", padx=(px(12), 0))
        self.view_btn = ttk.Button(head, text="View log entry", command=self._view_selected, state="disabled")
        self.view_btn.pack(side="right")
        split = self.evidence_split = ttk.PanedWindow(frame, orient="vertical", style="Card.TPanedwindow")
        split.pack(fill="both", expand=True)
        table = ttk.Frame(split, style="Card.TFrame")
        tree = self.tree = ttk.Treeview(table, columns=cols, show="headings", selectmode="browse", height=6)
        for c in cols:
            tree.heading(c, text=c, anchor="w")
        fit_columns(tree, cols, a.evidence)
        for i, row in enumerate(a.evidence):
            iid = str(i)
            self._rows[iid] = row
            tree.insert("", "end", iid=iid, values=[str(row.get(c, "")) for c in cols])
        self.sort = make_sortable(tree, cols)
        vsb = ttk.Scrollbar(table, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        split.add(table, weight=3)
        self._table_pane = table
        detail = ttk.Frame(split, style="Card.TFrame", padding=(0, px(8), 0, 0))
        self.row_text = scrolled_text(detail, self.links, height=5, background=theme.color("card"))
        split.add(detail, weight=1)
        self._detail_pane = detail
        self._columns = cols
        tree.bind("<<TreeviewSelect>>", lambda _e: self._show_row())
        tree.bind("<Double-1>", lambda e: self._view_selected() if tree.identify_row(e.y) else None)
        tree.bind("<Return>", lambda _e: self._view_selected())
        attach_table_menu(tree, self.links, self._rows.get)
        if a.evidence:
            tree.selection_set("0")
            tree.focus("0")
            self._show_row()
        return frame

    def _side_need(self) -> int:
        return self.side_text.text_height() if self.side else 0

    @property
    def paned(self) -> ttk.PanedWindow | None:
        """The splitter in use (None for alerts without evidence)."""
        return self._paneds.get(bool(self._wide)) if self._paneds else None

    @staticmethod
    def _cards_width(body_width: int) -> int:
        """Width of the cards column when the evidence stands beside it: readable lines, not the full width."""
        return max(px(900), min(px(1160), int(body_width * 0.4)))

    def _arrange(self, wide: bool, body_width: int = 0) -> None:
        """Cards beside the evidence (wide window) or above it.

        The cards pane is given its size BEFORE it is added to the splitter, so the very first layout in the new
        arrangement is already the final one (a splitter places a new pane at its requested size)."""
        if wide == self._wide:
            return
        old = self._paneds.get(self._wide) if self._wide is not None else None
        if old is not None:
            for pane in (self._info_pane, self._evidence_pane):
                old.forget(pane)
            old.pack_forget()
        if old is not None:  # a change-over: also the row detail under the table gets its final height at once
            detail_height = (min(self.row_text.text_height() + px(16), px(270)) if wide
                             else (self._tall_detail or px(90)))
            split = self.evidence_split
            for pane in (self._table_pane, self._detail_pane):
                split.forget(pane)
            self._detail_pane.grid_propagate(False)
            self._detail_pane.configure(height=detail_height)
            split.add(self._table_pane, weight=1)  # the table takes the rest
            split.add(self._detail_pane, weight=0)
        self._wide = wide
        new = self._paneds[wide]
        self._info_pane.pack_propagate(False)
        self._info_pane.configure(width=self._cards_width(body_width) if wide else 1,
                                  height=1 if wide else (self._tall_pos or px(400)))
        new.add(self._info_pane, weight=0 if wide else 1)
        new.add(self._evidence_pane, weight=1 if wide else 2)
        new.pack(fill="both", expand=True)
        for pane in (self._info_pane, self._evidence_pane):
            pane.lift()  # siblings of the splitter: keep them above it

    def _top_resized(self, event: tk.Event) -> None:
        """The window was resized or maximised. The arrangement (beside / above) is changed right here, before Tk
        lays the window out at its new size - the old arrangement is never drawn stretched to the new size. The
        fine-tuning that needs measured text heights follows once, when Tk is idle."""
        if event.widget is not self.top or (event.width, event.height) == self._top_size:
            return
        self._top_size = (event.width, event.height)
        body_width = event.width - 2 * px(BODY_MARGIN)
        self._arrange(body_width >= px(WIDE_FROM), body_width)
        if self._fit_job is None:
            self._fit_job = self.top.after_idle(self._refit)

    def _refit(self) -> None:
        self._fit_job = None
        self._fit_panes()

    @staticmethod
    def _set_sash(paned: ttk.PanedWindow, pos: int) -> None:
        if abs(paned.sashpos(0) - pos) > 1:  # leave it alone when it is already there: no extra redraw
            paned.sashpos(0, pos)

    def _fit_panes(self) -> None:
        """Split the room between the cards and the evidence by what each needs (both stay resizable).

        Depends on the window size only; runs before the window is shown and again when it is resized.
        - wide window: side by side - the cards in a readable column, the evidence gets the rest and the full height
        - otherwise: the cards on top get what they need (so the recommended action is visible) as long as the
          evidence keeps a usable minimum; spare room goes to the evidence table."""
        if not self._paneds or not self.exists():
            return
        try:
            self.top.update_idletasks()
            width, height = self.body.winfo_width(), self.body.winfo_height()
            if height < px(200) or width < px(200):
                return
            self._fitted = (width, height)
            self._top_size = (self.top.winfo_width(), self.top.winfo_height())
            was_wide = self._wide
            self._arrange(width >= px(WIDE_FROM), width)
            if self._wide != was_wide:
                self.top.update_idletasks()
            many = len(self.alert.evidence) > 3
            detail_need = min(self.row_text.text_height(), px(260 if self._wide else 160))
            if self._wide:
                self._set_sash(self.paned, self._cards_width(width))
            else:
                info_need = max(self.info.text_height() + px(4), self._side_need())
                tree_need = px(56) + min(len(self.alert.evidence), 12) * px(28)  # heading + rows + scrollbar
                evidence_need = px(80) + tree_need + min(detail_need, px(120))  # + card padding, title row, sash
                if info_need + evidence_need <= height:
                    pos = info_need  # everything fits: the spare room goes to the evidence table
                else:  # the texts come first; the evidence keeps a usable minimum (or what it needs, if less)
                    keep = min(evidence_need, max(px(MIN_EVIDENCE), int(height * 0.3)))
                    pos = max(int(height * 0.3), min(info_need, height - keep))
                self._tall_pos = max(px(140), pos)
                self._set_sash(self.paned, self._tall_pos)
            self.top.update_idletasks()
            inner = self.evidence_split.winfo_height()
            if inner > px(150) and not self._wide:  # (beside the cards the row detail has its height already)
                detail = min(detail_need + px(8), int(inner * (0.38 if many else 0.5)))
                self._set_sash(self.evidence_split, max(px(80), inner - detail - px(6)))
                self.top.update_idletasks()
                self._tall_detail = self._detail_pane.winfo_height()
        except tk.TclError:
            pass

    # ------------------------------------------------------------ animation
    def _draw_bar(self, progress: float) -> None:
        self._bar_progress = progress
        try:
            width = int(self.bar.cget("width"))  # the configured width (winfo_width lags behind a resize)
            self.bar.coords(self._bar_fill, 0, 0, int(width * self.alert.score / 100 * progress), px(6))
        except tk.TclError:
            pass

    def _animate_risk(self) -> None:
        """Risk bar grows to the score while the number counts up (instant with animations off)."""
        if not self.alert.factors or not self.exists():
            return
        score = self.alert.score
        theme.animate(self.bar, 700, lambda t: (self._draw_bar(t), self._set_score(int(round(score * t)))))

    # ------------------------------------------------------------ actions
    def selected_row(self) -> dict[str, str] | None:
        if not self.tree:
            return None
        sel = self.tree.selection()
        return self._rows.get(sel[0]) if sel else (self._rows.get("0") if self._rows else None)

    def _show_row(self) -> None:
        row = self.selected_row()
        entity = linkify.row_entity(row)
        acts = linkify.actions(entity) if entity else []
        self.view_btn.configure(text=acts[0][0] if acts else "View log entry", state="normal" if acts else "disabled")
        if self.row_text is None:
            return
        self.row_text.clear()
        if not row:
            return
        shown = [c for c in self._columns if str(row.get(c, "")).strip()]
        self.row_text.set_key_width(shown)
        for c in shown:
            self.row_text.write_field(c, row[c], row, name_tag="muted")

    def _view_selected(self) -> None:
        row = self.selected_row()
        entity = linkify.row_entity(row)
        if row and entity:
            self.links.default(entity, row)

    def _open_signin_logs(self) -> None:
        """No documented deep link to one entry exists: copy its Request ID, then open the log list."""
        row = self.selected_row() or {}
        request_id = row.get("Sign-in ID", "")
        if request_id:
            self.top.clipboard_clear()
            self.top.clipboard_append(request_id)
            tab = "non-interactive" if row.get("_event") == "nonInteractiveUser" else "interactive"
            self.status.show(portal_hint(request_id, tab, row.get("Time", "")[:10]))
        self.app.open_link(ENTRA_SIGNIN_LOGS)

    def _copy(self) -> None:
        self.top.clipboard_clear()
        self.top.clipboard_append(alert_as_text(self.alert, self.app.describe_origin(self.alert)))
        self.status.show("Copied the whole alert (fields, risk assessment and evidence) as text.")

    def _dismiss(self) -> None:
        self._on_dismiss(self.alert)
        self.top.destroy()

    def _snooze(self) -> None:
        if self._on_snooze:
            self._on_snooze(self.alert)
        self.top.destroy()
