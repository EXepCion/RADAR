"""'Offices' window: the sites of the company with their public IP addresses (tray > Settings > Offices...).

An office's addresses are what makes a sign-in "from the office": the detection rules trust them and the live map
shows the office as a place. The window is the same for the first set-up and for later changes; for the first
set-up it suggests addresses many people sign in from.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from PIL import ImageTk

from ..plugins.signin_threats import offices as model
from ..plugins.signin_threats.offices import Office
from . import icons, theme
from .cardtable import CardTable
from .parts import card, on_card
from .richtext import card_label, stable_label
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

COLS = ["Office", "City", "Country", "HQ", "Addresses"]
WIDTHS = {"Office": 170, "City": 140, "Country": 90, "HQ": 50, "Addresses": 100}
SUGGEST_COLS = ["Address", "People (30 d)", "Where Entra locates it", "Network"]
SUGGEST_WIDTHS = {"Address": 230, "People (30 d)": 110, "Where Entra locates it": 220, "Network": 240}
WIDTH = 1040
HELP = ("An office is a name, where it is, and the public IP addresses or ranges people there sign in from (one per "
        "line, e.g. 203.0.113.5 or 198.51.100.0/28). Sign-ins from these addresses count as 'in the office'.")
LONGEST_STATUS = ("CA office: '203.0.113.555' is not an IP address or range (examples: 203.0.113.5, 198.51.100.0/28). "
                  "UK office: add at least one IP address or range - without it nobody is ever seen there.")


class OfficesWindow:
    def __init__(self, root: tk.Tk, app: "App", offices: list[Office], on_save: Callable[[list[Office]], str | None],
                 first_time: bool = False, parent: tk.Misc | None = None, on_close=None):
        """``on_save(offices)`` stores them and returns None, or the reason why it could not."""
        self.app = app
        self.offices = [Office(**o.to_dict()) for o in offices]
        self._on_save = on_save
        self._current: Office | None = None
        self._loading = False
        self._suggestions: list[dict[str, Any]] = []
        top = self.top = theme.new_window(root, parent=parent, on_close=on_close)
        pad = 0 if theme.is_panel(top) else px(20)  # (a page has its host's margins)
        top.title("Offices")
        top.geometry(f"{px(WIDTH)}x{min(px(760), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(860), px(600))
        top.bind("<Escape>", lambda _e: theme.close(top))
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(pad, px(16), pad, px(4)))
        if not theme.is_panel(top):  # (as a page, the main window's settings carry the heading)
            header.pack(fill="x")
        ttk.Label(header, text="Offices", style="Title.TLabel").pack(fill="x")
        ttk.Label(header, text=HELP, style="Muted.TLabel", justify="left", wraplength=px(WIDTH - 40)).pack(
            fill="x", pady=(px(4), 0))

        c = theme.color
        body = ttk.Frame(top, padding=(pad, px(8), pad, px(8) if theme.is_panel(top) else px(14)))
        body.pack(fill="both", expand=True)

        # ---- the offices
        left = card(body)
        left.pack(fill="x")
        bar = on_card(left, padx=px(12), pady=px(10))
        bar.pack(side="bottom", fill="x")
        ttk.Button(bar, text="Add office", command=self.add).pack(side="left")
        self.remove_btn = ttk.Button(bar, text="Remove", command=self.remove, state="disabled")
        self.remove_btn.pack(side="left", padx=(px(6), 0))
        self.tree = CardTable(left, COLS, selectmode="browse", height=4, border=False)
        for col in COLS:
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, width=px(WIDTHS[col]), stretch=col == "Office", anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._select())

        # ---- the selected office: the name of every field above it
        right = self.form = card(body)
        right.pack(fill="x", pady=(px(10), 0))
        form = on_card(right, padx=px(16), pady=px(12))
        form.pack(fill="x")
        for column, weight in ((0, 4), (1, 3), (2, 2)):
            form.columnconfigure(column, weight=weight, uniform="office")
        self.vars = {k: tk.StringVar() for k in ("name", "city", "country", "lat", "lon")}
        self.hq = tk.BooleanVar()
        self.entries: dict[str, ttk.Entry] = {}

        def caption(parent: tk.Misc, text: str) -> tk.Label:
            return card_label(parent, text, "muted", font=theme.FONT_CAPTION)

        def field(column: int, label: str, key: str) -> None:
            caption(form, label).grid(row=0, column=column, sticky="w")
            e = ttk.Entry(form, textvariable=self.vars[key])
            e.grid(row=1, column=column, sticky="ew", padx=(0, px(12) if column < 2 else 0), pady=(px(3), px(10)))
            self.vars[key].trace_add("write", lambda *_a: self._edited())
            self.entries[key] = e

        field(0, "Name", "name")
        field(1, "City", "city")
        field(2, "Country (2 letters)", "country")
        caption(form, "IP addresses or ranges (one per line, e.g. 203.0.113.5 or 198.51.100.0/28)").grid(
            row=2, column=0, columnspan=2, sticky="w")
        self.ips = tk.Text(form, height=3, width=28, font=theme.FONT_MONO, wrap="none", relief="flat",
                           background=c("card"), foreground=c("text"), insertbackground=c("text"),
                           selectbackground=c("select"), selectforeground=c("text"), highlightthickness=1,
                           highlightbackground=c("border"), highlightcolor=c("link"), padx=px(8), pady=px(6))
        self.ips.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=(0, px(12)), pady=(px(3), 0))
        self.ips.bind("<<Modified>>", self._ips_modified)
        side = on_card(form)
        side.grid(row=2, column=2, rowspan=2, sticky="nw")
        self.hq_box = ttk.Checkbutton(side, text="Headquarters", variable=self.hq, command=self._edited,
                                      style="Card.TCheckbutton")
        self.hq_box.pack(anchor="w")
        caption(side, "Map position (optional)").pack(anchor="w", pady=(px(6), px(3)))
        pos = on_card(side)
        pos.pack(anchor="w")
        for key, text in (("lat", "Lat"), ("lon", "Lon")):
            card_label(pos, text, "muted").pack(side="left", padx=(0, px(4)))
            e = ttk.Entry(pos, textvariable=self.vars[key], width=9)
            e.pack(side="left", padx=(0, px(10)))
            self.vars[key].trace_add("write", lambda *_a: self._edited())
            self.entries[key] = e

        # ---- suggestions, and at the bottom what the editor has to say, with Save
        low = card(body)
        low.pack(fill="both", expand=True, pady=(px(10), 0))
        foot = on_card(low, padx=px(16), pady=px(10))
        foot.pack(side="bottom", fill="x")
        tk.Frame(low, height=1, background=c("border"), bd=0, highlightthickness=0).pack(side="bottom", fill="x")
        ttk.Button(foot, text="Discard changes" if theme.is_panel(top) else "Cancel",
                   command=lambda: theme.close(top)).pack(side="right")
        self.save_btn = ttk.Button(foot, text="Save", style="Accent.TButton", command=self.save)
        self.save_btn.pack(side="right", padx=(px(12), px(6)))
        self.status = stable_label(foot, LONGEST_STATUS, width=px(WIDTH - 330), background=c("card"))
        self.status.pack(fill="x")
        sbar = on_card(low, padx=px(12), pady=px(10))
        sbar.pack(side="bottom", fill="x")
        self.as_new_btn = ttk.Button(sbar, text="Add as new office", command=lambda: self._use_suggestion(new=True),
                                     state="disabled")  # (every row has this as its own button; kept for the keyboard)
        self.to_selected_btn = ttk.Button(sbar, text="Add the selected address to the office above",
                                          command=lambda: self._use_suggestion(new=False), state="disabled")
        self.to_selected_btn.pack(side="left")
        head = on_card(low, padx=px(16))
        head.pack(fill="x", pady=(px(12), px(4)))
        card_label(head, "Suggestions: addresses many people sign in from", font=theme.FONT_BOLD).pack(side="left")
        self.suggest_note = card_label(head, "Looking through the sign-in history...", "muted", font=theme.FONT_CAPTION)
        self.suggest_note.pack(side="left", padx=(px(10), 0))
        self.suggest = CardTable(low, SUGGEST_COLS, selectmode="browse", height=2, border=False)
        for col in SUGGEST_COLS:
            self.suggest.heading(col, text=col, anchor="w")
            self.suggest.column(col, width=px(SUGGEST_WIDTHS[col]), stretch=col == "Network", anchor="w")
        self.suggest.action("Add as office", lambda iid: self._use_suggestion(new=True, iid=iid))
        self.suggest.pack(fill="both", expand=True)
        self.suggest.bind("<<TreeviewSelect>>", lambda _e: self._buttons())

        self._fill_tree()
        if self.offices:
            self.tree.selection_set("0")
            self._select()
        else:
            self._load_form(None)
        self._say("No office yet: take a suggested address, or add one by hand."
                  if first_time or not self.offices else "")
        theme.style_window(top)
        top.lift()
        top.focus_force()

    # ------------------------------------------------------------- helpers
    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def focus(self) -> None:
        self.top.deiconify()
        self.top.lift()
        self.top.focus_force()

    def _say(self, text: str, error: bool = False) -> None:
        self.status.configure(text=text, foreground=theme.color("error" if error else "muted"))

    @staticmethod
    def _values(o: Office) -> list[str]:
        return [o.name or "(no name)", o.city, o.country, "HQ" if o.hq else "", str(len(o.ips))]

    def _fill_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, o in enumerate(self.offices):
            self.tree.insert("", "end", iid=str(i), values=self._values(o))

    def _buttons(self) -> None:
        has = self._current is not None
        self.remove_btn.configure(state="normal" if has else "disabled")
        picked = bool(self.suggest.selection())
        self.as_new_btn.configure(state="normal" if picked else "disabled")
        self.to_selected_btn.configure(state="normal" if picked and has else "disabled")

    def _load_form(self, office: Office | None) -> None:
        self._loading = True
        self._current = office
        for key in ("name", "city", "country"):
            self.vars[key].set(getattr(office, key) if office else "")
        self.vars["lat"].set("" if not office or office.lat is None else f"{office.lat:g}")
        self.vars["lon"].set("" if not office or office.lon is None else f"{office.lon:g}")
        self.hq.set(bool(office and office.hq))
        self.ips.configure(state="normal")
        self.ips.delete("1.0", "end")
        if office:
            self.ips.insert("1.0", "\n".join(office.ips))
        self.ips.edit_modified(False)
        state = "normal" if office else "disabled"
        for e in self.entries.values():
            e.configure(state=state)
        self.hq_box.configure(state=state)
        self.ips.configure(state=state)
        self._loading = False
        self._buttons()

    def _select(self) -> None:
        sel = self.tree.selection()
        self._load_form(self.offices[int(sel[0])] if sel else None)

    @staticmethod
    def _float(text: str) -> float | None:
        try:
            return float(text.replace(",", ".")) if text.strip() else None
        except ValueError:
            return None

    def _edited(self) -> None:
        """A field changed: take it over into the selected office and its row."""
        o = self._current
        if self._loading or o is None:
            return
        o.name, o.city = self.vars["name"].get().strip(), self.vars["city"].get().strip()
        o.country = self.vars["country"].get().strip().upper()[:2]
        o.lat, o.lon = self._float(self.vars["lat"].get()), self._float(self.vars["lon"].get())
        if self.hq.get() and not o.hq:  # there is one headquarters
            for other in self.offices:
                other.hq = False
        o.hq = bool(self.hq.get())
        o.ips = [line.strip() for line in self.ips.get("1.0", "end").replace(",", "\n").split("\n") if line.strip()]
        for i, office in enumerate(self.offices):
            self.tree.item(str(i), values=self._values(office))

    def _ips_modified(self, _e: tk.Event) -> None:
        if self.ips.edit_modified():
            self.ips.edit_modified(False)
            self._edited()

    # -------------------------------------------------------------- actions
    def add(self, office: Office | None = None) -> None:
        self.offices.append(office or Office(name=f"Office {len(self.offices) + 1}"))
        self._fill_tree()
        self.tree.selection_set(str(len(self.offices) - 1))
        self.tree.see(str(len(self.offices) - 1))
        self._select()  # at once (the selection event only arrives later)
        if office is None:
            self.entries["name"].focus_set()
            self.entries["name"].selection_range(0, "end")

    def remove(self) -> None:
        if self._current is None:
            return
        index = self.offices.index(self._current)
        del self.offices[index]
        self._fill_tree()
        if self.offices:
            self.tree.selection_set(str(min(index, len(self.offices) - 1)))
            self._select()
        else:
            self._load_form(None)

    def show_suggestions(self, rows: list[dict[str, Any]]) -> None:
        if not self.exists():
            return
        self._suggestions = rows
        self.suggest.delete(*self.suggest.get_children())
        for i, r in enumerate(rows):
            where = ", ".join(p for p in (r.get("city"), r.get("country")) if p)
            self.suggest.insert("", "end", iid=str(i), values=[r["ip"], r["users"], where, r.get("network", "")])
        self.suggest_note.configure(text=(
            "that are no office yet. A VPN exit can look like an office: check the network." if rows
            else "none that is not an office already."))
        self._buttons()

    def _use_suggestion(self, new: bool, iid: str | None = None) -> None:
        """Take a suggested address: as an office of its own, or into the selected office. ``iid``: the row whose
        button was clicked (otherwise the selected row)."""
        sel = [iid] if iid is not None else list(self.suggest.selection())
        if not sel or not self.suggest.exists(sel[0]):
            return
        r = self._suggestions[int(sel[0])]
        if new or self._current is None:
            self.add(Office(name=f"{r.get('city') or r['ip']} office", city=r.get("city") or "",
                            country=(r.get("country") or "")[:2].upper(), ips=[r["ip"]]))
        else:
            if r["ip"] not in self._current.ips:
                self._current.ips.append(r["ip"])
            self._load_form(self._current)
            self.tree.item(str(self.offices.index(self._current)), values=self._values(self._current))
        self.suggest.delete(sel[0])
        self._say("")  # (what was said before - "no office yet" - no longer holds)
        self._buttons()

    def save(self) -> None:
        problems = model.validate(self.offices)
        if problems:
            self._say(" ".join(problems[:2]) + (f" (+{len(problems) - 2} more)" if len(problems) > 2 else ""), error=True)
            return
        error = self._on_save([Office(**o.to_dict()) for o in self.offices])
        if error:
            self._say(f"Could not save: {error}", error=True)
            return
        theme.close(self.top)
