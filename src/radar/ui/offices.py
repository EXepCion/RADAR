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
from .richtext import card, card_label, stable_label
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
                 first_time: bool = False):
        """``on_save(offices)`` stores them and returns None, or the reason why it could not."""
        self.app = app
        self.offices = [Office(**o.to_dict()) for o in offices]
        self._on_save = on_save
        self._current: Office | None = None
        self._loading = False
        self._suggestions: list[dict[str, Any]] = []
        top = self.top = theme.new_window(root)
        top.title("Offices")
        top.geometry(f"{px(WIDTH)}x{min(px(760), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(860), px(600))
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(4)))
        header.pack(fill="x")
        ttk.Label(header, text="Offices", style="Title.TLabel").pack(fill="x")
        ttk.Label(header, text=HELP, style="Muted.TLabel", justify="left", wraplength=px(WIDTH - 40)).pack(
            fill="x", pady=(px(4), 0))

        footer = ttk.Frame(top, padding=(px(20), px(4), px(20), px(14)))
        footer.pack(side="bottom", fill="x")
        self.status = stable_label(footer, LONGEST_STATUS, width=px(WIDTH - 40))
        self.status.pack(fill="x", pady=(0, px(8)))
        buttons = ttk.Frame(footer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=top.destroy).pack(side="right")
        self.save_btn = ttk.Button(buttons, text="Save", style="Accent.TButton", command=self.save)
        self.save_btn.pack(side="right", padx=(0, px(6)))

        body = ttk.Frame(top, padding=(px(20), px(8), px(20), 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3, uniform="half")
        body.columnconfigure(1, weight=2, uniform="half")
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=2)

        # ---- the offices
        left = card(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, px(10)))
        bar = tk.Frame(left, background=theme.color("card"))
        bar.pack(side="bottom", fill="x", pady=(px(8), 0))
        ttk.Button(bar, text="Add office", command=self.add).pack(side="left")
        self.remove_btn = ttk.Button(bar, text="Remove", command=self.remove, state="disabled")
        self.remove_btn.pack(side="left", padx=(px(6), 0))
        self.tree = ttk.Treeview(left, columns=COLS, show="headings", selectmode="browse", height=6)
        for c in COLS:
            self.tree.heading(c, text=c, anchor="w")
            self.tree.column(c, width=px(WIDTHS[c]), stretch=c == "Office", anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._select())

        # ---- the selected office
        right = self.form = card(body)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)
        self.vars = {k: tk.StringVar() for k in ("name", "city", "country", "lat", "lon")}
        self.hq = tk.BooleanVar()
        self.entries: dict[str, ttk.Entry] = {}

        def field(row: int, label: str, key: str, width: int | None = None) -> None:
            card_label(right, label, "muted").grid(row=row, column=0, sticky="w", padx=(0, px(12)), pady=px(4))
            e = ttk.Entry(right, textvariable=self.vars[key], **({"width": width} if width else {}))
            e.grid(row=row, column=1, sticky="w" if width else "ew", pady=px(4))
            self.vars[key].trace_add("write", lambda *_a: self._edited())
            self.entries[key] = e

        field(0, "Name", "name")
        field(1, "City", "city")
        field(2, "Country (2 letters)", "country", 6)
        self.hq_box = ttk.Checkbutton(right, text="This is the headquarters", variable=self.hq, command=self._edited,
                                      style="Card.TCheckbutton")
        self.hq_box.grid(row=3, column=1, sticky="w", pady=px(4))
        card_label(right, "IP addresses / ranges", "muted").grid(row=4, column=0, sticky="nw", padx=(0, px(12)), pady=px(4))
        c = theme.color
        self.ips = tk.Text(right, height=5, width=28, font=theme.FONT_MONO, wrap="none", relief="flat",
                           background=c("window"), foreground=c("text"), insertbackground=c("text"),
                           selectbackground=c("select"), selectforeground=c("text"), highlightthickness=1,
                           highlightbackground=c("border"), highlightcolor=c("link"), padx=px(8), pady=px(6))
        self.ips.grid(row=4, column=1, sticky="nsew", pady=px(4))
        self.ips.bind("<<Modified>>", self._ips_modified)
        right.rowconfigure(4, weight=1)
        card_label(right, "Position on the map", "muted").grid(row=5, column=0, sticky="w", padx=(0, px(12)), pady=px(4))
        pos = tk.Frame(right, background=c("card"))
        pos.grid(row=5, column=1, sticky="w", pady=px(4))
        for key, text in (("lat", "Lat"), ("lon", "Lon")):
            card_label(pos, text, "muted").pack(side="left", padx=(0, px(4)))
            e = ttk.Entry(pos, textvariable=self.vars[key], width=9)
            e.pack(side="left", padx=(0, px(10)))
            self.vars[key].trace_add("write", lambda *_a: self._edited())
            self.entries[key] = e
        card_label(right, "Empty = where Entra locates the sign-ins from the office.", "muted",
                   font=theme.FONT_CAPTION, wraplength=px(250)).grid(row=6, column=1, sticky="w")

        # ---- suggestions
        low = card(body)
        low.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(px(10), 0))
        head = tk.Frame(low, background=c("card"))
        head.pack(fill="x", pady=(0, px(6)))
        card_label(head, "Addresses many people sign in from", font=theme.FONT_BOLD).pack(side="left")
        self.suggest_note = card_label(head, "Looking through the sign-in history...", "muted", font=theme.FONT_CAPTION)
        self.suggest_note.pack(side="left", padx=(px(10), 0))
        sbar = tk.Frame(low, background=c("card"))
        sbar.pack(side="bottom", fill="x", pady=(px(8), 0))
        self.as_new_btn = ttk.Button(sbar, text="Add as new office", command=lambda: self._use_suggestion(new=True),
                                     state="disabled")
        self.as_new_btn.pack(side="left")
        self.to_selected_btn = ttk.Button(sbar, text="Add to the selected office",
                                          command=lambda: self._use_suggestion(new=False), state="disabled")
        self.to_selected_btn.pack(side="left", padx=(px(6), 0))
        self.suggest = ttk.Treeview(low, columns=SUGGEST_COLS, show="headings", selectmode="browse", height=4)
        for col in SUGGEST_COLS:
            self.suggest.heading(col, text=col, anchor="w")
            self.suggest.column(col, width=px(SUGGEST_WIDTHS[col]), stretch=col == "Network", anchor="w")
        self.suggest.pack(fill="both", expand=True)
        self.suggest.bind("<<TreeviewSelect>>", lambda _e: self._buttons())

        self._fill_tree()
        if self.offices:
            self.tree.selection_set("0")
            self._select()
        else:
            self._load_form(None)
        self._say("No office yet. Pick an address below (most people sign in from the offices) or add one by hand."
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

    def _use_suggestion(self, new: bool) -> None:
        sel = self.suggest.selection()
        if not sel:
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
        self.top.destroy()
