"""'Virtual desktops' window (tray > Settings > Virtual desktops...).

Citrix, Azure Virtual Desktop, terminal servers: machines people work on from somewhere else. A sign-in from one
tells where the machine runs, not where the person is. The window lists the configured ones and proposes machines
found in the sign-ins that look like one (several accounts at the same time, or a managed machine in a cloud
data centre).
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from PIL import ImageTk

from ..plugins.signin_threats import hosts as model
from . import icons, theme
from .richtext import card, card_label, stable_label
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

COLS = ["Device name, pattern or IP range", "What it is"]
WIDTHS = {COLS[0]: 300, COLS[1]: 240}
SUGGEST_COLS = ["Machine", "Accounts", "At once", "Runs in", "Looks like", "Why"]
SUGGEST_WIDTHS = {"Machine": 160, "Accounts": 90, "At once": 80, "Runs in": 230, "Looks like": 190, "Why": 260}
WIDTH = 1080
HELP = ("Machines people work on from somewhere else: Citrix, Azure Virtual Desktop, terminal servers. A sign-in from one "
        "tells where the machine runs, not where the person is - so it is not used to place people on the map or to "
        "judge travel. Enter a device name, a pattern with * (TOR-CTX-*), or the IP range the machines send from.")
LONGEST_STATUS = ("'CX' would match almost every device - use a longer name or pattern. '20.50.10.999' looks like an IP "
                  "address but is not a valid one (examples: 20.50.10.4, 20.50.10.0/28).")


class HostsWindow:
    def __init__(self, root: tk.Tk, app: "App", entries: list[dict[str, str]],
                 on_save: Callable[[list[dict[str, str]]], str | None]):
        """``on_save(entries)`` stores them and returns None, or the reason why it could not."""
        self.app = app
        self.entries = [dict(e) for e in entries]
        self._on_save = on_save
        self._current: dict[str, str] | None = None
        self._loading = False
        self._suggestions: list[dict[str, Any]] = []
        top = self.top = theme.new_window(root)
        top.title("Virtual desktops")
        top.geometry(f"{px(WIDTH)}x{min(px(740), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(860), px(560))
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(4)))
        header.pack(fill="x")
        ttk.Label(header, text="Virtual desktops and shared hosts", style="Title.TLabel").pack(fill="x")
        ttk.Label(header, text=HELP, style="Muted.TLabel", justify="left", wraplength=px(WIDTH - 40)).pack(
            fill="x", pady=(px(4), 0))

        footer = ttk.Frame(top, padding=(px(20), px(4), px(20), px(14)))
        footer.pack(side="bottom", fill="x")
        self.status = stable_label(footer, LONGEST_STATUS, width=px(WIDTH - 40))
        self.status.pack(fill="x", pady=(0, px(8)))
        buttons = ttk.Frame(footer)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Cancel", command=top.destroy).pack(side="right")
        ttk.Button(buttons, text="Save", style="Accent.TButton", command=self.save).pack(side="right", padx=(0, px(6)))

        body = ttk.Frame(top, padding=(px(20), px(8), px(20), 0))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=2)
        body.rowconfigure(1, weight=3)
        c = theme.color

        # ---- configured
        upper = card(body)
        upper.grid(row=0, column=0, sticky="nsew")
        form = tk.Frame(upper, background=c("card"))
        form.pack(side="bottom", fill="x", pady=(px(8), 0))
        self.vars = {"match": tk.StringVar(), "label": tk.StringVar()}
        card_label(form, "Name, pattern or IP range", "muted").pack(side="left")
        self.match_entry = ttk.Entry(form, textvariable=self.vars["match"], width=28)
        self.match_entry.pack(side="left", padx=(px(8), px(14)))
        card_label(form, "What it is", "muted").pack(side="left")
        self.label_entry = ttk.Entry(form, textvariable=self.vars["label"], width=24)
        self.label_entry.pack(side="left", padx=(px(8), px(14)))
        for var in self.vars.values():
            var.trace_add("write", lambda *_a: self._edited())
        self.remove_btn = ttk.Button(form, text="Remove", command=self.remove, state="disabled")
        self.remove_btn.pack(side="right")
        ttk.Button(form, text="Add", command=self.add).pack(side="right", padx=(0, px(6)))
        self.tree = ttk.Treeview(upper, columns=COLS, show="headings", selectmode="browse", height=5)
        for col in COLS:
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, width=px(WIDTHS[col]), stretch=col == COLS[1], anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._select())

        # ---- suggestions
        low = card(body)
        low.grid(row=1, column=0, sticky="nsew", pady=(px(10), 0))
        head = tk.Frame(low, background=c("card"))
        head.pack(fill="x", pady=(0, px(6)))
        card_label(head, "Found in the sign-ins of the last 30 days", font=theme.FONT_BOLD).pack(side="left")
        self.suggest_note = card_label(head, "Looking through the sign-in history...", "muted", font=theme.FONT_CAPTION)
        self.suggest_note.pack(side="left", padx=(px(10), 0))
        sbar = tk.Frame(low, background=c("card"))
        sbar.pack(side="bottom", fill="x", pady=(px(8), 0))
        self.add_selected_btn = ttk.Button(sbar, text="Add selected", command=self._add_selected, state="disabled")
        self.add_selected_btn.pack(side="left")
        self.add_all_btn = ttk.Button(sbar, text="Add all", command=self._add_all, state="disabled")
        self.add_all_btn.pack(side="left", padx=(px(6), 0))
        card_label(sbar, "A shared PC people take turns on is not a virtual desktop: leave it out.", "muted",
                   font=theme.FONT_CAPTION).pack(side="left", padx=(px(14), 0))
        self.suggest = ttk.Treeview(low, columns=SUGGEST_COLS, show="headings", selectmode="extended", height=6)
        for col in SUGGEST_COLS:
            self.suggest.heading(col, text=col, anchor="w")
            self.suggest.column(col, width=px(SUGGEST_WIDTHS[col]), stretch=col == "Why", anchor="w")
        self.suggest.pack(fill="both", expand=True)
        self.suggest.bind("<<TreeviewSelect>>", lambda _e: self._buttons())

        self._fill_tree()
        self._load_form(None)
        self._say("")
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

    def _fill_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, e in enumerate(self.entries):
            self.tree.insert("", "end", iid=str(i), values=[e["match"], e.get("label", "")])

    def _buttons(self) -> None:
        self.remove_btn.configure(state="normal" if self._current is not None else "disabled")
        self.add_selected_btn.configure(state="normal" if self.suggest.selection() else "disabled")
        self.add_all_btn.configure(state="normal" if self.suggest.get_children() else "disabled")

    def _load_form(self, entry: dict[str, str] | None) -> None:
        self._loading = True
        self._current = entry
        self.vars["match"].set(entry["match"] if entry else "")
        self.vars["label"].set(entry.get("label", "") if entry else "")
        self._loading = False
        self._buttons()

    def _select(self) -> None:
        sel = self.tree.selection()
        self._load_form(self.entries[int(sel[0])] if sel else None)

    def _edited(self) -> None:
        e = self._current
        if self._loading or e is None:
            return
        e["match"], e["label"] = self.vars["match"].get().strip(), self.vars["label"].get().strip()
        self.tree.item(str(self.entries.index(e)), values=[e["match"], e["label"]])

    # -------------------------------------------------------------- actions
    def add(self, entry: dict[str, str] | None = None, select: bool = True) -> None:
        """A new entry: from the two fields (when nothing is selected), from a suggestion, or an empty one."""
        if entry is None:
            typed = self.vars["match"].get().strip() if self._current is None else ""
            entry = {"match": typed, "label": self.vars["label"].get().strip() if typed else ""}
        self.entries.append(entry)
        self._fill_tree()
        if select:
            self.tree.selection_set(str(len(self.entries) - 1))
            self.tree.see(str(len(self.entries) - 1))
            self._select()
            if not entry["match"]:
                self.match_entry.focus_set()

    def remove(self) -> None:
        if self._current is None:
            return
        index = self.entries.index(self._current)
        del self.entries[index]
        self._fill_tree()
        if self.entries:
            self.tree.selection_set(str(min(index, len(self.entries) - 1)))
            self._select()
        else:
            self._load_form(None)

    def show_suggestions(self, rows: list[dict[str, Any]]) -> None:
        if not self.exists():
            return
        have = {e["match"].lower() for e in self.entries}
        self._suggestions = [r for r in rows if r["name"].lower() not in have]
        self.suggest.delete(*self.suggest.get_children())
        for i, r in enumerate(self._suggestions):
            self.suggest.insert("", "end", iid=str(i), values=[r["name"], r["users"], r["together"], r["where"], r["label"], r["why"]])
        self.suggest_note.configure(text=(
            f"{len(self._suggestions)} machine(s) that look like a virtual desktop or shared host and are not listed above."
            if self._suggestions else "nothing that looks like a virtual desktop and is not listed above."))
        self._buttons()

    def _take(self, iids: list[str]) -> None:
        for iid in iids:
            r = self._suggestions[int(iid)]
            self.add({"match": r["name"], "label": r["label"]}, select=False)
            self.suggest.delete(iid)
        if iids:
            self.tree.selection_set(str(len(self.entries) - 1))
            self.tree.see(str(len(self.entries) - 1))
            self._select()
        self._buttons()

    def _add_selected(self) -> None:
        self._take(list(self.suggest.selection()))

    def _add_all(self) -> None:
        self._take(list(self.suggest.get_children()))

    def save(self) -> None:
        entries = [e for e in self.entries if e["match"].strip()]
        problems = model.validate(entries)
        if problems:
            self._say(" ".join(problems[:2]) + (f" (+{len(problems) - 2} more)" if len(problems) > 2 else ""), error=True)
            return
        error = self._on_save([dict(e) for e in entries])
        if error:
            self._say(f"Could not save: {error}", error=True)
            return
        self.top.destroy()
