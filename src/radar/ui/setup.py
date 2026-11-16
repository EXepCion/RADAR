"""'Set up RADAR' window: choose how RADAR signs in, then see - step by step - whether it can read what it needs.

Shown on the first start and from Settings > Account > Set-up and connection check. While set-up is not finished,
sign-in and permission problems are explained here (with "Check again") instead of being raised as alerts.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from PIL import ImageTk

from .. import identity, setup_check
from ..setup_check import Check
from . import icons, theme
from .parts import card, on_card
from .richtext import card_label, stable_label
from .theme import px

if TYPE_CHECKING:  # pragma: no cover
    from ..app import App

WIDTH = 780
INTRO = ("To read the logs from Microsoft Graph, RADAR has to sign in as an application. RADAR has no application "
         "identity of its own, so you choose once which one it uses.")
OWN_TEXT = ("RADAR appears in your sign-in logs under the name you gave the registration, and you can allow or block "
            "it like any other application. It needs the delegated Graph permissions AuditLog.Read.All, "
            "Directory.Read.All and Policy.Read.All with admin consent.")
CLI_TEXT = ("No set-up: RADAR uses the public ID of Microsoft's Azure CLI. RADAR then appears in your sign-in logs as "
            "\"Microsoft Azure CLI\", it does not work where Azure CLI is blocked, and Microsoft may change what this "
            "identity can do at any time. At your own risk.")
WORKING = ("RADAR is working. It keeps running in the notification area (the shield icon next to the clock), checks "
           "the logs every few minutes and shows a reminder when it finds something. You can close this window.")
WORKING_PARTLY = "RADAR is working, with one thing missing:"
NOT_YET = "RADAR cannot work yet:"
WAITING, RUNNING, OK, FAILED, SKIPPED = "waiting", "running", "ok", "failed", "skipped"
MARK = {WAITING: "○", RUNNING: "◔", OK: "✔", FAILED: "✖", SKIPPED: "–"}
ROLE = {WAITING: "muted", RUNNING: "link", OK: "neg", FAILED: "error", SKIPPED: "muted"}  # palette roles
LONGEST = "words that wrap " * 30  # room for the longest hint (the label keeps this height)


class SetupWindow:
    def __init__(self, root: tk.Tk, app: "App", run_now: bool = False, parent: tk.Misc | None = None, on_close=None):
        self.app = app
        self.busy = False
        kind, client, tenant = identity.current(app.cfg.get("auth", default={}) or {})
        top = self.top = theme.new_window(root, parent=parent, on_close=on_close)
        top.title("Set up RADAR")
        top.geometry(f"{px(WIDTH)}x{min(px(860), int(top.winfo_screenheight() * 0.9))}")
        top.resizable(False, False)
        top.bind("<Escape>", lambda _e: theme.close(top))
        self._icon = ImageTk.PhotoImage(icons.app_icon(32), master=root)
        top.iconphoto(False, self._icon)
        wrap = px(WIDTH - 40 - 28)
        full = px(WIDTH - 40)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(4)))
        if not theme.is_panel(top):  # (as a page, the main window's settings carry the heading)
            header.pack(fill="x")
        ttk.Label(header, text="Set up RADAR", style="Title.TLabel").pack(fill="x")
        ttk.Label(header, text=INTRO, style="Muted.TLabel", justify="left", wraplength=full).pack(fill="x", pady=(px(4), 0))

        c = theme.color
        pad = 0 if theme.is_panel(top) else px(20)  # (a page has its host's margins)
        body = ttk.Frame(top, padding=(pad, px(8), pad, px(8) if theme.is_panel(top) else px(14)))
        body.pack(fill="both", expand=True)
        box = card(body)
        box.pack(fill="both", expand=True)

        def section(text: str) -> None:
            strip = tk.Frame(box, background=c("heading_bg"), bd=0, highlightthickness=0, padx=px(16), pady=px(7))
            strip.pack(fill="x")
            tk.Label(strip, text=text, font=theme.FONT_CAPTION_BOLD, background=c("heading_bg"), foreground=c("muted"),
                     bd=0, padx=0, pady=0).pack(side="left")
            tk.Frame(box, height=1, background=c("border"), bd=0, highlightthickness=0).pack(fill="x")

        # ---- 1: the identity RADAR signs in with - two choices side by side, the chosen one outlined
        section("1 \u00b7 How RADAR signs in")
        self.kind = tk.StringVar(value=kind if kind != identity.UNSET else identity.OWN)
        choices = on_card(box, padx=px(16))
        choices.pack(fill="x", pady=(px(12), px(10)))
        self._choices: dict[str, Any] = {}
        for column, (value, title, text) in enumerate((
                (identity.OWN, "An app registration of our organisation (recommended)", OWN_TEXT),
                (identity.AZURE_CLI, "Quick start: the Azure CLI identity", CLI_TEXT))):
            choices.columnconfigure(column, weight=1, uniform="choice")
            cell = card(choices, padx=px(10), pady=px(8))
            cell.grid(row=0, column=column, sticky="nsew", padx=(0, px(12) if column == 0 else 0))
            ttk.Radiobutton(cell, text=title, value=value, variable=self.kind, command=self._sync,
                            style="Card.TRadiobutton").pack(anchor="w")
            about = card_label(cell, text, "muted", font=theme.FONT_CAPTION, wraplength=px(300))
            about.pack(anchor="w", fill="x", padx=(px(28), 0), pady=(px(2), 0))
            cell.bind("<Configure>", lambda e, label=about: label.configure(wraplength=max(px(160), e.width - px(60))))
            for widget in (cell, about):  # a click anywhere in the box chooses it
                widget.bind("<Button-1>", lambda _e, v=value: (self.kind.set(v), self._sync()))
            self._choices[value] = cell

        fields = on_card(box, padx=px(16))
        fields.pack(fill="x", pady=(0, px(10)))
        fields.columnconfigure(0, weight=1, uniform="id")
        fields.columnconfigure(1, weight=1, uniform="id")
        card_label(fields, "Application (client) ID", "muted", font=theme.FONT_CAPTION).grid(row=0, column=0, sticky="w")
        self.client = tk.StringVar(value=client if kind == identity.OWN else "")
        self.client_entry = ttk.Entry(fields, textvariable=self.client)
        self.client_entry.grid(row=1, column=0, sticky="ew", padx=(0, px(12)), pady=(px(3), 0))
        card_label(fields, "Directory (tenant) ID or domain", "muted", font=theme.FONT_CAPTION).grid(row=0, column=1, sticky="w")
        self.tenant = tk.StringVar(value=tenant if kind == identity.OWN else "")
        self.tenant_entry = ttk.Entry(fields, textvariable=self.tenant)
        self.tenant_entry.grid(row=1, column=1, sticky="ew", padx=(0, px(12)), pady=(px(3), 0))
        self.check_btn = ttk.Button(fields, text="Save and check", style="Accent.TButton", command=self.start)
        self.check_btn.grid(row=1, column=2)

        more = on_card(box, padx=px(16))
        more.pack(fill="x", pady=(0, px(12)))
        ttk.Button(more, text="How to register an application", command=lambda: app.open_link(identity.HELP_URL)).pack(side="left")
        self.other_btn = ttk.Button(more, text="Use a different account", command=lambda: self.start(other_account=True))
        self.other_btn.pack(side="left", padx=(px(6), 0))
        self.close_btn = ttk.Button(more, text="Close", command=lambda: theme.close(top))
        if not theme.is_panel(top):  # (as a page of the main window there is nothing to close)
            self.close_btn.pack(side="right")

        # ---- 2: can RADAR read what it needs? One line per step: its mark, its name, and what came of it
        tk.Frame(box, height=1, background=c("border"), bd=0, highlightthickness=0).pack(fill="x")
        section("2 \u00b7 Connection check")
        self.rows: dict[str, tuple[tk.Label, tk.Label]] = {}
        for key, title in setup_check.STEPS:
            row = on_card(box, padx=px(16), height=px(46))
            row.pack(fill="x")
            row.pack_propagate(False)  # the same height with and without a result: nothing moves when it arrives
            mark = tk.Label(row, text=MARK[WAITING], width=2, font=theme.FONT_BOLD, background=c("card"),
                            foreground=c("muted"), bd=0, padx=0, pady=0)
            mark.pack(side="left", padx=(0, px(10)))
            text = on_card(row)
            text.pack(side="left", fill="x", expand=True)  # (not filled vertically: it sits in the middle of the row)
            card_label(text, title).pack(anchor="w")
            detail = card_label(text, "", "muted", font=theme.FONT_CAPTION)  # shown once there is something to say
            tk.Frame(box, height=1, background=c("border"), bd=0, highlightthickness=0).pack(fill="x")
            self.rows[key] = (mark, detail)
        result = on_card(box, padx=px(16), pady=px(10))
        result.pack(fill="x")
        self.headline = tk.Label(result, text="", justify="left", anchor="w", wraplength=full, font=theme.FONT,
                                 background=c("card"), foreground=c("text"), bd=0, padx=0, pady=0)
        self.headline.pack(fill="x")
        result.bind("<Configure>", lambda e: self.headline.configure(wraplength=max(px(200), e.width - px(36))))
        self.hint = stable_label(result, LONGEST, width=full, max_lines=4, background=c("card"))  # fixed height
        self.hint.configure(text="")
        self.hint.pack(fill="x", pady=(px(2), 0))

        self._sync()
        self.reset_steps()
        theme.style_window(top)
        top.lift()
        top.focus_force()
        if run_now and kind != identity.UNSET:
            top.after(400, lambda: self.start(save=False))

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

    def _sync(self) -> None:
        own = self.kind.get() == identity.OWN
        for entry in (self.client_entry, self.tenant_entry):
            entry.configure(state="normal" if own and not self.busy else "disabled")
        for value, cell in self._choices.items():  # the chosen identity is outlined
            cell.set_edge("link" if value == self.kind.get() else "border")

    def reset_steps(self) -> None:
        for key in self.rows:
            self.set_step(key, WAITING, "")

    def set_step(self, key: str, state: str, detail: str = "") -> None:
        if not self.exists() or key not in self.rows:
            return
        mark, text = self.rows[key]
        mark.configure(text=MARK[state], foreground=theme.color(ROLE[state]))
        text.configure(text=detail)
        if detail:
            text.pack(anchor="w")
        else:
            text.pack_forget()  # the step's name alone, in the middle of its row

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        if not self.exists():
            return
        for button in (self.check_btn, self.other_btn):
            button.configure(state="disabled" if busy else "normal")
        self._sync()

    def _say(self, headline: str, hint: str = "", role: str = "text") -> None:
        if self.exists():
            self.headline.configure(text=headline, foreground=theme.color(role))
            self.hint.configure(text=hint)

    # ------------------------------------------------------------------ check
    def start(self, save: bool = True, other_account: bool = False) -> None:
        """Save the choice (if it changed) and run the check; the window shows each step as it comes in."""
        if self.busy:
            return
        if save:
            values, problem = identity.check(self.kind.get(), self.client.get(), self.tenant.get())
            if problem:
                self._say(problem, "", "error")
                return
            self.app.apply_identity(values)
        self.reset_steps()
        self._say("Checking ...", "")
        self._set_busy(True)
        self.set_step(setup_check.SIGN_IN, RUNNING, "Windows may ask you to sign in")
        self.app.run_setup_check(self, other_account)

    # called on the UI thread by the app while the check runs
    def step_done(self, check: Check) -> None:
        self.set_step(check.key, OK if check.ok else FAILED, "" if not check.ok else check.detail)
        keys = [k for k, _ in setup_check.STEPS]
        nxt = keys.index(check.key) + 1
        if check.ok and nxt < len(keys) or (check.key != setup_check.SIGN_IN and nxt < len(keys)):
            self.set_step(keys[nxt], RUNNING, "")

    def finished(self, checks: list[Check]) -> None:
        self._set_busy(False)
        if not self.exists():
            return
        done = {c.key for c in checks}
        for key in self.rows:
            if key not in done:
                self.set_step(key, SKIPPED, "not checked")
        problem = setup_check.first_problem(checks)
        if setup_check.working(checks):
            self.check_btn.configure(text="Check again")
            self.close_btn.configure(text="Done")
            if problem is None:
                self._say(WORKING, "", "neg")
            else:
                self._say(WORKING_PARTLY + " " + problem.detail, problem.hint + " Everything else runs in the notification area.", "text")
        else:
            self.check_btn.configure(text="Check again")
            self._say(NOT_YET + " " + (problem.detail if problem else "the check did not finish."), problem.hint if problem else "", "error")

