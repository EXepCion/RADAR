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
from .richtext import stable_label
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
    def __init__(self, root: tk.Tk, app: "App", run_now: bool = False):
        self.app = app
        self.busy = False
        kind, client, tenant = identity.current(app.cfg.get("auth", default={}) or {})
        top = self.top = theme.new_window(root)
        top.title("Set up RADAR")
        top.geometry(f"{px(WIDTH)}x{px(700)}")
        top.resizable(False, False)
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.app_icon(32), master=root)
        top.iconphoto(False, self._icon)
        wrap = px(WIDTH - 40 - 28)
        full = px(WIDTH - 40)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(4)))
        header.pack(fill="x")
        ttk.Label(header, text="Set up RADAR", style="Title.TLabel").pack(fill="x")
        ttk.Label(header, text=INTRO, style="Muted.TLabel", justify="left", wraplength=full).pack(fill="x", pady=(px(4), 0))

        footer = ttk.Frame(top, padding=(px(20), px(4), px(20), px(14)))
        footer.pack(side="bottom", fill="x")
        self.close_btn = ttk.Button(footer, text="Close", command=top.destroy)
        self.close_btn.pack(side="right")
        self.check_btn = ttk.Button(footer, text="Save and check", style="Accent.TButton", command=self.start)
        self.check_btn.pack(side="right", padx=(0, px(6)))
        self.other_btn = ttk.Button(footer, text="Use a different account", command=lambda: self.start(other_account=True))
        self.other_btn.pack(side="right", padx=(0, px(6)))
        ttk.Button(footer, text="How to register an application", command=lambda: app.open_link(identity.HELP_URL)).pack(side="left")

        body = ttk.Frame(top, padding=(px(20), px(10), px(20), 0))
        body.pack(fill="both", expand=True)
        self.kind = tk.StringVar(value=kind if kind != identity.UNSET else identity.OWN)
        ttk.Radiobutton(body, text="An app registration of our organisation (recommended)", value=identity.OWN,
                        variable=self.kind, command=self._sync).pack(anchor="w")
        own = ttk.Frame(body, padding=(px(28), px(2), 0, px(8)))
        own.pack(fill="x")
        ttk.Label(own, text=OWN_TEXT, style="Muted.TLabel", justify="left", wraplength=wrap).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(own, text="Application (client) ID").grid(row=1, column=0, sticky="w", pady=(px(8), 0))
        self.client = tk.StringVar(value=client if kind == identity.OWN else "")
        self.client_entry = ttk.Entry(own, textvariable=self.client, width=44)
        self.client_entry.grid(row=1, column=1, sticky="w", padx=(px(10), 0), pady=(px(8), 0))
        ttk.Label(own, text="Directory (tenant) ID or domain").grid(row=2, column=0, sticky="w", pady=(px(6), 0))
        self.tenant = tk.StringVar(value=tenant if kind == identity.OWN else "")
        self.tenant_entry = ttk.Entry(own, textvariable=self.tenant, width=44)
        self.tenant_entry.grid(row=2, column=1, sticky="w", padx=(px(10), 0), pady=(px(6), 0))
        ttk.Radiobutton(body, text="Quick start: the Azure CLI identity", value=identity.AZURE_CLI,
                        variable=self.kind, command=self._sync).pack(anchor="w", pady=(px(2), 0))
        cli = ttk.Frame(body, padding=(px(28), px(2), 0, px(6)))
        cli.pack(fill="x")
        ttk.Label(cli, text=CLI_TEXT, style="Muted.TLabel", justify="left", wraplength=wrap).pack(anchor="w")

        ttk.Separator(body).pack(fill="x", pady=(px(6), px(8)))
        ttk.Label(body, text="Connection check", font=theme.FONT_BOLD).pack(anchor="w")
        steps = ttk.Frame(body, padding=(0, px(4), 0, 0))
        steps.pack(fill="x")
        steps.columnconfigure(2, weight=1)
        self.rows: dict[str, tuple[ttk.Label, ttk.Label]] = {}
        for i, (key, title) in enumerate(setup_check.STEPS):
            mark = ttk.Label(steps, text=MARK[WAITING], width=2)
            mark.grid(row=i, column=0, sticky="w")
            ttk.Label(steps, text=title, width=28).grid(row=i, column=1, sticky="w")
            detail = ttk.Label(steps, text="", style="Muted.TLabel")
            detail.grid(row=i, column=2, sticky="w")
            self.rows[key] = (mark, detail)
        self.headline = ttk.Label(body, text="", justify="left", wraplength=full)
        self.headline.pack(fill="x", pady=(px(8), 0))
        self.hint = stable_label(body, LONGEST, width=full)  # fixed height: nothing moves when the result arrives
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

    def reset_steps(self) -> None:
        for key in self.rows:
            self.set_step(key, WAITING, "")

    def set_step(self, key: str, state: str, detail: str = "") -> None:
        if not self.exists() or key not in self.rows:
            return
        mark, text = self.rows[key]
        mark.configure(text=MARK[state], foreground=theme.color(ROLE[state]))
        text.configure(text=detail)

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

