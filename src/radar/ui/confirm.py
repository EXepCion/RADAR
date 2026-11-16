"""A question with two answers, in RADAR's own look (a small window that waits for the answer)."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .. import APP_DISPLAY_NAME
from . import theme
from .parts import card
from .theme import px

WIDTH = 460


def ask(root: tk.Misc, parent: tk.Misc | None, heading: str, lines: list[str], question: str,
        yes: str, no: str) -> bool:
    """Show ``heading``, the ``lines`` on a card and the ``question``; True when the ``yes`` button is chosen.
    Enter chooses yes, Escape or closing the window no. Other RADAR windows wait meanwhile."""
    top = theme.new_window(root)
    top.title(APP_DISPLAY_NAME)
    top.resizable(False, False)
    try:
        from PIL import ImageTk

        from . import icons

        top._icon = ImageTk.PhotoImage(icons.bell(32), master=top)  # (kept on the window: Tk holds no reference)
        top.iconphoto(False, top._icon)
    except Exception:  # noqa: BLE001 - a question without its icon is still a question
        pass
    answer = [False]

    def close(value: bool) -> None:
        answer[0] = value
        try:
            top.grab_release()
        except tk.TclError:
            pass
        top.destroy()

    body = ttk.Frame(top, padding=(px(20), px(18), px(20), px(16)))
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=heading, font=theme.FONT_BOLD, wraplength=px(WIDTH), justify="left").pack(anchor="w")
    box = card(body)
    box.pack(fill="x", pady=(px(10), px(12)))
    inner = tk.Frame(box, background=theme.color("card"), padx=px(14), pady=px(8), bd=0, highlightthickness=0)
    inner.pack(fill="x")
    for line in lines:
        ttk.Label(inner, text=line, style="Card.TLabel", wraplength=px(WIDTH - 30), justify="left").pack(anchor="w", pady=px(3))
    ttk.Label(body, text=question, wraplength=px(WIDTH), justify="left").pack(anchor="w")
    buttons = ttk.Frame(body)
    buttons.pack(fill="x", pady=(px(16), 0))
    first = ttk.Button(buttons, text=yes, style="Accent.TButton", command=lambda: close(True))
    first.pack(side="right")
    ttk.Button(buttons, text=no, command=lambda: close(False)).pack(side="right", padx=(0, px(8)))
    top.bind("<Return>", lambda _e=None: close(True))
    top.bind("<Escape>", lambda _e=None: close(False))
    top.protocol("WM_DELETE_WINDOW", lambda: close(False))

    def place() -> None:  # over the window it was asked from (else in the middle of the screen)
        w, h = top.winfo_reqwidth(), top.winfo_reqheight()
        host = parent.winfo_toplevel() if parent is not None and parent.winfo_exists() else None
        if host is not None and host.winfo_viewable():
            x = host.winfo_rootx() + (host.winfo_width() - w) // 2
            y = host.winfo_rooty() + (host.winfo_height() - h) // 3
        else:
            x, y = (top.winfo_screenwidth() - w) // 2, (top.winfo_screenheight() - h) // 3
        top.geometry(f"+{max(0, x)}+{max(0, y)}")

    theme.style_window(top, prepare=place)
    try:
        top.attributes("-topmost", True)  # the reminders are always on top: the question about them is, too
        top.grab_set()
        first.focus_set()
    except tk.TclError:
        pass
    root.wait_window(top)
    return answer[0]
