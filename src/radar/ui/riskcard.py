"""The risk assessment of an alert as a card: the score, large, a bar that fills to it in the colour of the
severity, and every reason with its points (what raises the score in one colour, what lowers it in another).

Written into a RichText that shows cards (``card_blocks``). The same code draws it wherever it is shown - an alert's
details, the alert selected in an incident's window - so it looks the same everywhere.
"""
from __future__ import annotations

import tkinter as tk
from typing import Any

from . import icons, theme
from .theme import px


class RiskCard:
    def __init__(self, text: Any, alert: Any, pad: int, first: bool = True):
        self.text, self.alert = text, alert
        self.progress = 1.0
        indent = pad + px(40)
        text.configure(tabs=(indent - px(8), "right", indent))
        text.tag_configure("score_num", font=theme.FONT_DISPLAY)
        text.tag_configure("bar_line", spacing1=px(2), spacing3=px(12))
        text.tag_configure("factor", lmargin2=indent, spacing3=px(8))
        text.tag_raise("factor", "card")
        text.begin_card("Risk assessment", first=first)
        text.write(str(alert.score), "card", "score_num")
        text.write(f"  / 100 \u00b7 {alert.severity.label}\n", "card", "muted")
        bar = self.bar = tk.Canvas(text, height=px(6), width=px(300), highlightthickness=0, bd=0,
                                   background=theme.color("track"))
        self.fill = bar.create_rectangle(0, 0, 0, px(6), width=0, fill="#%02x%02x%02x" % icons.SEVERITY_RGB[alert.severity])
        text.configure(state="normal")
        text.window_create("end-1c", window=bar)
        text.tag_add("card", "end-2c")
        text.configure(state="disabled")
        text.write("\n", "card", "bar_line")
        text.tag_add("bar_line", "end-3c linestart", "end-1c")

        def fit_bar(_e: tk.Event | None = None) -> None:
            try:
                bar.configure(width=max(px(60), text.winfo_width() - 2 * pad))
                self.draw(self.progress)
            except tk.TclError:
                pass
        self._fit = fit_bar
        text.bind("<Configure>", fit_bar, add="+")
        for points, reason in alert.factors:
            sign = "pos" if points > 0 else "neg" if points < 0 else "muted"
            text.write(f"\t{points:+d}" if points else "\t\u00b10", "card", "factor", "bold", sign)
            text.write("\t", "card", "factor")
            text.write_value(reason, tags=("card", "factor"))
            text.write("\n", "card", "factor")
        text.end_card()
        fit_bar()

    def draw(self, progress: float) -> None:
        """The bar, filled to ``progress`` (0..1) of the score."""
        self.progress = progress
        try:
            width = int(self.bar.cget("width"))  # the configured width (winfo_width lags behind a resize)
            self.bar.coords(self.fill, 0, 0, int(width * self.alert.score / 100 * progress), px(6))
        except tk.TclError:
            pass

    def score_text(self) -> str:
        try:
            return self.text.get("score_num.first", "score_num.last")
        except tk.TclError:
            return ""

    def set_score(self, value: int) -> None:
        t = self.text
        try:
            start = t.index("score_num.first")
            t.configure(state="normal")
            t.delete("score_num.first", "score_num.last")
            t.insert(start, str(value), ("card", "score_num"))
            t.configure(state="disabled")
        except tk.TclError:
            pass

    def animate(self) -> None:
        """The bar grows to the score while the number counts up (instant with animations off)."""
        score = self.alert.score
        theme.animate(self.bar, 700, lambda t: (self.draw(t), self.set_score(int(round(score * t)))))
