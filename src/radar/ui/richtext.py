"""Read-only, word-wrapping text with clickable entities (users, IPs, apps, log IDs ...) and right-click menus,
plus the same menus for table rows. What a click does is decided in radar.linkify / App.entity_action."""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk
from typing import Any, Callable

from .. import linkify
from ..linkify import Entity
from . import theme
from .theme import px


class StatusLine:
    """A label for messages ("Looking up ...", errors) that also shows what hovering a link would do."""

    def __init__(self, label: tk.Widget, default: str = ""):
        self.label = label
        self._message, self._error = default, False
        self.label.configure(text=default)

    def show(self, text: str, error: bool = False) -> None:
        self._message, self._error = text, error
        self._paint(text, error)

    def hover(self, text: str) -> None:
        self._paint(text, False)

    def unhover(self) -> None:
        self._paint(self._message, self._error)

    @property
    def text(self) -> str:
        return self._message

    def _paint(self, text: str, error: bool) -> None:
        try:
            self.label.configure(text=text, foreground=theme.color("error" if error else "muted"))
        except tk.TclError:
            pass  # window closed while a lookup was running


def wrapped_lines(widget: tk.Misc, text: str, width: int, font: str = theme.FONT) -> int:
    """Number of lines ``text`` takes when word-wrapped at ``width`` px (the way a tk.Label wraps)."""
    def measure(s: str) -> int:
        return int(widget.tk.call("font", "measure", font, s))

    lines = 0
    for paragraph in text.split("\n"):
        lines += 1
        line = ""
        for word in paragraph.split(" "):
            trial = f"{line} {word}" if line else word
            if line and measure(trial) > width:
                lines += 1
                line = word
            else:
                line = trial
    return lines


def stable_label(parent: tk.Misc, template: str = "", width: int = 0, min_lines: int = 1, max_lines: int = 5,
                 font: str = theme.FONT, **kw: Any) -> tk.Label:
    """A message label whose height never depends on the message, so nothing below it moves when data arrives.

    The height is what ``template`` (the longest message the label can show) needs at the current width; it only
    changes when the user resizes the window. ``width`` is the width the label will have when the window opens."""
    options = dict(font=font, anchor="nw", justify="left", bd=0, padx=0, pady=0, highlightthickness=0,
                   background=theme.color("window"), foreground=theme.color("muted"))
    options.update(kw)
    label = tk.Label(parent, **options)
    state = {"width": -1}

    def fit(width_px: int) -> None:
        if width_px < 2 or width_px == state["width"]:
            return
        state["width"] = width_px
        lines = wrapped_lines(label, template, width_px, font) if template else min_lines
        label.configure(wraplength=width_px, height=max(min_lines, min(max_lines, lines)))

    fit(width or px(600))
    label.bind("<Configure>", lambda e: fit(e.width), add="+")
    return label


class StackedNotebook(ttk.Notebook):
    """A notebook that switches pages without flicker.

    ttk.Notebook unmaps the old page and maps the new one; for a moment the empty pane (window colour) shows before
    the new page has painted - tables visibly flash. Here the pages stay mapped in one stack that covers the pane
    area, and switching only raises the chosen page. Create pages with ``.stack`` as parent and add them with
    ``add_page``; everything else (tab texts, select, index, <<NotebookTabChanged>>) is the normal notebook."""

    def __init__(self, parent: tk.Misc, **kw: Any):
        super().__init__(parent, **kw)
        self.stack = ttk.Frame(self)
        self.stack.rowconfigure(0, weight=1)
        self.stack.columnconfigure(0, weight=1)
        self.pages: list[tk.Misc] = []
        self._panes: list[ttk.Frame] = []
        # on a bind tag of its own: a window binding its own <<NotebookTabChanged>> handler cannot replace this one
        tag = f"StackedNotebook{id(self)}"
        self.bindtags((tag,) + tuple(self.bindtags()))
        self.bind_class(tag, "<<NotebookTabChanged>>", lambda _e: self._raise())

    def add_page(self, page: tk.Misc, text: str) -> None:
        pane = ttk.Frame(self)  # the (empty) pane the notebook itself manages; the stack lies over it
        pane.bind("<Configure>", lambda _e: self.fit(), add="+")
        self._panes.append(pane)
        self.pages.append(page)
        page.grid(row=0, column=0, sticky="nsew")
        self.add(pane, text=text)
        self._raise()

    def current(self) -> int:
        try:
            return self.index(self.select())
        except tk.TclError:
            return 0

    def fit(self) -> None:
        """Lay the stack exactly over the pane area (called on every resize, and before the window is shown)."""
        if not self._panes:
            return
        pane = self._panes[self.current()]
        if pane.winfo_width() > 1 and pane.winfo_height() > 1:
            self.stack.place(x=pane.winfo_x(), y=pane.winfo_y(), width=pane.winfo_width(), height=pane.winfo_height())
            self.stack.tkraise()

    def _raise(self) -> None:
        if self.pages:
            self.pages[self.current()].tkraise()
        self.fit()


LINK_ICON = 13  # px: the link icon in front of a link inside a text
LINK_HINT = "Text with the link icon in front is a link"


class LinkHandler:
    """Click / right-click behaviour of entities, shared by the texts and tables of one window."""

    def __init__(self, app: Any, widget: tk.Misc, status: StatusLine, alert: Any = None):
        self.app, self.widget, self.status, self.alert = app, widget, status, alert

    def hint(self, entity: Entity) -> str:
        acts = linkify.actions(entity)
        if not acts:
            return f"Click to copy {entity.short}"
        return f"Click: {acts[0][0]}   ·   right-click: more options"

    def default(self, entity: Entity, row: dict | None = None) -> None:
        acts = linkify.actions(entity)
        if acts:
            self.run(entity, acts[0][1], row)
        else:
            self.copy(entity.value)

    def run(self, entity: Entity, action: str, row: dict | None = None) -> None:
        self.app.entity_action(entity, action, row=row, alert=self.alert, status=self.status.show)

    def copy(self, text: str, what: str = "") -> None:
        self.widget.clipboard_clear()
        self.widget.clipboard_append(text)
        shown = text if len(text) <= 80 else text[:77] + "..."
        self.status.show(f"Copied {what or shown}")

    def entity_items(self, entity: Entity, row: dict | None = None) -> list[tuple[str, Callable[[], None]]]:
        items = [(label, lambda a=action: self.run(entity, a, row)) for label, action in linkify.actions(entity)]
        return items + [(f"Copy  {entity.short}", lambda: self.copy(entity.value))]

    def popup(self, event: tk.Event, groups: list[tuple[str, list[tuple[str, Callable[[], None]]]]]) -> tk.Menu | None:
        """Context menu of (title, items) groups; a title is shown greyed out when there are several groups."""
        groups = [(t, items) for t, items in groups if items]
        if not groups:
            return None
        menu = tk.Menu(self.widget, tearoff=False)
        for i, (title, items) in enumerate(groups):
            if i:
                menu.add_separator()
            if title and len(groups) > 1:
                menu.add_command(label=title, state="disabled")
            for label, fn in items:
                menu.add_command(label=label, command=fn)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return menu


def autoscroll(scrollbar: ttk.Scrollbar) -> Callable[[str, str], None]:
    """yscrollcommand that hides the (grid-managed) scrollbar while everything fits."""
    def update(first: str, last: str) -> None:
        if float(first) <= 0.0 and float(last) >= 1.0:
            scrollbar.grid_remove()
        else:
            scrollbar.grid()
        scrollbar.set(first, last)
    return update


class RichText(tk.Text):
    def __init__(self, parent: tk.Misc, links: LinkHandler | None = None, **kw: Any):
        c = theme.color
        options = dict(wrap="word", height=6, relief="flat", borderwidth=0, highlightthickness=1,
                       highlightbackground=c("border"), highlightcolor=c("border"), font=theme.FONT,
                       padx=px(12), pady=px(10), cursor="arrow", background=c("card"), foreground=c("text"),
                       insertwidth=0, insertbackground=c("text"), spacing1=px(2), spacing3=px(2),
                       selectbackground=c("select"), selectforeground=c("text"), inactiveselectbackground=c("select"))
        options.update(kw)
        super().__init__(parent, **options)
        self.links = links
        self.targets: dict[str, tuple[Entity, dict | None]] = {}
        self.actions: dict[str, str] = {}  # link tag -> explicit action (else the entity's first one)
        self._pressed: str | None = None
        self._bold = tkfont.Font(root=self, font=theme.FONT_BOLD)
        self.tag_configure("bold", font=theme.FONT_BOLD)
        self.tag_configure("heading", font=theme.FONT_BOLD, spacing1=px(10), spacing3=px(4))
        self.tag_configure("muted", foreground=c("muted"))
        self.tag_configure("caption", foreground=c("muted"), font=theme.FONT_CAPTION)
        # A link looks like the link buttons of the command bar: the link icon in front of normal text (no blue,
        # no underline). Under the mouse it is underlined and the pointer becomes a hand.
        self.tag_configure("link")
        self.tag_configure("link_hover", underline=True)
        self.tag_configure("pos", foreground=c("pos"))
        self.tag_configure("neg", foreground=c("neg"))
        self.tag_configure("mono", font=theme.FONT_MONO)
        self.tag_raise("sel")
        self.tag_bind("link", "<Enter>", self._enter)
        self.tag_bind("link", "<Leave>", self._leave)
        self.tag_bind("link", "<ButtonPress-1>", self._press)
        self.tag_bind("link", "<ButtonRelease-1>", self._release)
        self.bind("<Button-1>", lambda _e: self.focus_set(), add="+")
        self.bind("<Button-3>", self._context)
        self.bind("<Control-a>", self._select_all)
        self.bind("<Control-A>", self._select_all)
        self.configure(state="disabled")

    # ------------------------------------------------------------- writing
    def clear(self) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")
        for tag in self.targets:
            self.tag_delete(tag)
        self.targets.clear()
        self.actions.clear()

    def write(self, text: str, *tags: str) -> None:
        if text:
            self.configure(state="normal")
            self.insert("end", text, tags)
            self.configure(state="disabled")

    def write_link(self, text: str, entity: Entity, row: dict | None = None, tags: tuple[str, ...] = (),
                   action: str | None = None) -> None:
        """A link; a click runs ``action`` (an action id of linkify.ACTIONS) or the entity's first action."""
        tag = f"target{len(self.targets)}"
        self.targets[tag] = (entity, row)
        if action:
            self.actions[tag] = action
        image = theme.icon(self, "open", "link", LINK_ICON)
        if image is not None:  # the icon belongs to the link: same tags, so a click on it works too
            self.configure(state="normal")
            self.image_create("end", image=image, padx=px(2), align="center")
            for name in ("link", tag, *tags):
                self.tag_add(name, "end-2c", "end-1c")
            self.configure(state="disabled")
        self.write(text, "link", tag, *tags)

    def write_value(self, text: str, field: str = "", row: dict | None = None, tags: tuple[str, ...] = ()) -> None:
        """``text`` with every recognised entity (see linkify.find_entities) as a link."""
        text = str(text)
        pos = 0
        for e in linkify.find_entities(text, field) if self.links else []:
            self.write(text[pos:e.start], *tags)
            self.write_link(text[e.start:e.end], e, row, tags)
            pos = e.end
        self.write(text[pos:], *tags)

    def set_key_width(self, names: list[str], cap: int = 260, indent: int = 0) -> int:
        """Tab stop after the longest field name; wrapped value lines hang under the value column. ``indent``:
        the left margin of the block the fields sit in (a card block)."""
        width = min(px(cap), max([self._bold.measure(f"{n}:") for n in names] + [px(60)]) + px(14))
        self.configure(tabs=(indent + width,))
        self.tag_configure("field", lmargin2=indent + width)
        return width

    def card_blocks(self, padding: int = 20) -> int:
        """Prepare this text to show cards: blocks on the window background, written with the 'card' tag
        (see begin_card / end_card). Returns the inner left margin in px."""
        pad = px(padding)
        c = theme.color
        self.configure(background=c("window"), padx=0, pady=0, highlightthickness=0)
        self.tag_configure("card", background=c("card"), lmargin1=pad, lmargin2=pad, rmargin=pad,
                           lmargincolor=c("card"), rmargincolor=c("card"))
        self.tag_configure("card_pad", font=theme.FONT_PAD)
        self.tag_configure("card_gap", font=theme.FONT_PAD)
        self.tag_configure("card_heading", font=theme.FONT_BOLD, spacing3=px(6))
        self.tag_configure("field", spacing1=px(3), spacing3=px(3))
        for tag in ("heading", "field", "link", "muted", "pos", "neg", "bold"):
            self.tag_raise(tag, "card")  # their margins / colours win over the card's
        return pad

    def begin_card(self, title: str = "", first: bool = False) -> None:
        if not first:
            self.write("\n", "card_gap")
        self.write("\n", "card", "card_pad")
        if title:
            self.write(f"{title}\n", "card", "card_heading")

    def end_card(self) -> None:
        self.write("\n", "card", "card_pad")

    def write_field(self, name: str, value: Any, row: dict | None = None, kind_field: str | None = None,
                    name_tag: str = "bold", tags: tuple[str, ...] = ()) -> None:
        tags = ("field", *tags)
        self.write(f"{name}:" if name_tag == "bold" else name, name_tag, *tags)
        self.write("\t", *tags)
        for i, line in enumerate(str(value).split("\n")):
            if i:
                self.write("\n\t", *tags)
            self.write_value(line, kind_field or name, row, tags)
        self.write("\n", *tags)

    def auto_height(self, max_lines: int = 12) -> None:
        """Keep the widget exactly as tall as its wrapped content (re-fitted whenever its width changes)."""
        def fit(_e: tk.Event | None = None) -> None:
            try:
                self.tk.call(self._w, "sync")  # line metrics are computed lazily; bring them up to date
                breaks = self.count("1.0", "end-1c", "displaylines")  # line breaks crossed, not lines
                lines = int(breaks[0] if isinstance(breaks, tuple) else breaks or 0) + 1
                lines = max(1, min(max_lines, lines))
                if int(self.cget("height")) != lines:
                    self.configure(height=lines)
            except (tk.TclError, TypeError, ValueError):
                pass
        self.bind("<Configure>", fit, add="+")
        self.after_idle(fit)

    def text_height(self) -> int:
        """Pixels needed to show everything (valid once the widget is laid out)."""
        try:
            self.update_idletasks()
            self.tk.call(self._w, "sync")
            lines = self.count("1.0", "end", "ypixels")
            return int(lines[0] if isinstance(lines, tuple) else lines or 0) + 2 * int(str(self.cget("pady")))
        except (tk.TclError, TypeError, ValueError):
            return 0

    # -------------------------------------------------------------- events
    def target_at(self, index: str) -> str | None:
        return next((t for t in self.tag_names(index) if t in self.targets), None)

    def _enter(self, _e: tk.Event) -> None:
        self.configure(cursor="hand2")
        tag = self.target_at("current")
        self.tag_remove("link_hover", "1.0", "end")
        if tag and self.tag_ranges(tag):
            self.tag_add("link_hover", *self.tag_ranges(tag))
        if tag and self.links:
            entity = self.targets[tag][0]
            action = self.actions.get(tag)
            label = next((lbl for lbl, a in linkify.actions(entity) if a == action), "") if action else ""
            self.links.status.hover(f"Click: {label}   ·   right-click: more options" if label
                                    else self.links.hint(entity))

    def _leave(self, _e: tk.Event) -> None:
        self.configure(cursor="arrow")
        self.tag_remove("link_hover", "1.0", "end")
        if self.links:
            self.links.status.unhover()

    def _press(self, _e: tk.Event) -> None:
        self._pressed = self.target_at("current")

    def _release(self, _e: tk.Event) -> None:
        tag, self._pressed = self._pressed, None
        if not tag or tag != self.target_at("current") or self.tag_ranges("sel") or not self.links:
            return  # a drag to select text is not a click
        entity, row = self.targets[tag]
        if tag in self.actions:
            self.links.run(entity, self.actions[tag], row)
        else:
            self.links.default(entity, row)

    def _select_all(self, _e: tk.Event) -> str:
        self.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _context(self, event: tk.Event) -> None:
        if not self.links:
            return
        groups = []
        tag = self.target_at(f"@{event.x},{event.y}")
        if tag:
            entity, row = self.targets[tag]
            groups.append((entity.short, self.links.entity_items(entity, row)))
        items = []
        if self.tag_ranges("sel"):
            items.append(("Copy selection", lambda: self.links.copy(self.get("sel.first", "sel.last"), "the selection")))
        items.append(("Copy all text", lambda: self.links.copy(self.get("1.0", "end-1c"), "all text")))
        groups.append(("", items))
        self.links.popup(event, groups)


def scrolled_text(parent: tk.Misc, links: LinkHandler | None, **kw: Any) -> RichText:
    """A RichText with an automatic vertical scrollbar, filling ``parent`` (which must use no other manager)."""
    text = RichText(parent, links, **kw)
    sb = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=autoscroll(sb))
    text.grid(row=0, column=0, sticky="nsew")
    sb.grid(row=0, column=1, sticky="ns")
    parent.rowconfigure(0, weight=1)
    parent.columnconfigure(0, weight=1)
    # The scrollbar comes and goes with the amount of text; its place is kept free so that the text does not change
    # its width (and re-wrap) when it does.
    parent.columnconfigure(1, minsize=sb.winfo_reqwidth())
    return text


def card(parent: tk.Misc, padding: int = 14, **kw: Any) -> tk.Frame:
    """A Fluent card: a card-coloured panel on the window background (recoloured with the theme). No outline, like
    the card blocks inside texts (see card_blocks), which a Text widget cannot outline."""
    options = dict(background=theme.color("card"), highlightthickness=0, highlightbackground=theme.color("border"),
                   highlightcolor=theme.color("border"), bd=0, padx=px(padding), pady=px(padding))
    options.update(kw)
    return tk.Frame(parent, **options)


def pill(parent: tk.Misc, text: str, bg_role: str, fg_role: str, font: str | None = None,
         background: str | None = None) -> tk.Canvas:
    """A rounded label (severity badge): antialiased shape image + text, both following theme switches."""
    font = font or theme.FONT_CAPTION_BOLD
    f = tkfont.nametofont(font, root=parent)
    width, height = f.measure(text) + px(20), f.metrics("linespace") + px(4)
    canvas = tk.Canvas(parent, width=width, height=height, highlightthickness=0, bd=0,
                       background=background or theme.color("window"))
    canvas.create_image(0, 0, anchor="nw", image=theme.pill_image(parent, width, height, bg_role))
    canvas.create_text(width // 2, height // 2, text=text, fill=theme.color(fg_role), font=font)
    return canvas


def card_label(parent: tk.Misc, text: str = "", role: str = "text", font: str | None = None, **kw: Any) -> tk.Label:
    """A label on a card (classic Label: its colours follow theme switches)."""
    return tk.Label(parent, text=text, background=theme.color("card"), foreground=theme.color(role),
                    font=font or theme.FONT, bd=0, padx=0, pady=0, anchor="w", justify="left", **kw)


def row_text(row: dict[str, Any], columns: list[str]) -> str:
    return "\n".join(f"{c}: {row.get(c, '')}" for c in columns if str(row.get(c, "")).strip())


def attach_table_menu(tree: ttk.Treeview, links: LinkHandler, row_of: Callable[[str], dict | None]) -> None:
    """Right-click on a table row: actions for the row's log entry and for the entities in the clicked cell."""
    def popup(event: tk.Event) -> None:
        iid = tree.identify_row(event.y)
        row = row_of(iid) if iid else None
        if not iid or row is None:
            return
        tree.selection_set(iid)
        tree.focus(iid)
        columns = list(tree["columns"])
        col_id = tree.identify_column(event.x)
        index = int(col_id[1:]) - 1 if col_id.startswith("#") and col_id[1:].isdigit() else -1
        col = columns[index] if 0 <= index < len(columns) else ""
        cell = str(row.get(col, "")) if col else ""
        groups = []
        primary = linkify.row_entity(row)
        if primary:
            groups.append((primary.short, links.entity_items(primary, row)[:-1]))
        for e in linkify.find_entities(cell, col):
            if primary is None or (e.kind, e.value) != (primary.kind, primary.value):
                groups.append((e.short, links.entity_items(e, row)))
        copy = []
        if cell:
            copy.append((f"Copy {col}", lambda: links.copy(cell)))
        copy.append(("Copy row", lambda: links.copy(row_text(row, [c for c in columns if not c.startswith("_")]),
                                                   "the row")))
        groups.append(("", copy))
        links.popup(event, groups)

    tree.bind("<Button-3>", popup, add="+")


def fit_columns(tree: ttk.Treeview, columns: list[str], rows: list[dict[str, Any]] | list[list[str]],
                widths: dict[str, int] | None = None, cap: int = 360) -> None:
    """Column widths from the content (measured with the table font), capped; ``widths`` overrides."""
    cell = tkfont.nametofont(theme.FONT_TABLE, root=tree)
    head = tkfont.nametofont(theme.FONT_TABLE_BOLD, root=tree)
    pad = px(2 * theme.CELL_PAD + theme.HEADING_TEXT_SHIFT + 14)  # cell padding + Tk's own text inset + slack
    for i, c in enumerate(columns):
        if widths and c in widths:
            width = px(widths[c])
        else:
            values = [r.get(c, "") if isinstance(r, dict) else (r[i] if i < len(r) else "") for r in rows[:200]]
            longest = max([cell.measure(str(v)) for v in values] + [0])
            heading = head.measure(c) + pad + px(theme.HEADING_TEXT_SHIFT + 16)  # room for the sort arrow
            width = min(px(cap), max(px(56), longest + pad, heading))
        # the last column takes up spare room, so the table spans the card like the design (Fluent list)
        tree.column(c, width=width, minwidth=px(40), stretch=(i == len(columns) - 1), anchor="w")
