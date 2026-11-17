"""Windows showing original log entries: one Entra sign-in record (like the portal's "Activity details") and
the directory audit records of one operation (all entries with the same correlation id)."""
from __future__ import annotations

from .. import timefmt
import json
import re
import tkinter as tk
import webbrowser
from datetime import datetime, timezone
from tkinter import ttk
from typing import Any

from PIL import ImageTk

from .. import linkify
from ..linkify import Entity
from . import icons, theme
from .richtext import (LinkHandler, StatusLine, attach_table_menu, fit_columns, scrolled_text,
                       stable_label)
from .tables import make_sortable
from .cardtable import CardTable
from .parts import UnderlineTabs
from .theme import px

SIGNIN_LOGS_URL = linkify.SIGNIN_LOGS_URL
AUDIT_LOGS_URL = linkify.AUDIT_LOGS_URL

_FRACTION = re.compile(r"\.(\d+)")


def _local(value: str | None) -> str:
    """Graph UTC timestamp (up to 7 fraction digits) -> local 'YYYY-MM-DD HH:MM:SS'."""
    if not value:
        return ""
    try:
        text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value.replace("Z", "+00:00"), count=1)
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return timefmt.sortable(dt, seconds=True)
    except ValueError:
        return value


def _fmt(value: Any) -> str:
    if value is None or value == "" or value == []:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(_fmt(v) for v in value if _fmt(v))
    if isinstance(value, dict):
        return ", ".join(f"{k}: {_fmt(v)}" for k, v in value.items() if _fmt(v))
    return str(value)


Table = tuple[list[str], list[list[str]], list[Entity | None]]


def signin_sections(r: dict[str, Any]) -> list[tuple[str, list[tuple[str, str]] | Table]]:
    """Sections (title, key/value rows) or (title, (columns, rows, entity per row)) for a Graph signIn record."""
    status = r.get("status") or {}
    loc = r.get("location") or {}
    geo = loc.get("geoCoordinates") or {}
    dev = r.get("deviceDetail") or {}
    basic = [
        ("Date", _local(r.get("createdDateTime"))),
        ("Request ID", r.get("id")),
        ("Correlation ID", r.get("correlationId")),
        ("Status", "Success" if status.get("errorCode") == 0 else f"Failure ({status.get('errorCode')})"),
        ("Failure reason", status.get("failureReason")),
        ("Additional details", status.get("additionalDetails")),
        ("User", f"{r.get('userDisplayName') or ''} <{r.get('userPrincipalName') or ''}>"),
        ("User ID", r.get("userId")),
        ("User type", r.get("userType")),
        ("Application", f"{r.get('appDisplayName') or ''} ({r.get('appId') or ''})"),
        ("Resource", f"{r.get('resourceDisplayName') or ''} ({r.get('resourceId') or ''})"),
        ("Sign-in type", _fmt(r.get("signInEventTypes"))),
        ("Client app", r.get("clientAppUsed")),
        ("User agent", r.get("userAgent")),
        ("Authentication protocol", r.get("authenticationProtocol")),
        ("Original transfer method", r.get("originalTransferMethod")),
        ("Incoming token type", r.get("incomingTokenType")),
        ("Token protection", _fmt(r.get("signInTokenProtectionStatus"))),
        ("Session ID", r.get("sessionId")),
        ("Unique token identifier", r.get("uniqueTokenIdentifier")),
        ("Cross-tenant access", r.get("crossTenantAccessType")),
        ("Home tenant", r.get("homeTenantId")),
        ("Resource tenant", r.get("resourceTenantId")),
    ]
    location = [
        ("IP address", r.get("ipAddress")),
        ("Autonomous system (ASN)", f"AS{r.get('autonomousSystemNumber')}" if r.get("autonomousSystemNumber") else ""),
        ("City / state", ", ".join(x for x in (loc.get("city"), loc.get("state")) if x)),
        ("Country", loc.get("countryOrRegion")),
        ("Coordinates", f"{geo.get('latitude')}, {geo.get('longitude')}" if geo.get("latitude") is not None else ""),
        ("Network locations", "; ".join(f"{n.get('networkType')}: {_fmt(n.get('networkNames'))}"
                                        for n in r.get("networkLocationDetails") or [])),
        ("Through Global Secure Access", _fmt(r.get("isThroughGlobalSecureAccess"))),
    ]
    device = [
        ("Device ID", dev.get("deviceId")),
        ("Device name", dev.get("displayName")),
        ("Operating system", dev.get("operatingSystem")),
        ("Browser", dev.get("browser")),
        ("Join type", dev.get("trustType")),
        ("Compliant", _fmt(dev.get("isCompliant"))),
        ("Managed", _fmt(dev.get("isManaged"))),
    ]
    auth_cols = ["Time", "Step", "Method", "Detail", "Succeeded", "Result"]
    auth_rows = [[_local(d.get("authenticationStepDateTime")), _fmt(d.get("authenticationStepRequirement")),
                  _fmt(d.get("authenticationMethod")), _fmt(d.get("authenticationMethodDetail")),
                  _fmt(d.get("succeeded")), _fmt(d.get("authenticationStepResultDetail"))]
                 for d in r.get("authenticationDetails") or []]
    mfa = r.get("mfaDetail") or {}
    auth_summary = [("Requirement", r.get("authenticationRequirement")),
                    ("MFA method", _fmt(mfa.get("authMethod"))), ("MFA detail", _fmt(mfa.get("authDetail")))]
    ca_cols = ["Policy", "Result", "Grant controls", "Session controls"]
    policies = sorted(r.get("appliedConditionalAccessPolicies") or [],
                      key=lambda p: (p.get("result") in ("notApplied", "notEnabled"), p.get("displayName") or ""))
    ca_rows = [[_fmt(p.get("displayName")), _fmt(p.get("result")), _fmt(p.get("enforcedGrantControls")),
                _fmt(p.get("enforcedSessionControls"))] for p in policies]
    ca_entities = [Entity("policy", p["id"]) if p.get("id") else None for p in policies]
    risk = [
        ("Risk level during sign-in", r.get("riskLevelDuringSignIn")),
        ("Aggregated risk level", r.get("riskLevelAggregated")),
        ("Risk state", r.get("riskState")),
        ("Risk detail", r.get("riskDetail")),
        ("Risk detections", _fmt(r.get("riskEventTypes_v2") or r.get("riskEventTypes"))),
        ("Flagged for review", _fmt(r.get("flaggedForReview"))),
    ]
    return [
        ("Basic info", [(k, _fmt(v)) for k, v in basic]),
        ("Location", [(k, _fmt(v)) for k, v in location]),
        ("Device", [(k, _fmt(v)) for k, v in device]),
        ("Authentication", [(k, _fmt(v)) for k, v in auth_summary]),
        ("Auth steps", (auth_cols, auth_rows, [None] * len(auth_rows))),
        (f"Conditional Access ({_fmt(r.get('conditionalAccessStatus'))})", (ca_cols, ca_rows, ca_entities)),
        ("Risk", [(k, _fmt(v)) for k, v in risk]),
    ]


#: fields whose GUIDs mean something else in a sign-in record than in an alert
SIGNIN_KIND_FIELDS = {"Correlation ID": "sign-in correlation id"}


class _LogWindow:
    """Shared frame: header with title/subtitle/status, button bar, link handling."""

    def __init__(self, root: tk.Tk, title: str, subtitle: str, app: Any = None, size: tuple[int, int] = (900, 660),
                 longest_status: str = ""):
        """``longest_status``: the longest message the status line shows; its room is reserved from the start, so
        the content below does not move when the record has loaded."""
        self.app = app
        top = self.top = theme.new_window(root)
        top.title(title)
        top.geometry(f"{theme.fit_width(top, px(size[0]))}x{min(px(size[1]), int(top.winfo_screenheight() * 0.88))}")
        top.minsize(px(560), px(380))
        top.bind("<Escape>", lambda _e: top.destroy())
        self._icon = ImageTk.PhotoImage(icons.bell(32), master=root)
        top.iconphoto(False, self._icon)

        header = ttk.Frame(top, padding=(px(20), px(16), px(20), px(8)))
        header.pack(fill="x")
        ttk.Label(header, text=title, style="Title.TLabel").pack(fill="x")
        inner = px(size[0] - 40)
        sub = ttk.Label(header, text=subtitle, style="Muted.TLabel", justify="left", wraplength=inner)
        sub.pack(fill="x", pady=(px(4), 0))
        self.status_label = stable_label(header, longest_status, width=inner)
        self.status_label.pack(fill="x", pady=(px(2), 0))
        header.bind("<Configure>", lambda e: sub.configure(wraplength=max(px(200), e.width - px(40))))
        self.status = StatusLine(self.status_label, "Loading from Microsoft Graph...")
        self.links = LinkHandler(app, top, self.status) if app is not None else None
        self.buttons = ttk.Frame(top, padding=(px(20), px(10), px(20), px(14)))
        self.buttons.pack(side="bottom", fill="x")
        ttk.Button(self.buttons, text="Close", command=top.destroy).pack(side="right")
        theme.style_window(top)
        top.lift()
        top.focus_force()

    def exists(self) -> bool:
        try:
            return bool(self.top.winfo_exists())
        except tk.TclError:
            return False

    def show_error(self, message: str) -> None:
        if self.exists():
            self.status.show(f"Could not load the entry: {message}", error=True)

    def _copy(self, text: str, what: str) -> None:
        self.top.clipboard_clear()
        self.top.clipboard_append(text)
        self.status.show(f"Copied {what}.")

    def _kv_tab(self, parent: tk.Misc, rows: list[tuple[str, str]], kind_fields: dict[str, str] | None = None,
                ) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=px(8))
        text = scrolled_text(frame, self.links, height=10)
        shown = [(k, v) for k, v in rows if v]
        text.set_key_width([k for k, _ in shown])
        for k, v in shown:
            text.write_field(k, v, kind_field=(kind_fields or {}).get(k), name_tag="muted")
        return frame

    def _table_tab(self, parent: tk.Misc, cols: list[str], rows: list[list[str]],
                   entities: list[Entity | None]) -> ttk.Frame:
        frame = ttk.Frame(parent)
        tree = CardTable(frame, cols, selectmode="browse", xscroll=True, border=False)  # (the tabs' card is the frame)
        for c in cols:
            tree.heading(c, text=c, anchor="w")
        shown = rows or [["(none)"] + [""] * (len(cols) - 1)]
        fit_columns(tree, cols, shown, cap=420)
        tree.column(cols[-1], stretch=True)
        by_iid: dict[str, dict] = {}
        targets: dict[str, Entity] = {}
        for i, r in enumerate(shown):
            iid = tree.insert("", "end", values=r)
            by_iid[iid] = dict(zip(cols, r))
            if i < len(entities) and entities[i] is not None:
                targets[iid] = entities[i]
        make_sortable(tree, cols)
        if self.links:
            attach_table_menu(tree, self.links, by_iid.get)
            if targets:
                def open_row(e: tk.Event) -> None:
                    iid = tree.identify_row(e.y)
                    if iid in targets:
                        self.links.default(targets[iid])
                tree.bind("<Double-1>", open_row)
        tree.grid(row=0, column=0, sticky="nsew")
        if targets:
            ttk.Label(frame, text="Double-click a policy to open it in Entra.", style="Muted.TLabel").grid(
                row=2, column=0, sticky="w", pady=(px(4), 0))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return frame

    @staticmethod
    def _json_tab(parent: tk.Misc, record: Any) -> ttk.Frame:
        raw = ttk.Frame(parent, padding=px(6))
        c = theme.color
        text = tk.Text(raw, wrap="none", font=theme.FONT_MONO, background=c("card"), foreground=c("text"),
                       relief="flat", highlightthickness=1, highlightbackground=c("border"), highlightcolor=c("border"),
                       selectbackground=c("select"), selectforeground=c("text"), inactiveselectbackground=c("select"),
                       insertbackground=c("text"), padx=px(10), pady=px(8))
        text.insert("1.0", json.dumps(record, indent=2, ensure_ascii=False))
        text.configure(state="disabled")
        text.bind("<Button-1>", lambda _e: text.focus_set(), add="+")
        ys = ttk.Scrollbar(raw, orient="vertical", command=text.yview)
        xs = ttk.Scrollbar(raw, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        raw.rowconfigure(0, weight=1)
        raw.columnconfigure(0, weight=1)
        return raw


class EntryWindow(_LogWindow):
    def __init__(self, root: tk.Tk, request_id: str, subtitle: str, event_type: str = "", app: Any = None):
        super().__init__(root, "Sign-in log entry", subtitle, app, size=(1000, 720),
                         longest_status=self._portal_hint("User sign-ins (non-interactive)", "8888-88-88"))
        self.request_id = request_id
        self.event_type = event_type
        self.record: dict[str, Any] | None = None
        ttk.Button(self.buttons, text="Open in Entra portal", command=self.open_portal).pack(side="left")
        ttk.Button(self.buttons, text="Copy Request ID", command=self.copy_id).pack(side="left", padx=(px(6), 0))
        self.copy_json_btn = ttk.Button(self.buttons, text="Copy JSON", command=self.copy_json, state="disabled")
        self.copy_json_btn.pack(side="right", padx=(0, px(6)))
        self.tabs = UnderlineTabs(self.top)  # pages are swapped, not re-mapped: no flash
        self.tabs.pack(fill="both", expand=True, padx=px(20), pady=(px(4), 0))

    # ----------------------------------------------------------- content
    def show_record(self, record: dict[str, Any]) -> None:
        if not self.exists():
            return
        self.record = record
        self.status.show("Live record from the Entra sign-in logs (Microsoft Graph). Text with the link icon is "
                         "a link "
                         "(right-click for more options).")
        self.copy_json_btn.configure(state="normal")
        for title, content in signin_sections(record):
            if isinstance(content, tuple):
                frame = self._table_tab(self.tabs.stack, *content)
            else:
                frame = self._kv_tab(self.tabs.stack, content, SIGNIN_KIND_FIELDS)
            self.tabs.add_page(frame, title)
        self.tabs.add_page(self._json_tab(self.tabs.stack, record), "Raw JSON")

    # ----------------------------------------------------------- actions
    def copy_id(self) -> None:
        self._copy(self.request_id, f"Request ID {self.request_id}")

    def copy_json(self) -> None:
        if self.record:
            self._copy(json.dumps(self.record, indent=2, ensure_ascii=False), "the record as JSON")

    def open_portal(self) -> None:
        """The portal has no documented deep link to one entry: copy the Request ID and open the log list."""
        self.copy_id()
        tab = "User sign-ins (non-interactive)" if self.event_type == "nonInteractiveUser" else "User sign-ins (interactive)"
        self.status.show(self._portal_hint(tab, self._date()))
        webbrowser.open(SIGNIN_LOGS_URL)

    @staticmethod
    def _portal_hint(tab: str, date: str) -> str:
        return (f"Request ID copied. In Entra: tab '{tab}' > Add filters > Request ID > paste (Ctrl+V) > Apply. "
                f"Set the date range to include {date}.")

    def _date(self) -> str:
        if self.record:
            return _local(self.record.get("createdDateTime"))[:10]
        return "the sign-in date"


# ---------------------------------------------------------------- audit entries
def _decode(value: Any) -> Any:
    """Audit property values are JSON, often JSON strings inside JSON: decode all levels."""
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in "[{\"":
            try:
                return _decode(json.loads(s))
            except ValueError:
                return value
        return value
    if isinstance(value, list):
        return [_decode(v) for v in value]
    if isinstance(value, dict):
        return {k: _decode(v) for k, v in value.items()}
    return value


def pretty_value(value: Any) -> str:
    v = _decode(value)
    if isinstance(v, list) and len(v) == 1:
        v = v[0]  # audit values are mostly one-element lists
    if v in (None, "", [], {}):
        return ""
    if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
        return ", ".join(str(x) for x in v if str(x) != "")
    if isinstance(v, (dict, list)):
        return json.dumps(v, indent=2, ensure_ascii=False)
    return str(v)


# ---- what a change changed: every setting of the old and the new value, side by side
Change = tuple[str, str, str, str]  # (setting, before, after, "changed" | "added" | "removed" | "same")


def _plain(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _settings(value: Any, path: str, out: dict[str, list[str]]) -> None:
    """Every single setting of a (nested) value: {path: its text(s)} - several for a list of plain values."""
    if isinstance(value, dict):
        if not value:
            out.setdefault(path, [])
        for k, v in value.items():
            _settings(v, f"{path}.{k}" if path else str(k), out)
    elif isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value):
        for i, v in enumerate(value):
            # (an entry with an id is that entry wherever it stands: one put in front does not change all others)
            label = (v.get("id") or v.get("Id")) if isinstance(v, dict) else None
            _settings(v, f"{path}[{label if isinstance(label, (str, int)) and label != '' else i}]", out)
    else:
        out.setdefault(path, []).extend(t for t in map(_plain, value if isinstance(value, list) else [value]) if t)


def _whole(value: Any) -> Any:
    v = _decode(value)
    return v[0] if isinstance(v, list) and len(v) == 1 else v  # audit values are mostly one-element lists


def compare(old: Any, new: Any) -> list[Change]:
    """The old and the new value of a modified property, setting by setting. A list is compared entry by entry:
    what was taken out, what was put in (the order of plain values says nothing)."""
    before: dict[str, list[str]] = {}
    after: dict[str, list[str]] = {}
    _settings(_whole(old), "", before)
    _settings(_whole(new), "", after)
    rows: list[Change] = []
    for path in list(after) + [p for p in before if p not in after]:
        a, b = before.get(path, []), after.get(path, [])
        if len(a) <= 1 and len(b) <= 1:
            x, y = (a or [""])[0], (b or [""])[0]
            if x or y:
                rows.append((path, x, y, "same" if x == y else "added" if not x else "removed" if not y else "changed"))
            continue
        rows += [(path, x, "", "removed") for x in a if x not in b]
        rows += [(path, "", y, "added") for y in b if y not in a]
        rows += [(path, x, x, "same") for x in a if x in b]
    return rows


#: what the GUIDs of a setting are, by the last part of its name (for the links)
_SETTING_KINDS = (("user", "user id"), ("application", "app id"), ("serviceprincipal", "app id"))


def _setting_field(path: str) -> str:
    last = path.rsplit(".", 1)[-1].lower()
    return next((field for part, field in _SETTING_KINDS if part in last), "")


def set_compare_columns(text: Any) -> tuple[int, int, int]:
    """Setting | Before | After share the width of the text. Returns the room each has for its text (px)."""
    gap = px(16)
    try:
        width = max(px(560), text.winfo_width() - px(28))
        first = px(18) + int(width * 0.28)   # (the values need the room: an ID is 36 characters)
        second = first + int(width * 0.36)
        # (a line of the comparison does not wrap: write_changes breaks each column inside its own room. Not said
        # with the tag's wrap="none": Tk then puts a link's icon on a line of its own)
        text.tag_configure("diff", tabs=(first, second), lmargin1=px(18), lmargin2=px(18),
                           spacing1=px(2), spacing3=px(2))
        text.tag_configure("diff_old", background=theme.color("sev_high_bg"))
        text.tag_configure("diff_new", background=theme.color("diff_add"))
        return first - px(18) - gap, second - first - gap, px(18) + width - second - gap
    except tk.TclError:
        return px(180), px(180), px(180)


_BREAK = re.compile(r"(\s+|(?<=[,;./_=-]))")


def _wrap(value: str, room: int, measure: Any) -> list[str]:
    """``value`` in lines that fit ``room`` px: broken after a space or a separator, inside a word only when the
    word alone is too long."""
    if not value or measure(value) <= room:
        return [value]
    # what is a link (an ID, an address ...) stays in one piece: broken in two it would be no link any more
    parts, whole, at = [], set(), 0
    for e in linkify.find_entities(value):
        parts += [p for p in _BREAK.split(value[at:e.start]) if p]
        whole.add(len(parts))
        parts.append(value[e.start:e.end])
        at = e.end
    parts += [p for p in _BREAK.split(value[at:]) if p]
    lines, line = [], ""
    for n, part in enumerate(parts):
        if measure(line + part) <= room:
            line += part
            continue
        if line.strip():
            lines.append(line.rstrip())
        line = part.lstrip()
        while n not in whole and measure(line) > room and len(line) > 1:
            n = len(line) - 1
            while n > 1 and measure(line[:n]) > room:
                n -= 1
            lines.append(line[:n])
            line = line[n:]
    if line.strip():
        lines.append(line.rstrip())
    return lines or [value]


def write_changes(text: Any, properties: list[dict], unchanged: bool = False) -> int:
    """The modified properties of a target as one comparison: setting, before, after - what was taken out marked
    in the Before column, what was put in marked in the After column. Returns how many settings stayed as they
    were (shown only with ``unchanged``)."""
    import tkinter.font as tkfont

    rooms = set_compare_columns(text)
    try:
        measure = tkfont.nametofont(theme.FONT, root=text).measure
    except tk.TclError:
        measure = lambda s: px(8) * len(s)  # noqa: E731
    icon = px(22)  # a value that is a link has the link icon in front
    same, head = 0, False
    for p in properties:
        name = p.get("displayName") or "Property"
        rows = compare(p.get("oldValue"), p.get("newValue"))
        same += sum(1 for r in rows if r[3] == "same")
        shown = [r for r in rows if unchanged or r[3] != "same"]
        if not shown:
            continue
        if not head:
            text.write("Setting\tBefore\tAfter\n", "muted", "diff")
            head = True
        if any(r[0] for r in rows):  # a whole object (a policy ...): its settings stand under its name
            text.write(f"{name}\n", "bold", "diff")
        for path, before, after, kind in shown:
            field = _setting_field(path or name)
            old_tags = ("diff", "diff_old") if kind in ("changed", "removed") else ("diff",)
            new_tags = ("diff", "diff_new") if kind in ("changed", "added") else ("diff",)
            columns = [_wrap(path or name, rooms[0], measure), _wrap(before, rooms[1] - icon, measure),
                       _wrap(after, rooms[2] - icon, measure)]
            for k in range(max(len(c) for c in columns)):  # each column wraps inside its own room, side by side
                setting, was, now = ((c[k] if k < len(c) else "") for c in columns)
                text.write(setting + "\t", "diff")
                if was:
                    text.write_value(was, field, tags=old_tags)
                text.write("\t", "diff")
                if now:
                    text.write_value(now, field, tags=new_tags)
                text.write("\n", "diff")
    return same


TARGET_KINDS = {"user": "user", "group": "group", "serviceprincipal": "app", "device": "device"}


def _target_kinds(t: dict, record: dict) -> tuple[str, str]:
    """(kind of the target's name, kind of its id) for links."""
    ttype = str(t.get("type", "")).lower()
    if ttype == "policy" and "conditional access" in str(record.get("activityDisplayName", "")).lower():
        return "policy", "policy"
    if ttype == "application":
        return "app", "guid"
    kind = TARGET_KINDS.get(ttype)
    return (kind or "", kind or "guid")


def audit_summary(r: dict) -> list[str]:
    by = r.get("initiatedBy") or {}
    who = ((by.get("user") or {}).get("userPrincipalName") or (by.get("app") or {}).get("displayName") or "")
    targets = ", ".join(t.get("userPrincipalName") or t.get("displayName") or t.get("id") or ""
                        for t in r.get("targetResources") or [])
    result = r.get("result") or ""
    return [_local(r.get("activityDateTime")), r.get("activityDisplayName") or "", who, result, targets]


def write_audit(text: Any, r: dict, unchanged: bool = False) -> int:
    """One directory audit record into a RichText, with links for the people, apps and objects in it. What was
    modified is a comparison (see write_changes); returns how many settings of it stayed as they were."""
    same = 0
    reason = r.get("resultReason") or ""
    text.set_key_width(["Correlation ID", "Service principal ID", "Additional details", "Operation type"])
    # what was changed comes first: who did it and when is already in the list above
    targets = r.get("targetResources") or []
    text.write(f"Targets ({len(targets)})\n", "heading")
    for t in targets:
        name_kind, id_kind = _target_kinds(t, r)
        name = t.get("userPrincipalName") or t.get("displayName") or ""
        text.write(f"{t.get('type') or 'Object'}:", "bold", "field")
        text.write("\t", "field")
        if name and name_kind and name_kind != "user":
            text.write_link(name, Entity(name_kind, name), tags=("field",))
        elif name:
            text.write_value(name, tags=("field",))
        if t.get("id"):
            text.write("   id ", "muted", "field")
            text.write_link(t["id"], Entity(id_kind, t["id"]), tags=("field",))
        text.write("\n", "field")
        same += write_changes(text, t.get("modifiedProperties") or [], unchanged)
    text.write("Activity\n", "heading")
    for k, v, kind in (("Date", _local(r.get("activityDateTime")), None),
                       ("Activity", r.get("activityDisplayName"), None), ("Category", r.get("category"), None),
                       ("Service", r.get("loggedByService"), None), ("Operation type", r.get("operationType"), None),
                       ("Result", f"{r.get('result') or ''}" + (f" - {reason}" if reason else ""), None),
                       ("Audit ID", r.get("id"), "request id"), ("Correlation ID", r.get("correlationId"), "request id")):
        if v:
            text.write_field(k, v, kind_field=kind, name_tag="muted")
    by = r.get("initiatedBy") or {}
    user, app = by.get("user") or {}, by.get("app") or {}
    text.write("Initiated by\n", "heading")
    if user:
        upn = user.get("userPrincipalName") or ""
        name = user.get("displayName") or ""
        text.write_field("User", f"{name} <{upn}>" if name and upn else upn or name or user.get("id", ""),
                         name_tag="muted")
        for k, v, kind in (("User ID", user.get("id"), "user id"), ("IP address", user.get("ipAddress"), None)):
            if v:
                text.write_field(k, v, kind_field=kind, name_tag="muted")
    if app:
        if app.get("displayName"):
            text.write_field("App", app["displayName"], name_tag="muted")
        for k, v, kind in (("App ID", app.get("appId"), "app id"),
                           ("Service principal ID", app.get("servicePrincipalId"), "app id")):
            if v:
                text.write_field(k, v, kind_field=kind, name_tag="muted")
        text.write("App-only: Entra records no person for actions an app takes with its own credentials.\n", "muted")
    if not user and not app:
        text.write("(not recorded)\n", "muted")

    details = [(d.get("key"), d.get("value")) for d in r.get("additionalDetails") or [] if d.get("value")]
    if details:
        text.write("Additional details\n", "heading")
        for k, v in details:
            text.write_field(str(k), str(v), name_tag="muted")
    return same


AUDIT_COLS = ["Time", "Activity", "Initiated by", "Result", "Targets"]
AUDIT_WIDTHS = {"Time": 200, "Activity": 300, "Initiated by": 210, "Result": 90, "Targets": 200}


class AuditWindow(_LogWindow):
    def __init__(self, root: tk.Tk, app: Any, subtitle: str, highlight: str = ""):
        super().__init__(root, "Audit log entries", subtitle, app, size=(1120, 780),
                         longest_status=self._portal_hint("8888-88-88", "W" * 60))
        self.highlight = highlight
        self.records: list[dict] = []
        ttk.Button(self.buttons, text="Open audit logs in Entra", command=self.open_portal).pack(side="left")
        # a change of a policy names all its settings, old and new: shown is what differs - the rest on demand
        self.unchanged = tk.BooleanVar(self.top, False)
        self.unchanged_box = ttk.Checkbutton(self.buttons, text="Show unchanged settings", variable=self.unchanged,
                                             command=self._show_again, state="disabled")
        self.unchanged_box.pack(side="left", padx=(px(14), 0))
        self.copy_json_btn = ttk.Button(self.buttons, text="Copy JSON", command=self.copy_json, state="disabled")
        self.copy_json_btn.pack(side="right", padx=(0, px(6)))
        self.paned = ttk.PanedWindow(self.top, orient="vertical")
        self.paned.pack(fill="both", expand=True, padx=px(20), pady=(px(4), 0))
        # The list is there from the start with fixed columns: nothing is inserted or resized when the entries
        # have loaded.
        frame = ttk.Frame(self.paned)
        tree = self.list = CardTable(frame, AUDIT_COLS, selectmode="browse", height=3)
        for c in AUDIT_COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(AUDIT_WIDTHS[c]), stretch=c == AUDIT_COLS[-1], anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.paned.add(frame, weight=0)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._show(int(tree.selection()[0]) if tree.selection() else 0))
        detail = ttk.Frame(self.paned, padding=(0, px(8), 0, 0))
        self.text = scrolled_text(detail, self.links, height=12)
        self._text_width = 0
        self.text.bind("<Configure>", self._text_resized, add="+")
        self.paned.add(detail, weight=1)

    def show_records(self, records: list[dict]) -> None:
        if not self.exists():
            return
        self.records = records
        self.copy_json_btn.configure(state="normal")
        n = len(records)
        self.status.show(f"{n} audit entr{'y' if n == 1 else 'ies'} of this operation (same correlation ID), "
                         "live from the Entra audit log." + (" Select one to see it in full." if n > 1 else "")
                         + " Text with the link icon is a link (right-click for more options).")
        first = next((i for i, r in enumerate(records) if r.get("id") == self.highlight), 0)
        tree = self.list
        tree.delete(*tree.get_children())
        for i, r in enumerate(records):
            tree.insert("", "end", iid=str(i), values=audit_summary(r))
        if records:
            tree.selection_set(str(first))  # shows the entry through <<TreeviewSelect>>
            tree.see(str(first))
        self._show(first)

    def _show(self, index: int, keep_place: bool = False) -> None:
        place = self.text.yview()[0]
        self.text.clear()
        same = 0
        if 0 <= index < len(self.records):
            same = write_audit(self.text, self.records[index], unchanged=bool(self.unchanged.get()))
            self.text.yview_moveto(place if keep_place else 0)
        self.unchanged_box.configure(state="normal" if same else "disabled")

    def _text_resized(self, event: tk.Event) -> None:
        """The columns of the comparison follow the width: what is shown is laid out again for it."""
        if abs(event.width - self._text_width) < px(4):
            return
        self._text_width = event.width
        if self.records:
            self._show_again()

    def _show_again(self) -> None:
        sel = self.list.selection()
        self._show(int(sel[0]) if sel else 0, keep_place=True)

    def selected(self) -> dict | None:
        if not self.records:
            return None
        if self.list is not None and self.list.selection():
            return self.records[int(self.list.selection()[0])]
        return self.records[0]

    def copy_json(self) -> None:
        if self.records:
            self._copy(json.dumps(self.records, indent=2, ensure_ascii=False),
                       f"{len(self.records)} audit record(s) as JSON")

    def open_portal(self) -> None:
        rec = self.selected() or {}
        when = _local(rec.get("activityDateTime"))
        if rec.get("activityDisplayName"):
            self._copy(rec["activityDisplayName"], "the activity name")
            self.status.show(self._portal_hint(when[:10] or "the date", rec["activityDisplayName"]))
        webbrowser.open(AUDIT_LOGS_URL)

    @staticmethod
    def _portal_hint(date: str, activity: str) -> str:
        return (f"Entra has no link to one audit entry. In the audit log set the date range to include {date} and "
                f"filter Activity = '{activity}' (copied to the clipboard).")
