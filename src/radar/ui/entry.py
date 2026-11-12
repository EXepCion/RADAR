"""Windows showing original log entries: one Entra sign-in record (like the portal's "Activity details") and
the directory audit records of one operation (all entries with the same correlation id)."""
from __future__ import annotations

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
from .richtext import (LinkHandler, StackedNotebook, StatusLine, attach_table_menu, fit_columns, scrolled_text,
                       stable_label)
from .tables import make_sortable
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
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
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
        top.geometry(f"{px(size[0])}x{min(px(size[1]), int(top.winfo_screenheight() * 0.88))}")
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
        frame = ttk.Frame(parent, padding=px(8))
        tree = ttk.Treeview(frame, columns=cols, show="headings")
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
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
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
        self.tabs = StackedNotebook(self.top)  # pages are swapped, not re-mapped: no flash
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


def write_audit(text: Any, r: dict) -> None:
    """One directory audit record into a RichText, with links for the people, apps and objects in it."""
    reason = r.get("resultReason") or ""
    text.set_key_width(["Correlation ID", "Service principal ID", "Additional details", "Operation type"])
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

    targets = r.get("targetResources") or []
    text.write(f"Targets ({len(targets)})\n", "heading")
    text.tag_configure("prop", lmargin1=px(18), lmargin2=px(18))
    text.tag_configure("propval", lmargin1=px(36), lmargin2=px(36))
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
        for p in t.get("modifiedProperties") or []:
            old, new = pretty_value(p.get("oldValue")), pretty_value(p.get("newValue"))
            if not old and not new:
                continue
            text.write(f"{p.get('displayName') or 'Property'}\n", "bold", "prop")
            for label, value in (("old", old), ("new", new)):
                if value:
                    text.write(f"{label}: ", "muted", "propval")
                    text.write_value(value, tags=("propval",))
                    text.write("\n", "propval")
    details = [(d.get("key"), d.get("value")) for d in r.get("additionalDetails") or [] if d.get("value")]
    if details:
        text.write("Additional details\n", "heading")
        for k, v in details:
            text.write_field(str(k), str(v), name_tag="muted")


AUDIT_COLS = ["Time", "Activity", "Initiated by", "Result", "Targets"]
AUDIT_WIDTHS = {"Time": 150, "Activity": 300, "Initiated by": 210, "Result": 90, "Targets": 200}


class AuditWindow(_LogWindow):
    def __init__(self, root: tk.Tk, app: Any, subtitle: str, highlight: str = ""):
        super().__init__(root, "Audit log entries", subtitle, app, size=(1000, 760),
                         longest_status=self._portal_hint("8888-88-88", "W" * 60))
        self.highlight = highlight
        self.records: list[dict] = []
        ttk.Button(self.buttons, text="Open audit logs in Entra", command=self.open_portal).pack(side="left")
        self.copy_json_btn = ttk.Button(self.buttons, text="Copy JSON", command=self.copy_json, state="disabled")
        self.copy_json_btn.pack(side="right", padx=(0, px(6)))
        self.paned = ttk.PanedWindow(self.top, orient="vertical")
        self.paned.pack(fill="both", expand=True, padx=px(20), pady=(px(4), 0))
        # The list is there from the start with fixed columns: nothing is inserted or resized when the entries
        # have loaded.
        frame = ttk.Frame(self.paned)
        tree = self.list = ttk.Treeview(frame, columns=AUDIT_COLS, show="headings", selectmode="browse", height=5)
        for c in AUDIT_COLS:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=px(AUDIT_WIDTHS[c]), stretch=c == AUDIT_COLS[-1], anchor="w")
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.paned.add(frame, weight=0)
        tree.bind("<<TreeviewSelect>>", lambda _e: self._show(int(tree.selection()[0]) if tree.selection() else 0))
        detail = ttk.Frame(self.paned, padding=(0, px(8), 0, 0))
        self.text = scrolled_text(detail, self.links, height=12)
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

    def _show(self, index: int) -> None:
        self.text.clear()
        if 0 <= index < len(self.records):
            write_audit(self.text, self.records[index])
            self.text.yview_moveto(0)

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
