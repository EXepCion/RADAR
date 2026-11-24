"""The extension contract. Every monitoring "function" is a :class:`Plugin` subclass.

Minimal plugin (drop it as a .py file into %LOCALAPPDATA%\\RADAR\\plugins)::

    from radar.plugin_api import Plugin, Rule, Finding, Severity

    class RiskyUsers(Plugin):
        id = "risky_users"
        name = "Risky users"
        description = "Alerts on users Entra ID Protection marks as high risk."
        permissions = ["IdentityRiskyUser.Read.All"]

        def run(self, ctx):
            data = ctx.graph.get("/v1.0/identityProtection/riskyUsers",
                                 {"$filter": "riskLevel eq 'high'"})
            return [Finding(key=f"riskyuser|{u['id']}", title=f"High-risk user: {u['userPrincipalName']}",
                            severity=Severity.HIGH) for u in data.get("value", [])]

The plugin then shows up in the tray under *Settings > Detection* and can be enabled/disabled there.
"""
from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:  # pragma: no cover
    from .graph import GraphClient
    from .store import Store


class OperationCancelled(Exception):
    """Raised when the app shuts down while a plugin is running."""


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


@dataclass(frozen=True)
class Rule:
    """An individually switchable detection inside a plugin (shown as a sub-toggle in the tray)."""

    id: str
    name: str
    description: str = ""
    default_enabled: bool = True


@dataclass
class Finding:
    """Something a plugin wants to tell the user about.

    ``key`` must be stable: the same key is treated as the same alert (it is updated, not
    re-raised). Include a time bucket (e.g. the date) in the key if a repeat should alert again.
    """

    key: str
    title: str
    severity: Severity
    summary: str = ""
    rule_id: str = ""
    occurred_at: datetime | None = None
    fields: dict[str, str] = field(default_factory=dict)
    evidence: list[dict[str, str]] = field(default_factory=list)  # keys starting with "_" are hidden in the UI
    recommendation: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)
    score: int | None = None  # 0..100 risk score used for ranking (optional)
    factors: list[tuple[int, str]] = field(default_factory=list)  # (points, reason) explaining the score
    #: UPNs the finding is about (default: taken from the fields User/Account/Invited by/...), used for correlation
    subjects: list[str] = field(default_factory=list)
    #: non-empty = weak context signal of this kind: stored, but only becomes an alert when it correlates
    #: with other activity of the same person (see radar.correlation)
    signal: str = ""
    #: keys of earlier findings this one takes the place of (one alert for what used to be several): their open
    #: alerts leave the reminders and stay in the history, naming this one
    supersedes: list[str] = field(default_factory=list)


class PluginState:
    """Small persistent key/value store private to one plugin (JSON-serialisable values)."""

    def __init__(self, store: "Store", plugin_id: str):
        self._store = store
        self._ns = f"plugin:{plugin_id}"

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.kv_get(self._ns, key, default)

    def set(self, key: str, value: Any) -> None:
        self._store.kv_set(self._ns, key, value)

    def delete(self, key: str) -> None:
        self._store.kv_delete(self._ns, key)

    def clear(self) -> None:
        self._store.kv_delete(self._ns)


class StagedState:
    """A plugin's state for the time of one scan: what the scan writes is held back until :meth:`commit` - which
    happens when the scan's findings are in the alert store. A scan that is stopped, crashes or fails leaves the
    state as it was, so the next scan reads again from where the last complete one ended."""

    _GONE = object()

    def __init__(self, state: PluginState, direct: tuple[str, ...] = ()):
        self._state = state
        self._held: dict[str, Any] = {}
        self._direct = set(direct)  # keys written at once: what was looked up (a cache), no bookmark

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._held:
            return default if self._held[key] is self._GONE else self._held[key]
        return self._state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        if key in self._direct:
            self._state.set(key, value)
        else:
            self._held[key] = value

    def delete(self, key: str) -> None:
        self._held[key] = self._GONE

    def commit(self) -> None:
        for key, value in self._held.items():
            if value is self._GONE:
                self._state.delete(key)
            else:
                self._state.set(key, value)
        self._held = {}


@dataclass
class PluginContext:
    """Everything a plugin may use while running."""

    plugin_id: str
    graph: "GraphClient"
    settings: dict[str, Any]
    enabled_rules: frozenset[str]
    state: PluginState
    data_dir: Path
    log: logging.Logger
    stop_event: threading.Event = field(default_factory=threading.Event)
    status_callback: Callable[[str], None] | None = None
    #: the caller stores the findings itself and then calls :meth:`delivered` (the app does); otherwise what a
    #: plugin wants done "when delivered" is done at once
    defer: bool = False
    #: why this scan could not judge everything (a rule that failed ...): nothing is committed, the next scan
    #: judges it again
    incomplete: list[str] = field(default_factory=list)
    _after: list[Callable[[], None]] = field(default_factory=list, repr=False)

    def when_delivered(self, action: Callable[[], None]) -> None:
        """Do ``action`` once this scan's findings are in the alert store: moving a bookmark, forgetting what
        was waiting to be judged. A bookmark that moved before that would lose what lies behind it."""
        if self.defer:
            self._after.append(action)
        else:
            action()

    def delivered(self) -> None:
        """The findings are stored: do what was waiting for that."""
        actions, self._after[:] = list(self._after), []
        for action in actions:
            action()

    def rule_enabled(self, rule_id: str) -> bool:
        return rule_id in self.enabled_rules

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def set_status(self, text: str) -> None:
        """Short progress/result text shown in the tray submenu of the plugin."""
        if self.status_callback:
            self.status_callback(text)

    def check_cancelled(self) -> None:
        if self.stop_event.is_set():
            raise OperationCancelled()


class Plugin(ABC):
    """Base class for monitoring functions.

    Class attributes describe the plugin; :meth:`run` does the work and returns findings.
    ``run`` is called on a background thread every ``interval_minutes`` while enabled.
    Raise exceptions freely - they are caught, logged and shown in the tray.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    version: str = "1.0"
    default_enabled: bool = True
    default_interval_minutes: int = 15
    #: Graph permissions the plugin needs (informational, shown when access is denied).
    permissions: list[str] = []
    #: Plugin-specific settings, written to config.json under plugins.<id>.settings.
    default_settings: dict[str, Any] = {}
    #: Optional sub-detections that can be toggled individually from the tray.
    rules: list[Rule] = []

    @abstractmethod
    def run(self, ctx: PluginContext) -> list[Finding]:
        raise NotImplementedError

    #: Evidence column holding the id of a log entry that :meth:`fetch_entry` can retrieve.
    entry_id_field: str = ""

    def fetch_entry(self, ctx: PluginContext, evidence_row: dict[str, str]) -> dict[str, Any] | None:
        """Optional: return the full original log record behind an evidence row (shown in the UI)."""
        return None

    def reevaluate(self, ctx: PluginContext, hours: int) -> list[Finding]:
        """Optional: re-run detections over already collected data (``--rescore`` after tuning)."""
        return []
