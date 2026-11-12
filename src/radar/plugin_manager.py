"""Discovers plugins (built-in package + user drop-in folder) and runs them in isolation."""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import pkgutil
import re
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Callable

from . import paths
from .config import ConfigManager
from .graph import GraphClient
from .plugin_api import Finding, Plugin, PluginContext, PluginState
from .store import Store

log = logging.getLogger(__name__)
_ID_RE = re.compile(r"^[a-z0-9_]+$")


@dataclass
class PluginRuntime:
    plugin: Plugin
    source: str
    last_run: datetime | None = None
    last_success: datetime | None = None
    last_error: str | None = None
    status_text: str = ""
    last_findings: int = 0
    running: bool = False

    @property
    def builtin(self) -> bool:
        return self.source == "built-in"


@dataclass
class LoadError:
    source: str
    error: str


class PluginManager:
    def __init__(self, cfg: ConfigManager, store: Store, graph_factory: Callable[[], GraphClient],
                 user_dir: Path, stop_event: threading.Event, builtin_package: str = "radar.plugins"):
        self._cfg = cfg
        self._store = store
        self._graph_factory = graph_factory
        self.user_dir = Path(user_dir)
        self._stop = stop_event
        self._builtin_package = builtin_package
        self._lock = threading.RLock()
        self.runtimes: dict[str, PluginRuntime] = {}
        self.load_errors: list[LoadError] = []
        self.unapproved: list[str] = []  # files in the plugin folder the user has not allowed yet (not loaded)

    # ---------------------------------------------------------- discovery
    def allowed_user_plugins(self) -> list[str]:
        return [str(n) for n in (self._cfg.get("general", "allowed_user_plugins", default=[]) or [])]

    def allow_user_plugin(self, name: str) -> None:
        names = self.allowed_user_plugins()
        if name not in names:
            self._cfg.set("general", "allowed_user_plugins", value=names + [name])
    def discover(self) -> None:
        with self._lock:
            previous = self.runtimes
            self.runtimes = {}
            self.load_errors = []
            self.unapproved = []
            self._load_builtin()
            self._load_user_dir()
            for pid, rt in self.runtimes.items():  # keep run history across reloads
                old = previous.get(pid)
                if old:
                    rt.last_run, rt.last_success, rt.last_error = old.last_run, old.last_success, old.last_error
                    rt.status_text, rt.last_findings = old.status_text, old.last_findings
                self._cfg.ensure_plugin(rt.plugin)
            log.info("Plugins: %s; load errors: %d", ", ".join(self.runtimes) or "none", len(self.load_errors))

    def _register(self, module: ModuleType, source: str) -> None:
        found = 0
        for obj in list(vars(module).values()):
            if not (inspect.isclass(obj) and issubclass(obj, Plugin) and obj is not Plugin):
                continue
            if inspect.isabstract(obj) or not obj.__module__.startswith(module.__name__):
                continue
            pid = getattr(obj, "id", "")
            if not _ID_RE.match(pid or ""):
                self.load_errors.append(LoadError(source, f"{obj.__name__}: id must match [a-z0-9_]+"))
                continue
            if pid in self.runtimes:
                self.load_errors.append(LoadError(source, f"duplicate plugin id '{pid}'"))
                continue
            plugin = obj()
            plugin.name = plugin.name or pid
            self.runtimes[pid] = PluginRuntime(plugin=plugin, source=source)
            found += 1
        if not found:
            self.load_errors.append(LoadError(source, "no Plugin subclass found"))

    def _load_builtin(self) -> None:
        pkg = importlib.import_module(self._builtin_package)
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_"):
                continue
            name = f"{self._builtin_package}.{info.name}"
            try:
                self._register(importlib.import_module(name), "built-in")
            except Exception as exc:
                log.exception("Failed to load built-in plugin %s", name)
                self.load_errors.append(LoadError(name, f"{type(exc).__name__}: {exc}"))

    def _load_user_dir(self) -> None:
        if not self.user_dir.is_dir():
            return
        allowed = set(self.allowed_user_plugins())
        for path in sorted(self.user_dir.iterdir()):
            if path.name.startswith(("_", ".")):
                continue
            if path.is_file() and path.suffix == ".py":
                init, search = path, None
            elif path.is_dir() and (path / "__init__.py").is_file():
                init, search = path / "__init__.py", [str(path)]
            else:
                continue
            if path.name not in allowed:  # importing it would already run it: wait for the user's word
                self.unapproved.append(path.name)
                log.warning("User plugin %s is not loaded: not allowed yet (tray menu > Plugins)", path.name)
                continue
            modname = f"radar_user_plugin_{re.sub(r'[^0-9a-zA-Z_]', '_', path.stem)}"
            try:
                spec = importlib.util.spec_from_file_location(modname, init, submodule_search_locations=search)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot create module spec")
                module = importlib.util.module_from_spec(spec)
                sys.modules[modname] = module
                spec.loader.exec_module(module)
                self._register(module, str(path))
            except Exception as exc:
                sys.modules.pop(modname, None)
                log.exception("Failed to load user plugin %s", path)
                self.load_errors.append(LoadError(str(path), f"{type(exc).__name__}: {exc}"))

    # -------------------------------------------------------------- query
    def ordered(self) -> list[PluginRuntime]:
        with self._lock:
            return sorted(self.runtimes.values(), key=lambda rt: (not rt.builtin, rt.plugin.name.lower()))

    def get(self, plugin_id: str) -> PluginRuntime | None:
        return self.runtimes.get(plugin_id)

    def is_enabled(self, plugin_id: str) -> bool:
        return bool(self._cfg.get("plugins", plugin_id, "enabled", default=False))

    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        self._cfg.set("plugins", plugin_id, "enabled", value=bool(enabled))

    def rule_enabled(self, plugin_id: str, rule_id: str) -> bool:
        return bool(self._cfg.get("plugins", plugin_id, "rules", rule_id, default=False))

    def set_rule_enabled(self, plugin_id: str, rule_id: str, enabled: bool) -> None:
        self._cfg.set("plugins", plugin_id, "rules", rule_id, value=bool(enabled))

    def interval_seconds(self, plugin_id: str) -> int:
        rt = self.runtimes.get(plugin_id)
        default = rt.plugin.default_interval_minutes if rt else 15
        try:
            minutes = float(self._cfg.get("plugins", plugin_id, "interval_minutes", default=default))
        except (TypeError, ValueError):
            minutes = default
        return max(60, int(minutes * 60))

    # ---------------------------------------------------------------- run
    def build_context(self, plugin_id: str) -> PluginContext:
        rt = self.runtimes[plugin_id]
        rules_cfg = self._cfg.get("plugins", plugin_id, "rules", default={}) or {}
        enabled_rules = frozenset(r.id for r in rt.plugin.rules if rules_cfg.get(r.id, r.default_enabled))

        def _status(text: str) -> None:
            rt.status_text = text

        return PluginContext(
            plugin_id=plugin_id,
            graph=self._graph_factory(),
            settings=self._cfg.get("plugins", plugin_id, "settings", default={}) or {},
            enabled_rules=enabled_rules,
            state=PluginState(self._store, plugin_id),
            data_dir=paths.plugin_data_dir(plugin_id),
            log=logging.getLogger(f"radar.plugin.{plugin_id}"),
            stop_event=self._stop,
            status_callback=_status,
        )

    def run(self, plugin_id: str) -> list[Finding]:
        """Run one plugin. Exceptions propagate (after being recorded on the runtime)."""
        rt = self.runtimes[plugin_id]
        rt.running = True
        rt.last_run = datetime.now(timezone.utc)
        try:
            findings = list(rt.plugin.run(self.build_context(plugin_id)) or [])
            rt.last_success = datetime.now(timezone.utc)
            rt.last_error = None
            rt.last_findings = len(findings)
            return findings
        except Exception as exc:
            rt.last_error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            rt.running = False
