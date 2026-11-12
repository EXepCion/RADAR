"""JSON configuration with defaults, atomic saves and reload-on-change."""
from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Public client id of Microsoft's Azure CLI: the "quick start" sign-in identity (see radar.identity). It may read
# the sign-in and audit logs in most tenants without an app registration - at the price of RADAR appearing as
# "Microsoft Azure CLI". Not the default: a new installation asks how to sign in.
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

CORE_DEFAULTS: dict[str, Any] = {
    "auth": {
        "client_id": "",  # empty = not chosen yet: RADAR asks on first start (Settings > Account > Sign-in identity)
        "authority": "https://login.microsoftonline.com/organizations",
        "scopes": ["https://graph.microsoft.com/.default"],
        "use_broker": True,
        "account": "",
    },
    "general": {
        "paused": False,
        "tick_seconds": 30,
        "startup_delay_seconds": 20,
        "notify_min_severity": "low",
        "play_sound": True,
        "respect_system_mute": True,
        "flash_window": True,
        "default_snooze": "15 minutes",
        "dark_mode": False,      # tray > Settings > Appearance > Dark mode
        "animations": True,      # tray > Settings > Appearance > Animations (fades, risk bar, reminder glide-in)
        "alert_retention_days": 90,
        "check_for_updates": True,   # once a day: is there a newer release on GitHub? (tells, never downloads)
        "update_notified": "",       # the version the notification was last shown for
        "allowed_user_plugins": [],  # files in the plugins folder that may be loaded (tray menu > Plugins asks)
        "data_tenant": "",           # the tenant the stored data belongs to (radar.tenant); set at the first sign-in
        "start_fresh_for": "",       # set by 'Start fresh for this tenant': carried out at the next start
        "start_fresh_archive": "",
    },
    "plugins": {},
}


def deep_fill(target: dict, defaults: dict) -> bool:
    """Copy keys from ``defaults`` that are missing in ``target`` (recursively).

    Existing values are never overwritten. Returns True if anything was added.
    """
    changed = False
    for key, value in defaults.items():
        if key not in target:
            target[key] = copy.deepcopy(value)
            changed = True
        elif isinstance(value, dict) and isinstance(target[key], dict):
            changed |= deep_fill(target[key], value)
    return changed


class ConfigManager:
    """Thread-safe access to config.json. Every setter persists immediately."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {}
        self._mtime: int | None = None
        self.last_error: str | None = None
        self.load()

    # ------------------------------------------------------------------ io
    def _stat(self) -> int | None:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def load(self) -> bool:
        """(Re)load from disk. Returns False if the file was invalid and was not applied."""
        with self._lock:
            data: dict[str, Any] = {}
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8-sig"))
                    if not isinstance(data, dict):
                        raise ValueError("the top level must be a JSON object")
                    self.last_error = None
                except (OSError, ValueError) as exc:
                    self.last_error = f"config.json is invalid: {exc}"
                    log.error(self.last_error)
                    self._mtime = self._stat()
                    if self._data:
                        return False  # keep running with the last good configuration
                    backup = self.path.with_name(f"config.invalid-{time.strftime('%Y%m%d-%H%M%S')}.json")
                    try:
                        os.replace(self.path, backup)
                        log.error("Moved invalid configuration to %s and recreated defaults", backup)
                    except OSError:
                        pass
                    data = {}
            changed = deep_fill(data, CORE_DEFAULTS)
            self._data = data
            if changed or not self.path.exists():
                self._save_locked()
            else:
                self._mtime = self._stat()
            return True

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)
        self._mtime = self._stat()

    def save(self) -> None:
        with self._lock:
            self._save_locked()

    def reload_if_changed(self) -> bool:
        """Reload when the file was edited externally. Returns True if new values were applied."""
        mtime = self._stat()
        if mtime is not None and mtime != self._mtime:
            log.info("config.json changed on disk, reloading")
            return self.load()
        return False

    # ------------------------------------------------------------- access
    def get(self, *path: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            for part in path:
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return copy.deepcopy(node)

    def set(self, *path: str, value: Any) -> None:
        if not path:
            raise ValueError("path required")
        with self._lock:
            node = self._data
            for part in path[:-1]:
                nxt = node.get(part)
                if not isinstance(nxt, dict):
                    nxt = node[part] = {}
                node = nxt
            node[path[-1]] = copy.deepcopy(value)
            self._save_locked()

    def ensure_plugin(self, plugin) -> None:
        """Create/complete the config section of a plugin from its declared defaults."""
        defaults = {
            "enabled": bool(plugin.default_enabled),
            "interval_minutes": plugin.default_interval_minutes,
            "rules": {rule.id: bool(rule.default_enabled) for rule in plugin.rules},
            "settings": copy.deepcopy(plugin.default_settings),
        }
        with self._lock:
            plugins = self._data.setdefault("plugins", {})
            entry = plugins.setdefault(plugin.id, {})
            if not isinstance(entry, dict):
                entry = plugins[plugin.id] = {}
            if deep_fill(entry, defaults):
                self._save_locked()
