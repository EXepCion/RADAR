"""Locations of per-user data. Override the root with the RADAR_HOME environment variable."""
from __future__ import annotations

import os
from pathlib import Path

from . import APP_NAME


def _ensure(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    base = os.environ.get("RADAR_HOME")
    if not base:
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        base = os.path.join(local, APP_NAME)
    return _ensure(Path(base))


def config_path() -> Path:
    return data_dir() / "config.json"


def db_path() -> Path:
    return data_dir() / "radar.db"


def token_cache_path() -> Path:
    return data_dir() / "token_cache.bin"


def log_dir() -> Path:
    return _ensure(data_dir() / "logs")


def log_file() -> Path:
    return log_dir() / "radar.log"


def user_plugin_dir() -> Path:
    return _ensure(data_dir() / "plugins")


def plugin_data_dir(plugin_id: str) -> Path:
    return _ensure(data_dir() / "plugin-data" / plugin_id)
