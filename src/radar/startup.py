"""Start-at-logon via the per-user Run registry key (no admin rights needed)."""
from __future__ import annotations

import sys
import winreg
from pathlib import Path

from . import APP_NAME

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def launch_command() -> str:
    if getattr(sys, "frozen", False):  # the packaged program starts itself
        return f'"{sys.executable}"'
    scripts = Path(sys.executable).parent
    launcher = scripts / f"{APP_NAME}.exe"
    if launcher.exists():
        return f'"{launcher}"'
    pythonw = scripts / "pythonw.exe"
    return f'"{pythonw if pythonw.exists() else sys.executable}" -m radar'


def is_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, APP_NAME)
            return True
    except OSError:
        return False


def enable(command: str | None = None) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command or launch_command())


def disable() -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
    except FileNotFoundError:
        pass
