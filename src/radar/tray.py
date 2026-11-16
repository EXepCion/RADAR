"""Notification-area icon with a menu that is rebuilt every time it opens (always current)."""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Callable, Iterator

import pystray
from pystray._util import win32 as _w32

from . import APP_DISPLAY_NAME, APP_NAME, __version__
from .ui import icons

if TYPE_CHECKING:  # pragma: no cover
    from .app import App
    from .plugin_manager import PluginRuntime

log = logging.getLogger(__name__)
NIN_BALLOONUSERCLICK = 0x0405  # WM_USER + 5: the user clicked the notification
Item = pystray.MenuItem
SEP = pystray.Menu.SEPARATOR


class _Icon(pystray.Icon):
    """pystray icon that rebuilds its menu right before it is shown (on the tray thread)."""

    on_balloon_click = None  # set by Tray: called when the user clicks the notification

    def _on_notify(self, wparam, lparam):  # noqa: D401 - pystray override
        if (lparam & 0xFFFF) == NIN_BALLOONUSERCLICK:  # (the low word: also right if the icon uses the newer message layout)
            try:
                if self.on_balloon_click:
                    self.on_balloon_click()
            except Exception:
                log.exception("Notification click failed")
            return None
        if lparam == _w32.WM_RBUTTONUP:
            try:
                self._update_menu()
            except Exception:
                log.exception("Building the tray menu failed")
        return super()._on_notify(wparam, lparam)


class Tray:
    def __init__(self, app: "App"):
        self.app = app
        self.icon: _Icon | None = None
        self._ready = threading.Event()
        self._shown: tuple[str, str] | None = None

    # ----------------------------------------------------------- lifecycle
    def start(self) -> None:
        threading.Thread(target=self._run, name="tray", daemon=True).start()
        self._ready.wait(10)

    def _run(self) -> None:
        state, title = self.app.tray_state()
        self.icon = _Icon(APP_NAME, icon=icons.tray_icon(state), title=title, menu=pystray.Menu(self._items))
        self._shown = (state, title)
        try:
            self.icon.run(setup=self._setup)
        except Exception:
            log.exception("Tray loop crashed")

    def _setup(self, icon: pystray.Icon) -> None:
        icon.visible = True
        self._ready.set()

    def stop(self) -> None:
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass

    def refresh(self) -> None:
        """Update icon image and tooltip to the current app state."""
        if not self.icon:
            return
        state, title = self.app.tray_state()
        if (state, title) == self._shown:
            return
        try:
            if self._shown is None or state != self._shown[0]:
                self.icon.icon = icons.tray_icon(state)
            self.icon.title = title[:127]
            self._shown = (state, title)
        except Exception:
            log.debug("tray refresh failed", exc_info=True)

    def notify(self, message: str, title: str = APP_DISPLAY_NAME, on_click: Callable[[], Any] | None = None) -> None:
        """Show a notification. ``on_click`` runs when the user clicks it (the latest notification decides)."""
        try:
            if self.icon:
                self._click = on_click
                self.icon.on_balloon_click = self._clicked
                self.icon.notify(message, title)
        except Exception:
            log.debug("tray notify failed", exc_info=True)

    def _clicked(self) -> None:
        action, self._click = getattr(self, "_click", None), None
        if action:
            action()

    # --------------------------------------------------------------- menu
    def _act(self, fn: Callable[..., Any], *args: Any) -> Callable[[Any, Any], None]:
        def action(_icon, _item) -> None:
            try:
                fn(*args)
            except Exception:
                log.exception("Menu action %s failed", getattr(fn, "__name__", fn))
            self.refresh()
        return action

    @staticmethod
    def _chk(fn: Callable[..., bool], *args: Any) -> Callable[[Any], bool]:
        def checked(_item) -> bool:
            try:
                return bool(fn(*args))
            except Exception:
                return False
        return checked

    def _items(self) -> Iterator[Item]:
        """The menu, top to bottom: what is going on, the windows, the two everyday switches, Exit. Everything that
        is set once - detection, offices, sound, account, files - is in the main window's Settings."""
        a = self.app
        yield Item(f"{APP_DISPLAY_NAME} {__version__}", None, enabled=False)
        yield Item(a.status_line(), None, enabled=False)
        yield SEP
        n, unseen = a.alerts.count_active(), a.alerts.count_unseen()
        label = f"Show reminders ({n}" + (f", {unseen} new)" if unseen else ")") if n else "Show reminders"
        yield Item(f"Open {APP_DISPLAY_NAME}", self._act(a.show_main), default=True)  # also: a click on the icon
        yield Item(label, self._act(a.show_reminders_from_tray))
        yield Item("Live map...", self._act(a.show_map))
        yield SEP
        yield Item("Scan now", self._act(a.scan_now))
        yield Item("Pause monitoring", self._act(a.toggle_pause), checked=self._chk(lambda: a.paused))
        yield SEP
        newer = a.updates.available
        if newer is not None:
            yield Item(f"New version {newer.version} available...", self._act(a.open_update_page))
        yield Item("Settings...", self._act(a.show_main, "settings"))
        yield Item("Exit", self._act(a.quit))

    def _plugin_items(self, rt: "PluginRuntime") -> Iterator[Item]:
        pm, a, pid = self.app.plugins, self.app, rt.plugin.id
        enabled = pm.is_enabled(pid)
        yield Item("Enabled", self._act(a.toggle_plugin, pid), checked=self._chk(pm.is_enabled, pid))
        yield Item("Run now", self._act(a.scan_now, pid))
        yield Item(a.plugin_status_text(rt), None, enabled=False)
        if rt.plugin.rules:
            yield SEP
            notes = getattr(rt.plugin, "rule_notes", None) or {}
            for rule in rt.plugin.rules:
                note = notes.get(rule.id)
                yield Item(rule.name + (f"  ({note})" if note else ""), self._act(a.toggle_rule, pid, rule.id),
                           checked=self._chk(pm.rule_enabled, pid, rule.id), enabled=enabled)
