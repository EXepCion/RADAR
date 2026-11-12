"""Notification-area icon with a menu that is rebuilt every time it opens (always current)."""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Callable, Iterator

import pystray
from pystray._util import win32 as _w32

from . import APP_DISPLAY_NAME, APP_NAME, __version__, audio, startup
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
        """The menu, top to bottom: what is going on, the views, the two everyday switches, then everything that is
        set once (Settings) and Exit. Each group is a method of its own below."""
        a = self.app
        yield Item(f"{APP_DISPLAY_NAME} {__version__}", None, enabled=False)
        yield Item(a.status_line(), None, enabled=False)
        yield SEP
        yield from self._alert_items()
        yield SEP
        yield from self._view_items()
        yield SEP
        yield Item("Scan now", self._act(a.scan_now))
        yield Item("Pause monitoring", self._act(a.toggle_pause), checked=self._chk(lambda: a.paused))
        yield SEP
        newer = a.updates.available
        if newer is not None:
            yield Item(f"New version {newer.version} available...", self._act(a.open_update_page))
        yield Item("Settings", pystray.Menu(*self._settings_items()))
        yield Item("Exit", self._act(a.quit))

    def _alert_items(self) -> Iterator[Item]:
        """Reminders (the default action: a click on the icon) and the history of all alerts."""
        a = self.app
        n, unseen = a.alerts.count_active(), a.alerts.count_unseen()
        label = f"Show reminders ({n}" + (f", {unseen} new)" if unseen else ")") if n else "Show reminders"
        yield Item(label, self._act(a.show_reminders_from_tray), default=True)
        yield Item("Alert history...", self._act(a.show_history))

    def _view_items(self) -> Iterator[Item]:
        """The windows that show the current state on demand."""
        a = self.app
        yield Item("Ongoing attacks...", self._act(a.show_attacks))
        yield Item("Live map...", self._act(a.show_map))
        yield Item("MFA exposure report...", self._act(a.show_exposure_report))

    def _settings_items(self) -> Iterator[Item]:
        """Everything that is set up once: what is watched, where the offices are, how the app behaves, who it
        signs in as - and, last, the files behind it."""
        a = self.app
        yield Item("Detection", pystray.Menu(*self._detection_items()))
        yield Item("Offices...", self._act(a.show_offices))
        yield Item("Virtual desktops...", self._act(a.show_hosts))
        yield Item("Weekly MFA exposure reminder", self._act(a.toggle_exposure_reminder),
                   checked=self._chk(lambda: a.exposure_reminder))
        yield SEP
        yield Item("Reminder sound", pystray.Menu(*self._sound_items()))
        yield Item("Appearance", pystray.Menu(
            Item("Dark mode", self._act(a.toggle_dark_mode), checked=self._chk(lambda: a.dark_mode)),
            Item("Animations", self._act(a.toggle_animations), checked=self._chk(lambda: a.animations)),
        ))
        yield Item("Start with Windows", self._act(a.toggle_startup), checked=self._chk(startup.is_enabled))
        yield Item("Check for new versions", self._act(a.toggle_check_updates), checked=self._chk(lambda: a.check_updates))
        yield SEP
        account = a.auth.account or ("not set up" if not a.setup_done else
                                     "sign-in required" if a.auth.state == "required" else "Windows account")
        yield Item(f"Account: {account}", pystray.Menu(*self._account_items()))
        yield SEP
        yield Item("Advanced", pystray.Menu(*self._advanced_items()))

    def _account_items(self) -> Iterator[Item]:
        a = self.app
        yield Item("Sign in...", self._act(a.sign_in, False))
        yield Item("Sign in with a different account...", self._act(a.sign_in, True))
        yield Item("Use my Windows account", self._act(a.use_windows_account), enabled=a.auth.using_explicit_account)
        yield SEP
        yield Item(f"Set-up and connection check... ({a.identity_label})", self._act(a.show_setup, True))

    def _advanced_items(self) -> Iterator[Item]:
        """The files and folders behind the app, and reloading plugins after editing them."""
        a = self.app
        yield Item("Edit settings file (config.json)", self._act(a.open_config))
        yield Item("Open log file", self._act(a.open_log))
        yield Item("Open data folder", self._act(a.open_data_dir))
        yield SEP
        yield Item("Open plugins folder", self._act(a.open_plugins_dir))
        yield Item("Reload plugins", self._act(a.reload_plugins))
        yield SEP
        yield Item("Look for a new version now", self._act(a.look_for_update))

    def _sound_items(self) -> Iterator[Item]:
        a = self.app
        yield Item("Play sound for new reminders", self._act(a.toggle_sound), checked=self._chk(lambda: a.sound_enabled))
        yield Item("Stay silent when Windows audio is muted", self._act(a.toggle_respect_mute),
                   checked=self._chk(lambda: a.respect_mute), enabled=a.sound_enabled)
        yield SEP
        yield Item(f"Plays on: {audio.output_state().describe_device()}", None, enabled=False)  # the default device
        yield Item("Test sound", self._act(a.test_sound), enabled=a.sound_enabled)

    def _detection_items(self) -> Iterator[Item]:
        """What is watched: each detection plugin with its rules (a tick = on)."""
        pm = self.app.plugins
        for rt in pm.ordered():
            yield Item(rt.plugin.name, pystray.Menu(*self._plugin_items(rt)), checked=self._chk(pm.is_enabled, rt.plugin.id))
        for err in pm.load_errors:
            name = err.source.replace("\\", "/").rsplit("/", 1)[-1]
            yield Item(f"(!) {name}: failed to load", None, enabled=False)
        for name in getattr(pm, "unapproved", ()):
            yield Item(f"(new) {name}: allow it to load...", self._act(self.app.allow_user_plugin, name))

    def _plugin_items(self, rt: "PluginRuntime") -> Iterator[Item]:
        pm, a, pid = self.app.plugins, self.app, rt.plugin.id
        enabled = pm.is_enabled(pid)
        yield Item("Enabled", self._act(a.toggle_plugin, pid), checked=self._chk(pm.is_enabled, pid))
        yield Item("Run now", self._act(a.scan_now, pid))
        yield Item(a.plugin_status_text(rt), None, enabled=False)
        if rt.plugin.rules:
            yield SEP
            for rule in rt.plugin.rules:
                yield Item(rule.name, self._act(a.toggle_rule, pid, rule.id),
                           checked=self._chk(pm.rule_enabled, pid, rule.id), enabled=enabled)
