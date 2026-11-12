"""Background scheduler: runs due plugins, handles "run now", pause and snooze wake-ups."""
from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .app import App

log = logging.getLogger(__name__)
RETRY_AFTER_FAILURE = 300  # seconds


class Scheduler(threading.Thread):
    def __init__(self, app: "App"):
        super().__init__(name="scheduler", daemon=True)
        self.app = app
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._forced: set[str] = set()
        self._waiting: dict[str, list] = {}  # plugin id -> callbacks(ok) to call after its next run
        self._last_run: dict[str, float] = {}
        self._due: dict[str, float] = {}
        self._t0 = time.monotonic()

    # ------------------------------------------------------------ control
    def wake(self) -> None:
        self._wake.set()

    def trigger(self, plugin_id: str | None = None, done=None) -> None:
        """Run a plugin (or all enabled plugins) as soon as possible, even while paused.
        ``done(ok)`` is called (scheduler thread) when the run of ``plugin_id`` has finished."""
        with self._lock:
            self._forced.add(plugin_id or "*")
            if done is not None and plugin_id:
                self._waiting.setdefault(plugin_id, []).append(done)
        self._wake.set()

    def reschedule(self, plugin_id: str) -> None:
        """Make a plugin due now (e.g. right after it was enabled)."""
        with self._lock:
            self._due[plugin_id] = 0.0
        self._wake.set()

    def _map_wants_scan(self, pid: str) -> bool:
        try:
            if not self.app.map_open():
                return False
            last = self._last_run.get(pid, 0.0)
            return time.monotonic() - last >= self.app.MAP_SCAN_SECONDS
        except Exception:
            return False

    # --------------------------------------------------------------- loop
    def run(self) -> None:
        log.info("Scheduler started")
        while not self.app.stop_event.is_set():
            tick = max(5, int(self.app.cfg.get("general", "tick_seconds", default=30) or 30))
            self._wake.wait(timeout=tick)
            self._wake.clear()
            if self.app.stop_event.is_set():
                break
            try:
                self._tick()
            except Exception:
                log.exception("Scheduler tick failed")
        log.info("Scheduler stopped")

    def _tick(self) -> None:
        self.app.on_tick()
        with self._lock:
            forced, self._forced = self._forced, set()
        startup_delay = float(self.app.cfg.get("general", "startup_delay_seconds", default=20) or 0)
        paused = self.app.paused
        pm = self.app.plugins
        for rt in pm.ordered():
            if self.app.stop_event.is_set():
                return
            pid = rt.plugin.id
            enabled = pm.is_enabled(pid)
            is_forced = pid in forced or ("*" in forced and enabled)
            if not is_forced:
                due = self._due.setdefault(pid, self._t0 + startup_delay)
                if pid == getattr(self.app, "ATTACK_PLUGIN", None) and self._map_wants_scan(pid):
                    due = 0.0  # a live map is open: read sign-ins more often than the normal interval
                if paused or not enabled or due > time.monotonic():
                    continue
            with self._lock:
                waiting = self._waiting.pop(pid, [])
            try:
                ok = self.app.run_plugin(pid)
            except Exception:
                ok = False
                log.exception("Plugin run %s failed", pid)
            self._last_run[pid] = time.monotonic()
            for callback in waiting:
                try:
                    callback(ok)
                except Exception:
                    log.exception("Scan callback failed")
            interval = pm.interval_seconds(pid)
            self._due[pid] = time.monotonic() + (interval if ok else min(interval, RETRY_AFTER_FAILURE))
