"""Application wiring: Tk main thread + tray thread + scheduler thread."""
from __future__ import annotations

import logging
import os
import queue
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import APP_DISPLAY_NAME, __version__, audio, paths, startup
from .alerts import Alert, AlertCenter
from . import tenant
from .auth import AuthManager, AuthRequiredError, TenantChangedError
from .config import ConfigManager
from .graph import GraphClient, GraphError
from .plugin_api import Finding, OperationCancelled, Severity
from .plugin_manager import PluginManager, PluginRuntime
from .scheduler import Scheduler
from .store import Store
from .updates import UpdateChecker

log = logging.getLogger(__name__)
SIGN_IN_LINK = "radar://sign-in"
IDENTITY_LINK = "radar://identity"
FRESH_START_LINK = "radar://start-fresh"


class App:
    def __init__(self, demo: bool = False):
        self.demo = demo
        self.stop_event = threading.Event()
        self.cfg = ConfigManager(paths.config_path())
        self.store = Store(paths.db_path())
        self.auth = AuthManager(self.cfg, paths.token_cache_path(),
                                tenant_guard=lambda tenant_id: tenant.allows(self.cfg, tenant_id))
        self._next_purge = 0.0  # old alerts are removed at the first tick and then every few hours
        self.restart_requested = False  # set by a fresh start: the caller of run() starts RADAR again
        self.alerts = AlertCenter(self.store)
        try:  # alerts from before responses were linked (and whatever a crash left unlinked)
            self.alerts.relink_responses()
        except Exception:
            log.warning("Responses could not be linked to the stored alerts", exc_info=True)
        self.plugins = PluginManager(self.cfg, self.store, lambda: GraphClient(self.auth, self.stop_event),
                                     paths.user_plugin_dir(), self.stop_event)
        self.plugins.discover()
        self.updates = UpdateChecker(
            enabled=lambda: not self.demo and bool(self.cfg.get("general", "check_for_updates", default=True)),
            notified=lambda: str(self.cfg.get("general", "update_notified", default="") or ""),
            remember=lambda version: self.cfg.set("general", "update_notified", value=version))
        self.scheduler = Scheduler(self)
        self._ui_queue: queue.Queue = queue.Queue()
        self._running: set[str] = set()
        self.last_scan: datetime | None = None
        self.last_error: str | None = None
        self._auth_failures = 0
        self.root: tk.Tk | None = None
        self.reminders = None
        self.tray = None

    # ================================================================ run
    def run(self, on_ready: Callable[["App"], None] | None = None) -> None:
        from .tray import Tray
        from .ui import theme
        from .ui.reminder import ReminderWindow

        theme.set_dpi_awareness()
        theme.keep_ui_responsive()  # before the scheduler starts working
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.report_callback_exception = lambda *exc: log.error("UI error", exc_info=exc)
        theme.init(self.root, dark=self.dark_mode, animations=self.animations)
        self.reminders = ReminderWindow(self.root, self)
        self.tray = Tray(self)
        self.tray.start()
        if not self.demo:
            self.scheduler.start()
        self.root.after(150, self._pump)
        if self.alerts.count_active():  # at logon: only demand attention if something is unseen
            self.root.after(3000, lambda: self.reminders.show(attention=self.alerts.count_unseen() > 0))
        if not self.demo and not self.setup_done:  # a new installation (or one whose set-up never worked)
            self.root.after(1200, lambda: self.show_setup(run_now=self.auth.configured))
        if on_ready:
            self.root.after(500, lambda: on_ready(self))
        log.info("%s started (demo=%s)", APP_DISPLAY_NAME, self.demo)
        try:
            self.root.mainloop()
        finally:
            self.stop_event.set()
            self.scheduler.wake()
            self.tray.stop()
            if self.scheduler.is_alive():
                self.scheduler.join(timeout=5)
            self.store.close()
            log.info("%s stopped", APP_DISPLAY_NAME)

    def ui_call(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run ``fn`` on the Tk thread (safe from any thread)."""
        self._ui_queue.put((fn, args))

    def _pump(self) -> None:
        self._pump_count = getattr(self, "_pump_count", 0) + 1
        if self._pump_count % 6 == 0:  # about once a second
            try:
                self.take_map_requests()
            except Exception:
                log.exception("Map requests failed")
        while True:
            try:
                fn, args = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception:
                log.exception("UI task failed")
        if not self.stop_event.is_set() and self.root is not None:
            self.root.after(150, self._pump)

    def _background(self, fn: Callable[..., Any], *args: Any, name: str = "worker") -> None:
        def runner() -> None:
            try:
                fn(*args)
            except Exception:
                log.exception("Background task %s failed", name)
        threading.Thread(target=runner, name=name, daemon=True).start()

    def quit(self) -> None:
        self.stop_event.set()
        self.scheduler.wake()
        if self.tray:
            self.tray.stop()
        if self.root is not None:
            self.ui_call(self.root.quit)

    # ======================================================== scheduling
    @property
    def paused(self) -> bool:
        return bool(self.cfg.get("general", "paused", default=False))

    def on_tick(self) -> None:
        """Called by the scheduler on every tick (background thread)."""
        if self.cfg.reload_if_changed():
            self.on_alerts_changed()
        if self.alerts.wake_due_snoozes():
            self.ui_call(self.reminders.show, True)
            self.on_alerts_changed()
        if self.updates.due():
            self.check_for_update()
        if time.monotonic() >= self._next_purge:
            self._next_purge = time.monotonic() + 6 * 3600
            self.purge_old_alerts()

    def purge_old_alerts(self) -> int:
        """Delete dismissed and muted alerts last seen longer ago than ``general.alert_retention_days``."""
        try:
            days = max(1, int(self.cfg.get("general", "alert_retention_days", default=90)))
            removed = self.alerts.purge(days)
        except Exception:
            log.exception("Old alerts could not be removed")
            return 0
        if removed:
            log.info("Removed %d alert(s) last seen more than %d days ago", removed, days)
            self.ui_call(self._refresh_history_if_open)
        return removed

    def min_severity(self) -> Severity:
        try:
            return Severity.parse(self.cfg.get("general", "notify_min_severity", default="low"))
        except (KeyError, ValueError):
            return Severity.LOW

    def run_plugin(self, plugin_id: str) -> bool:
        """Run a plugin and process its findings (scheduler thread). Returns success."""
        rt = self.plugins.get(plugin_id)
        if rt is None:
            return True
        self._running.add(plugin_id)
        self._refresh_tray()
        try:
            findings = self.plugins.run(plugin_id)
        except TenantChangedError:
            self._other_tenant()
            return False
        except AuthRequiredError as exc:
            if not self.setup_done:  # set-up is not finished: explained in the set-up window, not raised as an alert
                self.last_error = "set-up not finished"
                self._setup_needed(f"sign-in: {exc}")
                return False
            self._auth_failures += 1
            self.last_error = "sign-in required"
            # Right after logon WAM/network may not be ready yet: only nag after a second failure.
            if self._auth_failures >= 2:
                self._report_problem("auth-required", "Sign-in required for RADAR",
                                     f"The app could not get a token silently: {exc}",
                                     "Click 'Sign in' below (or use the tray menu Settings > Account > Sign in...).",
                                     [("Sign in", SIGN_IN_LINK), ("Open the connection check", IDENTITY_LINK)])
            return False
        except OperationCancelled:
            return False
        except GraphError as exc:
            if exc.status in (401, 403) and not self.setup_done:
                self.last_error = "set-up not finished"
                self._setup_needed(f"{rt.plugin.name}: HTTP {exc.status} {exc.code}")
            elif exc.status in (401, 403):
                self._report_problem(
                    f"forbidden:{plugin_id}", f"{rt.plugin.name}: access denied by Microsoft Graph",
                    f"{exc.message} (HTTP {exc.status})",
                    "Required: " + ", ".join(rt.plugin.permissions or ["see plugin documentation"])
                    + f". Signed in as {self.auth.account or 'unknown'}.",
                    [("Open the connection check", IDENTITY_LINK), ("Sign in with a different account", "radar://sign-in-select")])
            else:
                self.last_error = f"{rt.plugin.name}: {exc}"
                log.warning("Plugin %s failed: %s", plugin_id, exc)
            return False
        except Exception as exc:
            self.last_error = f"{rt.plugin.name}: {type(exc).__name__}: {exc}"
            log.exception("Plugin %s crashed", plugin_id)
            return False
        finally:
            self._running.discard(plugin_id)
            self._refresh_tray()

        self.last_error = None
        self._auth_failures = 0
        self.last_scan = datetime.now(timezone.utc)
        for key in ("auth-required", "other-tenant", f"forbidden:{plugin_id}"):
            self.alerts.resolve_system(key)
        if not self.setup_done:  # it works now (a role that was assigned in the meantime, a later sign-in ...)
            self._setup_finished(scan=False)
        self.deliver(plugin_id, findings)
        return True

    def deliver(self, plugin_id: str, findings: list[Finding]) -> list[Alert]:
        popped = self.alerts.ingest(plugin_id, findings, self.min_severity())
        popped += self._update_chains()
        if popped:
            log.info("%d new alert(s) from %s: %s", len(popped), plugin_id, "; ".join(a.title for a in popped))
            self.ui_call(self.reminders.show, True)
            self.ui_call(self._refresh_open_windows)  # incidents, history and open alert details follow too
        else:
            self.ui_call(self._refresh_reminders_if_visible)
        self._refresh_tray()
        return popped

    def _update_chains(self) -> list[Alert]:
        """Attack-chain correlation over all alerts of the last days (any status, signals and Info included)."""
        from . import chains

        if not self.cfg.get("general", "attack_chains", default=True):
            return []
        try:
            recent = self.alerts.since(datetime.now(timezone.utc) - timedelta(days=chains.LOOKBACK_DAYS + 1))
            now = datetime.now(timezone.utc)
            return self.alerts.ingest(chains.CHAIN_PLUGIN,
                                      chains.chain_findings(recent, now) + chains.spread_findings(recent, now),
                                      self.min_severity())
        except Exception:
            log.exception("Attack-chain correlation failed")
            return []

    def _report_problem(self, key: str, title: str, summary: str, recommendation: str,
                        links: list[tuple[str, str]]) -> None:
        self.last_error = title
        if self.alerts.raise_system(key, title, summary, recommendation, links):
            self.ui_call(self.reminders.show, True)

    def _refresh_reminders_if_visible(self) -> None:
        if self.reminders and self.reminders.visible:
            self.reminders.refresh()
        self._refresh_open_windows()

    def _refresh_open_windows(self) -> None:
        """Every open window that shows stored alerts follows a change (Tk thread): the incidents, the alert
        history, and the details of each alert that is open - no window keeps showing what was true when it was
        opened."""
        self._refresh_history_if_open()
        refresh = getattr(self.reminders, "refresh_details", None)
        if refresh:
            try:
                refresh()
            except Exception:
                log.exception("Open alert details could not be updated")

    def _refresh_history_if_open(self) -> None:
        for name in ("_history", "_incidents"):
            win = getattr(self, name, None)
            if win is not None and win.exists():
                win.refresh()

    def _refresh_tray(self) -> None:
        if self.tray:
            self.tray.refresh()

    def on_alerts_changed(self) -> None:
        self._refresh_tray()
        self.ui_call(self._refresh_open_windows)  # on the UI thread, after the change that called us

    # ========================================================= alert history
    def show_history(self) -> None:
        """Tray: every alert still kept - also dismissed and logged-only ones - with a way to reactivate one."""
        from .ui.history import HistoryWindow

        def show() -> None:
            win = getattr(self, "_history", None)
            if win is not None and win.exists():
                win.refresh()
                win.focus()
                return
            self._history = HistoryWindow(self.root, self)
        self.ui_call(show)

    def show_incidents(self, select: str | None = None) -> None:
        """Tray: alerts that belong to one story (same account or same attacker address), as one incident each.
        ``select``: the incident to show (from the link in an alert's details)."""
        from .ui.incidents import IncidentsWindow

        def show() -> None:
            win = getattr(self, "_incidents", None)
            if win is not None and win.exists():
                win.refresh()
                win.focus()
            else:
                win = self._incidents = IncidentsWindow(self.root, self)
            if select:
                win.select(select)
        self.ui_call(show)

    def incident_of(self, alert: Alert):
        """The incident a stored alert belongs to (radar.incidents), or None."""
        from . import incidents

        if not alert.id:
            return None
        now = datetime.now(timezone.utc)
        for incident in incidents.group(self.alerts.since(now - timedelta(days=incidents.LOOKBACK_DAYS + 1)), now):
            if any(a.id == alert.id for a in incident.alerts):
                return incident
        return None

    def on_alerts_dismissed(self) -> None:
        """Reminders were dismissed from another window: the reminders, the history and the tray follow."""
        self._refresh_tray()
        self._refresh_reminders_if_visible()

    def open_alert(self, alert: Alert) -> None:
        """The details window of a stored alert (the same one the reminders open)."""
        self.reminders.open_details(alert)

    def on_alerts_reactivated(self) -> None:
        """Alerts were put back among the reminders: show them there."""
        self._refresh_tray()
        self.reminders.show(attention=False)

    # ========================================================= tray state
    def tray_state(self) -> tuple[str, str]:
        n = self.alerts.count_active()
        if self.paused:
            state, text = "paused", "monitoring paused"
        elif not self.demo and not self.setup_done:
            state, text = "warn", "set-up not finished"
        elif self.auth.state == "other_tenant":
            state, text = "warn", "signed in to another tenant"
        elif self.auth.state == "required":
            state, text = "warn", "sign-in required"
        elif n:
            unseen = self.alerts.count_unseen()
            state, text = "alert", f"{n} active alert{'s' if n != 1 else ''}" + (f", {unseen} new" if unseen else "")
        elif self.last_error:
            state, text = "warn", "last scan failed"
        elif self._running:
            state, text = "busy", "scanning..."
        else:
            state = "ok"
            text = f"last scan {self.last_scan.astimezone():%H:%M}" if self.last_scan else "starting..."
        return state, f"{APP_DISPLAY_NAME} - {text}"

    def status_line(self) -> str:
        if self.paused:
            return "Status: paused"
        if self._running:
            names = [self.plugins.get(p).plugin.name for p in self._running if self.plugins.get(p)]
            return f"Status: scanning ({', '.join(names)})"
        if self.auth.state == "required":
            return "Status: sign-in required"
        if self.last_error:
            return f"Status: {self.last_error[:80]}"
        if self.last_scan:
            return f"Status: OK, last scan {self.last_scan.astimezone():%H:%M}"
        return "Status: waiting for first scan"

    def plugin_status_text(self, rt: PluginRuntime) -> str:
        if rt.running:
            return (rt.status_text or "Running...")[:90]
        if rt.last_error:
            return f"Last run failed: {rt.last_error}"[:90]
        if rt.last_success:
            return f"Last run {rt.last_success.astimezone():%H:%M}: {rt.status_text or f'{rt.last_findings} finding(s)'}"[:90]
        return "Not run yet" if self.plugins.is_enabled(rt.plugin.id) else "Disabled"

    def entry_id_field(self, alert: Alert) -> str:
        rt = self.plugins.get(alert.plugin_id)
        return rt.plugin.entry_id_field if rt else ""

    def view_entry(self, alert: Alert | None, row: dict[str, str]) -> None:
        """Open the original sign-in log entry behind an evidence row (Tk thread; fetch runs in background)."""
        from .ui.entry import EntryWindow

        rt = self.plugins.get(alert.plugin_id) if alert else None
        if rt is None or not rt.plugin.entry_id_field:
            rt = self.plugins.get(self.ATTACK_PLUGIN)  # sign-in rows in alerts of other plugins (chains ...)
        if rt is None or not rt.plugin.entry_id_field:
            return
        entry_id = row.get(rt.plugin.entry_id_field, "")
        subtitle = "   ·   ".join(p for p in (row.get("User"), row.get("Time"), row.get("Application"),
                                               row.get("Result"), f"Request ID {entry_id}") if p)
        win = EntryWindow(self.root, entry_id, subtitle, row.get("_event", ""), app=self)
        plugin_id = rt.plugin.id

        def work() -> None:
            try:
                record = rt.plugin.fetch_entry(self.plugins.build_context(plugin_id), row)
            except Exception as exc:
                log.warning("Fetching log entry %s failed: %s", entry_id, exc)
                self.ui_call(win.show_error, str(exc))
                return
            if record:
                self.ui_call(win.show_record, record)
            else:
                self.ui_call(win.show_error, "entry not found (Entra keeps sign-in logs for 30 days)")

        self._background(work, name="fetch-entry")

    # ================================================ links in detail views
    @property
    def resolver(self):
        from .resolver import Resolver

        if getattr(self, "_resolver", None) is None:
            self._resolver = Resolver(lambda: GraphClient(self.auth, self.stop_event))
        return self._resolver

    def entity_action(self, entity: Any, action: str, row: dict | None = None, alert: Alert | None = None,
                      status: Callable[..., None] | None = None) -> None:
        """A click on a link in a detail view (Tk thread). ``status(text, error=False)`` reports progress."""
        from . import linkify

        say = status or (lambda text, error=False: None)
        url = linkify.static_url(entity, action)
        if url:
            self.open_link(url)
            say(f"Opened {url}")
            return
        if action == "view_signin":
            self.view_entry(alert, row if row and row.get("Sign-in ID") == entity.value else {"Sign-in ID": entity.value})
        elif action in ("view_audit", "view_correlation"):
            audit_id = entity.value if action == "view_audit" else ""
            corr = entity.value if action == "view_correlation" else (row or {}).get("Correlation ID", "")
            self.view_audit(audit_id, corr, row)
        elif action == "open_alert":
            if not self.open_alert_titled(entity.value):
                say(f"Alert '{entity.short}' is no longer stored (purged after the retention period).", True)
        elif action == "open_incident":
            self.show_incidents(select=entity.value)
        else:
            self._resolve_and_open(entity, action, say)

    def _resolve_and_open(self, entity: Any, action: str, say: Callable[..., None]) -> None:
        from . import linkify

        kind = linkify.resolve_kind(entity, action)
        say(f"Looking up {entity.short} in Entra ID...")

        def report(text: str, error: bool = False) -> None:
            self.ui_call(say, text, error)

        def work() -> None:
            try:
                info = self.resolver.resolve(kind, entity.value)
            except Exception as exc:
                log.warning("Lookup of %s %s failed: %s", kind, entity.value, exc)
                report(f"Could not look up {entity.short}: {exc}", True)
                return
            if info is None:
                report(f"{entity.short} was not found in this directory (deleted, external, or not a directory "
                       "object).", True)
                return
            target = linkify.PRIMARY_ACTION.get(info["kind"], "") if action == "find_id" else action
            url = linkify.portal_url(target, info) if target else ""
            text = linkify.describe(info)
            if url:
                self.open_link(url)
                report(f"Opened in Entra: {text}")
            elif target in ("app_credentials", "app_owners") and info.get("kind") == "app":
                report(f"{text}: no app registration in this tenant (it belongs to another organisation), "
                       "so there are no secrets or owners to show here.")
            else:
                report(f"{entity.short} is the {text}.")

        self._background(work, name="resolve")

    def view_audit(self, audit_id: str = "", correlation_id: str = "", row: dict | None = None) -> None:
        """Show the audit entries of one operation in the app (Tk thread; fetch runs in background)."""
        from .resolver import fetch_audit_entries
        from .ui.entry import AuditWindow

        row = row or {}
        subtitle = "   ·   ".join(p for p in (row.get("Time"), row.get("Activity"), row.get("Initiated by"),
                                               f"Correlation ID {correlation_id}" if correlation_id else "",
                                               f"Audit ID {audit_id}" if audit_id else "") if p)
        win = AuditWindow(self.root, self, subtitle, highlight=audit_id)

        def work() -> None:
            try:
                records = fetch_audit_entries(self.resolver.graph, audit_id, correlation_id)
            except Exception as exc:
                log.warning("Fetching audit entries %s/%s failed: %s", audit_id, correlation_id, exc)
                self.ui_call(win.show_error, str(exc))
                return
            if records:
                self.ui_call(win.show_records, records)
            else:
                self.ui_call(win.show_error, "entry not found (Entra keeps audit logs for 30 days)")

        self._background(work, name="fetch-audit")

    def open_alert_titled(self, title: str) -> bool:
        """Open the stored alert with this title (a step of an attack chain, a correlated alert)."""
        alert = self.alerts.find_by_title(title)
        if alert is None:
            return False
        self.reminders.open_details(alert)
        return True

    def describe_origin(self, alert: Alert) -> str:
        if alert.is_system:
            return "RADAR"
        if alert.plugin_id == "correlation":
            return "Attack-chain correlation (steps of several detections)"
        rt = self.plugins.get(alert.plugin_id)
        if not rt:
            return alert.plugin_id
        rule = next((r.name for r in rt.plugin.rules if r.id == alert.rule_id), "")
        return f"{rt.plugin.name} > {rule}" if rule else rt.plugin.name

    # ==================================================== ongoing attacks
    ATTACK_PLUGIN = "signin_threats"
    ATTACK_RULES = {"guessing": ("distributed_attack", "brute_force", "mfa_exempt_watch", "password_spray"),
                    "known": ("password_not_completed", "mfa_fatigue"),
                    "sessions": ("session_theft", "aitm_replay")}
    REMINDER_STATE = {"active": "open", "snoozed": "snoozed", "dismissed": "dismissed", "muted": "logged only"}

    def show_attacks(self) -> None:
        """Tray: live overview of running password attacks (independent of reminders)."""
        from .ui.attacks import AttacksWindow

        def show() -> None:
            win = getattr(self, "_attacks_win", None)
            if win and win.exists():
                win.focus()
                win.refresh()
                return
            win = self._attacks_win = AttacksWindow(self.root, self)
            win.load(then_refresh=True)  # at once what the app has, meanwhile fresh data in the background
        self.ui_call(show)

    def refresh_threat_data(self) -> str:
        """Read sign-ins AND accounts again now (one scan, so all data has the same age) and wait for it.
        Call from a worker thread. Returns '' or why it did not work."""
        rt = self.plugins.get(self.ATTACK_PLUGIN)
        if rt is None:
            return "sign-in threat detection is not available"
        if hasattr(rt.plugin, "request_full_refresh"):
            rt.plugin.request_full_refresh()
        finished, outcome = threading.Event(), {}
        self.scheduler.trigger(self.ATTACK_PLUGIN, done=lambda ok: (outcome.update(ok=ok), finished.set()))
        if not finished.wait(timeout=900):
            return "the scan did not finish within 15 minutes"
        if not outcome.get("ok"):
            return (rt.last_error or self.last_error or "the scan failed")[:160]
        return rt.plugin.refresh_error() if hasattr(rt.plugin, "refresh_error") else ""

    def threat_data_as_of(self) -> datetime | None:
        rt = self.plugins.get(self.ATTACK_PLUGIN)
        if rt is None or not hasattr(rt.plugin, "data_as_of"):
            return None
        return rt.plugin.data_as_of(self.plugins.build_context(self.ATTACK_PLUGIN))

    def load_attacks(self, win: Any, hours: float, refresh: bool = False, then_refresh: bool = False) -> None:
        """Compute the overview in the background (history analysis takes a few seconds).

        ``refresh``: read the data from Entra first. ``then_refresh``: show what the app has, then refresh."""
        rt = self.plugins.get(self.ATTACK_PLUGIN)
        if rt is None or not hasattr(rt.plugin, "ongoing"):
            win.show_error("sign-in threat detection is not available")
            return

        def work() -> None:
            error = self.refresh_threat_data() if refresh else ""
            try:
                result = rt.plugin.ongoing(self.plugins.build_context(self.ATTACK_PLUGIN), hours)
                as_of = self.threat_data_as_of()
            except Exception as exc:
                log.exception("Ongoing-attacks overview failed")
                self.ui_call(win.show_error, str(exc))
                return
            self.ui_call(self._show_attacks_result, win, result, as_of, then_refresh, error)
            if then_refresh:
                self.load_attacks(win, hours, refresh=True)

        self._background(work, name="attacks")

    def _show_attacks_result(self, win: Any, result: Any, as_of: datetime | None = None, busy: bool = False,
                             error: str = "") -> None:
        def reminder(section: str, row: Any) -> str:
            alert = self.alerts.latest_about(row.account, self.ATTACK_RULES[section], getattr(row, "user_id", ""))
            return self.REMINDER_STATE.get(alert.status, alert.status) if alert else "-"
        if result.hours != win.hours:
            return  # the user chose another period meanwhile; its own result follows
        win.show(result, reminder, as_of=as_of, busy=busy, error=error)

    # ========================================================= offices
    def show_offices(self) -> None:
        """Tray > Settings > Offices...: names, places and IP addresses of the offices (first set-up and later)."""
        from .plugins.signin_threats import offices as model
        from .ui.offices import OfficesWindow

        def settings() -> dict:
            return self.cfg.get("plugins", self.ATTACK_PLUGIN, "settings", default={}) or {}

        def save(items: list) -> str | None:
            try:
                self.cfg.set("plugins", self.ATTACK_PLUGIN, "settings", value=model.save_into(settings(), items))
            except Exception as exc:
                log.exception("Offices could not be saved")
                return str(exc)
            log.info("Offices saved: %s", ", ".join(o.name for o in items) or "none")
            return None

        def show() -> None:
            win = getattr(self, "_offices_win", None)
            if win and win.exists():
                win.focus()
                return
            current = model.load(settings())
            win = self._offices_win = OfficesWindow(self.root, self, current, save, first_time=not current)

            def work() -> None:
                rt = self.plugins.get(self.ATTACK_PLUGIN)
                try:
                    rows = rt.plugin.office_suggestions(self.plugins.build_context(self.ATTACK_PLUGIN)) if rt else []
                except Exception:
                    log.exception("Office suggestions failed")
                    rows = []
                self.ui_call(win.show_suggestions, rows)

            self._background(work, name="office-suggestions")
        self.ui_call(show)

    def show_hosts(self) -> None:
        """Tray > Settings > Virtual desktops...: Citrix / AVD / shared hosts whose place is not the person's."""
        from .plugins.signin_threats import hosts as model
        from .ui.hosts import HostsWindow

        def settings() -> dict:
            return self.cfg.get("plugins", self.ATTACK_PLUGIN, "settings", default={}) or {}

        def save(entries: list) -> str | None:
            try:
                self.cfg.set("plugins", self.ATTACK_PLUGIN, "settings", value=model.save_into(settings(), entries))
            except Exception as exc:
                log.exception("Virtual desktops could not be saved")
                return str(exc)
            log.info("Virtual desktops saved: %s", ", ".join(e["match"] for e in entries) or "none")
            return None

        def show() -> None:
            win = getattr(self, "_hosts_win", None)
            if win and win.exists():
                win.focus()
                return
            win = self._hosts_win = HostsWindow(self.root, self, model.load(settings()), save)

            def work() -> None:
                rt = self.plugins.get(self.ATTACK_PLUGIN)
                try:
                    rows = rt.plugin.host_suggestions(self.plugins.build_context(self.ATTACK_PLUGIN)) if rt else []
                except Exception:
                    log.exception("Virtual desktop suggestions failed")
                    rows = []
                self.ui_call(win.show_suggestions, rows)

            self._background(work, name="host-suggestions")
        self.ui_call(show)

    # ======================================================== live map
    MAP_HEARTBEAT = "map.open"   # touched by the map process while its window is open
    MAP_SCAN_SECONDS = 120       # sign-ins are read this often while the map is open

    @staticmethod
    def map_command() -> list[str]:
        """The live map runs as a process of its own (``python -m radar.mapview``): this app never imports it, so
        the map cannot slow down, block or crash the scanning and the reminders."""
        import sys

        exe = sys.executable
        if getattr(sys, "frozen", False):  # the packaged program: the same exe starts the map (a process of its own)
            return [exe, "--mapview"]
        windowless = os.path.join(os.path.dirname(exe), "pythonw.exe")
        return [windowless if os.path.exists(windowless) else exe, "-m", "radar.mapview"]

    def show_map(self) -> None:
        """Tray: open the live sign-in map (starts only now; nothing of it is loaded before)."""
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
            subprocess.Popen(self.map_command(), creationflags=flags, close_fds=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.info("Live map started")
        except Exception as exc:
            log.exception("Live map could not be started")
            self.tray.notify(f"The live map could not be started: {exc}")

    MAP_REQUESTS = "map-requests"  # written by the map process: "open this user / device"

    def take_map_requests(self) -> None:
        """Clicks in the live map on a user, device or sign-in: open their detail view (Tk thread, called about
        once a second). Only these kinds, only the actions the detail views offer; anything else is dropped."""
        import json

        from . import linkify

        if not self.map_open():
            return
        folder = paths.plugin_data_dir(self.ATTACK_PLUGIN) / self.MAP_REQUESTS
        try:
            files = sorted(p for p in folder.iterdir() if p.suffix == ".json")
        except OSError:
            return
        for path in files[:5]:
            try:
                request = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                request = {}
            try:
                path.unlink()
            except OSError:
                continue  # could not take it: do not act on it twice
            kind, value, action = (str(request.get(k) or "") for k in ("kind", "value", "action"))
            if kind not in ("user", "device", "signin") or action not in {a for _l, a in linkify.ACTIONS.get(kind, [])} \
                    or not value or len(value) > 200:
                log.warning("Map request ignored: %r", request)
                continue

            def say(text: str, error: bool = False) -> None:
                if error:
                    self.tray.notify(text)

            self.entity_action(linkify.Entity(kind, value, 0, len(value)), action, status=say)

    def map_open(self) -> bool:
        """Is a live map window open right now? (one file-stat; the map process touches the file every 20 s)"""
        try:
            path = paths.plugin_data_dir(self.ATTACK_PLUGIN) / self.MAP_HEARTBEAT
            return datetime.now().timestamp() - path.stat().st_mtime < 60
        except OSError:
            return False

    # ================================================ MFA exposure report
    EXPOSURE_RULE = "mfa_exposure_report"

    def show_exposure_report(self) -> None:
        """Tray: the MFA exposure report (independent of the weekly reminder).

        Opens at once with the data the app has and refreshes it in the background (sign-ins and accounts in one
        scan); the window shows the age of the data and has a Refresh button."""
        rt = self.plugins.get(self.ATTACK_PLUGIN)
        if rt is None or not hasattr(rt.plugin, "exposure_report"):
            self.tray.notify("Sign-in threat detection is not available.")
            return

        def work() -> None:
            if self.threat_data_as_of() is None:  # nothing read yet: there is nothing to show first
                self.tray.notify("Reading accounts and MFA exclusions from Entra ID - the report opens in a moment.")
                error = self.refresh_threat_data()
                finding = self._build_exposure_report()
                if finding is None:
                    self.tray.notify(f"MFA exposure report: {error}" if error else self.NO_EXPOSURE)
                    return
                self.ui_call(self._open_exposure_report, finding, self.threat_data_as_of(), False, error)
                return
            finding = self._build_exposure_report()
            if finding is None:
                self.tray.notify(self.NO_EXPOSURE)
                return
            self.ui_call(self._open_exposure_report, finding, self.threat_data_as_of(), True, "")

        self._background(work, name="exposure-report")

    NO_EXPOSURE = "No account can sign in without MFA (no exclusions from the MFA policies)."

    def _build_exposure_report(self) -> Finding | None:
        rt = self.plugins.get(self.ATTACK_PLUGIN)
        try:
            return rt.plugin.exposure_report(self.plugins.build_context(self.ATTACK_PLUGIN))
        except Exception:
            log.exception("MFA exposure report failed")
            return None

    def _open_exposure_report(self, finding: Finding, as_of: datetime | None, refresh: bool, error: str,
                              replace: Any = None) -> None:
        """Open the report window (Tk thread); ``refresh``: start the background refresh for it right away."""
        from .ui.details import DetailsWindow

        win: Any = None
        win = DetailsWindow(self.root, self, Alert.from_finding(self.ATTACK_PLUGIN, finding),
                            on_dismiss=lambda _a: None, on_refresh=lambda: self.refresh_exposure_report(win))
        win.report = finding
        win.age.set(as_of, busy=False, error=error)
        if replace is not None and replace.exists():  # the new report takes the place of the old one, seamlessly
            try:
                win.top.geometry(replace.top.geometry())
                win.top.keep_place = True  # not moved to the mouse's screen: it stands in for the old window
                replace.top.after(400, replace.top.destroy)  # once the new window is visible
            except Exception:
                log.debug("could not replace the report window", exc_info=True)
        if refresh:
            self.refresh_exposure_report(win)

    def refresh_exposure_report(self, win: Any) -> None:
        """Refresh the data behind an open report; the window is only rebuilt if the report changed."""
        if not win.exists() or win.age.busy:
            return
        win.age.set(busy=True, keep_time=True)

        def work() -> None:
            error = self.refresh_threat_data()
            finding = self._build_exposure_report()
            self.ui_call(done, finding, self.threat_data_as_of(), error)

        def done(finding: Finding | None, as_of: datetime | None, error: str) -> None:
            if not win.exists():
                return
            if finding is None:  # nothing is exposed any more
                win.top.destroy()
                self.tray.notify(self.NO_EXPOSURE)
            elif self._same_report(finding, win.report):
                win.age.set(as_of, busy=False, error=error)
            else:
                self._open_exposure_report(finding, as_of, False, error, replace=win)

        self._background(work, name="exposure-refresh")

    @staticmethod
    def _same_report(a: Finding, b: Finding) -> bool:
        def content(f: Finding) -> tuple:
            fields = {k: v for k, v in f.fields.items() if k != "Data as of"}
            return f.title, f.summary, fields, f.evidence, f.score
        return content(a) == content(b)

    @property
    def exposure_reminder(self) -> bool:
        return self.plugins.rule_enabled(self.ATTACK_PLUGIN, self.EXPOSURE_RULE)

    def toggle_exposure_reminder(self) -> None:
        self.toggle_rule(self.ATTACK_PLUGIN, self.EXPOSURE_RULE)

    def open_attack_details(self, account: Any) -> None:
        """Current assessment of one attacked account (a live finding, not a stored reminder)."""
        from .ui.details import DetailsWindow

        alert = Alert.from_finding(self.ATTACK_PLUGIN, account.as_finding())
        alert.fields = {"Status": f"{account.status} (last attempt {account.last.astimezone():%d.%m. %H:%M})",
                        **alert.fields}
        DetailsWindow(self.root, self, alert, on_dismiss=lambda _a: None)

    # ============================================================ actions
    def show_reminders_from_tray(self) -> None:
        def show() -> None:
            if not self.reminders.show(attention=False):
                self.tray.notify("No active security reminders.")
        self.ui_call(show)

    def scan_now(self, plugin_id: str | None = None) -> None:
        self.scheduler.trigger(plugin_id)

    def toggle_plugin(self, plugin_id: str) -> None:
        enabled = not self.plugins.is_enabled(plugin_id)
        self.plugins.set_enabled(plugin_id, enabled)
        log.info("Plugin %s %s", plugin_id, "enabled" if enabled else "disabled")
        if enabled:
            self.scheduler.reschedule(plugin_id)

    def toggle_rule(self, plugin_id: str, rule_id: str) -> None:
        self.plugins.set_rule_enabled(plugin_id, rule_id, not self.plugins.rule_enabled(plugin_id, rule_id))

    def toggle_pause(self) -> None:
        self.cfg.set("general", "paused", value=not self.paused)
        self.scheduler.wake()

    # ---------------------------------------------------------------- sound
    @property
    def sound_enabled(self) -> bool:
        return bool(self.cfg.get("general", "play_sound", default=True))

    @property
    def respect_mute(self) -> bool:
        return bool(self.cfg.get("general", "respect_system_mute", default=True))

    def play_reminder_sound(self) -> tuple[bool, str]:
        if not self.sound_enabled:
            return False, "reminder sound is turned off"
        return audio.play_reminder(respect_mute=self.respect_mute)

    def toggle_sound(self) -> None:
        self.cfg.set("general", "play_sound", value=not self.sound_enabled)

    def toggle_respect_mute(self) -> None:
        self.cfg.set("general", "respect_system_mute", value=not self.respect_mute)

    def test_sound(self) -> None:
        played, reason = self.play_reminder_sound()
        if not played:
            self.tray.notify(f"Reminder sound not played: {reason}.")

    # ----------------------------------------------------------- appearance
    @property
    def dark_mode(self) -> bool:
        return bool(self.cfg.get("general", "dark_mode", default=False))

    @property
    def animations(self) -> bool:
        return bool(self.cfg.get("general", "animations", default=True))

    def toggle_dark_mode(self) -> None:
        """Tray: switch light/dark; open windows recolour in place."""
        from .ui import theme

        dark = not self.dark_mode
        self.cfg.set("general", "dark_mode", value=dark)
        if self.root is not None:
            self.ui_call(theme.set_mode, self.root, dark)

    def toggle_animations(self) -> None:
        from .ui import theme

        enabled = not self.animations
        self.cfg.set("general", "animations", value=enabled)
        self.ui_call(theme.set_animations, enabled)

    def toggle_startup(self) -> None:
        if startup.is_enabled():
            startup.disable()
        else:
            startup.enable()

    def sign_in(self, select_account: bool = False) -> None:
        def work() -> None:
            try:
                user = self.auth.sign_in_interactive(select_account=select_account)
            except TenantChangedError:
                self._other_tenant()
                return
            except Exception as exc:
                log.warning("Interactive sign-in failed: %s", exc)
                self.tray.notify(f"Sign-in failed: {exc}"[:250])
                return
            for key in ("auth-required", "other-tenant"):
                self.alerts.resolve_system(key)
            self.last_error = None
            self.tray.notify(f"Signed in as {user}. Scanning now.")
            self.ui_call(self._refresh_reminders_if_visible)
            self.scan_now()
        self._background(work, name="sign-in")

    def use_windows_account(self) -> None:
        self.auth.use_windows_account()
        self.scan_now()

    # ------------------------------------------------------- another tenant
    def _other_tenant(self) -> None:
        """A sign-in led to another tenant than the stored data's: nothing is read; the user decides (reminder)."""
        self._report_problem(
            "other-tenant", "RADAR is signed in to another tenant than its stored data",
            f"Signed in as {self.auth.account or 'unknown'} (tenant {self.auth.other_tenant}). The alerts, sign-in "
            f"history and baselines RADAR has stored belong to tenant {tenant.known(self.cfg)}. Two tenants are "
            f"never mixed, so nothing is read until this is settled.",
            "Either sign in with an account of the original tenant, or start fresh for the new tenant: the stored "
            "data is moved to the folder 'archive' in RADAR's data folder (nothing is deleted) and RADAR restarts "
            "with new baselines. Settings stay - look through offices and exceptions afterwards.",
            [("Start fresh for this tenant", FRESH_START_LINK), ("Sign in with a different account", "radar://sign-in-select")])
        self.last_error = "signed in to another tenant"

    def start_fresh(self) -> None:
        """Reminder link: archive the stored data and restart for the tenant now signed in to (asks first)."""
        from tkinter import messagebox

        new = self.auth.other_tenant
        if not new or self.demo:
            return
        if not messagebox.askyesno(
                APP_DISPLAY_NAME,
                f"Start fresh for tenant {new}?\n\nThe stored alerts, sign-in history and baselines of tenant "
                f"{tenant.known(self.cfg) or 'unknown'} are moved to the folder 'archive' in RADAR's data folder. "
                f"Nothing is deleted.\n\nRADAR closes and starts again; close the live map first.", parent=self.root):
            return
        name = tenant.request_fresh_start(self.cfg, new)
        log.info("Fresh start requested for tenant %s (archive %s)", new, name)
        self.restart_requested = True
        self.quit()

    # ------------------------------------------------------------ new version
    def check_for_update(self, by_hand: bool = False) -> None:
        """Ask GitHub for the latest release (on the calling thread). A newer one is announced once with a
        notification - a click on it opens the release page - and stays in the tray menu."""
        release = self.updates.check()
        self._refresh_tray()
        if release is not None and self.tray:
            self.tray.notify(f"RADAR {release.version} is available (you have {__version__}). "
                             f"Click here to open the release page.", on_click=self.open_update_page)
        elif by_hand and self.tray:
            newer = self.updates.available
            if newer is not None:
                self.tray.notify(f"RADAR {newer.version} is available (you have {__version__}). "
                                 f"Click here to open the release page.", on_click=self.open_update_page)
            elif not self.check_updates:
                self.tray.notify("The check for new versions is switched off (Settings).")
            else:
                self.tray.notify(f"RADAR {__version__} is the current version - or GitHub could not be reached.")

    def look_for_update(self) -> None:
        """Tray > Settings > Advanced > Look for a new version now."""
        self._background(lambda: self.check_for_update(by_hand=True), name="update-check")

    def open_update_page(self) -> None:
        from . import updates

        release = self.updates.available
        webbrowser.open(release.url if release else updates.RELEASES_PAGE)

    @property
    def check_updates(self) -> bool:
        return bool(self.cfg.get("general", "check_for_updates", default=True))

    def toggle_check_updates(self) -> None:
        self.cfg.set("general", "check_for_updates", value=not self.check_updates)
        if not self.check_updates:
            self.updates.available = None

    # ------------------------------------------------------------- set-up
    @property
    def identity_label(self) -> str:
        from . import identity

        return identity.LABELS[identity.current(self.cfg.get("auth", default={}) or {})[0]]

    @property
    def setup_done(self) -> bool:
        """Has RADAR been set up - an identity chosen and a check passed? Until then sign-in and permission
        problems belong to the set-up window, not to the reminders."""
        done = self.cfg.get("general", "setup_done", default=None)
        if done is None:  # an installation from before this existed: set up if it has ever stored sign-ins
            done = self.auth.configured and (paths.plugin_data_dir(self.ATTACK_PLUGIN) / "signins.db").exists()
            self.cfg.set("general", "setup_done", value=bool(done))
        return bool(done)

    def apply_identity(self, values: dict[str, str]) -> None:
        """Store which application RADAR signs in as (from the set-up window); a change signs in afresh."""
        auth = self.cfg.get("auth", default={}) or {}
        if all(auth.get(k) == v for k, v in values.items()):
            return
        for key, value in values.items():
            self.cfg.set("auth", key, value=value)
        self.auth.reset()
        log.info("Set-up: sign-in identity set to %s", self.identity_label)

    def show_setup(self, run_now: bool = False) -> None:
        """Tray > Settings > Account > Set-up and connection check... - and by itself while set-up is not finished."""
        from .ui.setup import SetupWindow

        def show() -> None:
            win = getattr(self, "_setup", None)
            if win is not None and win.exists():
                win.focus()
                if run_now and not win.busy:
                    win.start(save=False)
                return
            log.info("Set-up window opened (set-up %s)", "finished" if self.setup_done else "not finished")
            self._setup = SetupWindow(self.root, self, run_now=run_now)
        self.ui_call(show)

    def _setup_needed(self, why: str) -> None:
        """A scan could not sign in or read while set-up is not finished: bring up the set-up window (once per
        start - after that the tray icon says so and the menu opens it)."""
        log.warning("Set-up not finished: %s", why)
        self._refresh_tray()
        if not getattr(self, "_setup_prompted", False):
            self._setup_prompted = True
            self.show_setup(run_now=self.auth.configured)

    def run_setup_check(self, win: Any, other_account: bool = False) -> None:
        """Sign in and try each thing RADAR reads; the window is told step by step (background thread)."""
        from . import identity, setup_check

        def work() -> None:
            kind = identity.current(self.cfg.get("auth", default={}) or {})[0]
            if other_account:
                try:
                    self.auth.sign_in_interactive(select_account=True)
                    first = setup_check.Check(setup_check.SIGN_IN, "Sign in", True, True, f"signed in as {self.auth.account}")
                except Exception as exc:  # noqa: BLE001
                    first = setup_check.Check(setup_check.SIGN_IN, "Sign in", False, True, *setup_check.explain_auth(str(exc), kind))
            else:
                first = setup_check.sign_in(self.auth, kind)
            if self.auth.state == "other_tenant":
                self._other_tenant()
            checks = [first]
            self.ui_call(win.step_done, first)
            if first.ok:
                checks += setup_check.probe(GraphClient(self.auth, self.stop_event), self.auth.account or "", kind,
                                            on_result=lambda c: self.ui_call(win.step_done, c))
            self.ui_call(self._setup_checked, win, checks)
        self._background(work, name="setup-check")

    def _setup_checked(self, win: Any, checks: list) -> None:
        from . import setup_check

        win.finished(checks)
        if setup_check.working(checks):
            self._setup_finished(scan=True)
        else:
            problem = setup_check.first_problem(checks)
            log.warning("Set-up check: RADAR cannot work yet (%s)", problem.detail if problem else "check did not finish")
            self._refresh_tray()

    def _setup_finished(self, scan: bool) -> None:
        """RADAR can sign in and read: from now on problems are reminders again, and the user is told it runs."""
        first_time = not self.setup_done
        self.cfg.set("general", "setup_done", value=True)
        for key in ["auth-required", "identity"] + [f"forbidden:{pid}" for pid in self.plugins.runtimes]:
            self.alerts.resolve_system(key)
        self.last_error = None
        self._auth_failures = 0
        log.info("Set-up %s: RADAR is working (signed in as %s, identity: %s)",
                 "finished" if first_time else "checked", self.auth.account, self.identity_label)
        if first_time and self.tray:
            self.tray.notify("RADAR is set up and working. It keeps running here in the notification area and shows "
                             "a reminder when it finds something.")
        self.ui_call(self._refresh_reminders_if_visible)
        self._refresh_tray()
        if scan:
            self.scan_now()


    def reload_plugins(self) -> None:
        self.plugins.discover()
        errors = len(self.plugins.load_errors)
        self.tray.notify(f"{len(self.plugins.runtimes)} plugin(s) loaded" + (f", {errors} failed" if errors else ""))
        self.scheduler.wake()

    def open_link(self, url: str) -> None:
        if url == IDENTITY_LINK:
            self.show_setup(run_now=True)
        elif url == SIGN_IN_LINK:
            self.sign_in(False)
        elif url == "radar://sign-in-select":
            self.sign_in(True)
        elif url == FRESH_START_LINK:
            self.start_fresh()
        else:
            webbrowser.open(url)

    def open_config(self) -> None:
        subprocess.Popen(["notepad.exe", str(paths.config_path())])

    def open_log(self) -> None:
        subprocess.Popen(["notepad.exe", str(paths.log_file())])

    def open_data_dir(self) -> None:
        os.startfile(paths.data_dir())  # noqa: S606 - opens Explorer

    def allow_user_plugin(self, name: str) -> None:
        """Tray > Plugins > (new) ...: a file in the plugins folder is only loaded after this question."""
        def ask() -> None:
            from tkinter import messagebox

            if not messagebox.askyesno(
                    APP_DISPLAY_NAME,
                    f"Load the plugin '{name}'?\n\nA plugin is a program. It runs with your rights and can use RADAR's "
                    f"sign-in to Microsoft Graph. Only allow a plugin you wrote or have read.", parent=self.root,
                    default=messagebox.NO):
                return
            self.plugins.allow_user_plugin(name)
            log.info("User plugin %s allowed", name)
            self.reload_plugins()
        self.ui_call(ask)

    def open_plugins_dir(self) -> None:
        os.startfile(paths.user_plugin_dir())  # noqa: S606
