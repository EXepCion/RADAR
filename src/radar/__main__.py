"""Entry point: ``RADAR.exe`` / ``pythonw -m radar``.

Options (mainly for diagnostics; run with python.exe to see console output):
  --scan-once      run all enabled plugins once in a temporary data folder and print the findings
  --check-auth     acquire a token silently and print the signed-in account
  --demo           show the reminder window with sample alerts (temporary data folder)
  --rescore [H]    re-assess open reminders with the current rules (after tuning; may lower ratings)
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import shutil
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone

from . import APP_DISPLAY_NAME, APP_NAME, __version__


def setup_logging(console: bool = False) -> None:
    from . import paths

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(paths.log_file(), maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    if console and sys.stderr:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    for noisy in ("msal", "urllib3", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    def _excepthook(exc_type, exc, tb):
        logging.getLogger("radar").critical("Unhandled exception", exc_info=(exc_type, exc, tb))

    sys.excepthook = _excepthook
    threading.excepthook = lambda a: _excepthook(a.exc_type, a.exc_value, a.exc_traceback)


def _use_temp_home(prefix: str) -> str:
    home = tempfile.mkdtemp(prefix=prefix)
    os.environ["RADAR_HOME"] = home
    return home


def cmd_check_auth() -> int:
    from . import paths
    from .auth import AuthManager, AuthRequiredError
    from .config import ConfigManager

    auth = AuthManager(ConfigManager(paths.config_path()), paths.token_cache_path())
    if not auth.configured:
        print("It has not been chosen yet how RADAR signs in: start RADAR and use Settings > Account > Sign-in identity...")
        return 1
    try:
        auth.get_token()
    except AuthRequiredError as exc:
        print(f"Silent sign-in failed: {exc}")
        return 1
    print(f"Signed in silently as {auth.account} (tenant {auth.tenant_id})")
    return 0


def cmd_scan_once(verbose: bool = False) -> int:
    from .app import App

    app = App(demo=True)
    status = 0
    for rt in app.plugins.ordered():
        if not app.plugins.is_enabled(rt.plugin.id):
            continue
        print(f"== {rt.plugin.name}")
        try:
            findings = app.plugins.run(rt.plugin.id)
        except Exception as exc:
            print(f"   FAILED: {type(exc).__name__}: {exc}")
            status = 1
            continue
        print(f"   {rt.status_text}")
        for f in sorted(findings, key=lambda f: (-f.severity, -(f.score or 0))):
            score = f" {f.score:>3}" if f.score is not None else ""
            print(f"   [{f.severity.label:<6}{score}] {f.title}\n               {f.summary}")
            if verbose:
                for points, reason in f.factors:
                    print(f"                  {points:+4d}  {reason}")
    for err in app.plugins.load_errors:
        print(f"Load error: {err.source}: {err.error}")
    app.store.close()
    return status


def cmd_rescore(hours: int) -> int:
    """Re-assess open reminders with the current rules (after an update/tuning). May lower ratings."""
    import threading

    from . import paths
    from .alerts import AlertCenter
    from .config import ConfigManager
    from .plugin_api import Severity
    from .plugin_manager import PluginManager
    from .store import Store

    cfg = ConfigManager(paths.config_path())
    store = Store(paths.db_path())
    alerts = AlertCenter(store)
    pm = PluginManager(cfg, store, graph_factory=lambda: None, user_dir=paths.user_plugin_dir(),
                       stop_event=threading.Event())
    pm.discover()
    try:
        min_sev = Severity.parse(cfg.get("general", "notify_min_severity", default="low"))
    except (KeyError, ValueError):
        min_sev = Severity.LOW
    changed = 0
    for rt in pm.ordered():
        if not pm.is_enabled(rt.plugin.id):
            continue
        for f in rt.plugin.reevaluate(pm.build_context(rt.plugin.id), hours):
            result = alerts.replace_assessment(f, min_sev)
            if result:
                before, after = result
                changed += 1
                print(f"  {before.severity.label} {before.score} -> {after.severity.label} {after.score} "
                      f"[{after.status}]  {after.title}")
    print(f"{changed} open reminder(s) re-assessed")
    store.close()
    return 0


def _demo_findings() -> list:
    from .plugin_api import Finding, Severity
    from .plugins.signin_threats.rules import SIGNIN_LOGS_URL

    now = datetime.now(timezone.utc)
    ev = lambda m, user, ip, loc, res: {"Time": (now - timedelta(minutes=m)).astimezone().strftime("%Y-%m-%d %H:%M:%S"),  # noqa: E731
                                         "User": user, "Application": "Office 365 Exchange Online",
                                         "IP address": ip, "Location": loc, "Result": res}
    return [
        Finding(key="demo|spray", rule_id="password_spray", severity=Severity.HIGH,
                title="Password spray from 185.220.101.47", occurred_at=now - timedelta(minutes=12),
                summary="41 failed sign-ins against 23 different accounts from 185.220.101.47 (Frankfurt am Main, DE) "
                        "within 60 minutes.",
                fields={"IP address": "185.220.101.47", "Targeted accounts": "23"},
                evidence=[ev(12 + i, f"user{i}@example.com", "185.220.101.47", "Frankfurt am Main, DE",
                             "Failure 50126: Invalid username or password") for i in range(8)],
                recommendation="Block the IP and verify every targeted account has MFA.",
                links=[("Open sign-in logs", SIGNIN_LOGS_URL)]),
        Finding(key="demo|travel", rule_id="impossible_travel", severity=Severity.HIGH, score=85,
                title="Impossible travel: maria.garcia@example.com (likely VPN / proxy)", occurred_at=now - timedelta(hours=2),
                summary="maria.garcia@example.com signed in from Toronto, CA and 9,350 km away from Singapore, SG "
                        "37 minutes later (~15,160 km/h).",
                fields={"User": "maria.garcia@example.com", "Risk score": "85/100  (likely VPN / proxy)"},
                factors=[(45, "9,350 km from the previous sign-in in 37 min"),
                         (25, "Hosting network: DigitalOcean (AS14061)"),
                         (10, "Network AS14061 never seen in the tenant"),
                         (10, "No device identity (unregistered device or anonymous browser)"),
                         (10, "Password only, no MFA"), (-15, "Risk remediated (MFA / password change completed)")],
                evidence=[ev(120, "maria.garcia@example.com", "203.0.113.5", "Singapore, SG", "Success"),
                          ev(157, "maria.garcia@example.com", "198.51.100.7", "Toronto, CA", "Success")],
                links=[("Entra: sign-in logs", SIGNIN_LOGS_URL)]),
        Finding(key="demo|legacy", rule_id="legacy_auth", severity=Severity.MEDIUM,
                title="Legacy authentication (IMAP4): scanner@example.com", occurred_at=now - timedelta(hours=5),
                summary="3 successful sign-in(s) for scanner@example.com using IMAP4, which cannot enforce MFA."),
        Finding(key="demo|country", rule_id="new_country", severity=Severity.LOW,
                title="Sign-in from new country (BR): john.smith@example.com", occurred_at=now - timedelta(days=1),
                summary="Successful sign-in from Sao Paulo, BR. The user normally signs in from CA, DE."),
    ]


def cmd_demo(screenshot: str | None) -> int:
    from .app import App

    def on_ready(app: App) -> None:
        app.deliver("signin_threats", _demo_findings())
        if screenshot:
            def grab() -> None:
                from PIL import ImageGrab
                top = app.reminders.top
                top.update()
                x, y = top.winfo_rootx(), top.winfo_rooty()
                ImageGrab.grab(bbox=(x - 8, y - 32, x + top.winfo_width() + 8, y + top.winfo_height() + 8),
                               all_screens=True).save(screenshot)
                if os.environ.get("RADAR_DEMO_DETAILS"):
                    app.reminders.open_selected()
                    app.root.after(1500, lambda: _grab_details(app, screenshot))
                else:
                    app.quit()
            app.root.after(2500, grab)

    App(demo=True).run(on_ready=on_ready)
    return 0


def _grab_details(app, screenshot: str) -> None:
    from PIL import ImageGrab

    for w in app.root.winfo_children():
        if w is not app.reminders.top and w.winfo_viewable():
            w.update()
            x, y = w.winfo_rootx(), w.winfo_rooty()
            ImageGrab.grab(bbox=(x - 8, y - 32, x + w.winfo_width() + 8, y + w.winfo_height() + 8),
                           all_screens=True).save(screenshot.replace(".png", "-details.png"))
    app.quit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=APP_DISPLAY_NAME)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--scan-once", action="store_true", help="run enabled plugins once (temp data) and print")
    parser.add_argument("--check-auth", action="store_true", help="test silent sign-in")
    parser.add_argument("--verbose", action="store_true", help="with --scan-once: print the risk factors")
    parser.add_argument("--demo", action="store_true", help="show the reminder window with sample alerts")
    parser.add_argument("--rescore", type=int, nargs="?", const=72, metavar="HOURS",
                        help="re-assess open reminders with the current rules (default: last 72 h of history)")
    parser.add_argument("--screenshot", help=argparse.SUPPRESS)
    parser.add_argument("--restarted", action="store_true", help=argparse.SUPPRESS)  # wait for the previous instance to end
    args = parser.parse_args(argv)

    temp_home = None
    if args.scan_once or args.demo:
        from . import paths

        real_config = paths.config_path()
        temp_home = _use_temp_home("radar-scan-" if args.scan_once else "radar-demo-")
        if args.scan_once and real_config.exists():  # dry-run with the user's real tuning
            shutil.copy(real_config, os.path.join(temp_home, "config.json"))
    setup_logging(console=bool(args.scan_once or args.check_auth or args.rescore))
    log = logging.getLogger("radar")
    log.info("%s %s starting (%s)", APP_DISPLAY_NAME, __version__, " ".join(sys.argv[1:]) or "tray")

    if args.check_auth:
        return cmd_check_auth()
    if args.rescore:
        return cmd_rescore(args.rescore)
    if temp_home:
        try:
            return cmd_scan_once(args.verbose) if args.scan_once else cmd_demo(args.screenshot)
        finally:  # the temp folder holds a copy of tenant sign-in data: do not leave it behind
            logging.shutdown()
            for h in list(logging.getLogger().handlers):
                logging.getLogger().removeHandler(h)
            shutil.rmtree(temp_home, ignore_errors=True)

    from .singleinstance import SingleInstance

    instance = SingleInstance(APP_NAME)
    if args.restarted:  # started by an instance that is closing (fresh start): give it time to end
        import time

        deadline = time.monotonic() + 20
        while instance.already_running and time.monotonic() < deadline:
            instance.close()
            time.sleep(0.5)
            instance = SingleInstance(APP_NAME)
    if instance.already_running:
        log.info("Already running - asking the running instance to show its reminders")
        instance.signal_running_instance()
        return 0

    from . import paths, tenant
    from .app import App
    from .config import ConfigManager

    try:  # a fresh start asked for in the last run: move the old tenant's data away before anything opens it
        tenant.apply_pending(ConfigManager(paths.config_path()), paths.data_dir(), paths.config_path())
    except Exception:
        log.exception("Fresh start failed")
    app = App()
    instance.listen(lambda: app.show_reminders_from_tray(), app.stop_event)
    app.run()
    if app.restart_requested:
        import subprocess

        command = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "radar"]
        log.info("Restarting")
        subprocess.Popen(command + ["--restarted"], close_fds=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
