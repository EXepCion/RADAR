"""``python -m radar.mapview``: serve the live map to an Edge app window and exit when it is closed.

Security: the page and its data (who signed in from where) are served on the loopback interface only, on a random
port, below a random path that only the window started here knows. Nothing is loaded from the internet - the map
library and the world outline ship with the app.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import account_events
from .. import paths, screens
from ..config import ConfigManager
from ..plugins.signin_threats.accounts import AccountDirectory
from ..plugins.signin_threats.history import SignInHistory
from . import data

log = logging.getLogger("radar.mapview")
PLUGIN = "signin_threats"
STATIC = Path(__file__).with_name("static")
STATIC_FILES = frozenset({"echarts.min.js", "world.js"})  # what the page loads (the page itself is the root route)
HEARTBEAT = "map.open"      # touched while the map is open: the tray app then scans more often
REQUESTS = "map-requests"   # folder: "open this user / device" requests for the tray app (it has the Entra sign-in)
OPEN_ACTIONS = {"user": {"user", "user_signins", "user_methods", "user_audit"}, "device": {"device"},
                "signin": {"view_signin"}}
CACHE_SECONDS = 15          # the snapshot is recomputed at most this often
RECOMPUTE_SECONDS = 300     # ... and at least this often (ages on the map move on) when no new data arrived
ATTACK_HOURS = (1, 24, 72)  # attack windows the page can ask for
IDLE_EXIT_SECONDS = 150     # the page has not asked for this long: its window is gone
START_GRACE_SECONDS = 60    # time for the window to appear and ask for the first time
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json"}


class MapData:
    """Reads what the tray app has collected. Opens the history per request and never writes to it."""

    def __init__(self, data_dir: Path | None = None, config_path: Path | None = None, db_path: Path | None = None):
        self.data_dir = data_dir or paths.plugin_data_dir(PLUGIN)
        self.config_path = config_path or paths.config_path()
        self.db_path = db_path or paths.db_path()
        self._lock = threading.Lock()
        self._cache: dict[Any, tuple[float, Any, dict[str, Any]]] = {}  # (attack hours, offline) -> (time, stamp, result)
        self._asn_names: dict[str, dict] | None = None

    def settings(self) -> dict:
        return ConfigManager(self.config_path).get("plugins", PLUGIN, "settings", default={}) or {}

    def as_of(self) -> datetime | None:
        """When the tray app last wrote the sign-in history (= its last scan)."""
        stamps = [p.stat().st_mtime for p in (self.data_dir / "signins.db", self.data_dir / "signins.db-wal") if p.exists()]
        return datetime.fromtimestamp(max(stamps), timezone.utc) if stamps else None

    def asn_name(self, asn: int | None) -> str | None:
        """Network names the tray app has looked up before (read-only; the map does no lookups itself)."""
        if self._asn_names is None:
            self._asn_names = {}
            try:
                conn = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True, timeout=5)
                try:
                    row = conn.execute("SELECT value FROM kv WHERE namespace=? AND key=?",
                                       (f"plugin:{PLUGIN}", "asn_names")).fetchone()
                finally:
                    conn.close()
                self._asn_names = json.loads(row[0]) if row else {}
            except (sqlite3.Error, ValueError, OSError):
                log.debug("network names not readable", exc_info=True)
        hit = self._asn_names.get(str(asn)) if asn else None
        return (hit or {}).get("n") or None

    def icon(self, size: str = "64") -> bytes:
        """RADAR's icon as PNG (drawn, not a file; kept after the first request)."""
        import io

        from ..ui import icons

        try:
            px = min(256, max(16, int(size)))
        except ValueError:
            px = 64
        cache = self.__dict__.setdefault("_icons", {})
        if px not in cache:
            buffer = io.BytesIO()
            icons.app_icon(px).save(buffer, format="PNG")
            cache[px] = buffer.getvalue()
        return cache[px]

    def _history(self) -> SignInHistory | None:
        path = self.data_dir / "signins.db"
        return SignInHistory(path) if path.exists() else None

    def snapshot(self, attack_hours: float = 24, offline: bool = False) -> dict[str, Any]:
        """The map's data. Recomputed when the tray app has written new sign-ins (at most every CACHE_SECONDS) or
        after RECOMPUTE_SECONDS, so an open map costs next to nothing between two scans."""
        attack_hours = min(ATTACK_HOURS, key=lambda h: abs(h - attack_hours))
        with self._lock:
            stamp = self.as_of()
            cache_key = (attack_hours, bool(offline))
            hit = self._cache.get(cache_key)
            if hit:
                age = time.monotonic() - hit[0]
                if age < CACHE_SECONDS or (hit[1] == stamp and age < RECOMPUTE_SECONDS):
                    return hit[2]
            history = self._history()
            if history is None:
                result: dict[str, Any] = {"empty": True, "places": [], "people": [], "attacks": [], "events": [],
                                          "stats": {}, "as_of": ""}
            else:
                try:
                    result = data.build_snapshot(history, self.settings(), AccountDirectory.load(self.data_dir / "accounts.json"),
                                                 datetime.now(timezone.utc), attack_hours=attack_hours, as_of=stamp,
                                                 asn_names=self.asn_name, include_offline=bool(offline),
                                                 account_events=account_events.load(
                                                     paths.plugin_data_dir(account_events.PLUGIN) / account_events.FILE))
                finally:
                    history.close()
            cfg = ConfigManager(self.config_path)
            result["ui"] = {"dark": bool(cfg.get("general", "dark_mode", default=False)),
                            "animations": bool(cfg.get("general", "animations", default=True))}
            self._cache[cache_key] = (time.monotonic(), stamp, result)
            return result

    def request_open(self, kind: str, value: str, action: str) -> bool:
        """Ask the tray app to open the detail view (Entra page) of a user or device. The map has no access to
        Entra itself; the request is a small file the app picks up within a second. False = not a valid request."""
        value = (value or "").strip()
        if action not in OPEN_ACTIONS.get(kind, ()) or not value or len(value) > 200 or any(ord(c) < 32 for c in value):
            return False
        folder = self.data_dir / REQUESTS
        folder.mkdir(parents=True, exist_ok=True)
        name = f"{time.time_ns()}-{secrets.token_hex(4)}"
        tmp = folder / f"{name}.tmp"
        tmp.write_text(json.dumps({"kind": kind, "value": value, "action": action}), encoding="utf-8")
        tmp.replace(folder / f"{name}.json")
        return True

    def person(self, user_id: str) -> dict[str, Any]:
        history = self._history()
        if history is None:
            return {}
        try:
            return data.person_detail(history, self.settings(), AccountDirectory.load(self.data_dir / "accounts.json"),
                                      datetime.now(timezone.utc), user_id, asn_names=self.asn_name)
        finally:
            history.close()


def make_handler(source: MapData, token: str, seen: list[float]):
    prefix = f"/{token}/"

    class Handler(BaseHTTPRequestHandler):
        server_version = "radar-map"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet: no request log on stderr
            log.debug(fmt, *args)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: Any) -> None:
            self._send(200, json.dumps(payload).encode("utf-8"), TYPES[".json"])

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            url = urlparse(self.path)
            host = (self.headers.get("Host") or "").split(":")[0]
            if not url.path.startswith(prefix) or host not in ("127.0.0.1", "localhost"):
                self._send(404, b"not found", "text/plain")
                return
            seen[0] = time.monotonic()
            route = url.path[len(prefix):]
            try:
                if route in ("", "index.html"):
                    self._send(200, (STATIC / "index.html").read_bytes(), TYPES[".html"])
                elif route == "data":
                    try:
                        hours = float((parse_qs(url.query).get("attacks") or ["24"])[0])
                    except ValueError:
                        hours = 24
                    self._json(source.snapshot(hours, offline=(parse_qs(url.query).get("offline") or ["0"])[0] == "1"))
                elif route == "person":
                    self._json(source.person((parse_qs(url.query).get("id") or [""])[0]))
                elif route == "open":
                    q = parse_qs(url.query)
                    self._json({"ok": source.request_open((q.get("kind") or [""])[0], (q.get("value") or [""])[0],
                                                          (q.get("action") or [""])[0])})
                elif route == "ping":
                    self._json({"ok": True})
                elif route == "icon.png":  # the window's icon (Edge takes the page's icon for an app window)
                    self._send(200, source.icon((parse_qs(url.query).get("size") or ["64"])[0]), "image/png")
                elif route.startswith("static/") and route[7:] in STATIC_FILES:  # by name: no path is ever built from a request
                    path = STATIC / route[7:]
                    if path.is_file():
                        self._send(200, path.read_bytes(), TYPES[path.suffix])
                    else:
                        self._send(404, b"not found", "text/plain")
                else:
                    self._send(404, b"not found", "text/plain")
            except Exception as exc:
                log.exception("request %s failed", route)
                self._send(500, json.dumps({"error": str(exc)}).encode("utf-8"), TYPES[".json"])

    return Handler


def find_edge() -> str | None:
    for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"), os.environ.get("LOCALAPPDATA")):
        if base:
            exe = Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            if exe.exists():
                return str(exe)
    return shutil.which("msedge")


def open_window(url: str, profile: Path) -> subprocess.Popen | None:
    """An Edge app window (no address bar) with a profile of its own: the process lives as long as the window."""
    edge = find_edge()
    if not edge:
        webbrowser.open(url)
        return None
    profile.mkdir(parents=True, exist_ok=True)
    args = [edge, f"--app={url}", f"--user-data-dir={profile}", "--no-first-run",
            "--no-default-browser-check", "--disable-sync", "--disable-extensions"]
    return subprocess.Popen(args + window_bounds(screens.pointer_area()))


def window_bounds(area: tuple[int, int, int, int] | None, width: int = 1500, height: int = 920) -> list[str]:
    """Size and place of the map window: on the screen the mouse is on (``area`` = that screen's work area), centred,
    never larger than it. Without a known screen only the size is given and the browser chooses the place."""
    if area is None:
        return [f"--window-size={width},{height}"]
    x, y, w, h = screens.place(width, height, area)
    return [f"--window-size={w},{h}", f"--window-position={x},{y}"]


def keep_serving(window_running: bool, since_start: float, since_request: float | None) -> bool:
    """Should the map's server go on? It lives as long as a page is using it - not as long as the browser process
    it started: when a map window is already open, the browser hands the new window to that instance and the
    started process ends at once, although the window is there and needs the server.

    - the page asks for data every few seconds: as long as it does, serve (IDLE_EXIT_SECONDS covers a window that
      is minimised, where browsers slow timers down)
    - no page has asked yet: give the window START_GRACE_SECONDS to appear
    - the page has gone silent: stop, unless the browser process we started is still running (then the window
      exists but is asleep)"""
    if since_request is None:
        return window_running or since_start < START_GRACE_SECONDS
    return since_request < IDLE_EXIT_SECONDS or (window_running and since_request < 15 * 60)


def serve(source: MapData | None = None, open_browser: bool = True) -> None:
    source = source or MapData()
    token = secrets.token_urlsafe(18)
    started = time.monotonic()
    seen = [0.0]  # time of the last request of a page (0 = none yet)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(source, token, seen))
    server.daemon_threads = True
    url = f"http://127.0.0.1:{server.server_address[1]}/{token}/"
    threading.Thread(target=server.serve_forever, name="map-http", daemon=True).start()
    log.info("Live map serving on port %s", server.server_address[1])
    heartbeat = source.data_dir / HEARTBEAT
    window = open_window(url, paths.data_dir() / "mapview-profile") if open_browser else None
    try:
        while True:
            try:
                heartbeat.touch()
            except OSError:
                pass
            time.sleep(5)
            now = time.monotonic()
            running = window is not None and window.poll() is None
            if not keep_serving(running, now - started, (now - seen[0]) if seen[0] else None):
                break
    finally:
        try:
            heartbeat.unlink(missing_ok=True)
        except OSError:
            pass
        server.shutdown()
        log.info("Live map closed")


def main() -> None:
    logging.basicConfig(filename=str(paths.log_dir() / "mapview.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    try:
        serve()
    except Exception:
        log.exception("Live map failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
