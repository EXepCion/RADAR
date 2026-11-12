"""Is there a newer RADAR? Asks GitHub once a day for the latest release and says so - nothing is downloaded.

RADAR does not update itself: the release files are not code-signed, and a program that fetches and runs unsigned
programs on its own would be a weak spot in a security tool. It tells you (a notification, a line in the tray
menu); the link opens the release page in the browser, and installing the new version over the old one is up to
you. The check can be switched off (Settings > Check for new versions, ``general.check_for_updates``).

The only thing sent is the request itself (to api.github.com, with "RADAR/<version>" as the user agent).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from . import __version__

log = logging.getLogger(__name__)

LATEST_URL = "https://api.github.com/repos/EXepCion/RADAR/releases/latest"
RELEASES_PAGE = "https://github.com/EXepCion/RADAR/releases"
CHECK_EVERY = 24 * 3600      # seconds between two checks
FIRST_CHECK_AFTER = 90       # seconds after the start (not in the way of the first scan)
RETRY_AFTER = 3600           # after a check that failed (no network, GitHub busy)


@dataclass(frozen=True)
class Release:
    version: str   # "1.2.0"
    url: str       # its page on GitHub


def parse_version(text: str) -> tuple[int, ...]:
    """'v1.2.0' -> (1, 2, 0). Anything that is not a plain release number (a pre-release, a name) gives ()."""
    m = re.fullmatch(r"v?(\d+(?:\.\d+){0,3})", str(text or "").strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else ()


def is_newer(candidate: str, current: str = __version__) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def latest_release(get: Callable[..., Any] | None = None, timeout: float = 10) -> Release | None:
    """The newest published release (not drafts, not pre-releases), or None when it could not be found out."""
    if get is None:
        import requests

        get = requests.get
    try:
        resp = get(LATEST_URL, headers={"Accept": "application/vnd.github+json", "User-Agent": f"RADAR/{__version__}"},
                   timeout=timeout)
        if resp.status_code != 200:
            log.debug("update check: GitHub answered %s", resp.status_code)
            return None
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - offline, proxy, GitHub down: simply no answer today
        log.debug("update check failed: %s", exc)
        return None
    version = str(data.get("tag_name") or "").strip().lstrip("v")
    if not parse_version(version) or data.get("draft") or data.get("prerelease"):
        return None
    url = str(data.get("html_url") or "")
    return Release(version, url if url.startswith("https://github.com/") else RELEASES_PAGE)


class UpdateChecker:
    """Decides when to look and whether to tell. ``available`` is the newer release, if any."""

    def __init__(self, enabled: Callable[[], bool], notified: Callable[[], str], remember: Callable[[str], None],
                 fetch: Callable[[], Release | None] = latest_release, clock: Callable[[], float] = time.monotonic):
        self._enabled, self._notified, self._remember = enabled, notified, remember
        self._fetch, self._clock = fetch, clock
        self._next = clock() + FIRST_CHECK_AFTER
        self.available: Release | None = None

    def due(self) -> bool:
        return self._enabled() and self._clock() >= self._next

    def check(self) -> Release | None:
        """Look now. Returns the release to announce - a newer one the user has not been told about yet - else None."""
        if not self._enabled():
            self.available = None
            return None
        release = self._fetch()
        self._next = self._clock() + (CHECK_EVERY if release is not None else RETRY_AFTER)
        if release is None:
            return None
        if not is_newer(release.version):
            self.available = None
            log.info("Update check: %s is the current version", __version__)
            return None
        self.available = release
        if self._notified() == release.version:
            return None  # told once; the tray menu keeps saying it
        self._remember(release.version)
        log.info("Update check: RADAR %s is available (running %s)", release.version, __version__)
        return release
