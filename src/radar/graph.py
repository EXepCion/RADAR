"""Small Microsoft Graph client: paging, throttling/retry handling and readable errors."""
from __future__ import annotations

import email.utils
import logging
import threading
from collections import Counter
import time
from datetime import timezone
from typing import Any, Iterator

from urllib.parse import urlsplit

import requests

from . import __version__
from .auth import AuthManager
from .plugin_api import OperationCancelled

log = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com"
GRAPH_HOST = "graph.microsoft.com"
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 5
BURST_SECONDS = 10   # the span Graph's limits for its log endpoints are counted in


class GraphError(Exception):
    def __init__(self, status: int, code: str, message: str, url: str = ""):
        super().__init__(f"Graph {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.url = url

    @classmethod
    def from_response(cls, resp: requests.Response) -> "GraphError":
        code, message = "", resp.text[:300]
        try:
            err = resp.json().get("error", {})
            code, message = err.get("code", ""), err.get("message", message)
        except ValueError:
            pass
        return cls(resp.status_code, code, message, resp.url)


class Page(list):
    """One page of a listing (its ``value`` array). ``cut``: the paging stopped after it at ``max_pages`` while Graph
    had more - what came after it was not read. (A plain list - what a test stands in with - never says so.)"""

    cut = False


def page_cut(page: Any) -> bool:
    """Did the paging stop after this page with more to come (see Page)?"""
    return bool(getattr(page, "cut", False))


def _retry_after(resp: requests.Response, attempt: int) -> float:
    """How long to wait before asking again: what Graph says (seconds, or an HTTP date), else a growing pause. A
    value that is neither counts as none - it never ends the request."""
    value = resp.headers.get("Retry-After")
    if value:
        try:
            return min(120.0, max(1.0, float(value)))
        except ValueError:
            try:
                parsed = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError, IndexError):
                parsed = None
            if parsed:
                if parsed.tzinfo is None:  # "-0000": UTC, said without saying it (not this PC's local time)
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return min(120.0, max(1.0, parsed.timestamp() - time.time()))
    return min(60.0, 2.0 ** attempt)


class GraphClient:
    def __init__(self, auth: AuthManager, stop_event: threading.Event | None = None,
                 timeout: tuple[float, float] = (15, 180)):
        self._auth = auth
        self._stop = stop_event or threading.Event()
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["User-Agent"] = f"RADAR/{__version__}"
        # what was asked of Graph through this client (one scan of a plugin has one): requests by what they ask for,
        # how many of them Graph answered with "too many requests", and the seconds waited before asking again
        self.asked: Counter[str] = Counter()
        self.throttled, self.waited = 0, 0.0
        self._times: list[float] = []   # when each request went out (Graph limits how many there may be in a short time)

    @staticmethod
    def _what(url: str) -> str:
        """What a request asks for, in a word or two: 'auditLogs/signIns', 'users' (no ids, no parameters)."""
        parts = [p for p in urlsplit(url).path.split("/") if p][1:]   # (without the version)
        named = [p for p in parts if not any(ch.isdigit() for ch in p) and "(" not in p]
        if named[:1] == ["auditLogs"] or named[:1] == ["identity"] or named[:1] == ["reports"] or named[:1] == ["policies"] or named[:1] == ["roleManagement"]:
            return "/".join(named[:2])
        return named[0] if named else "?"

    def busiest(self) -> int:
        """The most requests that went out within any BURST_SECONDS."""
        most, first = 0, 0
        for last, at in enumerate(self._times):
            while at - self._times[first] > BURST_SECONDS:
                first += 1
            most = max(most, last - first + 1)
        return most

    def usage(self) -> str:
        """What this client asked of Graph, for the log ('' when nothing)."""
        total = sum(self.asked.values())
        if not total:
            return ""
        text = f"{total:,} request{'s' if total != 1 else ''} to Microsoft Graph ({', '.join(f'{what} {n:,}' for what, n in self.asked.most_common())})"
        if total > 1:
            text += f"; at most {self.busiest():,} within {BURST_SECONDS} seconds"
        if self.throttled:
            text += f", {self.throttled:,} of them answered with 'too many requests' ({self.waited:.0f} s waited)"
        return text

    def _sleep(self, seconds: float) -> None:
        if self._stop.wait(seconds):
            raise OperationCancelled()

    @staticmethod
    def _url(path: str) -> str:
        """The address to ask. A full address (a next-page link) is only accepted when it leads to Microsoft Graph:
        the sign-in token is never sent anywhere else."""
        if "://" not in path:
            return f"{GRAPH}/{path.lstrip('/')}"
        parts = urlsplit(path)
        if parts.scheme != "https" or (parts.hostname or "").lower() != GRAPH_HOST or parts.port not in (None, 443) \
                or parts.username or parts.password:
            raise GraphError(0, "untrusted_url", f"refused to send the sign-in token to {parts.hostname or path[:60]!r}", path)
        return path

    def get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        url = self._url(path)
        attempt = 0
        refreshed = False
        force_refresh = False
        while True:
            if self._stop.is_set():
                raise OperationCancelled()
            token = self._auth.get_token(force_refresh=force_refresh)
            force_refresh = False
            self.asked[self._what(url)] += 1
            self._times.append(time.monotonic())
            try:
                resp = self._session.get(url, params=params, timeout=self._timeout,
                                         headers={"Authorization": f"Bearer {token}"})
            except requests.RequestException as exc:
                attempt += 1
                if attempt > MAX_RETRIES:
                    raise GraphError(0, "network", str(exc), url) from exc
                log.info("Network error (%s), retry %d", exc.__class__.__name__, attempt)
                self._sleep(min(60.0, 2.0 ** attempt))
                continue
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 401 and not refreshed:
                refreshed = force_refresh = True
                continue
            if resp.status_code == 429:
                self.throttled += 1
            if resp.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                attempt += 1
                delay = _retry_after(resp, attempt)
                self.waited += delay if resp.status_code == 429 else 0.0
                log.info("Graph %s, retrying in %.0fs (attempt %d)", resp.status_code, delay, attempt)
                self._sleep(delay)
                continue
            raise GraphError.from_response(resp)

    def get_pages(self, path: str, params: dict[str, str] | None = None,
                  max_pages: int | None = None) -> Iterator[list[dict[str, Any]]]:
        """Yield the ``value`` array of each page (a :class:`Page`), following ``@odata.nextLink``. When ``max_pages``
        ends the paging while Graph has more, the last page yielded says so (``cut``): the caller knows that it did
        not get everything - Graph lists sign-ins newest first, so what is missing is the oldest part."""
        url: str | None = path
        pages = 0
        while url:
            data = self.get(url, params)
            pages += 1
            url, params = data.get("@odata.nextLink"), None
            page = Page(data.get("value", []))
            page.cut = bool(url and max_pages and pages >= max_pages)
            if page.cut:
                # one page was asked for on purpose (a sample): nothing was cut short
                log.log(logging.DEBUG if max_pages == 1 else logging.WARNING,
                        "Stopped paging %s after %d pages (max_pages)", path, pages)
            yield page
            if page.cut:
                return

    def get_all(self, path: str, params: dict[str, str] | None = None,
                max_pages: int | None = None) -> Iterator[dict[str, Any]]:
        for page in self.get_pages(path, params, max_pages):
            yield from page
