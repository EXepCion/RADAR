"""Small Microsoft Graph client: paging, throttling/retry handling and readable errors."""
from __future__ import annotations

import email.utils
import logging
import threading
import time
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


def _retry_after(resp: requests.Response, attempt: int) -> float:
    value = resp.headers.get("Retry-After")
    if value:
        try:
            return min(120.0, max(1.0, float(value)))
        except ValueError:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed:
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
            if resp.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                attempt += 1
                delay = _retry_after(resp, attempt)
                log.info("Graph %s, retrying in %.0fs (attempt %d)", resp.status_code, delay, attempt)
                self._sleep(delay)
                continue
            raise GraphError.from_response(resp)

    def get_pages(self, path: str, params: dict[str, str] | None = None,
                  max_pages: int | None = None) -> Iterator[list[dict[str, Any]]]:
        """Yield the ``value`` array of each page, following ``@odata.nextLink``."""
        url: str | None = path
        pages = 0
        while url:
            data = self.get(url, params)
            yield data.get("value", [])
            pages += 1
            url, params = data.get("@odata.nextLink"), None
            if url and max_pages and pages >= max_pages:
                log.warning("Stopped paging %s after %d pages (max_pages)", path, pages)
                return

    def get_all(self, path: str, params: dict[str, str] | None = None,
                max_pages: int | None = None) -> Iterator[dict[str, Any]]:
        for page in self.get_pages(path, params, max_pages):
            yield from page
