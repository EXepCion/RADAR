"""AS holder names from RIPEstat, cached in plugin state.

Only the public AS *number* is sent (never IPs or user data). Disable with
``scoring.lookup_asn_names: false``.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

import requests

log = logging.getLogger(__name__)
URL = "https://stat.ripe.net/data/as-overview/data.json"
RETRY_FAILED_AFTER = 7 * 86400


class AsnNameResolver:
    def __init__(self, state: Any, enabled: bool = True, budget: int = 40, timeout: float = 5.0):
        self._state = state
        self._enabled = enabled
        self._budget = budget
        self._timeout = timeout
        self._cache: dict[str, dict] = dict(state.get("asn_names", {}) or {}) if state else {}
        self._dirty = False
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "RADAR (ASN name lookup)"

    def _known(self, key: str) -> bool:
        hit = self._cache.get(key)
        return bool(hit and (hit.get("n") or time.time() - hit.get("t", 0) < RETRY_FAILED_AFTER))

    def _fetch(self, asn: int, session: requests.Session | None = None) -> str:
        try:
            params = {"resource": f"AS{asn}"}
            if session is not None:  # the shared session (single lookups) already carries the User-Agent
                resp = session.get(URL, params=params, timeout=self._timeout)
            else:  # parallel lookups: requests.Session is not thread-safe, one request each
                resp = requests.get(URL, params=params, timeout=self._timeout,
                                    headers={"User-Agent": "RADAR (ASN name lookup)"})
            if resp.ok:
                return str((resp.json().get("data") or {}).get("holder") or "").strip()
        except (requests.RequestException, ValueError) as exc:
            log.debug("ASN lookup AS%s failed: %s", asn, exc)
        return ""

    def __call__(self, asn: int | None) -> str | None:
        if not asn:
            return None
        key = str(asn)
        if self._known(key):
            return self._cache[key].get("n") or None
        if not self._enabled or self._budget <= 0:
            return None
        self._budget -= 1
        name = self._fetch(asn, self._session)
        self._cache[key] = {"n": name, "t": time.time()}
        self._dirty = True
        return name or None

    def prefetch(self, asns: Iterable[int | None], workers: int = 8) -> int:
        """Look up the uncached names of many networks in parallel (the attack overview lists 100+ at once).
        Uses the same budget as single lookups. Returns how many were fetched."""
        if not self._enabled:
            return 0
        todo = [a for a in dict.fromkeys(a for a in asns if a) if not self._known(str(a))][:max(0, self._budget)]
        if not todo:
            return 0
        self._budget -= len(todo)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            names = list(pool.map(self._fetch, todo))
        now = time.time()
        for asn, name in zip(todo, names):
            self._cache[str(asn)] = {"n": name, "t": now}
        self._dirty = True
        return len(todo)

    def save(self) -> None:
        if self._dirty and self._state is not None:
            self._state.set("asn_names", self._cache)
            self._dirty = False
