"""AS-name lookups: cached, budgeted, and fetched in parallel for the attack overview."""
import threading
import time

from radar.plugins.signin_threats import asnames
from radar.plugins.signin_threats.asnames import AsnNameResolver


class State(dict):
    def set(self, key, value):
        self[key] = value


def test_prefetch_fetches_uncached_in_parallel_within_budget(monkeypatch):
    active, peak, calls = [0], [0], []
    lock = threading.Lock()

    def fetch(self, asn, session=None):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            calls.append(asn)
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return f"NET{asn}"

    monkeypatch.setattr(AsnNameResolver, "_fetch", fetch)
    state = State(asn_names={"1": {"n": "Cached", "t": time.time()}})
    r = AsnNameResolver(state, budget=11)
    assert r.prefetch([1, 2, 3, 3, None] + list(range(10, 18))) == 10  # 1 is cached, 3 is fetched once
    assert 1 not in calls and calls.count(3) == 1 and peak[0] > 1  # in parallel
    assert r(2) == "NET2" and r(1) == "Cached" and len(calls) == 10  # served from the cache
    assert r(99) == "NET99" and len(calls) == 11  # the last budget unit
    assert r(100) is None  # budget used up
    assert r.prefetch([200, 201]) == 0
    r.save()
    assert state["asn_names"]["2"]["n"] == "NET2"


def test_disabled_resolver_never_fetches(monkeypatch):
    monkeypatch.setattr(asnames.AsnNameResolver, "_fetch", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    r = AsnNameResolver(State(), enabled=False)
    assert r.prefetch([1, 2]) == 0 and r(1) is None
