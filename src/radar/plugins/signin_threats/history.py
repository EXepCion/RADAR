"""Local sign-in history (SQLite) used for baselines, windowed detections and risk scoring."""
from __future__ import annotations

import logging
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from . import netintel
from .models import AccountChange, SignIn

log = logging.getLogger(__name__)


def profile_values(s: SignIn) -> list[tuple[str, str]]:
    """(kind, value) pairs remembered per user for successful sign-ins (30 days, all sign-in types)."""
    pairs = [("asn", str(s.asn) if s.asn else ""), ("device", s.device_id), ("client", s.client),
             ("anonday", anon_day(s)), ("ip", s.ip), ("app", s.app), ("proto", (s.client_app or "").lower()),
             ("country", s.country), ("mfadev", s.mfa_device_id)]
    return [(k, v) for k, v in pairs if v]


def anon_day(s: SignIn) -> str:
    """Local date if the sign-in went through an anonymizing network (Entra flag or known VPN/hosting ASN)."""
    known = netintel.asn_info(s.asn)
    if any(e.lower() == "anonymizedipaddress" for e in s.risk_events) or (known and known[1] != "cloud"):
        return s.created.astimezone().strftime("%Y-%m-%d")
    return ""

_DETAIL_FIELDS = ("upn", "user_name", "asn", "country", "city", "device_id", "auth_methods", "session_id")


def _detail(s: SignIn) -> int:
    """How complete a record is (a preliminary Entra record lacks UPN, network, location ...)."""
    return sum(1 for f in _DETAIL_FIELDS if getattr(s, f))


def _complete(s: SignIn) -> bool:
    """Not a preliminary record: user, country and network are filled in."""
    return bool(s.upn or not s.user_id) and bool(s.country) and bool(s.asn)


def _row(s: SignIn) -> tuple:
    return (s.id, s.created.timestamp(), s.user_id, s.ip, s.country, s.error_code, int(s.interactive),
            int(s.lat is not None and s.lon is not None), s.asn, s.device_id, s.session_id, s.app_id, s.to_json())


SCHEMA_VERSION = 5
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signins (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    user_id     TEXT,
    ip          TEXT,
    country     TEXT,
    error_code  INTEGER NOT NULL,
    interactive INTEGER NOT NULL,
    has_geo     INTEGER NOT NULL,
    asn         INTEGER,
    device_id   TEXT,
    session_id  TEXT,
    app_id      TEXT,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_signins_ts ON signins(ts);
CREATE INDEX IF NOT EXISTS ix_signins_user ON signins(user_id, ts);
CREATE INDEX IF NOT EXISTS ix_signins_ip ON signins(ip, ts);
CREATE INDEX IF NOT EXISTS ix_signins_session ON signins(session_id);
CREATE INDEX IF NOT EXISTS ix_signins_asn ON signins(asn);
-- compact 30-day profile of successful sign-ins of ALL types (non-interactive rows themselves are kept 3 h)
CREATE TABLE IF NOT EXISTS profile (
    user_id  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    first_ts REAL NOT NULL,
    last_ts  REAL NOT NULL,
    n        INTEGER NOT NULL,
    PRIMARY KEY (user_id, kind, value)
);
CREATE INDEX IF NOT EXISTS ix_profile_value ON profile(kind, value);
-- MFA-method / password changes from the directory audit (see AccountChange); additive, no schema bump needed
CREATE TABLE IF NOT EXISTS changes (
    id       TEXT PRIMARY KEY,
    ts       REAL NOT NULL,
    user_id  TEXT NOT NULL,
    data     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_changes_ts ON changes(ts);
-- Activity record: when each person's device was active from which address, kept for the whole retention time.
-- One row per run of sign-ins (same person, device and address, no pause longer than ACTIVITY_GAP), built from ALL
-- successful sign-ins while they are stored - the background sign-ins themselves are purged after a few hours.
-- ``data`` is the first sign-in of the run (device, network, place). Additive, no schema bump needed.
CREATE TABLE IF NOT EXISTS activity (
    user_id  TEXT NOT NULL,
    device   TEXT NOT NULL,
    ip       TEXT NOT NULL,
    first_ts REAL NOT NULL,
    last_ts  REAL NOT NULL,
    n        INTEGER NOT NULL,
    data     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_activity_user ON activity(user_id, last_ts);
CREATE INDEX IF NOT EXISTS ix_activity_run ON activity(user_id, device, ip, last_ts);
CREATE INDEX IF NOT EXISTS ix_activity_last ON activity(last_ts);
"""
ACTIVITY_GAP = 2 * 3600  # seconds without a sign-in that end a run of activity


class SignInHistory:
    def __init__(self, path: Path | str):
        self._conn = sqlite3.connect(str(path), timeout=30)
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._backfill = False
        self.enriched = 0  # stored rows replaced by a more complete copy (see add)
        self.was_reset = self._migrate()
        self._conn.executescript(SCHEMA)
        if self._backfill:  # v2/v3 -> v4: (re)build the profile from the history we already have
            self._rebuild_profile()
        if not self._conn.execute("SELECT 1 FROM meta WHERE key='activity'").fetchone():
            self._rebuild_activity()  # once: from the sign-ins that are stored right now
            self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('activity', '1')")
        self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema', ?)", (str(SCHEMA_VERSION),))
        self._conn.commit()

    def _migrate(self) -> bool:
        """Drop history written by an older schema (it lacks fields the rules need). Returns True if reset."""
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "signins" not in tables:
            return False
        version = 1
        if "meta" in tables:
            row = self._conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            version = int(row[0]) if row else 1
        if version == SCHEMA_VERSION:
            return False
        if version in (2, 3, 4):
            self._backfill = True
            return False
        self._conn.executescript("DROP TABLE IF EXISTS signins; DROP TABLE IF EXISTS profile;")
        return True

    def _rebuild_profile(self) -> None:
        """Merge every stored successful sign-in into the profile (keeps entries of purged rows)."""
        agg: dict[tuple[str, str, str], list[float]] = {}
        for (data,) in self._conn.execute("SELECT data FROM signins WHERE error_code=0 AND user_id<>''"):
            s = SignIn.from_json(data)
            ts = s.created.timestamp()
            for kind, value in profile_values(s):
                if value:
                    entry = agg.setdefault((s.user_id, kind, value), [ts, ts, 0])
                    entry[0], entry[1], entry[2] = min(entry[0], ts), max(entry[1], ts), entry[2] + 1
        self._conn.executemany(
            "INSERT INTO profile(user_id, kind, value, first_ts, last_ts, n) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(user_id, kind, value) DO UPDATE SET first_ts=MIN(first_ts, excluded.first_ts), "
            "last_ts=MAX(last_ts, excluded.last_ts), n=MAX(n, excluded.n)",
            [(u, k, v, f, last, n) for (u, k, v), (f, last, n) in agg.items()])

    def _rebuild_activity(self) -> None:
        self._conn.execute("DELETE FROM activity")
        rows = [SignIn.from_json(data) for (data,) in
                self._conn.execute("SELECT data FROM signins WHERE error_code=0 AND user_id<>'' ORDER BY ts")]
        self._record_activity(rows)

    def _record_activity(self, signins: Sequence[SignIn]) -> None:
        """Extend the activity record with newly stored sign-ins (see the ``activity`` table). Sign-ins of services
        acting on a person's behalf are left out - they are not the person's device. Never fails the ingest."""
        try:
            from . import presence

            rows = sorted((s for s in signins if s.success and s.user_id and s.ip
                           and presence.device_class(s) != presence.SERVICE), key=lambda s: s.created)
            runs: dict[tuple[str, str, str], list] = {}  # key -> its current run [rowid, first, last, n]
            changed: dict[int, list] = {}                # rowid -> run that has to be written back
            for s in rows:
                key, ts = (s.user_id, presence.device_key(s), s.ip), s.created.timestamp()
                run = runs.get(key)
                if run is None:
                    row = self._conn.execute(
                        "SELECT rowid, first_ts, last_ts, n FROM activity WHERE user_id=? AND device=? AND ip=? "
                        "AND last_ts>=? AND first_ts<=? ORDER BY last_ts DESC LIMIT 1",
                        (*key, ts - ACTIVITY_GAP, ts + ACTIVITY_GAP)).fetchone()
                    run = list(row) if row else None
                if run is not None and run[1] - ACTIVITY_GAP <= ts <= run[2] + ACTIVITY_GAP:
                    run[1], run[2], run[3] = min(run[1], ts), max(run[2], ts), run[3] + 1
                    changed[run[0]] = run
                else:
                    cur = self._conn.execute(
                        "INSERT INTO activity(user_id, device, ip, first_ts, last_ts, n, data) VALUES(?,?,?,?,?,1,?)",
                        (*key, ts, ts, s.to_json()))
                    run = [cur.lastrowid, ts, ts, 1]
                runs[key] = run
            self._conn.executemany("UPDATE activity SET first_ts=?, last_ts=?, n=? WHERE rowid=?",
                                   [(run[1], run[2], run[3], rowid) for rowid, run in changed.items()])
        except Exception:  # the record is an extra: a problem with it must not stop the scan
            log.warning("Activity record not updated", exc_info=True)

    def activity(self, start: datetime, end: datetime, user_id: str | None = None) -> list[tuple[SignIn, datetime, datetime, int]]:
        """Runs of activity that overlap [start, end]: (first sign-in of the run, begin, end, number of sign-ins)."""
        sql = "SELECT data, first_ts, last_ts, n FROM activity WHERE last_ts>=? AND first_ts<=?" + (
            " AND user_id=?" if user_id else "") + " ORDER BY first_ts"
        params = (start.timestamp(), end.timestamp()) + ((user_id,) if user_id else ())
        return [(SignIn.from_json(data), datetime.fromtimestamp(first, timezone.utc), datetime.fromtimestamp(last, timezone.utc), n)
                for data, first, last, n in self._conn.execute(sql, params)]

    def close(self) -> None:
        self._conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        """The database connection, for companions that keep their own tables here (apps.AppStore)."""
        return self._conn

    # -------------------------------------------------------------- write
    def add(self, signins: Sequence[SignIn]) -> list[SignIn]:
        """Insert unknown sign-ins. Returns only the ones that were not stored before.

        Entra first logs some events as a preliminary record and completes it seconds to minutes later: without
        UPN, network and location (seen with 50074), or with a preliminary result (50097 "device authentication"
        that becomes 50074 / 500121). A more complete copy, or one with a different result, replaces the stored
        row (counted in ``enriched``) but is not returned as new; a less complete copy never does.
        """
        if not signins:
            return []
        known: dict[str, int] = {}          # id -> stored error code
        stored: dict[str, SignIn] = {}      # stored rows that may be replaced
        ids = [s.id for s in signins]
        incoming = {s.id: s for s in signins}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for sid, code, partial, data in self._conn.execute(
                    f"SELECT id, error_code, (asn IS NULL OR country='' OR (user_id<>'' AND data NOT LIKE '%\"upn\":%')), "
                    f"CASE WHEN asn IS NULL OR country='' OR (user_id<>'' AND data NOT LIKE '%\"upn\":%') "
                    f"THEN data END FROM signins WHERE id IN ({marks})", chunk):
                known[sid] = code
                if partial:
                    stored[sid] = SignIn.from_json(data)
        changed = [sid for sid, code in known.items() if sid not in stored and incoming[sid].error_code != code]
        for i in range(0, len(changed), 500):  # result changed: load the stored copy to compare (rare)
            chunk = changed[i:i + 500]
            for sid, data in self._conn.execute(
                    f"SELECT id, data FROM signins WHERE id IN ({','.join('?' * len(chunk))})", chunk):
                stored[sid] = SignIn.from_json(data)
        fresh: dict[str, SignIn] = {}
        richer: dict[str, SignIn] = {}
        for s in signins:
            if s.id not in known:
                fresh.setdefault(s.id, s)
                continue
            base = richer.get(s.id) or stored.get(s.id)
            # a changed result wins when the new copy is itself complete (the final record may list FEWER
            # passed steps than the preliminary one, e.g. 'Previously satisfied' disappears with 50097 -> 50074)
            if base is not None and (_detail(s) > _detail(base) or (s.error_code != base.error_code and _complete(s))):
                richer[s.id] = s
        self._conn.executemany(
            "INSERT OR IGNORE INTO signins(id, ts, user_id, ip, country, error_code, interactive, has_geo,"
            " asn, device_id, session_id, app_id, data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [_row(s) for s in fresh.values()],
        )
        self._conn.executemany(
            "UPDATE signins SET ts=?, user_id=?, ip=?, country=?, error_code=?, interactive=?, has_geo=?, asn=?,"
            " device_id=?, session_id=?, app_id=?, data=? WHERE id=?",
            [(*_row(s)[1:], s.id) for s in richer.values()],
        )
        self.enriched += len(richer)
        profile = []
        for s in fresh.values():
            if s.success and s.user_id:
                ts = s.created.timestamp()
                profile.extend((s.user_id, kind, value, ts, ts) for kind, value in profile_values(s))
        self._conn.executemany(
            "INSERT INTO profile(user_id, kind, value, first_ts, last_ts, n) VALUES(?,?,?,?,?,1) "
            "ON CONFLICT(user_id, kind, value) DO UPDATE SET first_ts=MIN(first_ts, excluded.first_ts), "
            "last_ts=MAX(last_ts, excluded.last_ts), n=n+1", profile)
        # values a completed record adds (network, device ...) join the profile without counting the sign-in twice
        self._conn.executemany(
            "INSERT INTO profile(user_id, kind, value, first_ts, last_ts, n) VALUES(?,?,?,?,?,1) "
            "ON CONFLICT(user_id, kind, value) DO UPDATE SET first_ts=MIN(first_ts, excluded.first_ts), "
            "last_ts=MAX(last_ts, excluded.last_ts)",
            [(s.user_id, kind, value, s.created.timestamp(), s.created.timestamp())
             for s in richer.values() if s.success and s.user_id for kind, value in profile_values(s)])
        self._record_activity(list(fresh.values()))
        self._conn.commit()
        return list(fresh.values())

    def add_changes(self, changes: Sequence[AccountChange]) -> int:
        """Store account changes (MFA methods, password resets). Returns how many were new."""
        cur = self._conn.executemany(
            "INSERT OR IGNORE INTO changes(id, ts, user_id, data) VALUES(?,?,?,?)",
            [(c.id, c.created.timestamp(), c.user_id, c.to_json()) for c in changes])
        self._conn.commit()
        return max(0, cur.rowcount)

    def changes(self, start: datetime, end: datetime, user_id: str | None = None) -> list[AccountChange]:
        sql = "SELECT data FROM changes WHERE ts>=? AND ts<=?" + (" AND user_id=?" if user_id else "") + " ORDER BY ts"
        params = (start.timestamp(), end.timestamp()) + ((user_id,) if user_id else ())
        return [AccountChange.from_json(r[0]) for r in self._conn.execute(sql, params)]

    def incomplete(self, since: datetime, limit: int = 10) -> list[SignIn]:
        """Recent rows that look like Entra's preliminary record (user known, UPN not filled in yet)."""
        sql = ("SELECT data FROM signins WHERE ts>=? AND user_id<>'' AND data NOT LIKE '%\"upn\":%' "
               "ORDER BY ts DESC LIMIT ?")
        return [SignIn.from_json(r[0]) for r in self._conn.execute(sql, (since.timestamp(), int(limit)))]

    def purge(self, interactive_before: datetime, noninteractive_before: datetime) -> int:
        cur = self._conn.execute(
            "DELETE FROM signins WHERE (interactive=1 AND ts<?) OR (interactive=0 AND ts<?)",
            (interactive_before.timestamp(), noninteractive_before.timestamp()))
        self._conn.execute("DELETE FROM profile WHERE last_ts<?", (interactive_before.timestamp(),))
        self._conn.execute("DELETE FROM changes WHERE ts<?", (interactive_before.timestamp(),))
        self._conn.execute("DELETE FROM activity WHERE last_ts<?", (interactive_before.timestamp(),))
        self._conn.commit()
        return cur.rowcount

    # --------------------------------------------------------------- read
    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM signins").fetchone()[0]

    def get(self, signin_id: str) -> SignIn | None:
        row = self._conn.execute("SELECT data FROM signins WHERE id=?", (signin_id,)).fetchone()
        return SignIn.from_json(row[0]) if row else None

    def query(self, start: datetime | None = None, end: datetime | None = None, *, user_id: str | None = None,
              ip: str | None = None, codes: Iterable[int] | None = None, success: bool | None = None,
              interactive_only: bool = False, session_id: str | None = None, device_id: str | None = None,
              limit: int | None = None) -> list[SignIn]:
        where, params = [], []
        for column, value in (("user_id", user_id), ("ip", ip), ("session_id", session_id), ("device_id", device_id)):
            if value is not None:
                where.append(f"{column}=?"); params.append(value)
        if start is not None:
            where.append("ts>=?"); params.append(start.timestamp())
        if end is not None:
            where.append("ts<=?"); params.append(end.timestamp())
        if codes is not None:
            codes = list(codes)
            where.append(f"error_code IN ({','.join('?' * len(codes))})"); params.extend(codes)
        if success is True:
            where.append("error_code=0")
        elif success is False:
            where.append("error_code<>0")
        if interactive_only:
            where.append("interactive=1")
        sql = "SELECT data FROM signins" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [SignIn.from_json(r[0]) for r in self._conn.execute(sql, params)]

    def candidates(self, start: datetime, end: datetime, codes: Iterable[int], group_by: str,
                   minimum: int, distinct_users: bool = False) -> list[str]:
        """Keys (user_id or ip) with at least ``minimum`` failures (or distinct users) in the range."""
        if group_by not in ("user_id", "ip"):
            raise ValueError(group_by)
        codes = list(codes)
        measure = "COUNT(DISTINCT user_id)" if distinct_users else "COUNT(*)"
        sql = (f"SELECT {group_by} FROM signins WHERE ts>=? AND ts<=? AND {group_by}<>'' "
               f"AND error_code IN ({','.join('?' * len(codes))}) GROUP BY {group_by} HAVING {measure}>=?")
        return [r[0] for r in self._conn.execute(sql, [start.timestamp(), end.timestamp(), *codes, minimum])]

    def user_countries(self, user_id: str, before: datetime, interactive_only: bool) -> Counter:
        sql = ("SELECT country, COUNT(*) FROM signins WHERE user_id=? AND ts<? AND error_code=0 AND country<>''"
               + (" AND interactive=1" if interactive_only else "") + " GROUP BY country")
        return Counter({c: n for c, n in self._conn.execute(sql, (user_id, before.timestamp()))})

    def previous_geo_success(self, user_id: str, before: datetime, after: datetime, exclude_id: str,
                             interactive_only: bool) -> SignIn | None:
        sql = ("SELECT data FROM signins WHERE user_id=? AND ts<=? AND ts>=? AND id<>? AND error_code=0 AND has_geo=1"
               + (" AND interactive=1" if interactive_only else "") + " ORDER BY ts DESC LIMIT 1")
        row = self._conn.execute(sql, (user_id, before.timestamp(), after.timestamp(), exclude_id)).fetchone()
        return SignIn.from_json(row[0]) if row else None

    # ------------------------------------------------- scoring baselines
    # These use the profile (all sign-in types, 30 days): phones and desktop apps mostly sign in
    # non-interactively, so the 3-hour non-interactive history alone would miss their devices/networks.
    def user_devices(self, user_id: str, before: datetime) -> set[str]:
        sql = "SELECT value FROM profile WHERE user_id=? AND kind='device' AND first_ts<?"
        return {r[0] for r in self._conn.execute(sql, (user_id, before.timestamp()))}

    def user_asns(self, user_id: str, before: datetime) -> set[int]:
        sql = "SELECT value FROM profile WHERE user_id=? AND kind='asn' AND first_ts<?"
        return {int(r[0]) for r in self._conn.execute(sql, (user_id, before.timestamp()))}

    def user_profile(self, user_id: str, kind: str, before: datetime) -> set[str]:
        """Values of one profile kind (ip, app, proto, country, asn, device, client) seen before ``before``."""
        sql = "SELECT value FROM profile WHERE user_id=? AND kind=? AND first_ts<?"
        return {r[0] for r in self._conn.execute(sql, (user_id, kind, before.timestamp()))}

    def user_clients(self, user_id: str, before: datetime) -> set[str]:
        sql = "SELECT value FROM profile WHERE user_id=? AND kind='client' AND first_ts<?"
        return {r[0] for r in self._conn.execute(sql, (user_id, before.timestamp()))}

    def user_anon_days(self, user_id: str, before: datetime) -> int:
        """Distinct earlier days on which the user signed in successfully through a VPN/anonymizer."""
        day = before.astimezone().strftime("%Y-%m-%d")
        sql = "SELECT COUNT(*) FROM profile WHERE user_id=? AND kind='anonday' AND value<?"
        return self._conn.execute(sql, (user_id, day)).fetchone()[0]

    def oldest(self, interactive_only: bool = True) -> datetime | None:
        row = self._conn.execute("SELECT MIN(ts) FROM signins" + (" WHERE interactive=1" if interactive_only else "")).fetchone()
        return datetime.fromtimestamp(row[0]).astimezone() if row and row[0] is not None else None

    def user_network_stats(self, user_id: str, asn: int) -> tuple[datetime, int] | None:
        """(first seen, successful sign-ins) of a network for the user, from the 30-day profile."""
        row = self._conn.execute("SELECT first_ts, n FROM profile WHERE user_id=? AND kind='asn' AND value=?",
                                 (user_id, str(asn))).fetchone()
        return (datetime.fromtimestamp(row[0]).astimezone(), int(row[1])) if row else None

    def asn_user_count(self, asn: int, before: datetime, exclude_user: str = "") -> int:
        sql = "SELECT COUNT(DISTINCT user_id) FROM profile WHERE kind='asn' AND value=? AND first_ts<? AND user_id<>?"
        return self._conn.execute(sql, (str(asn), before.timestamp(), exclude_user)).fetchone()[0]

    def ip_first_seen(self, ip: str) -> datetime | None:
        row = self._conn.execute("SELECT MIN(ts) FROM signins WHERE ip=?", (ip,)).fetchone()
        return datetime.fromtimestamp(row[0]).astimezone() if row and row[0] is not None else None

    def user_used_app(self, user_id: str, app_id: str, before: datetime) -> bool:
        sql = "SELECT 1 FROM signins WHERE user_id=? AND app_id=? AND ts<? AND error_code=0 LIMIT 1"
        return self._conn.execute(sql, (user_id, app_id, before.timestamp())).fetchone() is not None
