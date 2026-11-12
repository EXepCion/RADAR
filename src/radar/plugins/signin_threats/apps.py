"""App sign-ins (service principals): apps that sign in with their own secret or certificate.

Apps with tenant-wide permissions (calendar sync, backup, automation) sign in thousands of times a day from a
very stable place - in this tenant over a week: no new country, no new credential, one new network range. So:

- success from a country the app never used         -> Medium (stolen secret used elsewhere?)
- first use of a credential (secret / certificate)  -> Low   (intended rotation, or a secret someone added?)
- success from a new network range, known country   -> Info  (cloud egress ranges move)
- many credential failures in a week                -> Low   "credential failing" (expired / rotated secret);
  Medium when they come from networks outside the app's baseline (someone trying its secrets)

The raw rows are not stored (12,000 a day); only a baseline per app and a weekly failure counter.
"""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from ...plugin_api import Finding, Severity
from .models import parse_time

LEARN_DAYS = 3
FAILURES_PER_WEEK = 50
CREDENTIAL_ERRORS = {
    7000215: "invalid client secret", 7000222: "expired client secret", 700027: "invalid certificate signature",
    700024: "client assertion outside its validity", 7000112: "application disabled", 700016: "application not found",
    7000216: "client assertion required", 50012: "authentication failed (assertion)",
}
SELECT = ("id,createdDateTime,appDisplayName,appId,servicePrincipalId,ipAddress,location,status,"
          "servicePrincipalCredentialKeyId,clientCredentialType,resourceDisplayName")

SCHEMA = """
CREATE TABLE IF NOT EXISTS app_profile (
    sp_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
    n INTEGER NOT NULL, PRIMARY KEY (sp_id, kind, value));
CREATE TABLE IF NOT EXISTS app_seen (sp_id TEXT PRIMARY KEY, name TEXT, first_ts REAL NOT NULL, last_ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS app_failures (
    sp_id TEXT NOT NULL, week TEXT NOT NULL, code INTEGER NOT NULL, n INTEGER NOT NULL, ips TEXT NOT NULL,
    first_ts REAL NOT NULL, last_ts REAL NOT NULL, PRIMARY KEY (sp_id, week, code));
CREATE TABLE IF NOT EXISTS app_ids (id TEXT PRIMARY KEY, ts REAL NOT NULL);
"""


def network(ip: str) -> str:
    """/24 for IPv4, /48 for IPv6 (app sign-ins have no ASN in the log)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip or ""
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False))


def _week(dt: datetime) -> str:
    year, week, _ = dt.astimezone().isocalendar()
    return f"{year}-W{week:02d}"


@dataclass
class AppSignIn:
    id: str
    created: datetime
    sp_id: str
    app_id: str = ""
    app: str = ""
    ip: str = ""
    country: str = ""
    error_code: int = 0
    failure_reason: str = ""
    key_id: str = ""
    credential: str = ""
    resource: str = ""

    @classmethod
    def from_graph(cls, d: dict[str, Any]) -> "AppSignIn":
        status = d.get("status") or {}
        return cls(id=d["id"], created=parse_time(d["createdDateTime"]),
                   sp_id=d.get("servicePrincipalId") or d.get("appId") or "", app_id=d.get("appId") or "",
                   app=d.get("appDisplayName") or d.get("appId") or "", ip=d.get("ipAddress") or "",
                   country=((d.get("location") or {}).get("countryOrRegion") or "").upper(),
                   error_code=int(status.get("errorCode") or 0), failure_reason=status.get("failureReason") or "",
                   key_id=d.get("servicePrincipalCredentialKeyId") or "", credential=d.get("clientCredentialType") or "",
                   resource=d.get("resourceDisplayName") or "")

    @property
    def success(self) -> bool:
        return self.error_code == 0

    def evidence(self) -> dict[str, str]:
        return {"Time": self.created.astimezone().strftime("%Y-%m-%d %H:%M:%S"), "App": self.app,
                "IP address": self.ip, "Country": self.country or "?", "Network": network(self.ip),
                "Result": "Success" if self.success else f"Failure {self.error_code}: {self.failure_reason[:80]}",
                "Credential": f"{self.credential} {self.key_id[:8]}".strip(), "Resource": self.resource}


class AppStore:
    """Per-app baseline in the sign-in history database."""

    def __init__(self, conn: sqlite3.Connection):
        self.c = conn
        self.c.executescript(SCHEMA)

    def new_rows(self, rows: list[AppSignIn]) -> list[AppSignIn]:
        """Rows not processed before (the fetch overlaps); remembers them for two days."""
        if not rows:
            return []
        known = set()
        ids = [r.id for r in rows]
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            known |= {x for (x,) in self.c.execute(f"SELECT id FROM app_ids WHERE id IN ({','.join('?' * len(chunk))})", chunk)}
        fresh = list({r.id: r for r in rows if r.id not in known}.values())
        self.c.executemany("INSERT OR IGNORE INTO app_ids(id, ts) VALUES(?,?)", [(r.id, r.created.timestamp()) for r in fresh])
        return fresh

    def first_seen(self, sp_id: str) -> datetime | None:
        row = self.c.execute("SELECT first_ts FROM app_seen WHERE sp_id=?", (sp_id,)).fetchone()
        return datetime.fromtimestamp(row[0]).astimezone() if row else None

    def known(self, sp_id: str, kind: str) -> set[str]:
        return {v for (v,) in self.c.execute("SELECT value FROM app_profile WHERE sp_id=? AND kind=?", (sp_id, kind))}

    def learn(self, rows: list[AppSignIn]) -> None:
        """Add successful sign-ins to the baseline (after they were judged)."""
        seen: dict[str, tuple[str, float, float]] = {}
        profile = []
        for r in rows:
            ts = r.created.timestamp()
            name, lo, hi = seen.get(r.sp_id, (r.app, ts, ts))
            seen[r.sp_id] = (r.app or name, min(lo, ts), max(hi, ts))
            if r.success:
                profile += [(r.sp_id, k, v, ts, ts) for k, v in (("country", r.country), ("net", network(r.ip)),
                                                                 ("key", r.key_id)) if v]
        self.c.executemany(
            "INSERT INTO app_seen(sp_id, name, first_ts, last_ts) VALUES(?,?,?,?) ON CONFLICT(sp_id) DO UPDATE SET "
            "name=excluded.name, first_ts=MIN(first_ts, excluded.first_ts), last_ts=MAX(last_ts, excluded.last_ts)",
            [(sp, n, lo, hi) for sp, (n, lo, hi) in seen.items()])
        self.c.executemany(
            "INSERT INTO app_profile(sp_id, kind, value, first_ts, last_ts, n) VALUES(?,?,?,?,?,1) "
            "ON CONFLICT(sp_id, kind, value) DO UPDATE SET first_ts=MIN(first_ts, excluded.first_ts), "
            "last_ts=MAX(last_ts, excluded.last_ts), n=n+1", profile)
        self.c.commit()

    def count_failures(self, rows: list[AppSignIn]) -> None:
        agg: dict[tuple, list] = {}
        for r in rows:
            if r.success:
                continue
            key = (r.sp_id, _week(r.created), r.error_code)
            entry = agg.setdefault(key, [0, set(), r.created.timestamp(), r.created.timestamp()])
            entry[0] += 1
            entry[1].add(r.ip)
            entry[2], entry[3] = min(entry[2], r.created.timestamp()), max(entry[3], r.created.timestamp())
        for (sp, week, code), (n, ips, lo, hi) in agg.items():
            row = self.c.execute("SELECT n, ips FROM app_failures WHERE sp_id=? AND week=? AND code=?", (sp, week, code)).fetchone()
            all_ips = sorted(set(json.loads(row[1])) | ips) if row else sorted(ips)
            self.c.execute(
                "INSERT INTO app_failures(sp_id, week, code, n, ips, first_ts, last_ts) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(sp_id, week, code) DO UPDATE SET n=n+excluded.n, ips=excluded.ips, "
                "first_ts=MIN(first_ts, excluded.first_ts), last_ts=MAX(last_ts, excluded.last_ts)",
                (sp, week, code, n, json.dumps(all_ips[:50]), lo, hi))
        self.c.commit()

    def failures(self, sp_id: str, week: str) -> list[tuple[int, int, list[str], datetime, datetime]]:
        return [(code, n, json.loads(ips), datetime.fromtimestamp(lo).astimezone(), datetime.fromtimestamp(hi).astimezone())
                for code, n, ips, lo, hi in self.c.execute(
                    "SELECT code, n, ips, first_ts, last_ts FROM app_failures WHERE sp_id=? AND week=?", (sp_id, week))]

    def purge(self, now: datetime, days: int = 30) -> None:
        cut = (now - timedelta(days=days)).timestamp()
        self.c.execute("DELETE FROM app_profile WHERE last_ts<?", (cut,))
        self.c.execute("DELETE FROM app_ids WHERE ts<?", ((now - timedelta(days=2)).timestamp(),))
        self.c.execute("DELETE FROM app_failures WHERE last_ts<?", (cut,))
        self.c.commit()


def app_findings(store: AppStore, rows: list[AppSignIn], now: datetime) -> list[Finding]:
    """Judge a batch of new app sign-ins against each app's baseline, then learn from it."""
    out: list[Finding] = []
    by_app: dict[str, list[AppSignIn]] = defaultdict(list)
    for r in rows:
        if r.sp_id:
            by_app[r.sp_id].append(r)
    for sp, items in by_app.items():
        app = items[0].app
        first = store.first_seen(sp)
        mature = first is not None and now - first >= timedelta(days=LEARN_DAYS)
        countries, nets, keys = store.known(sp, "country"), store.known(sp, "net"), store.known(sp, "key")
        ok = [r for r in items if r.success]
        if mature and ok:
            new_cc = [r for r in ok if r.country and r.country not in countries]
            new_key = [r for r in ok if r.key_id and r.key_id not in keys]
            new_net = [r for r in ok if network(r.ip) not in nets and r not in new_cc]
            subjects = [f"app:{app.lower()}"]
            if new_cc:
                c = Counter(r.country for r in new_cc)
                factors = [(55, f"Signed in from a country it never used ({', '.join(c)}); usual: "
                                f"{', '.join(sorted(countries)) or '-'}")]
                if new_key:
                    factors.append((15, "...and with a credential never used before"))
                score = sum(p for p, _ in factors)
                out.append(Finding(
                    key=f"appcc|{sp}|{new_cc[0].created.astimezone():%Y-%m-%d}", rule_id="app_signins",
                    severity=_sev(score), score=score, factors=factors, subjects=subjects,
                    title=f"App signed in from a new country: {app} ({', '.join(c)})",
                    summary=(f"The app {app} signs in with its own credential and normally only from "
                             f"{', '.join(sorted(countries)) or 'elsewhere'}. Now it signed in from {', '.join(c)} "
                             f"({', '.join(sorted({r.ip for r in new_cc})[:5])}). Its secret or certificate may be used by "
                             f"someone else."),
                    occurred_at=new_cc[0].created,
                    fields={"App": app, "Usual countries": ", ".join(sorted(countries)) or "-",
                            "New": ", ".join(f"{k} ({n})" for k, n in c.items())},
                    evidence=[r.evidence() for r in new_cc[:50]],
                    recommendation=("Check with the app's owner / vendor whether it moved. If not: remove the "
                                    "credential in use, add a new one, and review what the app accessed."),
                    links=[("Entra: app sign-ins", "https://portal.azure.com/#view/Microsoft_AAD_IAM/"
                                                   "ActiveDirectoryMenuBlade/~/SignIns")]))
            for key in sorted({r.key_id for r in new_key}):
                used = [r for r in new_key if r.key_id == key]
                out.append(Finding(
                    key=f"appkey|{sp}|{key}", rule_id="app_signins", severity=Severity.LOW, score=30,
                    factors=[(30, f"Credential {key[:8]}... used for the first time")], subjects=subjects,
                    title=f"App uses a new credential: {app}",
                    summary=(f"{app} signed in with a credential (key {key}) it never used before - from "
                             f"{', '.join(sorted({r.country or '?' for r in used}))}. Expected after a planned "
                             f"rotation; otherwise someone added a secret to the app."),
                    occurred_at=used[0].created, fields={"App": app, "Credential key": key},
                    evidence=[r.evidence() for r in used[:20]],
                    recommendation="Confirm the rotation with the app owner; check the audit log for who added it."))
            if new_net:
                out.append(Finding(
                    key=f"appnet|{sp}|{new_net[0].created.astimezone():%Y-%m-%d}", rule_id="app_signins",
                    severity=Severity.INFO, score=10, factors=[(10, "New network range in a known country")],
                    subjects=subjects, title=f"App signs in from a new network range: {app}",
                    summary=f"{app}: {', '.join(sorted({network(r.ip) for r in new_net})[:5])} (logged only).",
                    occurred_at=new_net[0].created, fields={"App": app}, evidence=[r.evidence() for r in new_net[:20]]))
        store.learn(items)
    store.count_failures(rows)
    for sp in {r.sp_id for r in rows if not r.success and r.error_code in CREDENTIAL_ERRORS}:
        app = next(r.app for r in rows if r.sp_id == sp)
        week = _week(now)
        failed = [(c, n, ips, lo, hi) for c, n, ips, lo, hi in store.failures(sp, week) if c in CREDENTIAL_ERRORS]
        total = sum(n for _, n, _, _, _ in failed)
        if total < FAILURES_PER_WEEK:
            continue
        nets = store.known(sp, "net")
        ips = sorted({ip for _, _, ips, _, _ in failed for ip in ips})
        foreign = [ip for ip in ips if network(ip) not in nets]
        guessing = bool(nets) and bool(foreign)
        score = 55 if guessing else 30
        reasons = ", ".join(f"{CREDENTIAL_ERRORS[c]} ({n})" for c, n, _, _, _ in failed)
        out.append(Finding(
            key=f"appfail|{sp}|{week}", rule_id="app_signins", severity=_sev(score), score=score,
            factors=[(score, f"{total} failed sign-ins with the app's credential this week: {reasons}"
                             + (f" - from {len(foreign)} IP(s) outside its usual networks" if guessing else ""))],
            subjects=[f"app:{app.lower()}"],
            title=(f"Someone is trying the credentials of app {app}" if guessing
                   else f"App credential failing: {app} ({reasons})"),
            summary=((f"{total} failed sign-ins with {app}'s credential this week from IPs outside its usual networks "
                      f"({', '.join(foreign[:5])}). Someone may be trying stolen or guessed secrets.") if guessing else
                     (f"{app} failed to sign in {total} times this week ({reasons}) from {', '.join(ips[:5])}"
                      + (" and has not signed in successfully at all" if not nets else "")
                      + ". Usually an expired or rotated secret that was not updated where the app runs - the "
                        "integration does not work.")),
            occurred_at=min(lo for _, _, _, lo, _ in failed),
            fields={"App": app, "Failures this week": str(total), "Errors": reasons, "From": ", ".join(ips[:10])},
            recommendation=("Find out who runs the integration and update its secret / certificate (or remove the app "
                            "if it is no longer used)." if not guessing else
                            "Rotate the app's credentials and check which IPs tried them."),
        ))
    return out


def _sev(score: int) -> Severity:
    return Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
