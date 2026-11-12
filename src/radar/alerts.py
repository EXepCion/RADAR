"""AlertCenter: turns findings into persistent reminders with de-duplication, snooze and dismiss."""
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from . import correlation
from .plugin_api import Finding, Severity
from .store import Store

log = logging.getLogger(__name__)

MAX_EVIDENCE = 500
SYSTEM_PLUGIN = "core"

ACTIVE, SNOOZED, DISMISSED, MUTED = "active", "snoozed", "dismissed", "muted"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")  # fixed width: sortable as text


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


@dataclass
class Alert:
    id: int
    key: str
    plugin_id: str
    rule_id: str
    severity: Severity
    title: str
    summary: str
    recommendation: str
    fields: dict[str, str]
    evidence: list[dict[str, str]]
    links: list[tuple[str, str]]
    occurred_at: datetime | None
    first_seen: datetime
    last_seen: datetime
    status: str
    snooze_until: datetime | None = None
    score: int = 0
    factors: list[tuple[int, str]] = field(default_factory=list)
    seen: bool = True  # False until the user selected/opened it (shown bold as "new")
    subjects: list[str] = field(default_factory=list)
    signal: str = ""
    # The level the rule gave the alert. ``severity`` is what is shown: lower when a response to the alert is on
    # record (sessions revoked ...). Escalation is judged against this one, so a lowered alert does not "escalate"
    # back with every scan.
    base_severity: Severity | None = None
    dismissed_at: datetime | None = None  # when the user dismissed it (None while it is a reminder)

    @classmethod
    def from_row(cls, r) -> "Alert":
        base = Severity(r["severity"])
        score, factors = int(r["score"] or 0), [tuple(x) for x in json.loads(r["factors"] or "[]")]
        responded = any(str(text).startswith(correlation.RESPONSE_PREFIX) for _points, text in factors)
        continuing = any(correlation.CONTINUED_MARK in str(text) for _points, text in factors)
        shown = (max(base, _severity_for(score)) if continuing        # the response did not end it: may be worse
                 else min(base, _severity_for(score)) if responded    # answered: at most the rule's level
                 else base)
        return cls(
            id=r["id"], key=r["key"], plugin_id=r["plugin_id"], rule_id=r["rule_id"],
            severity=shown, base_severity=base,
            title=r["title"], summary=r["summary"],
            recommendation=r["recommendation"], fields=json.loads(r["fields"]),
            evidence=json.loads(r["evidence"]), links=[tuple(x) for x in json.loads(r["links"])],
            occurred_at=_parse(r["occurred_at"]), first_seen=_parse(r["first_seen"]),
            last_seen=_parse(r["last_seen"]), status=r["status"], snooze_until=_parse(r["snooze_until"]),
            score=score, factors=factors,
            seen=bool(r["seen_at"]),
            subjects=json.loads(r["subjects"] or "[]"), signal=r["signal"] or "",
            dismissed_at=_parse(r["dismissed_at"]) if "dismissed_at" in r.keys() else None,
        )

    @classmethod
    def from_finding(cls, plugin_id: str, f: Finding, status: str = "live") -> "Alert":
        """A transient alert (not stored) to show a live finding in the details window."""
        now = utcnow()
        return cls(id=0, key=f.key, plugin_id=plugin_id, rule_id=f.rule_id, severity=Severity.parse(f.severity),
                   title=f.title, summary=f.summary, recommendation=f.recommendation, fields=dict(f.fields),
                   evidence=list(f.evidence), links=list(f.links), occurred_at=f.occurred_at, first_seen=now,
                   last_seen=now, status=status, score=_score(f), factors=list(f.factors), subjects=list(f.subjects))

    @property
    def when(self) -> datetime:
        return self.occurred_at or self.first_seen

    @property
    def base_score(self) -> int:
        """The score the rule gave, without what responses on record took off (attack chains build on this one:
        they account for a revocation themselves, once for the whole chain)."""
        return self.score - sum(int(p) for p, t in self.factors if str(t).startswith(correlation.RESPONSE_PREFIX))

    @property
    def is_system(self) -> bool:
        return self.plugin_id == SYSTEM_PLUGIN


_SEVERITY_SCORE = {Severity.INFO: 10, Severity.LOW: 35, Severity.MEDIUM: 55, Severity.HIGH: 80}


def _severity_for(score: int) -> Severity:
    return Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO


def _score(f: Finding) -> int:
    """Findings without an explicit score get a representative one for their severity."""
    return int(f.score) if f.score is not None else _SEVERITY_SCORE[Severity.parse(f.severity)]


EVIDENCE_ID_FIELDS = ("Sign-in ID", "Audit ID", "Request ID", "ID")


def _evidence_sig(row: dict) -> str:
    """Identity of an evidence row: its log entry id if it has one (so a re-rendered row - e.g. a shorter
    Result text after an update - replaces the old copy instead of being listed twice), else its content."""
    for name in EVIDENCE_ID_FIELDS:
        if row.get(name):
            return f"{name}={row[name]}"
    return json.dumps(row, sort_keys=True)


def _merge_evidence(old: list[dict], new: list[dict], drop: set[str] | frozenset[str] = frozenset()) -> list[dict]:
    """New rows first, then old rows not in ``new`` (and not in ``drop``), newest first, capped."""
    seen: set[str] = set(drop)
    merged: list[dict] = []
    for row in list(new) + list(old):
        sig = _evidence_sig(row)
        if sig not in seen:
            seen.add(sig)
            merged.append(row)
    merged.sort(key=lambda r: r.get("Time", ""), reverse=True)
    return merged[:MAX_EVIDENCE]


class AlertCenter:
    def __init__(self, store: Store):
        self._store = store
        self._lock = threading.RLock()

    # ------------------------------------------------------------ ingest
    def ingest(self, plugin_id: str, findings: Iterable[Finding],
               min_severity: Severity = Severity.LOW, now: datetime | None = None) -> list[Alert]:
        """Persist findings. Returns alerts that just became active and should pop up."""
        now = now or utcnow()
        popped: list[int] = []
        touched: list[int] = []
        with self._lock:
            for f in findings:
                sev = Severity.parse(f.severity)
                row = self._store.query_one("SELECT * FROM alerts WHERE key=?", (f.key,))
                score = _score(f)
                subjects = correlation.subjects_from(f.fields, f.subjects)
                if row is None:
                    status = ACTIVE if sev >= min_severity and not f.signal else MUTED
                    new_id = self._store.execute(
                        "INSERT INTO alerts(key, plugin_id, rule_id, severity, title, summary, recommendation,"
                        " fields, evidence, links, occurred_at, first_seen, last_seen, status, score, factors,"
                        " subjects, signal) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (f.key, plugin_id, f.rule_id, int(sev), f.title, f.summary, f.recommendation,
                         json.dumps(f.fields), json.dumps(f.evidence[:MAX_EVIDENCE]),
                         json.dumps([list(x) for x in f.links]), _iso(f.occurred_at), _iso(now), _iso(now), status,
                         score, json.dumps([list(x) for x in f.factors]), json.dumps(subjects), f.signal),
                    )
                    if status == ACTIVE:
                        popped.append(new_id)
                    touched.append(new_id)
                    continue
                old = Alert.from_row(row)
                old_sev = old.base_severity if old.base_severity is not None else old.severity
                new_sev = max(old_sev, sev)
                status, snooze_until = old.status, row["snooze_until"]
                escalated = sev > old_sev and sev >= min_severity and not f.signal
                touched.append(old.id)
                if f.signal:
                    pass  # a signal only becomes active through correlation
                elif (old.status in (DISMISSED, SNOOZED, ACTIVE) and escalated) or (old.status == MUTED and sev >= min_severity):
                    # got worse (or crossed the notification threshold): back on screen with attention - a snooze
                    # ends early, a dismissed reminder returns, an open one is shown again (it may be hidden)
                    status, snooze_until = ACTIVE, None
                    popped.append(old.id)
                    self._store.execute("UPDATE alerts SET seen_at=NULL WHERE id=?", (old.id,))
                fields = dict(old.fields)
                fields.update(f.fields)
                merged_subjects = sorted(set(old.subjects) | set(correlation.subjects_from(fields, f.subjects)))
                if merged_subjects != sorted(old.subjects):  # e.g. alerts created before a field was renamed
                    self._store.execute("UPDATE alerts SET subjects=? WHERE id=?", (json.dumps(merged_subjects), old.id))
                occurred = old.occurred_at or f.occurred_at
                keep_new = score >= old.score  # keep the explanation of the highest score
                self._store.execute(
                    "UPDATE alerts SET severity=?, title=?, summary=?, recommendation=?, fields=?, evidence=?,"
                    " links=?, occurred_at=?, last_seen=?, status=?, snooze_until=?, score=?, factors=? WHERE id=?",
                    (int(new_sev), f.title if keep_new else old.title, (f.summary if keep_new else old.summary) or old.summary,
                     f.recommendation or old.recommendation,
                     json.dumps(fields), json.dumps(_merge_evidence(old.evidence, f.evidence)),
                     json.dumps([list(x) for x in (f.links or old.links)]), _iso(occurred), _iso(now),
                     status, snooze_until, max(score, old.score),
                     json.dumps([list(x) for x in (f.factors if keep_new else old.factors)]), old.id),
                )
            for alert_id in touched:
                popped.extend(self._correlate_around(alert_id))
            for alert_id in touched:
                popped.extend(self._respond_around(alert_id))  # back on screen: a response did not end it
        return [a for a in (self.get(i) for i in dict.fromkeys(popped)) if a]

    # ----------------------------------------------------------- responses
    def _respond_around(self, alert_id: int) -> list[int]:
        """A response signal (or one that takes a response back): link it to the alerts about that account. Any other
        alert: link the responses to it. Returns the alerts that came back because the response did not end them."""
        alert = self.get(alert_id)
        if alert is None:
            return []
        if alert.signal in correlation.RESPONSE_RELATED:
            return [o.id for o in self._alerts_about(alert.subjects, alert.id) if not o.signal and self._apply_responses(o.id)[1]]
        if not alert.signal:
            return [alert_id] if self._apply_responses(alert_id)[1] else []
        return []

    def relink_responses(self) -> int:
        """Link every stored alert with the responses on record (once at start: alerts from before this existed).
        Quietly: nothing comes back on screen from this."""
        with self._lock:
            ids = [r["id"] for r in self._store.query("SELECT id FROM alerts WHERE signal=''")]
            return sum(1 for i in ids if self._apply_responses(i, wake=False)[0])

    @staticmethod
    def _since(alert: Alert, when: datetime) -> tuple[int, int]:
        """Events of the alert after ``when``: (successful sign-ins, refused attempts)."""
        after = when + timedelta(minutes=correlation.RESPONSE_SLACK_MINUTES)
        ok = refused = 0
        for row in alert.evidence:
            at = _parse(row.get("_created"))
            if at is None or at <= after:
                continue
            if str(row.get("Result", "")).strip().lower().startswith("success"):
                ok += 1
            else:
                refused += 1
        return ok, refused

    def _apply_responses(self, alert_id: int, wake: bool = True) -> tuple[bool, bool]:
        """Responses on record about the alert's account that came after the alert began: each is listed with the
        alert ("Response"), and the response's own entry names the alert. A response lowers the risk score - unless
        successful sign-ins of the alert came after it: then it did not end this, counts for nothing, and the score
        goes UP (whoever is behind it can still get in). Refused attempts after a response change nothing.

        Worked out afresh every time (the rule's own score and factors come back with each scan).
        Returns (a response is linked, the alert came back on screen because the response did not end it)."""
        row = self._store.query_one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if row is None or row["signal"] or row["plugin_id"] == SYSTEM_PLUGIN:
            return False, False
        alert = Alert.from_row(row)
        began = alert.when - timedelta(minutes=correlation.RESPONSE_SLACK_MINUTES)
        about = self._alerts_about(alert.subjects, alert.id)
        latest: dict[str, Alert] = {}  # one per kind of response: the most recent
        for other in about:
            rule = correlation.RESPONSE_SIGNALS.get(other.signal)
            if rule is None or not rule.answers(alert.rule_id, alert.title):
                continue  # this response does nothing about this kind of alert
            if not (began <= other.when <= alert.when + timedelta(days=rule.days)):
                continue
            if rule.undone_by and any(x.signal == rule.undone_by and x.when > other.when for x in about):
                continue  # taken back since (the account was enabled again)
            if other.signal not in latest or other.when > latest[other.signal].when:
                latest[other.signal] = other
        mine = [(p, t) for p, t in alert.factors if str(t).startswith(correlation.RESPONSE_PREFIX)]
        own = [(p, t) for p, t in alert.factors if not str(t).startswith(correlation.RESPONSE_PREFIX)]
        base_score = alert.score - sum(p for p, _t in mine)
        was_continuing = any(correlation.CONTINUED_MARK in str(t) for _p, t in mine)
        added, lines, continued = [], [], 0
        for kind, other in sorted(latest.items(), key=lambda kv: kv[1].when):
            rule = correlation.RESPONSE_SIGNALS[kind]
            when, by = f"{other.when.astimezone():%d.%m.%Y %H:%M}", other.fields.get("Initiated by") or "unknown"
            ok, refused = self._since(alert, other.when)
            if ok:
                continued += ok
                added.append((0, f"{correlation.RESPONSE_PREFIX}{rule.label.lower()} {when} by {by} - but it did not end this: "
                                 f"{ok} successful sign-in(s) of this alert came after it"))
                lines.append(f"{rule.label} {when} by {by} - did NOT end it ({ok} successful sign-in(s) since)")
            else:
                since = f" ({refused} attempt(s) since, all refused)" if refused else ""
                added.append((rule.points, correlation.RESPONSE_PREFIX + rule.text.format(when=when, by=by) + since))
                lines.append(f"{rule.label} {when} by {by}{since}")
            note = f"{alert.title}"
            theirs = dict(other.fields)
            if note not in theirs.get("Related alerts", ""):
                theirs["Related alerts"] = "\n".join(x for x in (theirs.get("Related alerts"), note) if x)
                self._store.execute("UPDATE alerts SET fields=? WHERE id=?", (json.dumps(theirs), other.id))
        if continued:
            added.append((correlation.CONTINUED_POINTS,
                          f"{correlation.RESPONSE_PREFIX}the activity {correlation.CONTINUED_MARK} - whoever is behind it "
                          f"can still sign in (the password is known, or there is another way in)"))
        fields = dict(alert.fields)
        if lines:
            fields["Response"] = "\n".join(lines)
        else:
            fields.pop("Response", None)
        score = max(0, min(100, base_score + sum(p for p, _t in added)))
        factors = own + added
        woke = bool(continued) and not was_continuing and wake and alert.status in (DISMISSED, SNOOZED)
        if score != alert.score or factors != list(alert.factors) or fields != alert.fields or woke:
            self._store.execute(
                "UPDATE alerts SET score=?, factors=?, fields=?, status=CASE WHEN ? THEN ? ELSE status END, "
                "snooze_until=CASE WHEN ? THEN NULL ELSE snooze_until END, seen_at=CASE WHEN ? THEN NULL ELSE seen_at END WHERE id=?",
                (score, json.dumps([list(x) for x in factors]), json.dumps(fields), int(woke), ACTIVE, int(woke), int(woke), alert_id))
        return bool(added), woke

    # -------------------------------------------------------- correlation
    def correlate_all(self) -> list[Alert]:
        """Re-check every stored signal (after upgrades / rule changes). Returns newly activated signals."""
        with self._lock:
            ids = [r["id"] for r in self._store.query("SELECT id FROM alerts WHERE signal<>''")]
            activated = [i for i in ids if self._correlate_signal(i)]
        return [a for a in (self.get(i) for i in activated) if a]

    def _alerts_about(self, subjects: list[str], exclude_id: int) -> list[Alert]:
        if not subjects:
            return []
        cond = " OR ".join("subjects LIKE ?" for _ in subjects)
        rows = self._store.query(f"SELECT * FROM alerts WHERE id<>? AND ({cond})",
                                 (exclude_id, *[f'%"{s}"%' for s in subjects]))
        return [Alert.from_row(r) for r in rows]

    def _correlate_around(self, alert_id: int) -> list[int]:
        """Correlate the alert itself (if it is a signal) and every signal about the same people."""
        alert = self.get(alert_id)
        if alert is None:
            return []
        candidates = [alert] if alert.signal else []
        candidates += [a for a in self._alerts_about(alert.subjects, alert.id) if a.signal]
        return [a.id for a in candidates if self._correlate_signal(a.id)]

    def _correlate_signal(self, signal_id: int) -> bool:
        """Escalate a signal when a partner exists. Returns True if it just became active."""
        sig = self.get(signal_id)
        if sig is None or not sig.signal:
            return False
        hits: list[tuple[correlation.Correlation, Alert]] = []
        for rule in correlation.CORRELATIONS:
            if rule.signal != sig.signal or sig.score < rule.min_signal_score:
                continue
            for other in self._alerts_about(sig.subjects, sig.id):
                if rule.partner == correlation.ANY_ALERT:
                    ok = (not other.signal and other.severity >= Severity.MEDIUM and other.plugin_id != SYSTEM_PLUGIN
                          and other.rule_id not in correlation.NOT_A_PARTNER_RULES and other.status != MUTED
                          and other.rule_id not in rule.exclude_partner_rules)
                else:
                    ok = other.signal == rule.partner
                delta = (other.when - sig.when).total_seconds() / 86400
                if ok and -rule.days_before <= delta <= rule.days_after:
                    hits.append((rule, other))
        if not hits:
            return False
        factors = [tuple(x) for x in sig.factors]
        reasons = [r for _, r in factors]
        partners = list(sig.fields.get("Correlated with", "").split("\n")) if sig.fields.get("Correlated with") else []
        for rule, other in hits:
            days = max(0, round((other.when - sig.when).total_seconds() / 86400))
            reason = rule.reason.format(partner=other.title, days=days)
            if reason not in reasons:
                factors.append((rule.points, reason))
                reasons.append(reason)
            if other.title not in partners:
                partners.append(other.title)
            if not other.signal:  # tell the partner alert about the signal, too
                fields = dict(other.fields)
                note = f"{sig.title} ({sig.when.astimezone():%d.%m.%Y})"
                if note not in fields.get("Related signals", ""):
                    fields["Related signals"] = "\n".join(x for x in (fields.get("Related signals"), note) if x)
                    self._store.execute("UPDATE alerts SET fields=? WHERE id=?", (json.dumps(fields), other.id))
        score = min(100, sum(p for p, _ in factors))
        fields = dict(sig.fields)
        fields["Correlated with"] = "\n".join(partners)
        activate = sig.status == MUTED and score >= 25
        self._store.execute(
            "UPDATE alerts SET score=?, severity=?, factors=?, fields=?, status=?, seen_at=CASE WHEN ? THEN NULL "
            "ELSE seen_at END WHERE id=?",
            (score, int(_severity_for(score)), json.dumps([list(x) for x in factors]), json.dumps(fields),
             ACTIVE if activate else sig.status, int(activate), sig.id))
        return activate

    def replace_assessment(self, f: Finding, min_severity: Severity = Severity.LOW) -> tuple[Alert, Alert] | None:
        """Overwrite score/severity/explanation of an open alert with a newer assessment of the same events.

        Unlike :meth:`ingest` this may LOWER the rating (used after tuning). Returns (before, after) or None.
        An alert that drops below ``min_severity`` is muted (it stays in the history, no reminder).
        """
        row = self._store.query_one("SELECT * FROM alerts WHERE key=? AND status IN (?,?)", (f.key, ACTIVE, SNOOZED))
        if row is None:
            return None
        before = Alert.from_row(row)
        sev = Severity.parse(f.severity)
        status = before.status if sev >= min_severity else MUTED
        fields = dict(before.fields)
        fields.update(f.fields)
        evidence = before.evidence
        if f.evidence:
            # An old row inside the time span the new evidence covers, but left out, was excluded on purpose
            # (e.g. the user's own MFA prompt). Older rows, rows without a timestamp and non-interactive rows
            # (purged from the local history after a few hours) are kept.
            new_sigs = {_evidence_sig(r) for r in f.evidence}
            times = [r["_created"] for r in f.evidence if r.get("_created")]
            lo, hi = (min(times), max(times)) if times else ("", "")
            drop = {_evidence_sig(r) for r in before.evidence
                    if lo and lo <= (r.get("_created") or "") <= hi and r.get("Type") != "Non-interactive"
                    and _evidence_sig(r) not in new_sigs}
            evidence = _merge_evidence(before.evidence, f.evidence, drop)
        self._store.execute(
            "UPDATE alerts SET severity=?, score=?, factors=?, title=?, summary=?, recommendation=?, fields=?, status=?, "
            "evidence=?, snooze_until=CASE WHEN ?='muted' THEN NULL ELSE snooze_until END WHERE id=?",
            (int(sev), _score(f), json.dumps([list(x) for x in f.factors]), f.title, f.summary or before.summary,
             f.recommendation or before.recommendation, json.dumps(fields), status, json.dumps(evidence), status,
             before.id))
        self._apply_responses(before.id)
        return before, self.get(before.id)

    # -------------------------------------------------------- system notes
    def raise_system(self, key: str, title: str, summary: str, recommendation: str = "",
                     links: list[tuple[str, str]] | None = None, severity: Severity = Severity.MEDIUM) -> Alert | None:
        """App-health reminder (sign-in needed, access denied ...). Pops once until resolved."""
        finding = Finding(key=f"{SYSTEM_PLUGIN}:{key}", title=title, severity=severity, summary=summary,
                          recommendation=recommendation, links=links or [], rule_id="health",
                          occurred_at=utcnow())
        popped = self.ingest(SYSTEM_PLUGIN, [finding], min_severity=Severity.INFO)
        return popped[0] if popped else None

    def resolve_system(self, key: str) -> bool:
        """Remove a system reminder once the problem is gone (so it can pop again if it recurs)."""
        return self._store.execute("DELETE FROM alerts WHERE key=?", (f"{SYSTEM_PLUGIN}:{key}",)) > 0

    # ------------------------------------------------------------ queries
    def get(self, alert_id: int) -> Alert | None:
        row = self._store.query_one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        return Alert.from_row(row) if row else None

    def active(self) -> list[Alert]:
        rows = self._store.query("SELECT * FROM alerts WHERE status=? ORDER BY severity DESC, score DESC, last_seen DESC",
                                 (ACTIVE,))
        return [Alert.from_row(r) for r in rows]

    def count_unseen(self) -> int:
        row = self._store.query_one("SELECT COUNT(*) AS n FROM alerts WHERE status=? AND seen_at IS NULL", (ACTIVE,))
        return int(row["n"]) if row else 0

    def mark_seen(self, ids: Iterable[int]) -> None:
        now = _iso(utcnow())
        for i in ids:
            self._store.execute("UPDATE alerts SET seen_at=? WHERE id=? AND seen_at IS NULL", (now, int(i)))

    def count_active(self) -> int:
        row = self._store.query_one("SELECT COUNT(*) AS n FROM alerts WHERE status=?", (ACTIVE,))
        return int(row["n"]) if row else 0

    def latest_about(self, subject: str, rule_ids: Iterable[str], user_id: str = "") -> Alert | None:
        """Most recent alert (any status) of these rules about a UPN (or with the user's object id in its key) -
        e.g. a dismissed attack reminder."""
        rule_ids = list(rule_ids)
        if not (subject or user_id) or not rule_ids:
            return None
        row = self._store.query_one(
            f"SELECT * FROM alerts WHERE rule_id IN ({','.join('?' * len(rule_ids))}) AND (subjects LIKE ? OR key LIKE ?) "
            f"ORDER BY last_seen DESC LIMIT 1",
            (*rule_ids, f'%"{(subject or "-").lower()}"%', f"%|{user_id}|%" if user_id else "-"))
        return Alert.from_row(row) if row else None

    def find_by_title(self, title: str) -> Alert | None:
        """Most recent alert with this title (exact, else the title as a prefix - titles may get a suffix)."""
        title = (title or "").strip()
        if not title:
            return None
        row = (self._store.query_one("SELECT * FROM alerts WHERE title=? ORDER BY last_seen DESC LIMIT 1", (title,))
               or self._store.query_one("SELECT * FROM alerts WHERE title LIKE ? ESCAPE '\\' ORDER BY last_seen DESC "
                                        "LIMIT 1", (title.replace("\\", "\\\\").replace("%", "\\%")
                                                    .replace("_", "\\_") + "%",)))
        return Alert.from_row(row) if row else None

    def since(self, when: datetime) -> list[Alert]:
        """All alerts (any status) updated or occurred since ``when``."""
        rows = self._store.query("SELECT * FROM alerts WHERE last_seen>=? OR occurred_at>=?", (_iso(when), _iso(when)))
        return [Alert.from_row(r) for r in rows]

    def recent(self, limit: int = 200) -> list[Alert]:
        rows = self._store.query("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,))
        return [Alert.from_row(r) for r in rows]

    # ------------------------------------------------------------ actions
    def dismiss(self, ids: Iterable[int]) -> None:
        now = _iso(utcnow())
        for i in ids:
            self._store.execute("UPDATE alerts SET status=?, dismissed_at=?, snooze_until=NULL WHERE id=?",
                                (DISMISSED, now, int(i)))

    def reactivate(self, ids: Iterable[int]) -> int:
        """Put dismissed, snoozed or logged-only alerts back among the reminders, marked as new (unseen).
        Returns how many changed. (System notes are left alone: they come and go with their cause.)"""
        changed = 0
        for i in ids:
            changed += self._store.execute(
                "UPDATE alerts SET status=?, dismissed_at=NULL, snooze_until=NULL, seen_at=NULL "
                "WHERE id=? AND status IN (?,?,?) AND plugin_id<>?", (ACTIVE, int(i), DISMISSED, SNOOZED, MUTED, SYSTEM_PLUGIN))
        return changed

    def dismiss_all(self) -> None:
        self._store.execute("UPDATE alerts SET status=?, dismissed_at=?, snooze_until=NULL WHERE status=?",
                            (DISMISSED, _iso(utcnow()), ACTIVE))

    def snooze(self, ids: Iterable[int], minutes: int, now: datetime | None = None) -> None:
        until = _iso((now or utcnow()) + timedelta(minutes=minutes))
        for i in ids:
            self._store.execute("UPDATE alerts SET status=?, snooze_until=? WHERE id=?", (SNOOZED, until, int(i)))

    def wake_due_snoozes(self, now: datetime | None = None) -> int:
        """Re-activate snoozed alerts whose time has come. Returns how many woke up."""
        return self._store.execute("UPDATE alerts SET status=?, snooze_until=NULL WHERE status=? AND snooze_until<=?",
                                   (ACTIVE, SNOOZED, _iso(now or utcnow())))

    def purge(self, older_than_days: int, now: datetime | None = None) -> int:
        cutoff = _iso((now or utcnow()) - timedelta(days=older_than_days))
        return self._store.execute("DELETE FROM alerts WHERE status IN (?,?) AND last_seen<?",
                                   (DISMISSED, MUTED, cutoff))
