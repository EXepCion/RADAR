"""Reminders the user switched off: "this rule about this account (or application) - not again", for a time.

Dismissing says "seen". The same routine thing comes back the next day, though, and is dismissed again. From an
alert it can be switched off instead: for the rule it came from and one account or application it is about, until
a date. What then matches is still judged, kept in the alert history ("logged only") and counted as a step of an
attack chain - it just does not come up as a reminder.

It never hides what is worse: an entry covers findings up to the severity of the alert it was made from. Chains
and RADAR's own notices cannot be switched off, nor alerts that are about no account in particular.

Kept in the settings file (``general.quiet_reminders``), so it can be read and edited there too.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import timefmt

KEY = ("general", "quiet_reminders")
NOTE_FIELD = "Reminder"
PERIODS = [("for 30 days", 30), ("for 90 days", 90), ("for a year", 365)]
# conclusions drawn from other alerts (chains.CHAIN_PLUGIN), and RADAR's own notices (alerts.SYSTEM_PLUGIN; not
# imported: alerts imports this module)
NOT_FOR_PLUGINS = ("correlation", "core")


@dataclass(frozen=True)
class Quiet:
    rule_id: str
    subject: str        # an account (UPN) or "app:<name>", lower case - as alerts name what they are about
    until: datetime
    severity: int       # the highest severity it covers
    since: datetime
    title: str = ""     # the alert it was made from

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule_id, "subject": self.subject, "until": self.until.isoformat(),
                "severity": self.severity, "since": self.since.isoformat(), "title": self.title}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Quiet | None":
        try:
            return cls(str(d["rule"]), str(d["subject"]).strip().lower(), _time(d["until"]), int(d.get("severity", 1)),
                       _time(d.get("since") or d["until"]), str(d.get("title") or ""))
        except (KeyError, TypeError, ValueError):
            return None  # an entry somebody edited into something else: ignored

    def note(self) -> str:
        return f"Switched off for {label(self.subject)} until {timefmt.stamp_year(self.until)} (Settings > Reminders)"


def _time(value: Any) -> datetime:
    dt = datetime.fromisoformat(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def label(subject: str) -> str:
    return f"the application {subject[4:]}" if subject.startswith("app:") else subject


def _stored(cfg: Any) -> list[Quiet]:
    raw = cfg.get(*KEY, default=[]) or []
    return [q for q in (Quiet.from_dict(d) for d in raw if isinstance(d, dict)) if q is not None]


def _save(cfg: Any, entries: Iterable[Quiet]) -> None:
    cfg.set(*KEY, value=[q.to_dict() for q in entries])


def active(cfg: Any, now: datetime | None = None) -> list[Quiet]:
    """What is switched off right now. Entries whose time is over are cleared away."""
    now = now or datetime.now(timezone.utc)
    stored = _stored(cfg)
    current = [q for q in stored if q.until > now]
    if len(current) != len(stored):
        _save(cfg, current)
    return current


def load(cfg: Any) -> list[Quiet]:
    """Every entry in the settings file (see ``active`` for the ones that still count)."""
    return _stored(cfg)


def choices(alert: Any) -> list[str]:
    """What an alert can be switched off for: the accounts and applications it is about."""
    if getattr(alert, "plugin_id", "") in NOT_FOR_PLUGINS or getattr(alert, "is_system", False) \
            or getattr(alert, "signal", "") or not getattr(alert, "rule_id", ""):
        return []
    return sorted({str(s).strip().lower() for s in getattr(alert, "subjects", None) or [] if str(s).strip()})


def add(cfg: Any, alert: Any, subject: str, days: float, now: datetime | None = None) -> Quiet:
    """Switch the alert's rule off for one of the accounts / applications it is about (replaces an earlier entry)."""
    now = now or datetime.now(timezone.utc)
    subject = subject.strip().lower()
    q = Quiet(alert.rule_id, subject, now + timedelta(days=float(days)), int(alert.severity), now, str(alert.title))
    _save(cfg, [x for x in _stored(cfg) if (x.rule_id, x.subject) != (q.rule_id, q.subject)] + [q])
    return q


def remove(cfg: Any, rule_id: str, subject: str) -> bool:
    stored = _stored(cfg)
    kept = [q for q in stored if (q.rule_id, q.subject) != (rule_id, subject.strip().lower())]
    if len(kept) == len(stored):
        return False
    _save(cfg, kept)
    return True


def match(entries: Iterable[Quiet], rule_id: str, subjects: Iterable[str], severity: Any, now: datetime) -> Quiet | None:
    """The entry that keeps a finding of this rule about these subjects from coming up, if there is one."""
    about = {str(s).strip().lower() for s in subjects or []}
    for q in entries or ():
        if q.rule_id == rule_id and q.subject in about and int(severity) <= q.severity and q.until > now:
            return q
    return None
