"""Times as RADAR shows them: local time, always with its time zone ("16.11. 07:50 UTC+1").

A time without its zone is half a statement - the people who read an alert, the logs they compare it with and the
accounts it is about are often in different zones. So every clock time RADAR shows or writes into an alert goes
through this module (tests/test_timezones.py holds the rest of the code to that): the zone is the offset to UTC at
that moment, so summer and winter time are told apart.

Dates without a time, and spans like "3 days ago", need no zone and are not handled here.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

DAY, DAY_YEAR, SORTABLE = "%d.%m. %H:%M", "%d.%m.%Y %H:%M", "%Y-%m-%d %H:%M"
LONG = "%A %d.%m.%Y %H:%M"
ELLIPSIS = "…"


def zone(dt: datetime) -> str:
    """The zone of an aware time as its offset to UTC: 'UTC', 'UTC+1', 'UTC-3:30'."""
    offset = dt.utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    if minutes == 0:
        return "UTC"
    hours, rest = divmod(abs(minutes), 60)
    return f"UTC{'+' if minutes > 0 else '-'}{hours}" + (f":{rest:02d}" if rest else "")


def stamp(dt: datetime | None, fmt: str = DAY) -> str:
    """A time in local time with its zone ('' for None). ``fmt``: how the date and time are written."""
    if dt is None:
        return ""
    local = dt.astimezone()
    return f"{local.strftime(fmt)} {zone(local)}"


def clock(dt: datetime | None) -> str:
    """Hour and minute with the zone: '07:50 UTC+1'."""
    return stamp(dt, "%H:%M")


def stamp_year(dt: datetime | None) -> str:
    """Date with the year, time and zone: '16.11.2026 07:50 UTC+1'."""
    return stamp(dt, DAY_YEAR)


def sortable(dt: datetime | None, seconds: bool = False) -> str:
    """A time that sorts as text - for table columns and evidence rows: '2026-11-16 07:50[:24] UTC+1'."""
    return stamp(dt, SORTABLE + (":%S" if seconds else ""))


ZONE = r"UTC(?:[+-]\d{1,2}(?::\d{2})?)?"
# a clock time, with the date in front of it when there is one (the ways RADAR has written dates), and its zone
_TIME = re.compile(
    r"(?<![\da-fA-F:.\-/])"  # (not inside an address: 2a02:1210:..., fe80::12:34)
    r"(?:(?P<iso>\d{4}-\d{2}-\d{2})[ T]|(?P<day>\d{2}\.\d{2}\.)(?P<year>\d{4})? ?)?"
    r"(?P<clock>(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?)"
    r"(?!\d|:[\da-fA-F]|[a-fA-F])(?P<zone>Z| ?" + ZONE + r")?")


_ZONE_BEGUN = re.compile(r"\s*(?:U|UT|UTC[+-]?\d{0,2}:?\d?)?")


def keep_whole(cut: str) -> str:
    """A text that was shortened to fit its place (it ends in an ellipsis): when the cut went through a time and
    its zone, the whole time goes - a time is shown with its zone or not at all."""
    if not cut.endswith(ELLIPSIS):
        return cut
    body = cut[:-len(ELLIPSIS)]
    last = None
    for last in _TIME.finditer(body):
        pass
    if last is None or not _ZONE_BEGUN.fullmatch(body[last.end():]):
        return cut
    if last.group("zone") and last.end() < len(body):
        return cut  # the zone is all there, and text follows it
    return body[:last.start()].rstrip(" ,;:(-\u2013\u00b7") + ELLIPSIS


def unzoned(text: str) -> list[str]:
    """The clock times in a text that do not say their zone (for tests: there should be none on the screen)."""
    return [m.group(0) for m in _TIME.finditer(str(text)) if not m.group("zone")]


def zoned_text(text: str, now: datetime | None = None) -> str:
    """``text`` with the zone added to every clock time that lacks one - for what was written before RADAR named
    the zone. Such times were local times of this PC: the zone is the local one on that date (with only a time,
    today's; a day and month without a year is taken as the most recent such day)."""
    now = (now or datetime.now()).astimezone()

    def add(m: re.Match) -> str:
        if m.group("zone"):
            return m.group(0)
        hour, minute = int(m.group("clock")[:2]), int(m.group("clock")[3:5])
        try:
            if m.group("iso"):
                year, month, day = (int(x) for x in m.group("iso").split("-"))
            elif m.group("day"):
                day, month = int(m.group("day")[:2]), int(m.group("day")[3:5])
                year = int(m.group("year") or now.year)
                if not m.group("year") and datetime(year, month, day) > now.replace(tzinfo=None) + timedelta(days=2):
                    year -= 1
            else:
                year, month, day = now.year, now.month, now.day
            local = datetime(year, month, day, hour, minute).astimezone()
        except ValueError:
            local = now
        return f"{m.group(0)} {zone(local)}"

    return _TIME.sub(add, str(text))
