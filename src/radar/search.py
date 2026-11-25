"""Search, and the page about one account.

One field that finds accounts, devices, IP addresses, applications, sign-ins and alerts in what RADAR has stored - for
looking something up, hunting, forensics. And for an account everything RADAR knows about it, in order: who it is,
what is open, its habits, what stands out, and one timeline of sign-ins, changes and alerts.

Pure logic: it reads the sign-in history, the account directory and the alerts it is given, asks nobody else and
changes nothing. What it finds is stored data; how old that is, the caller says.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from . import geo, timefmt
from .plugins.signin_threats import netintel, presence
from .plugins.signin_threats.models import SignIn

KINDS = ("account", "device", "address", "application", "alert", "signin")
MIN_LENGTH = 2          # shorter than this finds too much to be an answer
DAYS = 30               # how far back sign-ins are kept
NEW_WITHIN = timedelta(hours=24)   # "new": first seen this recently
SAME_BURST = timedelta(minutes=5)  # (failed attempts this close together are "in N minutes"; further apart: "over N hours")
OPEN = ("active", "snoozed")
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ADDRESS = re.compile(r"[0-9a-f:.]+")
LEGACY_CLIENTS = {"authenticated smtp", "other clients", "imap4", "pop3", "exchange activesync", "exchange web services", "mapi over http"}
WRONG_PASSWORD = {50126, 50056}
LOCKED_OUT = {50053}   # smart lockout: too many attempts, or the address is one Entra blocks
# Steps of an ordinary sign-in that Entra logs as an "error": the user was asked for something (MFA, a device, to
# pick an account) and the sign-in went on. They are no failed sign-ins and get no line of their own ...
INTERRUPTS = {50058, 50072, 50074, 50076, 50078, 50079, 50097, 50125, 50129, 50140, 16000, 16001}
# ... unless it did not go on. Asked for MFA means the first step passed - with a stolen password this is where the
# thief stops: the same codes, and no sign-in that worked after them. Those are shown (see _stopped_at_mfa).
MFA_ASKED = {50072, 50074, 50076, 50079}
SET_UP_FIRST = {50072, 50079}             # MFA is required and the account has none yet: whoever goes on registers one
FOLLOWED_WITHIN = timedelta(minutes=10)   # a sign-in that worked this soon after the prompt: it was answered
DEVICE_TOKEN = "primaryrefreshtoken"


@dataclass(frozen=True)
class Hit:
    kind: str                      # one of KINDS
    key: Any                       # what opens it: user id, device id, address, application name, alert id, sign-in id
    title: str
    line: str = ""                 # the second, quieter line
    note: str = ""                 # what stands at the right ("2 open alerts", a role)
    when: datetime | None = None


@dataclass
class Results:
    text: str
    hits: dict[str, list[Hit]] = field(default_factory=lambda: {k: [] for k in KINDS})
    counts: dict[str, int] = field(default_factory=lambda: {k: 0 for k in KINDS})

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _like(text: str) -> str:
    """The text as a LIKE pattern that means the text itself ('%' and '_' are not wildcards here)."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _open_about(alerts: Iterable[Any], upn: str) -> list[Any]:
    low = (upn or "").lower()
    return [a for a in alerts if a.status in OPEN and low and low in {str(s).lower() for s in a.subjects}]


def _place(s: SignIn) -> str:
    return ", ".join(p for p in (s.city, s.country) if p)


def search(text: str, history: Any, accounts: Any, alerts: Sequence[Any], now: datetime, limit: int = 5,
           days: int = DAYS) -> Results:
    """Everything stored that matches ``text``: per kind the best ``limit`` hits and how many there are in all."""
    text = " ".join(str(text or "").replace("\x00", " ").split())
    out = Results(text)
    if len(text) < MIN_LENGTH:
        return out
    low = text.lower()
    words = low.split()
    conn = history.conn
    since = (now - timedelta(days=days)).timestamp()
    alerts = list(alerts)

    # accounts: every word in the name or the sign-in name; or the id itself
    found = [a for a in accounts.accounts.values()
             if a.user_id.lower() == low or all(w in f"{a.display_name} {a.upn}".lower() for w in words)]
    found.sort(key=lambda a: (not f"{a.display_name} {a.upn}".lower().startswith(low), not a.enabled, -len(a.last_signin or ""), a.display_name.lower()))
    out.counts["account"] = len(found)
    for a in found[:limit]:
        about = len(_open_about(alerts, a.upn))
        note = _plural(about, "open alert") if about else (a.roles[0] if a.roles else "" if a.enabled else "disabled")
        out.hits["account"].append(Hit("account", a.user_id, a.display_name or a.upn, a.upn, note))

    # addresses: what is typed is the beginning of one
    if _ADDRESS.fullmatch(low) and any(c in low for c in ".:") and not _GUID.fullmatch(low):
        rows = conn.execute(
            "SELECT ip, count(*), count(DISTINCT user_id), max(ts), max(json_extract(data, '$.city')), max(country) FROM signins "
            "WHERE ts>=? AND ip>=? AND ip<? GROUP BY ip ORDER BY max(ts) DESC", (since, low, low + "￿")).fetchall()
        out.counts["address"] = len(rows)
        for ip, n, users, last, city, country in rows[:limit]:
            when = datetime.fromtimestamp(last, timezone.utc)
            where = ", ".join(p for p in (city, country) if p)
            out.hits["address"].append(Hit("address", ip, ip, " · ".join(p for p in (where, _plural(users, "account"), _plural(n, "sign-in")) if p), when=when))

    # sign-ins, devices and applications in one pass over the stored records: a record that has the text anywhere is a
    # sign-in hit; where the text is in the device's or the application's name (or is their id), that one is a hit too
    one = history.get(text) or history.get(low)
    if one is not None:
        out.counts["signin"], newest = 1, [one]
    else:
        rows = conn.execute(
            "SELECT id, ts, user_id, device_id, app_id, json_extract(data, '$.device_name'), json_extract(data, '$.app') FROM signins "
            "WHERE ts>=? AND data LIKE ? ESCAPE '\\'", (since, _like(text))).fetchall()
        out.counts["signin"] = len(rows)
        groups: dict[tuple[str, str], list] = {}   # (kind, key) -> [title, sign-ins, accounts, last]
        for _id, ts, user, device_id, app_id, device_name, app in rows:
            for kind, key, title, ident in (("device", device_id, device_name, device_id), ("application", app, app, app_id)):
                if key and title and (low in title.lower() or low == (ident or "").lower()):
                    g = groups.setdefault((kind, key), [title, 0, set(), 0.0])
                    g[1] += 1
                    g[2].add(user)
                    g[3] = max(g[3], ts)
        for kind in ("device", "application"):
            mine = sorted(((k[1], g) for k, g in groups.items() if k[0] == kind), key=lambda x: -x[1][3])
            out.counts[kind] = len(mine)
            for key, (title, n, users, last) in mine[:limit]:
                when = datetime.fromtimestamp(last, timezone.utc)
                out.hits[kind].append(Hit(kind, key, title, f"{_plural(len(users), 'account')} · {_plural(n, 'sign-in')} · last seen {timefmt.stamp(when)}", when=when))
        newest = [x for x in (history.get(r[0]) for r in sorted(rows, key=lambda r: -r[1])[:limit]) if x is not None]
    for s in newest:
        device = s.device_name or "no device"
        out.hits["signin"].append(Hit("signin", s.id, " · ".join(p for p in (s.upn, s.app, _place(s), device) if p),
                                      note="success" if s.success else "failed", when=s.created))

    # alerts: every word in the title, the summary, who it is about or one of its fields
    def says(a: Any) -> str:
        return " ".join([a.title, a.summary, " ".join(map(str, a.subjects)), " ".join(map(str, (a.fields or {}).values()))]).lower()

    matching = sorted((a for a in alerts if all(w in says(a) for w in words)),
                      key=lambda a: (a.status not in OPEN, -(a.last_seen or now).timestamp()))
    out.counts["alert"] = len(matching)
    for a in matching[:limit]:
        out.hits["alert"].append(Hit("alert", a.id, a.title, " · ".join(a.subjects[:1]), f"{a.severity.label} · {'open' if a.status in OPEN else a.status}"
                                     if hasattr(a.severity, "label") else str(a.status), when=a.occurred_at or a.last_seen))
    return out


# ======================================================================================== one account
@dataclass(frozen=True)
class Fact:
    label: str
    value: str
    warn: bool = False


@dataclass(frozen=True)
class Entry:
    name: str
    count: int
    new: bool = False
    ref: tuple[str, str] | None = None   # (kind, key) of the page about it


@dataclass(frozen=True)
class Kind:
    label: str
    entries: list[Entry]


@dataclass(frozen=True)
class Worth:
    label: str
    detail: str
    count: int
    ids: list[str]      # the sign-ins it counts: the timeline can show exactly these
    points: list = field(default_factory=list, compare=False, repr=False)   # ... as (when, address), to find them in a run


@dataclass
class Line:
    when: datetime
    kind: str            # "Sign-in", "Failed", "Change" or "Alert"
    what: str
    place: str = ""
    ip: str = ""
    device: str = ""
    device_id: str = ""
    marks: list[str] = field(default_factory=list)
    ref: tuple[str, Any] | None = None   # ("signin", id) / ("alert", id) / ("change", id)
    count: int = 1                       # how many sign-ins the line stands for
    level: str = ""                      # an alert's severity
    record: Any = field(default=None, compare=False, repr=False)   # the sign-in itself, when the line is one
    ids: frozenset = field(default=frozenset(), compare=False, repr=False)   # the sign-ins the line stands for, where known
    begin: datetime | None = field(default=None, compare=False, repr=False)  # a run of sign-ins: when it began (it ends at ``when``)
    account: str = field(default="", compare=False)    # whose it is - on pages that are about more than one account
    user_id: str = field(default="", compare=False)


@dataclass(frozen=True)
class Place:
    """A place a device of the account was seen at: an office by its name, else the town and country the address
    database gives its address."""
    key: str
    label: str              # "Zurich, CH", "Singapore office"
    short: str              # what a bar has room for: "Zurich"


@dataclass(frozen=True)
class Run:
    """A device at one place: from its first sign-in there until its last, without a silence of more than STAY_GAP."""
    place: str              # the key of its Place
    begin: datetime
    end: datetime
    network: str = ""       # the networks its sign-ins came through ("Example Telecom", "office network")


@dataclass(frozen=True)
class Lane:
    """One device of the account and where it was, in the order of time."""
    key: str                # its device id; "os:<system>" for a device that does not name itself; "" for sign-ins that name no device
    name: str               # "LT-0042", "Phone", "No device"
    kind: str               # the second line: "work computer, managed", "iOS, not managed"
    runs: tuple[Run, ...] = ()


@dataclass
class Movement:
    """Where the account's devices were in the last days (the Movement card): a lane for every device, the places in
    the order of the time spent there (the colours are given in that order)."""
    since: datetime
    now: datetime
    lanes: list[Lane]
    places: list[Place]


@dataclass
class AccountView:
    user_id: str
    title: str
    upn: str = ""
    enabled: bool = True
    member: str = ""
    facts: list[Fact] = field(default_factory=list)
    open_alerts: list[Any] = field(default_factory=list)
    incidents: list[Any] = field(default_factory=list)
    earlier_alerts: int = 0
    risk: int | None = None
    habits: list[Kind] = field(default_factory=list)
    worth: list[Worth] = field(default_factory=list)
    timeline: list[Line] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    kind: str = "account"                     # what the page is about (account, device, address, network, country, application)
    key: str = ""
    tags: list[tuple[str, bool]] = field(default_factory=list)   # short words under the title; True: one to notice
    habits_title: str = "Habits"
    risk_level: str = ""                      # the level of the alert the highest open risk comes from
    per_day: list[int] = field(default_factory=list)      # sign-ins per day, oldest first (DAYS values)
    movement: Movement | None = None   # where the account's devices were (an account's page; None: at one place only)
    now: datetime | None = None   # as of when all this was read


def _day(value: str | None) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone().strftime("%d.%m.%Y") if value else ""
    except ValueError:
        return ""


def _how(s: SignIn) -> str:
    """How a successful sign-in was authenticated, in a few words ('' when the record does not say)."""
    real = [m for m in s.auth_methods if m and m.lower() not in ("previously satisfied", "password")]
    if real:
        return "MFA by " + real[0]
    if (s.incoming_token or "").lower() == DEVICE_TOKEN:
        return "signed in by the device, no prompt"
    return "password only" if (s.auth_requirement or "").lower().startswith("single") and s.interactive else ""


def marks_of(s: SignIn) -> list[str]:
    """What is unusual about a sign-in - shown as small tags. A normal sign-in has none."""
    marks = []
    if (s.ca_status or "").lower() == "failure":
        marks.append("blocked by policy")
    if (s.risk_during or "none").lower() not in ("none", "", "hidden"):
        marks.append(f"Entra risk: {s.risk_during.lower()}")
    if "devicecode" in ((s.auth_protocol or "") + (s.transfer_method or "")).lower():
        marks.append("device code")
    if (s.client_app or "").lower() in LEGACY_CLIENTS:
        marks.append("old protocol")
    if any("text message" in str(m).lower() for m in s.auth_methods):
        marks.append("text message")
    return marks


def _why_failed(s: SignIn) -> str:
    if s.error_code in WRONG_PASSWORD:
        return "wrong password"
    if s.error_code in LOCKED_OUT:
        return "locked out"
    if s.error_code in SET_UP_FIRST:
        return "MFA has to be set up first, stopped there"
    if s.error_code in MFA_ASKED:
        return "stopped at the MFA prompt"
    if (s.ca_status or "").lower() == "failure":
        return ""
    reason = (s.failure_reason or f"error {s.error_code}").strip().rstrip(".")
    return reason


def _stopped_at_mfa(rows: Iterable[SignIn], history: Any) -> list[SignIn]:
    """The sign-ins among ``rows`` that got as far as the MFA prompt and no further: no sign-in of that account from
    that address worked in the minutes after. (From that address: the account's owner working elsewhere at the same
    time does not answer for whoever stands at the prompt. The sign-ins that worked are looked up in everything
    stored - a page or a search holds only a part of it.)"""
    conn, out = history.conn, []
    for s in rows:
        if s.success or s.error_code not in MFA_ASKED:
            continue
        at = s.created.timestamp()
        args: tuple = (s.user_id, at - 60, at + FOLLOWED_WITHIN.total_seconds())
        there = ""
        if s.ip:   # (a record Entra has not completed yet has no address: any sign-in that worked answers for it)
            there, args = " AND ip=?", args + (s.ip,)
        if conn.execute("SELECT 1 FROM signins WHERE user_id=? AND error_code=0 AND ts BETWEEN ? AND ?" + there + " LIMIT 1", args).fetchone():
            continue
        if conn.execute("SELECT 1 FROM activity WHERE user_id=? AND last_ts>=? AND first_ts<=?" + there + " LIMIT 1", args).fetchone():
            continue
        out.append(s)
    return out


def _failed(rows: Sequence[SignIn], history: Any) -> list[SignIn]:
    """The sign-ins that failed: not the steps of an ordinary sign-in - but those that stopped at such a step."""
    stopped = {s.id for s in _stopped_at_mfa(rows, history)}
    return [s for s in rows if not s.success and (s.error_code not in INTERRUPTS or s.id in stopped)]


def _span(delta: timedelta) -> str:
    """'in 2 minutes' for attempts in one go, 'over 6 hours' for attempts spread over the day."""
    minutes = max(1, round(delta.total_seconds() / 60 + 0.49))
    return f"in {_plural(minutes, 'minute')}" if minutes <= 90 else f"over {_plural(round(minutes / 60), 'hour')}"


def _signin_lines(prompted: list[SignIn], failed: list[SignIn], runs: Iterable[tuple], who: Any = None) -> list[Line]:
    """The sign-ins of a timeline: each sign-in somebody was prompted for; the failed ones as one line per kind and
    day; everything else as runs ("212 sign-ins until 13:58"). ``who(user id)``: the account's name - given on pages
    that are about more than one account, where each line then says whose it is."""
    def whose(s: SignIn) -> dict:
        return dict(account=who(s.user_id) or s.upn or s.user_id, user_id=s.user_id) if who else {}

    lines: list[Line] = []
    for s in prompted:
        lines.append(Line(s.created, "Sign-in", " · ".join(p for p in (s.app, _how(s)) if p), _place(s), s.ip, s.device_name, s.device_id,
                          marks_of(s), ("signin", s.id), record=s, ids=frozenset({s.id}), **whose(s)))
    # One line per kind of failure and day, whatever address the attempts come from and however they are spread: an
    # account that is being guessed at all day long has one line that says so, not hundreds
    by_day: dict[tuple[str, int], list[SignIn]] = {}
    for s in failed:
        what = "mfa" if s.error_code in MFA_ASKED - SET_UP_FIRST else s.error_code   # (asked for MFA has more than one code)
        by_day.setdefault((s.created.astimezone().strftime("%Y-%m-%d"), what), []).append(s)
    for burst in by_day.values():
        first, last_one = burst[0], burst[-1]
        why = _why_failed(last_one)
        addresses, users = {s.ip for s in burst}, {s.user_id for s in burst}
        times = f", {len(burst):,} times {_span(last_one.created - first.created)}" if len(burst) > 1 else ""
        spread = f" from {len(addresses):,} addresses" if len(addresses) > 1 else ""
        if who and len(users) > 1:
            spread += f" against {len(users):,} accounts"
        app = Counter(s.app for s in burst).most_common(1)[0][0]
        one_place = len(addresses) == 1
        lines.append(Line(last_one.created, "Failed", " · ".join(p for p in (app, ((why + times) if why else times.lstrip(", ")) + spread) if p),
                          _place(last_one) if one_place else "", last_one.ip if one_place else "", last_one.device_name if one_place else "",
                          last_one.device_id if one_place else "", marks_of(last_one), ("signin", last_one.id), len(burst), record=last_one,
                          ids=frozenset(s.id for s in burst), **(whose(last_one) if len(users) == 1 else {})))
    for first, begin, end, n in runs:
        rest = n - sum(1 for s in prompted if s.ip == first.ip and s.user_id == first.user_id and begin <= s.created <= end)
        if rest <= 0:
            continue
        what = first.app if rest == 1 else f"{first.app} · {_plural(rest, 'sign-in')} until {timefmt.clock(end)}"
        if rest == 1 and _how(first):
            what = f"{first.app} · {_how(first)}"
        lines.append(Line(end, "Sign-in", what, _place(first), first.ip, first.device_name, first.device_id, [], ("signin", first.id), rest,
                          record=first, begin=begin, **whose(first)))
    return lines


def account_view(user_id: str, history: Any, accounts: Any, alerts: Sequence[Any], incidents: Sequence[Any], now: datetime,
                 names: dict | None = None, days: int = DAYS, settings: dict | None = None) -> AccountView:
    """Everything stored about one account. ``names``: network numbers -> {"n": name} (the plugin's cache);
    ``incidents``: the incidents of the alerts given (the caller groups them); ``settings``: the sign-in plugin's
    (its offices and what it trusts - where the account's devices were is read with them, as the Live map does)."""
    info = accounts.get(user_id)
    start = now - timedelta(days=days)
    rows = history.query(start, now, user_id=user_id)
    upn = (info.upn if info else "") or next((s.upn for s in reversed(rows) if s.upn), "")
    view = AccountView(user_id, (info.display_name if info else "") or upn or user_id, upn, info.enabled if info else True,
                       (info.user_type if info else "") or "")
    conn = history.conn
    profile = conn.execute("SELECT kind, value, first_ts, n FROM profile WHERE user_id=? ORDER BY n DESC", (user_id,)).fetchall()
    if info is None and not rows and not profile:
        return view
    fresh = (now - NEW_WITHIN).timestamp()
    by_kind: dict[str, list[tuple[str, float, int]]] = {}
    for kind, value, first, n in profile:
        by_kind.setdefault(kind, []).append((value, first, n))

    # ---- what is open
    about = [a for a in alerts if upn and upn.lower() in {str(s).lower() for s in a.subjects}]
    view.open_alerts = sorted((a for a in about if a.status in OPEN), key=lambda a: (-int(a.severity), -a.score))
    view.earlier_alerts = len(about) - len(view.open_alerts)
    view.incidents = [i for i in incidents if getattr(i, "open", False) and any(a in view.open_alerts for a in i.alerts)]
    view.risk, view.risk_level = _risk(view.open_alerts)

    # ---- the head
    risky = [s for s in rows if (s.risk_during or "none").lower() not in ("none", "", "hidden")]
    if risky:
        worst = max(risky, key=lambda s: ("low", "medium", "high").index(s.risk_during.lower()) if s.risk_during.lower() in ("low", "medium", "high") else -1)
        day = "today" if now - worst.created < NEW_WITHIN else "on " + worst.created.astimezone().strftime("%d.%m.")
        risk_fact = Fact("Risk in Entra", f"{worst.risk_during.lower()} on a sign-in {day}", True)
    else:
        risk_fact = Fact("Risk in Entra", "None seen")
    phones = by_kind.get("mfadev", [])
    new_phones = sum(1 for _v, first, _n in phones if first >= fresh)
    phone_fact = Fact("MFA approved from", (_plural(len(phones), "phone") + (f" · {new_phones} new today" if new_phones else "")) if phones else "Not seen",
                      bool(new_phones))
    last = max((s.created for s in rows if s.success), default=None)
    view.facts = [risk_fact, phone_fact,
                  Fact("Roles", ", ".join(info.roles) if info and info.roles else "None"),
                  Fact("Last sign-in", timefmt.stamp(last) if last else (_day(info.last_signin) if info else "") or "Not seen")]
    if info is not None:
        view.facts += [
            Fact("MFA methods", ", ".join(info.mfa_methods) or ("None registered" if info.mfa_registered is False else "Not known"),
                 info.mfa_registered is False),
            Fact("Password changed", _day(info.pwd_changed) or "Not known"),
            Fact("Roles it can activate", ", ".join(info.pim_roles) or "None"),
            Fact("Excluded from MFA", "; ".join(info.mfa_excluded) or "No", bool(info.mfa_excluded)),
            Fact("Created", _day(info.created) or "Not known"),
            Fact("Directory", "Synced from on-premises" if info.synced_onprem else "Cloud only"),
            Fact("Licences", ", ".join(info.licenses) or "None"),
        ]
        if info.breakglass:
            view.facts.append(Fact("Break-glass account", "Yes", True))

    # ---- habits: what the profile of the last 30 days holds (successful sign-ins of every kind)
    def device_name(device_id: str) -> str:
        row = conn.execute("SELECT json_extract(data, '$.device_name') FROM signins WHERE user_id=? AND device_id=? ORDER BY ts DESC LIMIT 1",
                           (user_id, device_id)).fetchone()
        return (row[0] if row and row[0] else "") or device_id

    def network_name(number: str) -> str:
        return str(((names or {}).get(str(number)) or {}).get("n") or f"AS{number}")

    def entries(kind: str, name=lambda v: v, ref: str | None = None, top: int = 6) -> list[Entry]:
        return [Entry(name(value), n, first >= fresh and len(by_kind.get(kind, [])) > 1, (ref, value) if ref else None)
                for value, first, n in by_kind.get(kind, [])[:top]]

    successes = sum(n for _v, _f, n in by_kind.get("country", []))
    prompted = [s for s in rows if s.success and s.interactive and (s.incoming_token or "").lower() != DEVICE_TOKEN]
    with_mfa = [s for s in prompted if not (s.auth_requirement or "").lower().startswith("single")]
    password_only = [s for s in prompted if (s.auth_requirement or "").lower().startswith("single")]
    failed = _failed(rows, history)
    how = [Entry("Known device", successes - len(prompted)), Entry("MFA", len(with_mfa)), Entry("Password only", len(password_only)),
           Entry("Failed", len(failed))]
    view.habits = [k for k in (
        Kind("Countries", entries("country", geo.country_name, "country")),
        Kind("Networks", entries("asn", network_name, "network")),
        Kind("Devices", entries("device", device_name, "device")),
        Kind("Applications", entries("app", ref="application")),
        Kind("How it signs in", [e for e in how if e.count > 0]),
        Kind("With what", entries("proto", lambda v: v[:1].upper() + v[1:])),
    ) if k.entries]

    # ---- worth a look: what stands out, each with the sign-ins it counts
    def worth(label: str, picked: list[SignIn], detail: str = "") -> None:
        if picked:
            newest = max(picked, key=lambda s: s.created)
            view.worth.append(Worth(label, detail or f"{newest.app} · {timefmt.stamp(newest.created)}", len(picked), [s.id for s in picked],
                                    [(s.created, s.ip) for s in picked]))

    worth("Stopped at the MFA prompt, nothing followed", [s for s in failed if s.error_code in MFA_ASKED])
    worth("Entra saw risk on a sign-in", risky)
    worth("Blocked by a policy", [s for s in rows if (s.ca_status or "").lower() == "failure"])
    worth("Device code sign-in", [s for s in rows if "device code" in marks_of(s)])
    worth("Old protocol", [s for s in rows if "old protocol" in marks_of(s)])
    worth("MFA by text message", [s for s in rows if "text message" in marks_of(s)])
    worth("Token not bound to a device", [s for s in prompted if (s.token_protection or "").lower() == "unbound"])
    worth("Password only, no MFA", password_only, _plural(len({s.app for s in password_only}), "application"))
    if new_phones:
        view.worth.append(Worth("MFA approved from a new phone", "first seen today", new_phones, []))
    anon = len(by_kind.get("anonday", []))
    if anon:
        view.worth.append(Worth("Used an anonymiser", _plural(anon, "day"), anon, []))

    # ---- the timeline
    runs = history.activity(start, now, user_id)
    lines = _signin_lines(prompted, failed, runs)
    view.per_day = _per_day([(r[1], r[3]) for r in runs], now, days)
    view.movement = _movement(history, rows, runs, now, settings or {}, accounts, lambda number: ((names or {}).get(str(number)) or {}).get("n"))
    view.now = now
    changes = history.changes(start, now, user_id)
    for c in changes:
        by = f", by {c.actor}" if c.by_admin and c.actor else ""
        lines.append(Line(c.created, "Change", (c.detail or c.kind) + by, "", c.actor_ip, ref=("change", c.id)))
    for a in about:
        when = a.occurred_at or a.last_seen
        if when is not None and when >= start:
            lines.append(_alert_line(a, when))
    order = {"Alert": 2, "Change": 1}
    view.timeline = sorted(lines, key=lambda ln: (ln.when, order.get(ln.kind, 0)), reverse=True)
    view.counts = {"Sign-in": successes, "Failed": len(failed), "Change": len(changes), "Alert": sum(1 for ln in lines if ln.kind == "Alert")}
    return view


NETWORK_KINDS = {"hosting": "Hosting provider", "vpn": "VPN provider", "cloud": "Cloud provider", "bulletproof": "Bulletproof hosting"}
_ADDRESSES = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})(?![\w:])")
FAST = 900   # km/h: faster than this between two places is not a person travelling


def _text_of(alert: Any) -> str:
    return " ".join([alert.title, alert.summary, " ".join(map(str, alert.subjects)), " ".join(map(str, (alert.fields or {}).values()))]).lower()


def _risk(open_alerts: Sequence[Any]) -> tuple[int | None, str]:
    """The highest open risk and the level of the alert it comes from."""
    if not open_alerts:
        return None, ""
    top = max(open_alerts, key=lambda a: a.score)
    return top.score, getattr(top.severity, "label", str(top.severity))


def _alert_line(a: Any, when: datetime) -> Line:
    """An alert on a timeline - with the address and the device it names, where it names one."""
    fields = a.fields or {}
    found = _ADDRESSES.findall(str(fields.get("IP address", "")).lower())
    return Line(when, "Alert", a.title, str(fields.get("Country", "") or ""), found[0] if found else "", str(fields.get("Device", "") or ""),
                str(fields.get("_Device ID", "") or ""), ref=("alert", a.id),
                level=getattr(a.severity, "label", str(a.severity)).lower() if a.status in OPEN else "closed")


def _per_day(counted: Iterable[tuple[datetime, int]], now: datetime, days: int) -> list[int]:
    """Sign-ins per local day, oldest first, today last."""
    today = now.astimezone().date()
    out = [0] * days
    for when, n in counted:
        back = (today - when.astimezone().date()).days
        if 0 <= back < days:
            out[days - 1 - back] += n
    return out


# ======================================================================================== movement
MOVES_DAYS = 7                        # the Movement card reaches back over today and the six days before it
STAY_GAP = timedelta(hours=4)         # a silence this long ends a device's stay at a place (as on the Live map)
MOBILE_SYSTEMS = ("iOS", "Android")
_SYSTEMS = (("iOS", ("ios", "iphone", "ipad")), ("Android", ("android",)), ("Windows", ("windows",)), ("macOS", ("mac",)),
            ("ChromeOS", ("chrome",)), ("Linux", ("linux",)))


def _system(os_name: str) -> str:
    """The operating system without its version: 'Windows10' -> 'Windows', 'iOS 18.1' -> 'iOS'."""
    low = (os_name or "").lower()
    return next((name for name, words in _SYSTEMS if any(w in low for w in words)), (os_name or "").split(" ")[0])


def _lane_key(s: SignIn) -> str:
    """The lane a sign-in belongs on. A device is known by its id; one without (not registered) only by its operating
    system - its sign-ins cannot be told apart from those of another such device with that system. A sign-in that
    names no system names no device."""
    if s.device_id:
        return s.device_id
    system = _system(s.os)
    return f"os:{system}" if system else ""


def _lane_words(key: str, s: SignIn) -> tuple[str, str, int]:
    """(name, the second line, rank) of a lane, from its newest sign-in: work computers first, then managed phones,
    other registered devices, devices that are not, and last the sign-ins that name none."""
    if not key:
        return "No device", "the sign-ins name none", 4
    system = _system(s.os)
    if key.startswith("os:"):
        return s.device_name or ("Phone" if system in MOBILE_SYSTEMS else f"{system} computer"), f"{system}, not managed", 3
    kind = presence.device_class(s)
    managed = bool(s.compliant or s.managed or (s.trust_type or "").lower() in presence.JOINED)
    what = "work computer" if kind == presence.WORK_COMPUTER else system or "system not known"
    rank = 0 if kind == presence.WORK_COMPUTER else 1 if kind == presence.MANAGED_MOBILE else 2
    return s.device_name or (f"{system} device" if system else "Unnamed device"), f"{what}, {'managed' if managed else 'not managed'}", rank


def _movement(history: Any, rows: Sequence[SignIn], runs: Sequence[tuple], now: datetime, settings: dict, accounts: Any,
              asn_name: Any) -> Movement | None:
    """Where the account's devices were from the beginning of the day six days ago until ``now`` (see Movement), from
    its successful sign-ins (``rows``, those still stored) and its runs of activity (``runs``, which also stand for the
    sign-ins no longer stored) - every device, managed or not, a phone like a computer; not a service acting for the
    account, nor a virtual desktop (where it runs is not where anybody is). A device's sign-ins at one place without a
    silence of more than STAY_GAP are one stay. None where everything was at one place: then there is no movement."""
    from .mapview import data as where
    from .plugins.signin_threats.rules import RuleContext

    day = (now.astimezone() - timedelta(days=MOVES_DAYS - 1)).date()
    since = datetime(day.year, day.month, day.day).astimezone()
    rc = RuleContext.build([], history, settings, now, accounts=accounts)
    offices, extra = where.Places(rc), rc.assessor.extra_asns
    known: dict[str, Place] = {}

    def place_of(s: SignIn) -> str:
        if rc.trusted(s):   # an office by its name
            key = offices.key(s)
            label = short = str(offices.items[key]["label"])
        elif s.city or s.country:
            key, label, short = f"city:{s.city}|{s.country}", ", ".join(p for p in (s.city, s.country) if p), s.city or s.country
        else:
            return ""
        known.setdefault(key, Place(key, label, short))
        return key

    def network(s: SignIn) -> str:
        if rc.trusted(s):
            return "office network"
        info = netintel.asn_info(s.asn, extra)
        return f"{info[0]} ({info[1]})" if info else str(asn_name(s.asn) or (f"AS{s.asn}" if s.asn else ""))

    def mine(items: Iterable[SignIn]) -> list[SignIn]:
        return rc.keep(s for s in items if s.success and since <= s.created <= now and presence.device_class(s) != presence.SERVICE
                       and not rc.on_virtual_host(s))

    signins = mine(rows)
    recent = [r for r in runs if r[2] >= since and r[1] <= now]
    lanes: dict[str, dict] = {}
    for s in sorted(signins + mine(where.points_of(recent, since, now)), key=lambda s: s.created):
        place = place_of(s)
        if not place:
            continue
        key = _lane_key(s)
        lane = lanes.setdefault(key, dict(n=0, runs=[], newest=s))
        lane["n"] += 1
        if not s.id.startswith("activity:") or lane["newest"].id.startswith("activity:"):
            lane["newest"] = s   # (what a device is called and how it is managed: from its newest sign-in - a run's copies are its first one)
        stays, net = lane["runs"], network(s)
        if stays and stays[-1]["place"] == place and s.created - stays[-1]["end"] <= STAY_GAP:
            stays[-1]["end"] = s.created
        else:
            stays.append(dict(place=place, begin=s.created, end=s.created, nets=[]))
        if net and net not in stays[-1]["nets"]:
            stays[-1]["nets"].append(net)
    if len(known) < 2:
        return None
    built = []
    for key, lane in lanes.items():
        name, kind, rank = _lane_words(key, lane["newest"])
        stays = tuple(Run(x["place"], x["begin"], x["end"], ", ".join(x["nets"][:3])) for x in lane["runs"])
        built.append((rank, -lane["n"], name.lower(), Lane(key, name, kind, stays)))
    ordered = [lane for *_order, lane in sorted(built, key=lambda b: b[:3])]
    spent: Counter = Counter()
    for lane in ordered:
        for run in lane.runs:
            spent[run.place] += max((run.end - run.begin).total_seconds(), 60.0)
    places = sorted(known.values(), key=lambda p: (-spent[p.key], p.label))
    return Movement(since, now, ordered, places)


def signin_list(text: str, history: Any, accounts: Any, now: datetime, limit: int = 3000, days: int = DAYS) -> list[Line]:
    """The sign-ins a search found, as timeline lines (newest first): each prompted sign-in, failed attempts as one line
    per kind and day, each with its account. At most the newest ``limit`` records are read."""
    text = " ".join(str(text or "").replace("\x00", " ").split())
    if len(text) < MIN_LENGTH:
        return []
    one = history.get(text) or history.get(text.lower())
    if one is not None:
        rows = [one]
    else:
        rows = [SignIn.from_json(r[0]) for r in history.conn.execute(
            "SELECT data FROM signins WHERE ts>=? AND data LIKE ? ESCAPE '\\' ORDER BY ts DESC LIMIT ?",
            ((now - timedelta(days=days)).timestamp(), _like(text), limit))]
    rows.sort(key=lambda s: s.created)

    def name_of(user_id: str) -> str:
        info = accounts.get(user_id)
        return (info.display_name or info.upn) if info else ""

    succeeded = [s for s in rows if s.success]
    failed = _failed(rows, history)
    return sorted(_signin_lines(succeeded, failed, [], name_of), key=lambda ln: ln.when, reverse=True)


def names_it(alert: Any, value: str) -> bool:
    """Does the alert name this value - an address, an id, a name - as a whole? '10.0.0.1' is not named by an alert
    about 110.0.0.12 or 10.0.0.12, a network number not by a risk score that happens to contain it: the value must
    stand by itself, not inside a longer word, number or address. (A full stop after it ends a sentence.)"""
    value = str(value or "").strip().lower()
    if len(value) < 3:
        return False
    text = " ".join([alert.title, alert.summary, " ".join(map(str, alert.subjects)), " ".join(map(str, (alert.fields or {}).values()))]).lower()
    return re.search(r"(?<![\w.:\-])" + re.escape(value) + r"(?![\w:\-])(?!\.\w)", text) is not None


def covers(line: Line, worth: Worth) -> bool:
    """Does this timeline line show one of the sign-ins a "Worth a look" entry counts? A line can stand for many:
    a day's failed attempts (it knows them by id), or a run of sign-ins from one address (it knows when and where)."""
    if line.ids & set(worth.ids):
        return True
    return line.begin is not None and any(line.begin <= when <= line.when and ip == line.ip for when, ip in worth.points)


POLICY = {"success": "all policies passed", "failure": "blocked by a policy", "notapplied": "no policy applied"}
TOKEN = {"unbound": "the token is not bound to a device", "bound": "the token is bound to the device"}


def unfold(history: Any, line: Line) -> list[tuple[str, str]]:
    """The three short rows a timeline line opens into: how it was authenticated, with what, and its session."""
    if not line.ref or line.ref[0] != "signin":
        return []
    s = line.record or history.get(line.ref[1])   # (a run of background sign-ins keeps its first one itself)
    if s is None:
        return []
    methods = [m for m in s.auth_methods if m and m.lower() != "previously satisfied"]
    how = " · ".join(p for p in (", then ".join(methods) or _how(s), POLICY.get((s.ca_status or "").lower(), "")) if p)
    with_what = " · ".join(p for p in (s.browser or s.os, s.client_app, TOKEN.get((s.token_protection or "").lower(), "")) if p)
    out = [("How", how), ("With", with_what)]
    if s.session_id or s.correlation_id:
        together = len(history.query(session_id=s.session_id)) if s.session_id else 0
        out.append(("Session", " · ".join(p for p in (
            _plural(together, "sign-in") + " in this session" if together else "",
            f"session {s.session_id}" if s.session_id else "", f"correlation ID {s.correlation_id}" if s.correlation_id else "") if p)))
    return [(k, v) for k, v in out if v]


# ============================================== a device, an address, a network, a country, an application
THINGS = {  # kind -> (the sign-ins that are its own, the runs of activity that are, the title of its "Seen with")
    "device": ("device_id=?", "device=?"),
    "address": ("ip=?", "ip=?"),
    "network": ("asn=?", "json_extract(data, '$.asn')=?"),
    "country": ("country=?", "json_extract(data, '$.country')=?"),
    "application": ("json_extract(data, '$.app')=?", "json_extract(data, '$.app')=?"),
}
SEEN_WITH = {  # what each page counts beside itself, in this order
    "device": ("Accounts", "Networks", "Countries", "Applications"),
    "address": ("Accounts", "Devices", "Applications", "Results"),
    "network": ("Accounts", "Addresses", "Countries", "Results"),
    "country": ("Accounts", "Networks", "Devices", "Applications"),
    "application": ("Accounts", "Networks", "Countries", "Results"),
}
APP_FIELDS = ("Application", "App", "Applications", "Resource", "Targeted apps")   # where an alert names applications
GUESSED_WITHIN = timedelta(minutes=30)   # a success this soon after wrong passwords: the guessing may have worked


def thing_view(kind: str, key: str, history: Any, accounts: Any, alerts: Sequence[Any], incidents: Sequence[Any], now: datetime,
               names: dict | None = None, days: int = DAYS) -> AccountView:
    """Everything stored about a device (its id), an IP address, a network (its number), a country (its code) or an
    application (its name) - built like the page about an account: what it is, what is open, what it is seen with,
    what stands out, and the timeline (where each line says whose sign-in it is)."""
    key = str(key)
    own, own_runs = THINGS[kind]
    arg: Any = int(key) if kind == "network" and key.isdigit() else key
    start = now - timedelta(days=days)
    conn = history.conn
    rows = [SignIn.from_json(r[0]) for r in conn.execute(f"SELECT data FROM signins WHERE ts>=? AND {own} ORDER BY ts", (start.timestamp(), arg))]
    runs = [(SignIn.from_json(data), datetime.fromtimestamp(first, timezone.utc), datetime.fromtimestamp(last, timezone.utc), n)
            for data, first, last, n in conn.execute(
                f"SELECT data, first_ts, last_ts, n FROM activity WHERE last_ts>=? AND {own_runs} ORDER BY first_ts", (start.timestamp(), arg))]

    def network_name(number: Any) -> str:
        return str(((names or {}).get(str(number)) or {}).get("n") or f"AS{number}")

    def name_of(user_id: str) -> str:
        info = accounts.get(user_id)
        return (info.display_name or info.upn) if info else ""

    # An application is one of many a device signs in to: the runs of activity know a run's first application only.
    # Who uses it, and how often, the per-account profile knows; its own sign-ins are those still stored one by one.
    usage: list[tuple[str, float, int]] = []
    if kind == "application":
        usage = conn.execute("SELECT user_id, first_ts, n FROM profile WHERE kind='app' AND value=? ORDER BY n DESC", (key,)).fetchall()
        runs = []
    newest = max(rows + [r[0] for r in runs], key=lambda s: s.created, default=None)
    title = {"device": (newest.device_name if newest else "") or key, "network": network_name(key), "country": geo.country_name(key)}.get(kind, key)
    view = AccountView(key, title, kind=kind, key=key, habits_title="Seen with")
    if newest is None:
        return view
    first_seen = min([s.created for s in rows] + [r[1] for r in runs])
    last_seen = max([s.created for s in rows] + [r[2] for r in runs])
    succeeded = sum(n for _u, _f, n in usage) if kind == "application" else sum(n for _f, _b, _e, n in runs)
    samples = [(s, s.created, 1) for s in rows if s.success] if kind == "application" else [(r[0], r[1], r[3]) for r in runs]
    failed = _failed(rows, history)
    users = {s.user_id for s in rows if s.user_id} | {r[0].user_id for r in runs} | {u for u, _f, _n in usage}

    # ---- what it is
    if kind == "device":
        view.upn = " · ".join(p for p in (newest.os, newest.trust_type) if p)
        view.tags = [("Compliant" if newest.compliant else "Not compliant", not newest.compliant), ("Managed" if newest.managed else "Not managed", False)]
    elif kind == "address":
        view.upn = " · ".join(p for p in (_place(newest), network_name(newest.asn) if newest.asn else "") if p)
    elif kind == "network":
        view.upn = " · ".join(p for p in (f"AS{key}", ", ".join(sorted({s.country for s in rows if s.country} | {r[0].country for r in runs if r[0].country}))) if p)
    elif kind == "country":
        view.upn = ", ".join(c for c, _n in Counter(s.city for s in rows if s.city).most_common(3))
    if kind in ("address", "network"):
        known = netintel.asn_info(int(key) if kind == "network" and key.isdigit() else newest.asn)
        if known:
            view.tags.append((NETWORK_KINDS.get(known[1], known[1].capitalize()), True))
    if kind == "application":
        own = (newest.app_owner_tenant or "") in netintel.MICROSOFT_TENANTS
        view.tags = [("Microsoft application" if own else "Not a Microsoft application", False),
                     ("People sign in to it" if (newest.client_credential or "none").lower() == "none" else "Signs in on its own", False)]
    if now - first_seen < NEW_WITHIN:
        view.tags.append(("First seen today", True))
    view.facts = [Fact("Accounts", f"{len(users):,}"), Fact("Sign-ins", f"{succeeded + len(failed):,} · {len(failed):,} failed", bool(failed) and not succeeded),
                  Fact("First seen", timefmt.stamp(first_seen)), Fact("Last seen", timefmt.stamp(last_seen))]
    if kind == "device":
        view.facts += [Fact("Operating system", newest.os or "Not known"), Fact("Browser", newest.browser or "Not known"), Fact("Device ID", key)]
    elif kind == "address":
        view.facts += [Fact("Network", network_name(newest.asn) if newest.asn else "Not known"), Fact("Country", newest.country or "Not known")]
    elif kind == "network":
        view.facts.append(Fact("Addresses", f"{len({s.ip for s in rows} | {r[0].ip for r in runs}):,}"))
    elif kind == "country":
        view.facts.append(Fact("Networks", f"{len({s.asn for s in rows if s.asn} | {r[0].asn for r in runs if r[0].asn}):,}"))

    # ---- what is open: the alerts that name it - as a whole value, never as a part of another one (see names_it)
    needles = {"network": {f"AS{key}", title}, "country": set()}.get(kind, {key, title})
    about = [a for a in alerts if any(names_it(a, n) for n in needles)]
    if kind == "network":  # an alert about one of the network's addresses is about the network
        mine = {s.ip for s in rows} | {r[0].ip for r in runs}
        about += [a for a in alerts if a not in about and mine & set(_ADDRESSES.findall(_text_of(a)))]
    if kind == "application":  # one application's name often begins another's: here only what an alert says it is about counts
        def about_app(a: Any) -> bool:
            named = {str(x).lower() for x in a.subjects}
            for field_name in APP_FIELDS:
                named |= {"app:" + part.strip().lower() for part in re.split("[,;\\n]", str((a.fields or {}).get(field_name, "")))}
            return "app:" + key.lower() in named

        about = [a for a in alerts if about_app(a)]
    view.open_alerts = sorted((a for a in about if a.status in OPEN), key=lambda a: (-int(a.severity), -a.score))
    view.earlier_alerts = len(about) - len(view.open_alerts)
    view.incidents = [i for i in incidents if getattr(i, "open", False) and any(a in view.open_alerts for a in i.alerts)]
    view.risk, view.risk_level = _risk(view.open_alerts)
    view.per_day = _per_day([(begin, n) for _r, begin, n in samples], now, days)

    # ---- seen with: counted over the runs of activity (every successful sign-in is in one), new where first seen today
    def counted(label: str, value: Any, ref: str | None, name: Any = str) -> Kind:
        tally: Counter = Counter()
        first: dict[Any, datetime] = {}
        for record, begin, n in samples:
            v = value(record)
            if v not in ("", None):
                tally[v] += n
                first[v] = min(first.get(v, begin), begin)
        return Kind(label, [Entry(name(v) or str(v), n, now - first[v] < NEW_WITHIN and len(tally) > 1, (ref, str(v)) if ref else None)
                            for v, n in tally.most_common(6)])

    results = Counter("Wrong password" if s.error_code in WRONG_PASSWORD else "Locked out" if s.error_code in LOCKED_OUT else
                      "Stopped at MFA" if s.error_code in MFA_ASKED else
                      "Blocked by a policy" if (s.ca_status or "").lower() == "failure" else "Other failure" for s in failed)
    all_kinds = {
        "Accounts": counted("Accounts", lambda r: r.user_id, "account", name_of),
        "Devices": counted("Devices", lambda r: r.device_id, "device", lambda v: next((r[0].device_name for r in runs if r[0].device_id == v), "")),
        "Networks": counted("Networks", lambda r: r.asn, "network", network_name),
        "Countries": counted("Countries", lambda r: r.country, "country", geo.country_name),
        "Addresses": counted("Addresses", lambda r: r.ip, "address"),
        "Applications": counted("Applications", lambda r: r.app, "application"),
        "Results": Kind("Results", [Entry("Success", succeeded)] * bool(succeeded) + [Entry(k, n) for k, n in results.most_common()]),
    }
    if kind == "application":
        fresh = (now - NEW_WITHIN).timestamp()
        all_kinds["Accounts"] = Kind("Accounts", [Entry(name_of(u) or u, n, first >= fresh and len(usage) > 1, ("account", u)) for u, first, n in usage[:6]])
    view.habits = [all_kinds[label] for label in SEEN_WITH[kind] if all_kinds[label].entries]

    # ---- worth a look
    def worth(label: str, picked: list[SignIn], detail: str = "") -> None:
        if picked:
            latest = max(picked, key=lambda s: s.created)
            view.worth.append(Worth(label, detail or f"{name_of(latest.user_id) or latest.upn} · {timefmt.stamp(latest.created)}", len(picked),
                                    [s.id for s in picked], [(s.created, s.ip) for s in picked]))

    prompted = [s for s in rows if s.success and s.interactive and (s.incoming_token or "").lower() != DEVICE_TOKEN]
    guesses = [s for s in failed if s.error_code in WRONG_PASSWORD | LOCKED_OUT]
    won = [s for s in prompted if any(g.user_id == s.user_id and timedelta(0) <= s.created - g.created <= GUESSED_WITHIN for g in guesses)]
    worth("Wrong password, then a success", won)
    worth("Stopped at the MFA prompt, nothing followed", [s for s in failed if s.error_code in MFA_ASKED])
    only_failed = {s.user_id for s in failed} - {s.user_id for s in rows if s.success} - {r[0].user_id for r in runs} - {u for u, _f, _n in usage}
    if kind in ("address", "network", "country"):  # (from a place this is guessing; for a device or an application it says little)
        worth("Only failed sign-ins for an account", [s for s in failed if s.user_id in only_failed], _plural(len(only_failed), "account"))
    worth("Entra saw risk on a sign-in", [s for s in rows if (s.risk_during or "none").lower() not in ("none", "", "hidden")])
    worth("Blocked by a policy", [s for s in rows if (s.ca_status or "").lower() == "failure"])
    worth("Device code sign-in", [s for s in rows if "device code" in marks_of(s)])
    worth("Old protocol", [s for s in rows if "old protocol" in marks_of(s)])
    worth("Token not bound to a device", [s for s in prompted if (s.token_protection or "").lower() == "unbound"])
    worth("Sign-ins without a device", [s for s in prompted if not s.device_id] if kind in ("address", "network", "country") else [])

    # ---- the timeline: every line says whose sign-in it is
    lines = _signin_lines(prompted, failed, runs, name_of)
    for a in about:
        when = a.occurred_at or a.last_seen
        if when is not None and when >= start:
            lines.append(_alert_line(a, when))
    view.timeline = sorted(lines, key=lambda ln: (ln.when, ln.kind == "Alert"), reverse=True)
    view.counts = {"Sign-in": succeeded, "Failed": len(failed), "Alert": sum(1 for ln in lines if ln.kind == "Alert")}
    return view
