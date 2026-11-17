"""Every clock time RADAR shows says its time zone.

Three guards:
* the formatter itself (radar.timefmt);
* the source: no clock time is formatted anywhere but through that formatter (so a new rule or window cannot
  forget the zone), and the live map's page has one function that writes a time, which names the zone;
* the screen: every window is opened with example data and everything it shows is read back - no clock time
  without a zone anywhere.
"""
import ast
import pathlib
import re
import time
from datetime import datetime, timedelta, timezone

import pytest
from test_main_window import app, settle  # noqa: F401  (a real App on an empty data folder)
from test_ui import root  # noqa: F401  (the Tk fixture)

from radar import timefmt

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "radar"
ZONED_BY = {"stamp", "local_time", "strptime"}   # calls a format with a clock time may be handed to
MARK = "# not a shown time"                      # a format for a file name or for Microsoft Graph says so on its line


def test_a_time_is_written_with_its_zone_and_summer_time_is_told_apart():
    utc = datetime(2026, 11, 16, 6, 50, 24, tzinfo=timezone.utc)
    assert timefmt.zone(utc) == "UTC"
    assert timefmt.zone(utc.astimezone(timezone(timedelta(hours=1)))) == "UTC+1"
    assert timefmt.zone(utc.astimezone(timezone(timedelta(hours=-3, minutes=-30)))) == "UTC-3:30"
    assert timefmt.zone(utc.astimezone(timezone(timedelta(hours=5, minutes=45)))) == "UTC+5:45"
    local = utc.astimezone()
    assert timefmt.stamp(utc) == f"{local:%d.%m. %H:%M} {timefmt.zone(local)}"
    assert timefmt.clock(utc) == f"{local:%H:%M} {timefmt.zone(local)}"
    assert timefmt.sortable(utc, seconds=True) == f"{local:%Y-%m-%d %H:%M:%S} {timefmt.zone(local)}"
    assert timefmt.stamp(None) == ""
    for text in (timefmt.stamp(utc), timefmt.clock(utc), timefmt.stamp_year(utc), timefmt.sortable(utc)):
        assert timefmt.unzoned(text) == []
    winter, summer = datetime(2026, 1, 15, 12, 0).astimezone(), datetime(2026, 7, 15, 12, 0).astimezone()
    if winter.utcoffset() != summer.utcoffset():   # where the clocks change: each time has the zone of its day
        assert timefmt.stamp(winter)[-6:] != timefmt.stamp(summer)[-6:]


def test_times_without_a_zone_are_found_and_older_texts_get_theirs():
    assert timefmt.unzoned("From 06.11. 15:53 - 16.11. 12:27") == ["06.11. 15:53", "16.11. 12:27"]
    assert timefmt.unzoned("at 2026-11-16 07:50:24 and 14:02, 09.11.2026 11:00") == ["2026-11-16 07:50:24", "14:02", "09.11.2026 11:00"]
    assert timefmt.unzoned("at 07:50 UTC+1, 07:50Z, 2026-11-16 07:50 UTC-3:30, 16.11. 07:50 UTC") == []
    # what only looks like a time: addresses, versions, counts
    assert timefmt.unzoned("2409:8924:9a11:172c:b0bc:29bd:94f:d41f fe80::12:34 10.0.26100.1 error 50126 3 of 4 1:5") == []
    assert timefmt.unzoned("2a02:1210:1402:ab00:15b2:d166:7ef1:3de4 and 2602:fad4:22:60a0:ccc9:bd9f:6f10:37b1") == []
    assert timefmt.unzoned("MFA at 14:02: Lyon, FR") == ["14:02"]            # (a colon after it does not hide a time)
    july = datetime(2026, 7, 1, 10, 0).astimezone()
    assert timefmt.zoned_text("seen 2026-07-01 10:00") == f"seen 2026-07-01 10:00 {timefmt.zone(july)}"   # the zone of THAT day
    once = timefmt.zoned_text("From 06.11. 15:53 - 16.11. 12:27, MFA at 14:02")
    assert timefmt.unzoned(once) == [] and timefmt.zoned_text(once) == once                                # and only once


def _clock_formats(tree):
    """(line, how it is used) of every format with a clock time in a module."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str) and "%H" in node.value):
            continue
        up, inside_spec = node, False
        while up in parents and not isinstance(up, ast.Call):
            inside_spec = inside_spec or isinstance(parents[up], ast.FormattedValue) and parents[up].format_spec is up
            up = parents[up]
        name = ""
        if isinstance(up, ast.Call) and not inside_spec:
            name = getattr(up.func, "attr", getattr(up.func, "id", ""))
        yield node.lineno, name


def test_no_clock_time_is_formatted_anywhere_but_through_the_formatter():
    found = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "timefmt.py":
            continue
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        for line, used_by in _clock_formats(ast.parse(source)):
            if used_by in ZONED_BY or MARK in lines[line - 1]:
                continue
            found.append(f"{path.relative_to(SRC.parent.parent)}:{line}: {lines[line - 1].strip()[:110]}")
    assert not found, "a clock time formatted without radar.timefmt (it would lack its zone):\n" + "\n".join(found)


def test_the_live_map_writes_times_in_one_place_that_names_the_zone():
    page = (SRC / "mapview" / "static" / "index.html").read_text(encoding="utf-8")
    assert page.count("getHours()") == 0                    # no clock time put together by hand
    assert page.count('hour: "2-digit"') == 1               # ... one place formats one,
    start = page.index("function clockWithZone(")
    assert 'hour: "2-digit"' in page[start:page.index("\n  }\n", start)]   # the function that adds the zone
    assert "function zoneLabel(" in page and "UTC" in page[page.index("function zoneLabel("):][:900]


# ------------------------------------------------------------------ the screen
def _shown(widget):
    """Everything a window shows as text: labels, buttons, text boxes, what is drawn on canvases, table cells."""
    import tkinter as tk

    from radar.ui.cardtable import CardTable

    out = []
    try:
        if isinstance(widget, (tk.Toplevel, tk.Tk)):
            out.append(widget.title())
        if isinstance(widget, CardTable):
            for column in widget.columns:
                out.append(str(widget.heading(column, "text")))
                for iid in widget.get_children(""):
                    out.append(widget.shown_text(iid, column))
                    if column in widget._notes:
                        out.append(widget._notes[column](iid))
        elif isinstance(widget, tk.Text):
            out.append(widget.get("1.0", "end"))
        elif isinstance(widget, tk.Canvas):
            out += [widget.itemcget(item, "text") for item in widget.find_all() if widget.type(item) == "text"]
        else:
            try:
                out.append(str(widget.cget("text")))
            except tk.TclError:
                pass
            try:
                out.append(str(widget.get())) if widget.winfo_class() in ("TCombobox", "TEntry", "Entry") else None
            except tk.TclError:
                pass
    except tk.TclError:
        return out
    for child in widget.winfo_children():
        out += _shown(child)
    return out


def _unzoned(widget):
    return sorted({t for text in _shown(widget) for t in timefmt.unzoned(text)})


def _example_alerts():
    """Alerts with times in every place a rule or the store writes one: evidence rows, fields, reasons, responses."""
    import test_incidents as ti

    from radar.__main__ import _demo_findings
    from radar.plugin_api import Finding, Severity

    now = datetime.now(timezone.utc)
    stamp = timefmt.stamp(now - timedelta(hours=3))
    rows = [{"Time": timefmt.sortable(now - timedelta(hours=h), seconds=True), "User": ti.ANNA, "Application": "Office 365",
             "IP address": "203.0.113.77", "Location": "Lyon, FR", "Result": "Success",
             "_created": (now - timedelta(hours=h)).isoformat()} for h in (3, 2)]

    def alert(key, rule, score, days, user=ti.ANNA, **fields):
        f = ti.alert(key, rule, score, days, user=user, **fields)
        f.occurred_at = now - timedelta(days=days)
        f.evidence = rows
        f.factors = [(score, f"The person reported an MFA prompt as not theirs ({stamp}): the password is known")]
        f.summary = f"Seen at {timefmt.clock(now)}; MFA at {timefmt.clock(now - timedelta(hours=1))} from Lyon, FR."
        f.fields = {**f.fields, "Changes": f"{stamp} User registered Passkey", "Data as of": timefmt.sortable(now)}
        return f

    findings = [alert("a1", "password_not_completed", 75, 3, **ti.ADDRESS), alert("b1", "mfa_change", 40, 2, user=ti.BEA, **ti.ADDRESS),
                alert("c1", "new_country", 45, 2, user=ti.CARL), alert("c2", "legacy_auth", 30, 1, user=ti.CARL),
                alert("lone", "risky_signin", 80, 0.2, user="dora@contoso.com")]
    revoked = Finding(key="rev", rule_id="session_revocations", severity=Severity.INFO, score=0, title=f"Sessions revoked: {ti.CARL}",
                      occurred_at=now - timedelta(hours=1), fields={"Account": ti.CARL, "Initiated by": "admin@contoso.com"},
                      signal="sessions_revoked")
    return findings + _demo_findings(), [revoked]


def test_no_window_shows_a_clock_time_without_its_zone(app, root):  # noqa: F811
    from radar import chains, incidents
    from radar.ui import freshness
    from radar.ui.main import SECTIONS, SETTINGS_PAGES
    from radar.ui.reminder import ReminderWindow

    findings, signals = _example_alerts()
    app.reminders = ReminderWindow(root, app)
    app.alerts.ingest("signin_threats", findings)
    app.alerts.ingest("directory_audit", signals)
    app._update_chains()
    app.last_scan = datetime.now(timezone.utc)
    problems = {}

    def look(name, widget):
        settle(root, 6)
        missing = _unzoned(widget)
        if missing:
            problems[name] = missing

    try:
        win = app._open_main()
        for key, _label, _icon in SECTIONS:
            if key == "map":
                continue
            win.show(key)
            settle(root, 20)
            look(f"page {key}", win.top)
        win.page("incidents").show_filter("all")
        look("page incidents, all", win.top)
        for key, _label in SETTINGS_PAGES:
            win.show("settings", key)
            look(f"settings {key}", win.top)
        win.refresh()
        look("navigation and status", win.top)
        # the reminders: every row selected once, so that the header has shown each of them
        app.reminders.refresh()
        for row in app.reminders.tree.get_children():
            app.reminders.tree.selection_set(row)
            app.reminders._update_header()
            look(f"reminders, {row}", app.reminders.top)
        # the details of every alert (also the dismissed and logged ones), with every evidence row shown below it
        for alert in app.alerts.recent():
            app.reminders.open_details(alert)
            details = app.reminders._details[alert.id]
            look(f"details of {alert.rule_id}", details.top)
            if details.tree is not None:
                for iid in details.tree.get_children(""):
                    details.tree.selection_set(iid)
                    details._show_row()
                    look(f"details of {alert.rule_id}, row", details.top)
            details.top.destroy()
        # every incident in its own window, with every alert of it selected once
        now = datetime.now(timezone.utc)
        for inc in incidents.group(app.alerts.since(now - timedelta(days=31)), now):
            assert app.open_incident(inc.id)
            window = app._incident_windows[inc.id]
            for iid in window.steps.get_children(""):
                window.steps.selection_set(iid)
                window._step_selected()
                look(f"incident {inc.title[:30]}", window.top)
            window.top.destroy()
        # the age of live data, for today's data and for older
        for as_of in (now, now - timedelta(days=3)):
            assert timefmt.unzoned(freshness.stamp(as_of)) == [] and timefmt.unzoned(freshness.describe(as_of, False)) == []
        assert any(a.plugin_id == chains.CHAIN_PLUGIN for a in app.alerts.recent())      # (a chain was among them)
    finally:
        app.reminders.top.destroy()
    assert not problems, "clock times shown without their zone:\n" + "\n".join(f"  {k}: {v}" for k, v in problems.items())


def test_times_in_tables_keep_their_zone_and_older_rows_get_one(root):  # noqa: F811
    from radar.ui.cardtable import friendly_time

    now = datetime(2026, 11, 16, 12, 0)
    assert friendly_time("2026-11-16 09:47 UTC+1", now) == "Today 09:47 UTC+1"
    assert friendly_time("2026-11-15 17:28 UTC-3:30", now) == "Yesterday 17:28 UTC-3:30"
    assert friendly_time("2026-11-10 17:28 UTC", now) == "10.11. 17:28 UTC"
    assert friendly_time("2025-11-10 17:28 UTC+1", now) == "10.11.2025 17:28 UTC+1"
    old = friendly_time("2026-11-10 17:28", now)                       # written before the zone was named
    assert old.startswith("10.11. 17:28 UTC") and timefmt.unzoned(old) == []
    assert friendly_time("not a time", now) == "not a time"


def test_alerts_stored_before_the_zone_was_named_get_it_once():
    from radar.alerts import AlertCenter
    from radar.plugin_api import Finding, Severity
    from radar.store import Store

    ac = AlertCenter(Store(":memory:"))
    old = Finding(key="old", rule_id="mfa_change", severity=Severity.LOW, score=30, title="MFA method registered for anna@contoso.com",
                  summary="Change made at 14:42 from 2409:8924:9a11:172c:b0bc:29bd:94f:d41f.",
                  fields={"User": "anna@contoso.com", "Changes": "16.11. 14:42 User registered Passkey", "From / to": "06.11. 15:53 - 16.11. 12:27"},
                  factors=[(30, "Response: sessions revoked 09.11.2026 11:00 by admin - sign-ins from before no longer work")],
                  evidence=[{"Time": "2026-11-16 07:50:24", "User": "anna@contoso.com", "User agent": "Mozilla/5.0 Chrome/130.0.0.0"}])
    new = Finding(key="new", rule_id="mfa_change", severity=Severity.LOW, score=30, title="t", summary=f"Seen {timefmt.clock(datetime.now(timezone.utc))}")
    ac.ingest("signin_threats", [old, new])
    assert ac.name_zones() == 1                                        # the old one; the new one already names its zone
    a = next(x for x in ac.recent() if x.key == "old")
    texts = [a.summary, *a.fields.values(), *(t for _p, t in a.factors), *(r["Time"] for r in a.evidence)]
    assert all(timefmt.unzoned(t) == [] for t in texts), texts
    assert a.evidence[0]["Time"].startswith("2026-11-16 07:50:24 UTC") and a.evidence[0]["User agent"] == "Mozilla/5.0 Chrome/130.0.0.0"
    assert "2409:8924:9a11:172c:b0bc:29bd:94f:d41f" in a.summary        # an address is no time
    assert ac.name_zones() == 0                                        # nothing left to do


def test_a_shortened_text_never_ends_in_a_time_without_its_zone():
    e = timefmt.ELLIPSIS
    assert timefmt.keep_whole("last 09.11. 12:56 UT" + e) == "last" + e          # cut inside the zone: the time goes
    assert timefmt.keep_whole("last 09.11. 12:56" + e) == "last" + e             # cut before the zone
    assert timefmt.keep_whole("last 09.11. 12:56 UTC+1 and mo" + e) == "last 09.11. 12:56 UTC+1 and mo" + e
    assert timefmt.keep_whole("no time he" + e) == "no time he" + e
    assert timefmt.keep_whole("last 09.11. 12:56 UTC+1") == "last 09.11. 12:56 UTC+1"   # not shortened: untouched
