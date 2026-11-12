"""Incidents: alerts about the same account or the same attacker address, within days, are one thing to handle."""
import tkinter as tk
from datetime import datetime, timedelta, timezone

import pytest

from radar import chains, incidents
from radar.alerts import ACTIVE, DISMISSED, AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store

NOW = datetime.now(timezone.utc)
ANNA, BEA, CARL = "anna@contoso.com", "bea@contoso.com", "carl@contoso.com"
ADDRESS = {chains.ATTACKER_ADDRESS_FIELD: "203.0.113.77 - a stolen session (anna@contoso.com, 08.11. 10:00)"}


def alert(key, rule, score, days_ago, user=ANNA, signal="", **fields):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule}: {user}", signal=signal,
                   occurred_at=NOW - timedelta(days=days_ago), fields={"User": user, **fields})


def center(*findings, chain=True):
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", list(findings))
    if chain:
        recent = ac.since(NOW - timedelta(days=31))
        ac.ingest(chains.CHAIN_PLUGIN, chains.chain_findings(recent, NOW) + chains.spread_findings(recent, NOW))
    return ac


def grouped(ac):
    return incidents.group(ac.since(NOW - timedelta(days=31)), NOW)


def test_alerts_about_one_account_within_days_are_one_incident_named_after_its_chain():
    ac = center(alert("pw", "password_not_completed", 60, 3), alert("mfa", "mfa_change", 40, 2),
                alert("role", "role_assignment", 55, 1), alert("other", "new_country", 45, 2, user=CARL))
    found = grouped(ac)
    assert len(found) == 1                      # Carl's single alert is no incident
    inc = found[0]
    assert inc.accounts == [ANNA] and inc.own == 3 and inc.open and inc.severity == Severity.HIGH
    assert inc.title.startswith("Possible attack chain: anna@contoso.com") and inc.stage_name == "Escalation"
    assert [a.rule_id for a in inc.alerts][:3] == ["password_not_completed", "mfa_change", "role_assignment"]


def test_a_shared_attacker_address_joins_accounts_and_time_separates_stories():
    ac = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                alert("old1", "new_country", 45, 25), alert("old2", "legacy_auth", 30, 24),   # Anna, three weeks earlier
                alert("c1", "new_country", 45, 2, user=CARL))
    found = grouped(ac)
    assert len(found) == 2
    now_, earlier = found
    assert now_.accounts == [ANNA, BEA] and now_.addresses == ["203.0.113.77"] and now_.own == 2
    assert now_.title.startswith("Attack across 2 accounts")           # the cross-account chain names it
    assert earlier.accounts == [ANNA] and earlier.own == 2 and earlier.title == "2 alerts about anna@contoso.com"
    assert not any(a.key.endswith("c1") for i in found for a in i.alerts)


def test_responses_join_the_incident_and_dismissed_incidents_are_closed():
    ac = center(alert("pw", "password_not_completed", 60, 3), alert("mfa", "mfa_change", 40, 2),
                alert("rev", "session_revocations", 0, 1, signal="sessions_revoked"), chain=False)
    inc = grouped(ac)[0]
    assert inc.own == 2 and len(inc.alerts) == 3 and inc.responses == ["session_revocations"]
    ac.dismiss([a.id for a in inc.open_alerts])
    closed = grouped(ac)[0]
    assert not closed.open and closed.open_alerts == [] and closed.severity == Severity.MEDIUM
    assert closed.state == "closed - all dismissed" and closed.state_text.startswith("Closed: all 2 alerts were dismissed, the last on ")
    assert inc.state == "open - 2 of 2" and inc.state_text == "Open: 2 of its 2 alerts are still reminders."
    # open incidents come first
    ac.ingest("signin_threats", [alert("x1", "new_country", 45, 1, user=CARL), alert("x2", "legacy_auth", 30, 0.5, user=CARL)])
    assert [i.open for i in grouped(ac)] == [True, False]
    # findings that were only logged (an admin's routine work) never make an incident, however many there are -
    # but one that falls into an incident's time is shown with it as context
    ac.ingest("signin_threats", [alert(f"log{i}", "consent_grant", 10, 6 - i, user="admin@contoso.com") for i in range(5)]
              + [alert("logctx", "device_registration", 10, 2.5)])
    found = grouped(ac)
    assert len(found) == 2 and not any("admin@contoso.com" in i.accounts for i in found)
    anna = next(i for i in found if ANNA in i.accounts)
    assert anna.own == 2 and "device_registration" in [x.rule_id for x in anna.alerts]
    # reminders about the app itself are never part of an incident
    ac.ingest("system", [alert("h1", "health", 50, 1), alert("h2", "health", 50, 0.5)])
    assert len(grouped(ac)) == 2


@pytest.fixture(scope="module")
def root():
    from radar.ui import theme

    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - no desktop available
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    theme.init(r)
    yield r
    r.destroy()


def test_incident_window_shows_the_story_and_dismisses_it_as_one(root):
    from radar.ui.incidents import ABOUT_TEMPLATE, IncidentsWindow, about

    class App:
        def __init__(self):
            self.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                                 alert("c1", "new_country", 45, 2, user=CARL), alert("c2", "legacy_auth", 30, 1, user=CARL))
            self.opened, self.dismissed = [], 0

        def open_alert(self, a):
            self.opened.append(a.title)

        def on_alerts_dismissed(self):
            self.dismissed += 1

    app = App()
    win = IncidentsWindow(root, app)
    try:
        root.update()
        rows = [(win.tree.set(i, "Severity"), win.tree.set(i, "State"), win.tree.set(i, "Alerts"), win.tree.set(i, "Accounts"))
                for i in win.tree.get_children("")]
        assert rows == [("High", "open - 3 of 3", "2", "anna@contoso.com, bea@contoso.com"),
                        ("Medium", "open - 2 of 2", "2", "carl@contoso.com")]
        assert "2 incidents in the last 30 days: 2 open (with reminders left), 0 closed (all dismissed). Data as of" in win.summary.cget("text")
        # the first incident is selected: its alerts in order, the cross-account chain among them
        steps = [(win.steps.set(i, "Stage"), win.steps.set(i, "Account")) for i in win.steps.get_children("")]
        assert steps == [("2 Password known", ANNA), ("4 Persistence", BEA), ("chain", f"{ANNA}, {BEA}")]
        text = win.about.cget("text")
        assert text.startswith(f"Open: 3 of its 3 alerts are still reminders. · Accounts: {ANNA}, {BEA} · "
                               f"Attacker addresses: 203.0.113.77 · ") and len(text) < len(ABOUT_TEMPLATE)
        assert str(win.open_btn.cget("state")) == "disabled" and str(win.dismiss_btn.cget("state")) == "normal"
        win.steps.selection_set(win.steps.get_children("")[0])
        win._buttons()
        win.open_selected()
        assert app.opened == [f"password_not_completed: {ANNA}"]
        win.dismiss_incident()
        assert app.dismissed == 1 and "3 reminders of the incident dismissed" in win.hint.label.cget("text")
        states = {win.tree.set(i, "Accounts"): win.tree.set(i, "State") for i in win.tree.get_children("")}
        assert states == {"anna@contoso.com, bea@contoso.com": "closed - all dismissed", "carl@contoso.com": "open - 2 of 2"}
        win.tree.selection_set([i for i in win.tree.get_children("") if win.tree.set(i, "State").startswith("closed")])
        win._incident_selected()
        why = win.about.cget("text")   # the closed incident says why it is closed
        assert why.startswith("Closed: all 3 alerts were dismissed, the last on ") and "opens again by itself" in why
        assert str(win.dismiss_btn.cget("state")) == "disabled"
        assert {a.status for a in app.alerts.since(NOW - timedelta(days=31)) if BEA in a.subjects} == {DISMISSED}
        assert {a.status for a in app.alerts.since(NOW - timedelta(days=31)) if CARL in a.subjects} == {ACTIVE}
    finally:
        win.top.destroy()
    # the line on what holds an incident together fits its reserved space also when everything is long
    inc = incidents.Incident("k", [], [f"user{i}long@contoso.com" for i in range(9)], [f"203.0.113.{i}" for i in range(7)],
                             NOW, NOW, Severity.HIGH, True, 5, "t", 2, ["Sessions revoked", "Password reset", "Account disabled"])
    assert len(about(inc)) <= len(ABOUT_TEMPLATE)


def test_an_alert_says_in_its_details_which_incident_it_belongs_to_and_leads_there(root):
    from test_links import links_in
    from test_ui import FakeApp

    from radar.app import App
    from radar.linkify import Entity, actions
    from radar.ui.details import DetailsWindow
    from radar.ui.incidents import IncidentsWindow

    app = FakeApp()
    app.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                        alert("c1", "new_country", 45, 2, user=CARL))
    app.incident_of = lambda a: App.incident_of(app, a)
    by_key = {a.key: a for a in app.alerts.since(NOW - timedelta(days=31))}

    win = DetailsWindow(root, app, by_key["b1"], on_dismiss=lambda a: None)
    try:
        root.update()
        text = win.info.get("1.0", "end")
        assert "Part of an incident" in text and "Attack across 2 accounts" in text
        assert f"Open: 3 of its 3 alerts are still reminders. This alert and 2 others about {ANNA}, {BEA} belong together." in text
        linked = [(kind, label) for kind, label in links_in(win.info) if kind == "incident"]
        assert len(linked) == 1 and linked[0][1].startswith("Attack across 2 accounts")
        assert actions(Entity("incident", "x")) == [("Show this incident", "open_incident")]
    finally:
        win.top.destroy()
    alone = DetailsWindow(root, app, by_key["c1"], on_dismiss=lambda a: None)   # an alert on its own: no such card
    try:
        root.update()
        assert "Part of an incident" not in alone.info.get("1.0", "end")
    finally:
        alone.top.destroy()

    # the link opens the incident window on that incident
    incident = App.incident_of(app, by_key["b1"])
    assert incident is not None and App.incident_of(app, by_key["c1"]) is None
    inc_win = IncidentsWindow(root, app)
    try:
        other = [i for i in inc_win.tree.get_children("") if i != incident.id]
        assert inc_win.select(incident.id) and inc_win.tree.selection() == (incident.id,)
        assert not inc_win.select("gone") and "no longer there" in inc_win.hint.label.cget("text") and not other
    finally:
        inc_win.top.destroy()
