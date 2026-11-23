"""Incidents: alerts about the same account or the same attacker address, within days, are one thing to handle."""
import tkinter as tk
from datetime import datetime, timedelta, timezone

import pytest

from radar import chains, incidents
from radar.alerts import ACTIVE, DISMISSED, AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store
from radar.ui import theme

NOW = datetime.now(timezone.utc)
ANNA, BEA, CARL = "anna@contoso.com", "bea@contoso.com", "carl@contoso.com"
ADDRESS = {chains.ATTACKER_ADDRESS_FIELD: "203.0.113.77 - a stolen session (anna@contoso.com, 08.11. 10:00 UTC+1)"}


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
    assert [a.rule_id for a in inc.alerts] == ["attack_chain", "password_not_completed", "mfa_change", "role_assignment"]  # summed up, then in order


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
    from radar.ui.incidents import IncidentsWindow, clamp, facts, progress

    class App:
        def __init__(self):
            self.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                                 alert("c1", "new_country", 45, 2, user=CARL), alert("c2", "legacy_auth", 30, 1, user=CARL))
            self.opened, self.dismissed = [], 0

        def open_alert(self, a):
            self.opened.append(a.title)

        def on_alerts_dismissed(self):
            self.dismissed += 1

        def dismiss_alerts(self, ids, parent=None):
            ids = list(ids)
            self.alerts.dismiss(ids)
            return ids

        def open_incident(self, incident_id):
            self.opened.append(f"incident {incident_id}")

    app = App()
    win = IncidentsWindow(root, app)
    try:
        root.update()
        rows = [(win.tree.set(i, "Severity"), win.tree.set(i, "Incident"), progress(win._incidents[i]))
                for i in win.tree.get_children("")]
        assert rows == [("High \u00b7 90", "anna, bea", "Persistence \u00b7 3/3 open"),   # how bad, who, how far
                        ("Medium \u00b7 45", "carl", "Suspicious access \u00b7 2/2 open")]
        assert win.summary.cget("text").startswith("Last 30 days. Data as of ")      # (how many: on the buttons beside it)
        # the first incident is selected: its alerts in order, the cross-account chain among them
        steps = [(win.steps.set(i, "Stage"), win.steps.set(i, "Severity")) for i in win.steps.get_children("")]
        assert steps == [("Summary", "High"), ("Password known", "High"), ("Persistence", "Low")]   # what sums it up, then
        assert win.steps.heading("State", "text").endswith("\u25b2")                                    # what needs a look first
        # the chosen incident: who, how bad and how open is said once, in the list - the right side does not repeat it,
        # an arrowhead at the height of the selected incident shows whose it is
        root.update()
        assert not win.title_label.winfo_ismapped() and not win.badge.winfo_ismapped() and not win.state_label.winfo_ismapped()
        first, second = win.tree.get_children("")
        assert win.pointer.shown_at == win.tree.row_middle(first) - win.pointer.winfo_rooty()
        win.tree.selection_set(second)
        win._incident_selected()
        assert win.pointer.shown_at == win.tree.row_middle(second) - win.pointer.winfo_rooty() > 0
        win.tree.selection_set(first)
        win._incident_selected()
        track = win.track.texts()
        assert [(n, state) for n, _note, state in track] == [
            ("Targeted", "skipped"), ("Password known", "reached"), ("Suspicious access", "skipped"),
            ("Persistence", "reached"), ("Escalation", "ahead")]
        assert all(note for _n, note, state in track if state == "reached")          # when each was reached
        assert win._fact_full["Accounts"] == f"{ANNA}, {BEA}" and win._fact_full["Attacker addresses"] == "203.0.113.77"
        assert win._fact_full["Done so far"] == "Nothing on record"
        assert win._fact_full["Strongest finding"].startswith(f"password_not_completed: {ANNA} (High, 75)")
        assert "Treat these accounts as one incident" in win._fact_full["What to do"]      # what the chain advises
        assert win.hint.label.cget("text") == ""                                         # no words on how to use the page
        # the open ones are shown first; the buttons say how many there are of each
        assert win.filter.chosen == "open" and win.filter.text("open") == "Open 2"
        assert str(win.open_btn.cget("state")) == "normal" and str(win.dismiss_btn.cget("state")) == "normal"
        win.open_selected()                                    # nothing selected: the incident in its own window
        assert app.opened == ["incident a1"]
        win.steps.selection_set(win.steps.get_children("")[1])
        win._buttons()
        win.open_selected()
        assert app.opened[-1] == f"password_not_completed: {ANNA}"
        win.dismiss_incident()
        assert app.dismissed == 1 and win.hint.label.cget("text") == "3 reminders dismissed."
        # the incident is closed now: gone from the open ones, there under "Closed" and "All"
        assert [win.tree.set(i, "Incident") for i in win.tree.get_children("")] == ["carl"]
        assert win.filter.text("closed") == "Closed 1"
        win.show_filter("all")
        states = {win.tree.set(i, "Incident"): progress(win._incidents[i]) for i in win.tree.get_children("")}
        assert states == {"anna, bea": "Persistence \u00b7 closed " + datetime.now().strftime("%d.%m."), "carl": "Suspicious access \u00b7 2/2 open"}
        win.tree.selection_set([i for i in win.tree.get_children("") if not win._incidents[i].open])
        win._incident_selected()
        assert "closed " in win._fact_full["Period"]     # when it was closed: with the period
        assert all(state in ("settled", "skipped", "ahead") for _n, _note, state in win.track.texts())   # nothing of it is open
        app.opened.clear()
        win.open_incident()                                    # (a double-click on it in the list)
        assert app.opened == ["incident a1"]
        assert str(win.dismiss_btn.cget("state")) == "disabled"
        assert {a.status for a in app.alerts.since(NOW - timedelta(days=31)) if BEA in a.subjects} == {DISMISSED}
        assert {a.status for a in app.alerts.since(NOW - timedelta(days=31)) if CARL in a.subjects} == {ACTIVE}
    finally:
        win.top.destroy()
    # what holds an incident together is all there, and what is long is shortened to its place with an ellipsis
    inc = incidents.Incident("k", [], [f"user{i}long@contoso.com" for i in range(9)], [f"203.0.113.{i}" for i in range(7)],
                             NOW, NOW, Severity.HIGH, True, 5, "t", 2, ["Sessions revoked", "Password reset", "Account disabled"])
    full = facts(inc)
    assert full["Accounts"].count("@") == 9 and full["Done so far"] == "Sessions revoked, Password reset, Account disabled"
    short = clamp(full["Accounts"], theme.FONT, 200, 2, root)
    assert short.count("\n") == 1 and short.endswith("\u2026") and clamp("short", theme.FONT, 200, 2, root) == "short"


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


def _f(key, rule, score, days, plugin="signin_threats", **fields):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    return plugin, Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule} ({key})",
                           occurred_at=NOW - timedelta(days=days), fields=fields, subjects=fields.pop("subjects", []))


def _grouped(*items, dismiss=()):
    ac = AlertCenter(Store(":memory:"))
    for plugin, finding in items:
        ac.ingest(plugin, [finding], now=NOW)
    ac.dismiss([a.id for a in ac.recent() if a.key in dismiss])
    return incidents.group(ac.since(NOW - timedelta(days=31)), NOW), ac


def test_what_an_administrator_did_is_an_incident_only_after_an_alert_about_their_own_account():
    admin = "admin@contoso.com"
    work = (_f("consent", "consent_grant", 55, 3, "directory_audit", **{"Initiated by": admin}),
            _f("keys", "sensitive_reads", 25, 2, "directory_audit", **{"Initiated by": admin}),
            _f("policy", "conditional_access", 55, 1, "directory_audit", **{"Initiated by": admin}))
    assert _grouped(*work)[0] == []                                   # a week of work: three alerts, no incident
    found, _ac = _grouped(_f("code", "device_code", 30, 2.5, User=admin), *work)
    assert len(found) == 1
    assert [a.key for a in found[0].own_alerts] == ["code", "keys", "policy"]   # what came after the odd sign-in
    found, _ac = _grouped(*work, _f("code", "device_code", 30, 0.5, User=admin))
    assert found == []                                                # the work came first: not explained by it


def test_an_application_is_an_incident_through_its_own_sign_ins_not_through_being_set_up():
    app = ["app:backup tool"]
    setup = (_f("secret", "app_credentials", 50, 3, "directory_audit", **{"Initiated by": "IT Automations"}, subjects=list(app)),
             _f("grant", "consent_grant", 55, 3, "directory_audit", **{"Initiated by": "IT Automations"}, subjects=list(app)))
    assert _grouped(*setup)[0] == []
    found, _ac = _grouped(*setup, _f("abroad", "app_signins", 55, 1, App="Backup tool", subjects=list(app)))
    assert len(found) == 1 and {a.key for a in found[0].own_alerts} == {"secret", "grant", "abroad"}
    assert found[0].title == "3 alerts about the application Backup tool"


def test_how_far_an_incident_got_is_told_by_what_is_still_open():
    user = "dora@contoso.com"
    items = (_f("code", "device_code", 30, 2, User=user), _f("policy", "conditional_access", 55, 1, "directory_audit",
                                                              **{"Initiated by": user}))
    found, _ac = _grouped(*items)
    assert found[0].stage_name == "Escalation"                         # both open: as far as the furthest
    found, _ac = _grouped(*items, dismiss=("policy",))
    inc = found[0]
    assert inc.open and inc.stage_name == "Suspicious access"          # the policy change was looked at and dismissed
    assert {k: still for k, (_when, still) in inc.stages.items()} == {3: True, 5: False}
    found, _ac = _grouped(_f("ro", "new_country_background", 55, 3, User=user), _f("sg", "new_country_background", 35, 1, User=user),
                          dismiss=("ro",))
    assert found[0].stage_name == "Suspicious access"                  # background activity abroad is a stage, too


def test_alerts_that_were_merged_away_and_chains_that_no_longer_hold_are_not_part_of_an_incident():
    user = "erin@contoso.com"
    found, ac = _grouped(_f("one", "distributed_attack", 50, 3, Account=user), _f("risky", "risky_signin", 60, 2, User=user),
                         _f("both", "distributed_attack", 50, 1, Account=user, subjects=[user]))
    ac.ingest("signin_threats", [Finding(key="both", rule_id="distributed_attack", severity=Severity.MEDIUM, score=50,
                                         title="distributed_attack (both)", occurred_at=NOW - timedelta(days=1),
                                         fields={"Account": user}, supersedes=["one"])], now=NOW)
    ac.ingest(chains.CHAIN_PLUGIN, [Finding(key="chain", rule_id="attack_chain", severity=Severity.MEDIUM, score=60,
                                            title=f"Possible attack chain: {user}", occurred_at=NOW - timedelta(days=3),
                                            fields={"Account": user})], now=NOW)
    ac.settle_summaries(chains.CHAIN_PLUGIN, [], NOW - timedelta(days=30))     # the chain no longer holds
    inc = incidents.group(ac.since(NOW - timedelta(days=31)), NOW)[0]
    assert [a.key for a in inc.alerts] == ["risky", "both"] and inc.title.startswith("2 alerts about")


def test_an_application_that_does_not_work_is_no_incident():
    app = ["app:branch vpn"]
    found, _ac = _grouped(_f("w1", "app_signins", 30, 6, App="Branch VPN", Kind="Operational: an integration that does not work",
                             subjects=list(app)),
                          _f("w2", "app_signins", 30, 1, App="Branch VPN", Kind="Operational: an integration that does not work",
                             subjects=list(app)))
    assert found == []


def test_an_incident_has_a_window_of_its_own_with_the_same_summary_and_the_reasons_of_each_alert(root):
    from radar.ui.incident import IncidentWindow
    from radar.ui.incidents import Summary

    class App:
        def __init__(self):
            self.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                                 alert("lone", "risky_signin", 80, 1, user=CARL))
            self.opened, self.changed = [], 0

        def open_alert(self, a):
            self.opened.append(a.key)

        def on_alerts_dismissed(self):
            self.changed += 1

    app = App()
    inc = incidents.group(app.alerts.since(NOW - timedelta(days=31)), NOW)[0]
    win = IncidentWindow(root, app, inc)
    try:
        root.update()
        assert isinstance(win.block, Summary)                                   # the block the page shows, not a copy
        root.update()                                                           # its name and state: in the title bar,
        assert win.top.title() == f"Incident  \u00b7  High 90  \u00b7  Open \u00b7 3 of 3 alerts  \u00b7  Attack across 2 accounts: {ANNA}, {BEA}"
        assert not win.block.title_label.winfo_ismapped() and not win.block.state_label.winfo_ismapped()   # not again inside
        assert win.block.full["Attacker addresses"] == "203.0.113.77"
        assert "Treat these accounts as one incident" in win.block.fact_labels["What to do"].cget("text")   # the advice
        assert win.block.full["Strongest finding"].startswith(f"password_not_completed: {ANNA} (High, 75)")   # what weighs most
        assert [win.steps.set(i, "Stage") for i in win.steps.get_children("")] == ["Summary", "Password known", "Persistence"]
        win.step_sort("Severity")                                               # a click on a header: by that column
        assert [win.steps.set(i, "Severity") for i in win.steps.get_children("")] == ["Low", "High", "High"]
        win.step_sort("Time")
        # the first row is selected to begin with - here what sums the incident up: why it is rated as it is
        assert win.steps.selection() == (win.steps.get_children("")[0],)
        assert win._why_full.startswith("Attack across 2 accounts") and not win.why_title.winfo_ismapped()   # no title of its own:
        assert "Risk assessment" in win.reasons.get("1.0", "end")
        # shown, not said, that the assessment is the selected alert's: an arrowhead at the height of its row
        rows = win.steps.get_children("")
        root.update()
        heights = []
        for iid in rows:
            win.steps.selection_set(iid)
            win._step_selected()
            root.update()
            heights.append(win.pointer.shown_at)
            assert win.steps.row_middle(iid) - win.pointer.winfo_rooty() == heights[-1]
        assert heights == sorted(heights) and len(set(heights)) == len(rows)       # it follows the selection down the list
        win.steps.selection_set(rows[1])
        win._step_selected()
        win.open_selected()
        assert app.opened == ["a1"]                                             # its evidence and links: the alert's details
        win.snooze()
        assert {a.status for a in app.alerts.recent() if a.key != "lone"} == {"snoozed"} and app.changed == 1
        win.dismiss()                                                           # all of it at once, the summing-up alert too
        assert {a.status for a in app.alerts.recent() if a.key != "lone"} == {DISMISSED}
        assert next(a for a in app.alerts.recent() if a.key == "lone").status == ACTIVE   # what is not part of it stays
        assert str(win.dismiss_btn.cget("state")) == "disabled" and "  \u00b7  Closed" in win.top.title()
    finally:
        win.top.destroy()


def test_the_reminders_show_an_incident_as_one_row_that_is_dismissed_or_snoozed_as_one(root):
    from test_ui import FakeApp

    from radar.ui.reminder import ReminderWindow

    app = FakeApp()
    app.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                        alert("c1", "new_country", 45, 2, user=CARL), alert("c2", "legacy_auth", 30, 1, user=CARL),
                        alert("lone", "risky_signin", 80, 1, user="dora@contoso.com"))
    opened = []
    app.open_incident = lambda incident_id: opened.append(incident_id) or True
    win = ReminderWindow(root, app)
    try:
        win.refresh()
        rows = [(win.tree.set(i, "subject"), win.tree.set(i, "severity")) for i in win.tree.get_children()]
        assert rows == [("Incident: anna, bea  ·  3 alerts  ·  Persistence", "High · 90"),   # the chain is in it,
                        ("risky_signin: dora@contoso.com", "High · 80"),                              # not a row of its own
                        ("Incident: carl  ·  2 alerts  ·  Suspicious access", "Medium · 45")]
        assert win.top.title() == "3 Reminders (3 new)"                 # things to handle, not alerts
        first, lone, second = win.tree.get_children()
        win.tree.selection_set(first)
        win._update_header()
        assert win.h_title.cget("text").startswith("Attack across 2 accounts")
        # the header adds what the row does not say (the period, what weighs most) - not the level and count again
        assert "alerts" not in win._header_text[1] and "risk" not in win._header_text[1] and "UTC" in win._header_text[1]
        assert win._header_text[2].startswith("Strongest finding: ") and "(High" not in win._header_text[2]
        win.open_selected()
        assert opened == ["a1"]                                          # an incident opens in its own window
        assert win.top.title() == "3 Reminders (2 new)"                 # looked at: all of its alerts are seen
        win.tree.selection_set(second)
        win.snooze_selected()
        assert {a.key: a.status for a in app.alerts.recent() if a.key in ("c1", "c2")} == {"c1": "snoozed", "c2": "snoozed"}
        win.tree.selection_set(first)
        win.dismiss_selected()                                           # all of it, the summing-up alert too
        assert {a.key for a in app.alerts.active()} == {"lone"}
        assert [win.tree.set(i, "subject") for i in win.tree.get_children()] == ["risky_signin: dora@contoso.com"]
    finally:
        win.top.destroy()


def test_the_risk_assessment_in_an_incidents_window_is_the_card_of_the_alerts_details(root):
    from test_ui import FakeApp

    from radar.ui.details import DetailsWindow
    from radar.ui.incident import IncidentWindow
    from radar.ui.riskcard import RiskCard

    reasons = [(65, "ROPC sign-in: the password alone"), (20, "Highly privileged account"), (-10, "Corporate network"), (0, "No device identity")]
    first = alert("a1", "password_not_completed", 75, 3, **ADDRESS)
    first.factors = reasons
    app = FakeApp()
    app.alerts = center(first, alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS))
    app.open_alert = lambda a: None
    app.on_alerts_dismissed = lambda: None
    stored = next(a for a in app.alerts.recent() if a.key == "a1")
    inc = incidents.group(app.alerts.since(NOW - timedelta(days=31)), NOW)[0]
    details = DetailsWindow(root, app, stored, on_dismiss=lambda a: None)
    win = IncidentWindow(root, app, inc)
    try:
        root.update()
        assert isinstance(details.risk, RiskCard) and isinstance(win.risk, RiskCard)     # one class draws both

        def shown(text):
            start = text.search("Risk assessment", "1.0")
            body = text.get(start, "end").split("Open in Entra")[0]
            return [line.strip() for line in body.splitlines() if line.strip()]

        win.steps.selection_set(str(stored.id))                                          # the same alert in both windows
        win._step_selected()
        root.update()
        details.risk.set_score(stored.score)                                             # (its count-up animation, finished)
        assert shown(win.reasons) == shown(details.side_text)                            # the same words, line by line
        assert shown(win.reasons)[1].startswith("75  / 100") and "+65" in shown(win.reasons)[2]
        for tag in ("score_num", "factor", "pos", "neg", "card"):                        # ... in the same look
            assert win.reasons.tag_ranges(tag) and details.side_text.tag_ranges(tag), tag
            for option in ("font", "foreground", "lmargin2", "spacing3"):
                assert str(win.reasons.tag_cget(tag, option)) == str(details.side_text.tag_cget(tag, option)), (tag, option)
        assert win.risk.bar.itemcget(win.risk.fill, "fill") == details.risk.bar.itemcget(details.risk.fill, "fill")
    finally:
        win.top.destroy()
        details.top.destroy()


def test_the_page_opens_on_what_is_open_and_says_plainly_when_that_is_nothing(root):
    from radar.ui.incidents import IncidentsWindow, progress

    class App:
        def __init__(self):
            self.alerts = center(alert("a1", "password_not_completed", 75, 3, **ADDRESS), alert("b1", "mfa_change", 40, 2, user=BEA, **ADDRESS),
                                 alert("lone", "risky_signin", 80, 1, user=CARL))

        def on_alerts_dismissed(self):
            pass

        def dismiss_alerts(self, ids, parent=None):
            self.alerts.dismiss(list(ids))
            return list(ids)

    app = App()
    app.alerts.dismiss([a.id for a in app.alerts.recent() if a.key != "lone"])     # the incident is closed, one alert is open
    win = IncidentsWindow(root, app)
    try:
        root.update()
        assert win.filter.chosen == "open" and win.tree.get_children("") == ()     # not "all": nothing open is shown as that
        assert win.empty_title.cget("text") == "No open incidents"
        assert win.empty_link.cget("text") == "1 closed in the last 30 days"
        assert "1 more open alert is not part of an incident (1 High)" in win.empty_note.cget("text")   # not "all clear"
        assert win.pointer.shown_at is None and not win._right.winfo_ismapped()     # the right side is nobody's: empty
        assert str(win.open_btn.cget("state")) == "disabled"
        win.empty_link.event_generate("<Button-1>")                                 # the closed ones are one click away
        root.update()
        assert win.filter.chosen == "closed" and len(win.tree.get_children("")) == 1
        row = win.tree.get_children("")[0]
        assert progress(win._incidents[row]).startswith("Persistence \u00b7 closed ")   # ... and look closed: when, and
        assert win.tree.tag_configure("closed", "pill") == "sev_info_bg|sev_info_fg"      # without the alarm colour
        assert win.frame._edge == "link" and win.pointer.shown_at is not None and win._right.winfo_ismapped()
        win.show_filter("open")
        root.update()
        assert win.empty_title.cget("text") == "No open incidents" and win.tree.get_children("") == ()
    finally:
        win.top.destroy()


def test_what_was_only_logged_is_context_and_not_a_stop_of_the_line():
    """The line shows a stop as passed over when only a logged finding stands for it - the table must not name
    that stop for the logged finding."""
    from radar.ui.incidents import step_rows

    ac = center(alert("a1", "new_country", 45, 3), alert("a2", "sensitive_app", 0, 2), alert("a3", "role_assignment", 55, 1),
                chain=False)
    inc = next(i for i in incidents.group(ac.since(NOW - timedelta(days=31)), NOW) if i.open)
    kinds = {a.rule_id: row[2] for a, row in step_rows(inc)}
    assert set(inc.stages) == {3, 5}                                  # Persistence (4): nothing that counts
    assert kinds == {"new_country": "Suspicious access", "sensitive_app": "Context", "role_assignment": "Escalation"}


def test_a_time_and_its_zone_are_never_put_on_two_lines(root):
    from radar.ui.incidents import clamp

    text = "From 14.11. 14:14 UTC+1 to 17.11. 14:14 UTC+1"
    for width in range(60, 400, 7):
        for line in clamp(text, theme.FONT, width, 3, root).split(chr(10)):
            assert not line.startswith("UTC"), (width, line)


# ------------------------------------------------------------- the order of an incident's alerts
def _mixed_incident():
    """An account with something old that was dismissed, a record, a snoozed alert and two open ones - with a chain."""
    ac = center(alert("old", "new_country", 50, 9), alert("record", "device_registration", 30, 3, signal="device_registered"),
                alert("pw", "password_not_completed", 60, 2), alert("later", "mfa_change", 45, 1),
                alert("snoozed", "risky_signin", 50, 1.5), chain=False)
    by = {a.key: a.id for a in ac.since(NOW - timedelta(days=31))}
    ac.dismiss([by["old"]])
    ac.snooze([by["snoozed"]], 600)
    recent = ac.since(NOW - timedelta(days=31))
    ac.ingest(chains.CHAIN_PLUGIN, chains.chain_findings(recent, NOW) + chains.spread_findings(recent, NOW))
    return ac


def test_an_incidents_alerts_come_in_the_order_of_what_still_needs_a_look():
    """Open first - the summary, then what it sums up in the order it happened -, then snoozed, dismissed, and what
    was only logged. Not by time alone: that put a ten days old dismissed alert on top and the open ones last."""
    from radar.ui.incidents import step_rows

    inc = next(i for i in grouped(_mixed_incident()) if len(i.alerts) >= 5)
    rows = [(row[3], row[2], a.key.split("|")[0]) for a, row in step_rows(inc)]
    assert [state for state, _kind, _key in rows] == ["open", "open", "open", "snoozed", "dismissed", "logged only"]
    assert rows[0][1] == "Summary"
    assert [key for _s, _k, key in rows[1:3]] == ["pw", "later"]          # in the order it happened
    assert [key for _s, _k, key in rows[3:]] == ["snoozed", "old", "record"]


def test_the_state_column_sorts_by_what_needs_a_look_not_by_the_alphabet():
    from radar.ui.tables import sort_key

    states = ["logged only", "dismissed", "open", "snoozed"]
    assert sorted(states, key=sort_key) == ["open", "snoozed", "dismissed", "logged only"]


def test_both_incident_tables_open_in_that_order_and_a_header_still_sorts(root):
    from radar.ui.incident import IncidentWindow
    from radar.ui.incidents import IncidentsWindow

    class App:
        def __init__(self):
            self.alerts = _mixed_incident()

        def open_alert(self, a):
            pass

        def on_alerts_dismissed(self):
            pass

    app = App()
    inc = next(i for i in grouped(app.alerts) if len(i.alerts) >= 5)
    expected = ["open", "open", "open", "snoozed", "dismissed", "logged only"]
    one = IncidentWindow(root, app, inc)
    try:
        root.update()
        steps = one.steps
        assert [steps.set(i, "State") for i in steps.get_children("")] == expected
        assert steps.set(steps.get_children("")[0], "Stage") == "Summary"
        assert steps.heading("State", "text").endswith("▲") and steps.heading("Time", "text") == "Time"
        # the first row is the one selected to begin with - whatever the order puts on top, nothing to work out
        assert steps.selection() == (steps.get_children("")[0],)
        assert one._why_full.startswith("Possible attack chain")              # ... and its reasons are shown
        one.step_sort("Time")                                                  # a click on a header: by that column
        times = [steps.set(i, "Time") for i in steps.get_children("")]
        assert times == sorted(times)
        one.step_sort("State")                                                 # and back
        assert [steps.set(i, "State") for i in steps.get_children("")] == expected
        steps.selection_set(steps.get_children("")[2])                         # what the user chose stays chosen
        chosen = steps.selection()
        one.refresh()                                                          # after a scan: the same order
        root.update()
        assert [steps.set(i, "State") for i in steps.get_children("")] == expected
        assert steps.selection() == chosen
    finally:
        one.top.destroy()
    every = IncidentsWindow(root, app)
    try:
        root.update()
        every.tree.selection_set(next(i for i in every.tree.get_children("") if len(every._incidents[i].alerts) >= 5))
        root.update()
        assert [every.steps.set(i, "State") for i in every.steps.get_children("")] == expected
        assert every.steps.heading("State", "text").endswith("▲")
        assert every.steps.selection() == ()   # in the overview nothing is chosen: "Open" there means the incident
    finally:
        every.top.destroy()
