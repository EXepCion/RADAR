from datetime import datetime, timedelta, timezone

from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store


def center():
    return AlertCenter(Store(":memory:"))


def f(key="k1", sev=Severity.MEDIUM, ev=None, **kw):
    return Finding(key=key, title=f"title {key}", severity=sev, evidence=ev or [], **kw)


def test_new_finding_pops_once_and_updates_merge_evidence():
    ac = center()
    popped = ac.ingest("p", [f(ev=[{"a": "1"}])])
    assert len(popped) == 1 and ac.count_active() == 1
    again = ac.ingest("p", [f(ev=[{"a": "2"}, {"a": "1"}])])
    assert again == []
    alert = ac.active()[0]
    assert alert.evidence == [{"a": "2"}, {"a": "1"}]


def row(sid, t, result="Failure 50053: The account is locked", **kw):
    return {"Time": f"2026-11-09 {t}:00", "Result": result, "Sign-in ID": sid, "_created": f"2026-11-09T{t}:00+00:00", **kw}


def test_rerendered_row_replaces_old_copy_instead_of_duplicating():
    ac = center()
    ac.ingest("p", [f(ev=[row("s1", "10:00", result="Failure 50053: This error can be returned for two reasons ...")])])
    ac.ingest("p", [f(ev=[row("s2", "11:00"), row("s1", "10:00")])])
    ev = ac.active()[0].evidence
    assert [r["Sign-in ID"] for r in ev] == ["s2", "s1"] and ev[1]["Result"] == "Failure 50053: The account is locked"


def test_rescore_drops_rows_it_excluded_but_keeps_older_and_non_interactive_ones():
    ac = center()
    old = [row("own", "13:57", result="Failure 50074"), row("a2", "14:29"), row("a1", "08:00"),
           row("bg", "12:00", Type="Non-interactive"), row("early", "01:00")]
    ac.ingest("p", [f(sev=Severity.HIGH, score=90, ev=old)])
    _, after = ac.replace_assessment(f(sev=Severity.MEDIUM, score=50, ev=[row("a2", "14:29"), row("a1", "08:00")]))
    assert [r["Sign-in ID"] for r in after.evidence] == ["a2", "bg", "a1", "early"]  # 'own' was excluded on purpose


def test_below_min_severity_is_muted_until_escalated():
    ac = center()
    assert ac.ingest("p", [f(sev=Severity.INFO)], min_severity=Severity.LOW) == []
    assert ac.count_active() == 0
    assert len(ac.ingest("p", [f(sev=Severity.LOW)], min_severity=Severity.LOW)) == 1


def test_dismissed_does_not_reappear_unless_escalated():
    ac = center()
    a = ac.ingest("p", [f(sev=Severity.MEDIUM)])[0]
    ac.dismiss([a.id])
    assert ac.ingest("p", [f(sev=Severity.MEDIUM)]) == []
    assert ac.count_active() == 0
    assert len(ac.ingest("p", [f(sev=Severity.HIGH)])) == 1
    assert ac.active()[0].severity == Severity.HIGH


def test_snooze_and_wake():
    ac = center()
    a = ac.ingest("p", [f()])[0]
    now = datetime.now(timezone.utc)
    ac.snooze([a.id], 10, now=now)
    assert ac.count_active() == 0
    assert ac.wake_due_snoozes(now + timedelta(minutes=5)) == 0
    assert ac.wake_due_snoozes(now + timedelta(minutes=11)) == 1
    assert ac.count_active() == 1


def test_active_sorted_by_severity():
    ac = center()
    ac.ingest("p", [f("low", Severity.LOW), f("high", Severity.HIGH), f("med", Severity.MEDIUM)])
    assert [a.key for a in ac.active()] == ["high", "med", "low"]


def test_system_alert_pops_once_and_resolve_allows_repop():
    ac = center()
    assert ac.raise_system("auth", "Sign-in required", "x") is not None
    assert ac.raise_system("auth", "Sign-in required", "x") is None
    assert ac.resolve_system("auth")
    assert ac.raise_system("auth", "Sign-in required", "x") is not None


def test_new_alerts_are_unseen_until_marked_and_escalation_makes_them_new_again():
    ac = center()
    a = ac.ingest("p", [f("k", Severity.MEDIUM)])[0]
    assert not a.seen and ac.count_unseen() == 1
    ac.mark_seen([a.id])
    assert ac.get(a.id).seen and ac.count_unseen() == 0
    ac.ingest("p", [f("k", Severity.MEDIUM)])  # same severity: stays seen
    assert ac.get(a.id).seen
    ac.ingest("p", [f("k", Severity.HIGH)])  # got worse: new again
    assert not ac.get(a.id).seen


def test_snoozed_alert_comes_back_as_seen():
    ac = center()
    a = ac.ingest("p", [f()])[0]
    ac.mark_seen([a.id])
    now = datetime.now(timezone.utc)
    ac.snooze([a.id], 5, now=now)
    ac.wake_due_snoozes(now + timedelta(minutes=6))
    assert ac.get(a.id).status == "active" and ac.get(a.id).seen


def test_escalation_ends_a_snooze_but_same_severity_keeps_it():
    ac = center()
    a = ac.ingest("p", [f("k", Severity.MEDIUM)])[0]
    ac.mark_seen([a.id])
    ac.snooze([a.id], 10080)  # 1 week
    assert ac.ingest("p", [f("k", Severity.MEDIUM)]) == [] and ac.get(a.id).status == "snoozed"
    popped = ac.ingest("p", [f("k", Severity.HIGH)])  # e.g. the attack got past the password
    b = ac.get(a.id)
    assert [x.id for x in popped] == [a.id] and b.status == "active" and b.snooze_until is None and not b.seen


def test_escalation_of_an_open_reminder_pops_it_again():
    ac = center()
    a = ac.ingest("p", [f("k", Severity.LOW)])[0]
    assert ac.ingest("p", [f("k", Severity.LOW)]) == []  # unchanged: no new pop-up
    assert [x.id for x in ac.ingest("p", [f("k", Severity.HIGH)])] == [a.id]  # worse: window again, with attention


def test_dismiss_all_and_purge():
    ac = center()
    ac.ingest("p", [f("a"), f("b")])
    ac.dismiss_all()
    assert ac.count_active() == 0
    assert ac.purge(0, now=datetime.now(timezone.utc) + timedelta(days=1)) == 2
