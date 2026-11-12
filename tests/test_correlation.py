"""Weak context signals (guest invites, account disables) only alert in combination with other activity."""
from datetime import datetime, timedelta, timezone

from radar import correlation
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store

T = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


def center():
    return AlertCenter(Store(":memory:"))


def invite(score=65, guest="jane.doe1@gmail.com", when=T, key="guest|g1"):
    return Finding(key=key, rule_id="guest_invites", severity=Severity.MEDIUM, score=score, signal="guest_invite",
                   title=f"Guest invited by jane.doe@contoso.com: {guest}", occurred_at=when,
                   factors=[(score, "Invited what looks like their own private mailbox")],
                   subjects=["jane.doe@contoso.com", guest], fields={"Invited by": "jane.doe@contoso.com"})


def suspicious(score=60, when=T + timedelta(days=2), key="session|x", user="jane.doe@contoso.com"):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW
    return Finding(key=key, rule_id="session_theft", severity=sev, score=score, title=f"Possible session token theft: {user}",
                   occurred_at=when, fields={"User": user})


def disabled(when):
    return Finding(key="disabled|e1", rule_id="guest_invites", severity=Severity.INFO, score=0, signal="account_disabled",
                   title="Account disabled: jane.doe@contoso.com", occurred_at=when, subjects=["jane.doe@contoso.com"],
                   fields={"Account": "jane.doe@contoso.com"})


def test_invite_alone_is_recorded_but_silent():
    ac = center()
    assert ac.ingest("directory_audit", [invite()]) == []
    assert ac.count_active() == 0
    row = ac._store.query_one("SELECT status, signal FROM alerts WHERE key='guest|g1'")
    assert (row["status"], row["signal"]) == ("muted", "guest_invite")


def test_invite_then_suspicious_activity_activates_both_ways():
    ac = center()
    ac.ingest("directory_audit", [invite()])
    popped = ac.ingest("signin_threats", [suspicious()])
    titles = sorted(a.title for a in popped)
    assert titles == ["Guest invited by jane.doe@contoso.com: jane.doe1@gmail.com", "Possible session token theft: jane.doe@contoso.com"]
    sig = next(a for a in popped if a.signal)
    assert sig.score == 80 and sig.severity == Severity.HIGH and not sig.seen
    assert "Possible session token theft" in sig.fields["Correlated with"]
    other = next(a for a in popped if not a.signal)
    assert "Guest invited by" in other.fields["Related signals"]

    ac2 = center()  # reverse order: suspicious alert first, invite later
    ac2.ingest("signin_threats", [suspicious(when=T - timedelta(days=3))])
    popped2 = ac2.ingest("directory_audit", [invite()])
    assert [a.signal for a in popped2] == ["guest_invite"]


def test_low_partner_or_outside_window_does_not_count():
    ac = center()
    ac.ingest("directory_audit", [invite()])
    assert [a for a in ac.ingest("signin_threats", [suspicious(score=30)]) if a.signal] == []
    assert [a for a in ac.ingest("signin_threats", [suspicious(when=T + timedelta(days=12), key="late")]) if a.signal] == []
    assert [a for a in ac.ingest("signin_threats", [suspicious(user="other@contoso.com", key="o")]) if a.signal] == []


def test_private_mailbox_invite_then_account_disabled_is_leaver_pattern():
    ac = center()
    ac.ingest("directory_audit", [invite()])
    popped = ac.ingest("directory_audit", [disabled(T + timedelta(days=10))])
    assert len(popped) == 1 and popped[0].signal == "guest_invite"
    assert any("disabled 10 day(s) after" in r for _, r in popped[0].factors) and popped[0].score == 90
    business = center()
    business.ingest("directory_audit", [invite(score=20, guest="bob@partner.cz")])
    assert business.ingest("directory_audit", [disabled(T + timedelta(days=10))]) == []


def test_correlate_all_for_existing_signals():
    ac = center()
    ac.ingest("signin_threats", [suspicious()])
    ac.ingest("directory_audit", [invite()])  # correlates immediately
    ac._store.execute("UPDATE alerts SET status='muted', score=65 WHERE key='guest|g1'")  # simulate older state
    activated = ac.correlate_all()
    assert len(activated) == 1 and activated[0].status == "active"


def test_subjects_from_fields_and_explicit():
    assert correlation.subjects_from({"User": "Jane.Doe@Contoso.com", "Other": "x@y.z"}) == ["jane.doe@contoso.com"]
    assert correlation.subjects_from({"Account": "a@b.org (3 sign-ins)"}, ["Explicit@C.com"]) == ["explicit@c.com"]
    assert correlation.subjects_from({"Risk score": "50/100"}) == []


# ---------------------------------------------------------------- responses (sessions revoked, account disabled)
def revoked(when, user="jane.doe@contoso.com", key="revoked|r1", by="admin@contoso.com"):
    return Finding(key=key, rule_id="session_revocations", severity=Severity.INFO, score=0, signal="sessions_revoked",
                   subjects=[user], title=f"Sessions revoked: {user}", occurred_at=when,
                   fields={"Account": user, "Initiated by": by})


def test_response_after_an_alert_is_linked_both_ways_and_lowers_the_risk():
    c = center()
    c.ingest("signin_threats", [suspicious(score=50, when=T)])
    alert = c.recent(10)[0]
    assert alert.severity == Severity.MEDIUM and "Response" not in alert.fields
    c.ingest("directory_audit", [revoked(T + timedelta(hours=3))])
    alert = c.get(alert.id)
    assert alert.score == 35 and alert.severity == Severity.LOW and alert.base_severity == Severity.MEDIUM
    assert alert.fields["Response"].startswith("Sessions revoked ") and alert.fields["Response"].endswith("by admin@contoso.com")
    assert alert.factors[-1][0] == -15 and alert.factors[-1][1].startswith(correlation.RESPONSE_PREFIX + "sessions revoked ")
    assert alert.base_score == 50
    signal = [a for a in c.recent(10) if a.signal == "sessions_revoked"][0]
    assert signal.fields["Related alerts"] == "Possible session token theft: jane.doe@contoso.com" and signal.status == "muted"


def test_response_survives_rescans_and_does_not_make_the_alert_pop_again():
    c = center()
    c.ingest("signin_threats", [suspicious(score=50, when=T)])
    alert = c.recent(10)[0]
    c.dismiss([alert.id])
    c.ingest("directory_audit", [revoked(T + timedelta(hours=3))])
    for _ in range(3):  # every scan brings the same finding with the rule's own score again
        popped = c.ingest("signin_threats", [suspicious(score=50, when=T)])
        assert popped == []  # lowered to Low by the response - Medium again is no escalation
        now = c.get(alert.id)
        assert (now.score, now.severity, now.status) == (35, Severity.LOW, "dismissed")
        assert sum(1 for _p, t in now.factors if t.startswith(correlation.RESPONSE_PREFIX)) == 1  # not piling up
    # a real escalation (the rule now says High) still brings it back - and the response still counts
    popped = c.ingest("signin_threats", [suspicious(score=80, when=T)])
    assert [a.id for a in popped] == [alert.id] and c.get(alert.id).score == 65


def test_only_responses_after_the_alert_and_about_the_same_account_count():
    c = center()
    c.ingest("directory_audit", [revoked(T - timedelta(days=1), key="revoked|early"),          # before the alert began
                                 revoked(T + timedelta(hours=1), user="someone.else@contoso.com", key="revoked|other")])
    c.ingest("signin_threats", [suspicious(score=50, when=T)])
    alert = [a for a in c.recent(10) if not a.signal][0]
    assert alert.score == 50 and "Response" not in alert.fields
    # a later revocation and the account being disabled: both listed, the newest of each kind once
    c.ingest("directory_audit", [revoked(T + timedelta(hours=2), key="revoked|a"), revoked(T + timedelta(hours=5), key="revoked|b"),
                                 disabled(T + timedelta(hours=6))])
    alert = c.get(alert.id)
    assert alert.score == 50 - 15 - 20 and alert.severity == Severity.INFO
    assert len(alert.fields["Response"].split(chr(10))) == 2 and "Account disabled" in alert.fields["Response"]
    # ... until the account is enabled again: "disabled" no longer counts, the revocation still does
    c.ingest("directory_audit", [Finding(key="enabled|e2", rule_id="guest_invites", severity=Severity.INFO, score=0, signal="account_enabled",
                                         title="Account enabled: jane.doe@contoso.com", occurred_at=T + timedelta(hours=7),
                                         subjects=["jane.doe@contoso.com"], fields={"Account": "jane.doe@contoso.com"})])
    alert = c.get(alert.id)
    assert alert.score == 50 - 15 and alert.fields["Response"].startswith("Sessions revoked") and "disabled" not in alert.fields["Response"]
    # reports and the app's own notes are not "responded to"
    c.ingest("signin_threats", [Finding(key="rep", rule_id="mfa_exposure_report", severity=Severity.LOW, score=30, title="MFA exposure report",
                                        occurred_at=T, fields={"User": "jane.doe@contoso.com"})])
    assert "Response" not in [a for a in c.recent(20) if a.rule_id == "mfa_exposure_report"][0].fields


def test_alerts_from_before_get_linked_once_at_start():
    c = center()
    c.ingest("directory_audit", [revoked(T + timedelta(hours=3))])
    c._store.execute("INSERT INTO alerts(key, plugin_id, rule_id, severity, title, occurred_at, first_seen, last_seen, status, score, factors,"
                     " subjects, signal, fields) VALUES('old','signin_threats','account_state',2,'Disabled account keeps being tried: x',"
                     "?,?,?,'dismissed',45,'[[45, \"base\"]]','[\"jane.doe@contoso.com\"]','','{}')", (T.isoformat(), T.isoformat(), T.isoformat()))
    assert c.relink_responses() == 1
    old = [a for a in c.recent(10) if a.key == "old"][0]
    assert old.score == 30 and old.severity == Severity.LOW and "Sessions revoked" in old.fields["Response"]


def test_a_response_only_counts_for_alerts_it_does_something_about():
    """Revoking sessions ends a stolen session - it does nothing about password guessing from outside. A disabled
    account takes the point out of both."""
    c = center()
    attack = Finding(key="dpa|u|w", rule_id="distributed_attack", severity=Severity.MEDIUM, score=50, occurred_at=T,
                     title="Password attack from rotating IPs: jane.doe@contoso.com", fields={"Account": "jane.doe@contoso.com"})
    c.ingest("signin_threats", [attack, suspicious(score=50, when=T)])
    c.ingest("directory_audit", [revoked(T + timedelta(hours=3))])
    got = {a.rule_id: a for a in c.recent(10) if not a.signal}
    assert got["distributed_attack"].score == 50 and "Response" not in got["distributed_attack"].fields
    assert got["session_theft"].score == 35
    c.ingest("directory_audit", [disabled(T + timedelta(hours=4))])
    got = {a.rule_id: a for a in c.recent(10) if not a.signal}
    assert got["distributed_attack"].score == 30 and got["distributed_attack"].fields["Response"].startswith("Account disabled")
    assert got["session_theft"].score == 15


def with_events(score, events, key="session|x", rule="session_theft"):
    """An alert whose evidence has these (minutes after T, result) events."""
    rows = [{"Time": str(i), "Result": result, "_created": (T + timedelta(minutes=m)).isoformat(), "Sign-in ID": f"s{i}"}
            for i, (m, result) in enumerate(events)]
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"Alert {key}: jane.doe@contoso.com", occurred_at=T,
                   fields={"User": "jane.doe@contoso.com"}, evidence=rows)


def test_successful_signins_after_a_response_cancel_it_raise_the_risk_and_bring_the_alert_back():
    c = center()
    c.ingest("signin_threats", [with_events(50, [(0, "Success"), (20, "Success")])])
    alert = c.recent(10)[0]
    c.dismiss([alert.id])
    assert c.ingest("directory_audit", [revoked(T + timedelta(hours=1))]) == []
    assert (c.get(alert.id).score, c.get(alert.id).severity) == (35, Severity.LOW)        # answered: lower
    # the same alert again, now with a successful sign-in two hours AFTER the revocation
    popped = c.ingest("signin_threats", [with_events(50, [(0, "Success"), (20, "Success"), (180, "Success")])])
    now = c.get(alert.id)
    assert [a.id for a in popped] == [alert.id] and now.status == "active" and not now.seen   # back on screen, as new
    assert now.score == 50 + correlation.CONTINUED_POINTS and now.severity == Severity.MEDIUM
    assert "did NOT end it (1 successful sign-in(s) since)" in now.fields["Response"]
    texts = [t for _p, t in now.factors]
    assert any("but it did not end this: 1 successful sign-in(s)" in t for t in texts)
    assert any(correlation.CONTINUED_MARK in t for t in texts)
    assert sum(p for p, t in now.factors if t.startswith(correlation.RESPONSE_PREFIX)) == correlation.CONTINUED_POINTS  # the revocation itself: 0
    # it comes back once, not with every scan; dismissed again it stays dismissed while nothing new happens
    c.dismiss([alert.id])
    assert c.ingest("signin_threats", [with_events(50, [(0, "Success"), (20, "Success"), (180, "Success")])]) == []
    assert c.get(alert.id).status == "dismissed" and c.get(alert.id).score == 65
    # the level shown can go above the rule's own when it continues: 60 + 15 = High
    c.ingest("signin_threats", [with_events(60, [(0, "Success"), (180, "Success")], key="session|y")])
    high = [a for a in c.recent(10) if a.key == "session|y"][0]
    assert high.score == 75 and high.severity == Severity.HIGH and high.base_severity == Severity.MEDIUM


def test_refused_attempts_after_a_response_leave_it_standing():
    """A disabled account that is still being tried after its sessions were revoked: every attempt is refused, the
    response stands - and says so."""
    c = center()
    refused = "Failure 50057: The user account is disabled."
    c.ingest("signin_threats", [with_events(45, [(0, refused), (30, refused)], key="acctstate|dis-tried|u|w", rule="account_state")])
    alert = c.recent(10)[0]
    c.dismiss([alert.id])
    c.ingest("directory_audit", [revoked(T + timedelta(hours=1))])
    popped = c.ingest("signin_threats", [with_events(45, [(0, refused), (30, refused), (90, refused), (120, refused)],
                                                     key="acctstate|dis-tried|u|w", rule="account_state")])
    now = c.get(alert.id)
    assert popped == [] and now.status == "dismissed" and now.score == 30 and now.severity == Severity.LOW
    assert now.fields["Response"].endswith("(2 attempt(s) since, all refused)")
    # sign-ins within a few minutes of the revocation do not count as "after" (the two logs differ by minutes)
    c.ingest("signin_threats", [with_events(50, [(0, "Success"), (65, "Success")], key="session|z")])
    close = [a for a in c.recent(10) if a.key == "session|z"][0]
    assert close.score == 35 and "did NOT" not in close.fields["Response"]


def reset(when, user="jane.doe@contoso.com", key="pwreset|p1"):
    return Finding(key=key, rule_id="session_revocations", severity=Severity.INFO, score=0, signal="password_reset",
                   subjects=[user], title=f"Password reset: {user}", occurred_at=when,
                   fields={"Account": user, "Initiated by": "helpdesk@contoso.com", "How": "reset by an admin"})


def test_password_reset_answers_password_alerts_only():
    """A new password ends "the password is known". It does nothing about a stolen session, and about password
    guessing only when the guessing got somewhere. With the sessions revoked as well both count."""
    c = center()

    def alert(rule, title, score=60):
        return Finding(key=rule + title, rule_id=rule, severity=Severity.MEDIUM, score=score, occurred_at=T, title=title + ": jane.doe@contoso.com",
                       fields={"User": "jane.doe@contoso.com"})

    c.ingest("signin_threats", [
        alert("password_not_completed", "Correct password used, sign-in not completed"),
        alert("session_theft", "Possible session token theft"),
        alert("distributed_attack", "Password attack from rotating IPs"),
        alert("distributed_attack", "Password attack got past the password"),
        alert("risky_signin", "Risky sign-in"),
    ])
    c.ingest("directory_audit", [reset(T + timedelta(hours=2))])
    got = {a.title.split(":")[0]: a for a in c.recent(20) if not a.signal}
    assert got["Correct password used, sign-in not completed"].score == 45
    assert got["Correct password used, sign-in not completed"].fields["Response"] ==         f"Password reset {(T + timedelta(hours=2)).astimezone():%d.%m.%Y %H:%M} by helpdesk@contoso.com"
    assert got["Possible session token theft"].score == 60 and "Response" not in got["Possible session token theft"].fields
    assert got["Password attack from rotating IPs"].score == 60          # guessing that got nowhere: a reset changes nothing
    assert got["Password attack got past the password"].score == 45       # the password was known: it is not any more
    assert got["Risky sign-in"].score == 45
    # the sessions are revoked a minute later (Entra does that after a reset): both are on record, both count
    c.ingest("directory_audit", [revoked(T + timedelta(hours=2, minutes=1))])
    got = {a.title.split(":")[0]: a for a in c.recent(20) if not a.signal}
    assert got["Risky sign-in"].score == 30 and len(got["Risky sign-in"].fields["Response"].split(chr(10))) == 2
    assert got["Possible session token theft"].score == 45               # the revocation is what answers this one
    assert got["Correct password used, sign-in not completed"].score == 45  # ... and does nothing for a known password
    signal = [a for a in c.recent(20) if a.signal == "password_reset"][0]
    assert "Risky sign-in: jane.doe@contoso.com" in signal.fields["Related alerts"]
