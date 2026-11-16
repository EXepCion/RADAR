"""What the alert store does by itself: merged alerts, chains that no longer hold, what goes with a dismissal,
Low alerts that close after a while, reports that are no reminders."""
from datetime import datetime, timedelta, timezone

from radar import chains, correlation
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store

NOW = datetime.now(timezone.utc)
ANNA, BEN = "anna@contoso.com", "ben@contoso.com"


def finding(key, rule, score, days_ago=1.0, user=ANNA, **kw):
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    kw.setdefault("fields", {"User": user})
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule} {user}",
                   occurred_at=NOW - timedelta(days=days_ago), **kw)


def center(*findings):
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", list(findings))
    return ac


def by_key(ac):
    return {a.key: a for a in ac.recent()}


def update_chains(ac):
    recent = ac.since(NOW - timedelta(days=31))
    found = chains.chain_findings(recent, NOW) + chains.spread_findings(recent, NOW)
    popped = ac.ingest(chains.CHAIN_PLUGIN, found)
    ac.settle_summaries(chains.CHAIN_PLUGIN, found, NOW - timedelta(days=chains.LOOKBACK_DAYS))
    return popped


def test_a_finding_that_takes_the_place_of_others_closes_their_reminders():
    ac = center(finding("one", "distributed_attack", 50), finding("two", "distributed_attack", 50, user=BEN))
    both = finding("both", "distributed_attack", 50, fields={"Accounts": f"{ANNA}, {BEN}"}, subjects=[ANNA, BEN],
                   supersedes=["one", "two", "never-existed"])
    assert [a.key for a in ac.ingest("signin_threats", [both])] == ["both"]
    alerts = by_key(ac)
    assert [alerts[k].status for k in ("one", "two", "both")] == ["muted", "muted", "active"]
    assert alerts["one"].fields["Merged into"] == both.title


def test_an_alert_about_several_accounts_is_not_answered_by_what_was_done_about_one():
    ac = center(finding("both", "distributed_attack", 50, fields={"Accounts": f"{ANNA}, {BEN}"}, subjects=[ANNA, BEN]),
                finding("one", "distributed_attack", 50))
    off = Finding(key="off", rule_id="guest_invites", severity=Severity.INFO, score=0, title=f"Account disabled: {ANNA}",
                  occurred_at=NOW, fields={"Account": ANNA, "Initiated by": "admin@contoso.com"}, signal="account_disabled")
    ac.ingest("directory_audit", [off])
    alerts = by_key(ac)
    assert alerts["both"].score == 50 and "Response" not in alerts["both"].fields
    assert alerts["one"].score == 30 and "Account disabled" in alerts["one"].fields["Response"]


def test_a_chain_lists_each_step_once_and_leaves_when_its_steps_no_longer_add_up():
    ac = center(finding("dpa", "distributed_attack", 50, 3), finding("pw", "password_not_completed", 40, 2),
                finding("mfa", "mfa_change", 30, 1))
    assert len(update_chains(ac)) == 1
    chain = next(a for a in ac.active() if a.plugin_id == chains.CHAIN_PLUGIN)
    assert chain.score == 80 and [r["_key"] for r in chain.evidence] == ["dpa", "pw", "mfa"]
    ac.snooze([by_key(ac)["mfa"].id], 60)                         # the step changes its state ...
    update_chains(ac)
    chain = ac.get(chain.id)
    assert [(r["_key"], r["Reminder"]) for r in chain.evidence] == [("dpa", "active"), ("pw", "active"), ("mfa", "snoozed")]
    ac.dismiss([by_key(ac)[k].id for k in ("dpa", "pw")])         # two steps settled: the chain is rated lower
    update_chains(ac)
    assert ac.get(chain.id).score == 50 and ac.get(chain.id).status == "active"
    ac.dismiss([by_key(ac)["mfa"].id])                            # all settled: it leaves the reminders
    update_chains(ac)
    chain = ac.get(chain.id)
    assert chain.status == "muted" and "no longer make a chain" in chain.fields["Reassessed"]


def test_dismissing_offers_what_goes_with_it():
    ac = center(finding("dpa", "distributed_attack", 50, 3), finding("pw", "password_not_completed", 40, 2),
                finding("mfa", "mfa_change", 30, 1), finding("other", "legacy_auth", 40, 1, user=BEN))
    update_chains(ac)
    alerts = by_key(ac)
    chain = next(a for a in ac.active() if a.plugin_id == chains.CHAIN_PLUGIN)
    assert {a.key for a in ac.companions([chain.id])} == {"dpa", "pw", "mfa"}          # a chain: its open steps
    assert ac.companions([alerts["dpa"].id]) == []                                     # one step of three: nothing
    assert [a.id for a in ac.companions([alerts[k].id for k in ("dpa", "pw", "mfa")])] == [chain.id]   # its last steps
    assert ac.companions([alerts["other"].id]) == []
    ac.dismiss([alerts["dpa"].id, alerts["pw"].id])
    assert [a.id for a in ac.companions([alerts["mfa"].id])] == [chain.id]             # the last open step


def test_low_alerts_that_were_seen_close_by_themselves_after_a_while():
    ac = AlertCenter(Store(":memory:"))
    old = NOW - timedelta(days=10)
    ac.ingest("signin_threats", [finding("low", "new_country", 30), finding("unseen", "new_country", 30, user=BEN),
                                 finding("medium", "risky_signin", 50)], now=old)
    alerts = by_key(ac)
    ac.mark_seen([alerts["low"].id, alerts["medium"].id])
    assert ac.close_stale(7, NOW - timedelta(days=5)) == 0        # not long enough yet
    assert ac.close_stale(7, NOW) == 1
    alerts = by_key(ac)
    assert alerts["low"].status == "dismissed" and "unchanged for 7 days" in alerts["low"].fields["Closed"]
    assert alerts["unseen"].status == "active" and alerts["medium"].status == "active"


def test_a_report_is_kept_but_is_no_reminder():
    ac = center(finding("report|w1", "mfa_exposure_report", 35))
    assert by_key(ac)["report|w1"].status == "active"            # stored by an earlier version as a reminder
    assert ac.to_signal("mfa_exposure_report", correlation.REPORT_SIGNAL) == 1
    assert by_key(ac)["report|w1"].status == "muted"
    assert ac.ingest("signin_threats", [finding("report|w2", "mfa_exposure_report", 55, signal=correlation.REPORT_SIGNAL)]) == []
    assert by_key(ac)["report|w2"].status == "muted" and ac.count_active() == 0
