"""Attack-chain correlation: weak steps against one account, in takeover order, within days."""
from datetime import datetime, timedelta, timezone

from radar import chains
from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.store import Store

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
USER = "anna@contoso.com"


def step(key, rule, score, days_ago, user=USER, last_days_ago=None, factors=()):
    when = NOW - timedelta(days=days_ago)
    evidence = [{"Time": "x", "_created": (NOW - timedelta(days=last_days_ago)).isoformat()}] if last_days_ago is not None else []
    sev = Severity.HIGH if score >= 70 else Severity.MEDIUM if score >= 45 else Severity.LOW if score >= 25 else Severity.INFO
    return Finding(key=key, rule_id=rule, severity=sev, score=score, title=f"{rule} {user}", occurred_at=when,
                   fields={"User": user}, evidence=evidence, factors=list(factors))


def store(*findings, dismiss=()):
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("signin_threats", list(findings))
    ids = [a.id for a in ac.since(NOW - timedelta(days=30)) if a.key in dismiss]
    ac.dismiss(ids)
    return ac


def chain_for(ac):
    return chains.chain_findings(ac.since(NOW - timedelta(days=30)), NOW)


def test_guessing_then_password_known_then_new_mfa_method_is_a_chain_even_if_dismissed():
    ac = store(step("dpa", "distributed_attack", 50, 3), step("pwok", "password_not_completed", 40, 2),
               step("mfa", "mfa_change", 30, 1), dismiss=("dpa", "pwok"))
    out = chain_for(ac)
    assert len(out) == 1
    f = out[0]
    assert f.fields["Chain"] == "Targeted -> Password known -> Persistence"
    assert f.score == 50 + 2 * chains.STEP_POINTS + 10 and f.severity == Severity.HIGH
    assert [r["Reminder"] for r in f.evidence] == ["dismissed", "dismissed", "active"]
    assert f.subjects == [USER]


def test_travel_then_new_passkey_is_quiet():
    ac = store(step("nc", "new_country", 45, 2), step("mfa", "mfa_change", 25, 1))
    assert chain_for(ac) == []


def test_three_stages_without_password_stage_is_a_chain():
    ac = store(step("rs", "risky_signin", 45, 2), step("mfa", "mfa_change", 30, 1), step("role", "role_assignment", 55, 0.5))
    assert chain_for(ac)[0].fields["Chain"] == "Suspicious access -> Persistence -> Escalation"


def test_steps_weeks_apart_or_harmless_steps_are_no_chain():
    assert chain_for(store(step("pwok", "password_not_completed", 60, 12), step("mfa", "mfa_change", 30, 1))) == []
    assert chain_for(store(step("pwok", "password_not_completed", 60, 2), step("mfa", "mfa_change", 10, 1))) == []


def test_a_campaign_still_running_links_to_a_later_step():
    # guessing started 10 days ago but is still going (last attempt yesterday) -> the success today follows it
    ac = store(step("dpa", "distributed_attack", 50, 10, last_days_ago=1), step("rs", "risky_signin", 40, 0.2))
    assert chain_for(ac)[0].fields["Chain"] == "Targeted -> Suspicious access"


def test_two_steps_are_capped_at_medium_and_password_worked_counts_as_known():
    ac = store(step("pwok", "password_not_completed", 65, 2), step("mfa", "mfa_change", 25, 1))
    f = chain_for(ac)[0]
    assert f.score == 69 and f.severity == Severity.MEDIUM
    assert chains.stage_of("distributed_attack", [(30, "Attacker got past the password 1 time(s)")]) == 2


def test_blocked_risky_attempts_are_targeting_not_access():
    # old "risky sign-in" alerts for attempts
    # of the rotating-IP campaign that Smart Lockout blocked
    risky = step("rs", "risky_signin", 90, 1)
    risky.evidence = [{"Result": "Failure 50053: The account is locked", "_created": (NOW - timedelta(days=1)).isoformat()}]
    assert chain_for(store(step("dpa", "distributed_attack", 50, 3), risky)) == []
    risky.evidence.append({"Result": "Success", "_created": (NOW - timedelta(hours=20)).isoformat()})
    assert chain_for(store(step("dpa", "distributed_attack", 50, 3), risky))  # one success: access


def test_one_rule_alone_is_no_chain():
    # break-glass: "sign-in attempts" (failed) and "account used" both come from account_state and remind anyway
    attempts = step("bg-fail", "account_state", 45, 2)
    attempts.evidence = [{"Result": "Failure 50126", "_created": (NOW - timedelta(days=2)).isoformat()}]
    assert chain_for(store(attempts, step("bg", "account_state", 95, 1))) == []


def test_other_accounts_and_reactions_do_not_mix():
    ac = store(step("pwok", "password_not_completed", 60, 2), step("mfa", "mfa_change", 30, 1, user="bob@contoso.com"))
    assert chain_for(ac) == []
    disabled = Finding(key="dis", rule_id="guest_invites", severity=Severity.INFO, score=0, signal="account_disabled",
                       title="Account disabled", occurred_at=NOW - timedelta(days=1), subjects=[USER])
    ac = store(step("pwok", "password_not_completed", 60, 2), disabled)
    assert chain_for(ac) == []
