"""Correlation of weak "context signals" with other alerts about the same person.

A finding with ``signal`` set (e.g. a guest invitation) is stored but never pops up on its own. It becomes
an alert only when a partner exists for one of its subjects (UPNs) within a time window:
any regular alert of at least Medium severity, or a specific other signal (e.g. the account being disabled).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SUBJECT_FIELDS = ("User", "Account", "Invited by", "Initiated by", "Member", "Guest")
_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ANY_ALERT = "*"
NOT_A_PARTNER_RULES = {"mfa_exposure_report", "health"}


@dataclass(frozen=True)
class Correlation:
    signal: str          # signal kind that gets escalated
    partner: str         # ANY_ALERT (regular alert >= Medium) or another signal kind
    days_before: int     # partner may occur this many days before the signal ...
    days_after: int      # ... or this many days after it
    points: int
    reason: str          # may use {partner} and {days}
    min_signal_score: int = 0
    exclude_partner_rules: frozenset[str] = frozenset()  # ANY_ALERT partners from these rules do not count


CORRELATIONS = [
    Correlation("guest_invite", ANY_ALERT, 7, 7, 15,
                "Inviter has other suspicious activity: {partner}"),
    Correlation("guest_invite", "account_disabled", 0, 30, 25,
                "Inviter's account was disabled {days} day(s) after inviting a private mailbox (leaver taking data?)",
                min_signal_score=50),
    # an admin consent is routine IT work - unless the admin (phished / compromised) or the app is involved in
    # something else suspicious. App onboarding itself (new secret + consent) is not a partner.
    Correlation("app_consent", ANY_ALERT, 7, 7, 25,
                "The admin or app behind this consent has other suspicious activity: {partner}",
                exclude_partner_rules=frozenset({"consent_grant", "app_credentials"})),
]


@dataclass(frozen=True)
class Response:
    """Something that was DONE about an account (seen in the audit log as a context signal). It is linked to the
    alerts about that account it came after, and lowers their risk: the alert stays true, but less is left to do."""
    signal: str    # the context signal that records the response
    points: int    # change of the alert's risk score (negative)
    days: int      # counts for alerts that began at most this many days before the response
    text: str      # may use {when} and {by}
    label: str     # short form for the alert's "Response" field
    rules: frozenset[str]   # the alerts it actually does something about
    undone_by: str = ""     # a later signal of this kind about the same account cancels the response
    # further rules for which it counts only when the alert's title says so (rule id -> words, any of them)
    rules_if: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def answers(self, rule_id: str, title: str) -> bool:
        """Does this response do something about an alert of that rule (with that title)?"""
        if rule_id in self.rules:
            return True
        return any(word in title.lower() for word in self.rules_if.get(rule_id, ()))


RESPONSE_PREFIX = "Response: "
# Alerts where a sign-in, session or token may be in the wrong hands: revoking the sessions ends that. It does
# nothing about password guessing from outside or a password that is known - those are not in the list.
_SESSION_RULES = frozenset({"session_theft", "aitm_replay", "risky_signin", "new_country", "new_country_background",
                            "impossible_travel", "device_code", "account_state", "pinned_accounts", "sensitive_app",
                            "legacy_auth", "mfa_exempt_watch"})
# A disabled account cannot sign in at all: that also takes the point out of attacks on its password.
_ACCOUNT_RULES = _SESSION_RULES | {"distributed_attack", "brute_force", "password_not_completed", "mfa_fatigue"}
# Alerts where somebody knew or may have used the PASSWORD: a new password ends that. (Tokens that were already
# handed out live on until the sessions are revoked - that is the other response; after a reset Entra usually
# revokes them too, and then both are on record.) Not session theft: a stolen token does not need the password.
_PASSWORD_RULES = frozenset({"password_not_completed", "mfa_fatigue", "risky_signin", "new_country", "new_country_background",
                             "impossible_travel", "mfa_exempt_watch", "pinned_accounts", "legacy_auth"})
RESPONSES = [
    # Password guessing from outside is only answered by a reset when the guessing got somewhere.
    Response("password_reset", -15, 30,
             "password reset {when} by {by} - the old password no longer works", "Password reset",
             rules=_PASSWORD_RULES,
             rules_if={"distributed_attack": ("got past the password", "break-in"), "brute_force": ("successful sign-in",)}),
    Response("sessions_revoked", -15, 30,
             "sessions revoked {when} by {by} - sign-ins and tokens from before that no longer work", "Sessions revoked",
             rules=_SESSION_RULES),
    Response("account_disabled", -20, 30,
             "account disabled {when} by {by} - it cannot sign in any more", "Account disabled",
             rules=_ACCOUNT_RULES, undone_by="account_enabled"),  # ... unless it was enabled again afterwards
]
RESPONSE_SIGNALS = {r.signal: r for r in RESPONSES}
RESPONSE_RELATED = set(RESPONSE_SIGNALS) | {r.undone_by for r in RESPONSES if r.undone_by}  # signals that change the picture
RESPONSE_SLACK_MINUTES = 10  # the audit log and the sign-in log do not agree to the minute
# Successful sign-ins of the alert AFTER a response: it did not end this. The response then counts for nothing and
# the risk goes up - the sessions were cut off and whoever is behind it is in again.
CONTINUED_MARK = "continued after the response"
CONTINUED_POINTS = 15


def subjects_from(fields: dict[str, str], explicit: list[str] | None = None) -> list[str]:
    """Lower-case UPNs/e-mails (or 'app:<name>') a finding is about: explicit list, else its well-known fields."""
    found = [s.strip().lower() for s in explicit or [] if s and ("@" in s or s.lower().startswith("app:"))]
    if not found:
        for key in SUBJECT_FIELDS:
            found.extend(m.lower() for m in _EMAIL.findall(str(fields.get(key, ""))))
    return sorted(set(found))
