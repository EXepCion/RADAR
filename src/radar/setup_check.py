"""Set-up check: can RADAR sign in, and may it read what it needs? In plain words, with what to do about it.

Used by the set-up window (first start and Settings > Account > Set-up and connection check). While set-up is not
finished, sign-in and permission problems are shown there - they are not alerts. No UI in here.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from . import identity, tenant_settings
from .auth import AuthRequiredError, TenantChangedError
from .graph import GraphError

log = logging.getLogger(__name__)

ROLES = "Global Reader, Security Reader or Reports Reader"
SIGN_IN = "signin"


@dataclass
class Check:
    key: str
    title: str
    ok: bool
    required: bool = True
    detail: str = ""   # what was found, one line
    hint: str = ""     # what to do about it


# what RADAR reads, in the order it is checked: (key, title, path, parameters, required, what depends on it)
PROBES = [
    ("signins", "Sign-in log", "/beta/auditLogs/signIns", {"$top": "1"}, True, "the sign-in checks"),
    ("audit", "Audit log", "/v1.0/auditLogs/directoryAudits", {"$top": "1"}, True, "the directory change checks"),
    ("directory", "Accounts in the directory", "/v1.0/users", {"$top": "1", "$select": "id"}, True, "the account context"),
    ("policies", "Conditional Access policies", "/v1.0/identity/conditionalAccess/policies", {"$top": "1"}, False,
     "the MFA exposure report and the stricter rules for accounts excluded from MFA"),
]
REPORT = "report"
STEPS = [(SIGN_IN, "Sign in")] + [(key, title) for key, title, *_ in PROBES] + [(REPORT, tenant_settings.REPORT_TITLE)]

_AAD_CODE = re.compile(r"AADSTS(\d+)")
_AUTH_HINTS = {
    "65001": ("The application has not been granted the permissions yet.",
              "An administrator has to grant admin consent for the application's Graph permissions "
              "(AuditLog.Read.All, Directory.Read.All, Policy.Read.All)."),
    "65004": ("Consent was declined.", "The permissions have to be accepted - by an administrator for the whole organisation."),
    "700016": ("This application ID is not known in that directory.",
               "Check the application (client) ID and the directory (tenant) ID."),
    "90002": ("That directory (tenant) was not found.", "Check the directory (tenant) ID or domain."),
    "50020": ("This account does not belong to that directory.", "Sign in with an account of the organisation."),
    "50105": ("Your account is not assigned to the application.",
              "Assign the account to the application in Entra (Enterprise applications > Users and groups), or switch off "
              "'Assignment required'."),
    "53003": ("Sign-in was blocked by a Conditional Access policy.",
              "With the Azure CLI identity: that identity may be blocked in this organisation - use an app registration "
              "of your own. Otherwise ask whoever manages Conditional Access."),
    "53000": ("Sign-in was blocked: the device is not compliant.", "Use a device that meets the organisation's rules."),
    "50076": ("Sign-in needs multi-factor authentication.", "Choose 'Check again' and complete the sign-in prompt."),
    "50079": ("Sign-in needs multi-factor authentication to be set up.", "Set up MFA for the account, then check again."),
    "7000218": ("The application is not registered as a public client.",
                "In the app registration: Authentication > Allow public client flows = Yes."),
    "50011": ("The application's redirect address does not match.",
              "In the app registration: Authentication > add the platform 'Mobile and desktop applications' with the "
              "redirect URI ms-appx-web://Microsoft.AAD.BrokerPlugin/<application id>."),
}


def explain_auth(error: str, kind: str = "") -> tuple[str, str]:
    """(what went wrong, what to do) for a failed sign-in."""
    text = str(error or "")
    low = text.lower()
    code = _AAD_CODE.search(text)
    if code and code.group(1) in _AUTH_HINTS:
        return _AUTH_HINTS[code.group(1)]
    if "cancel" in low:
        return "The sign-in was cancelled.", "Choose 'Check again' and complete the sign-in."
    if "not been chosen" in low:
        return "It has not been chosen yet how RADAR signs in.", "Choose one of the two ways above."
    if "no cached account" in low or "no windows account" in low or "signed out" in low:
        return "RADAR is not signed in.", "Choose 'Check again' and sign in when Windows asks."
    hint = "Choose 'Check again'. If it keeps failing, sign in with a different account or check the application identity."
    if kind == identity.AZURE_CLI:
        hint += " The Azure CLI identity does not work in every organisation."
    return f"Sign-in failed: {text[:200] or 'no reason given'}", hint


def explain_graph(exc: GraphError, title: str, account: str, kind: str, needed_for: str) -> tuple[str, str]:
    """(what went wrong, what to do) for a refused read."""
    text = f"{exc.code} {exc.message}".lower()
    who = account or "your account"
    if "premium" in text or "nonpremiumtenant" in text or "license" in text or "licence" in text:
        return (f"{title}: this organisation has no Microsoft Entra ID P1 or P2 licence.",
                "Microsoft only offers this log through its API with Entra ID P1 or P2. Without it RADAR cannot do "
                f"{needed_for}.")
    if exc.status == 403:
        hint = f"{who} needs one of these Entra roles: {ROLES}. A role that was just assigned can take a few minutes."
        if kind == identity.OWN:
            hint += (" With an app registration of your own, also check that AuditLog.Read.All, Directory.Read.All and "
                     "Policy.Read.All are granted with admin consent.")
        return f"{title}: {who} is not allowed to read it.", hint
    if exc.status == 401:
        return (f"{title}: the sign-in was not accepted.",
                "Check again; if it stays like this, the application identity lacks its permissions (admin consent).")
    if exc.status == 429:
        return f"{title}: Microsoft is throttling requests right now.", "Wait a minute and check again."
    return f"{title}: Microsoft Graph answered {exc.status} ({exc.code or 'error'}).", "Check again in a moment."


def sign_in(auth: Any, kind: str, interactive: bool = True) -> Check:
    """Get a token: silently first, then - if allowed - with the Windows sign-in prompt."""
    try:
        try:
            auth.get_token()
        except TenantChangedError:
            raise
        except AuthRequiredError:
            if not (interactive and auth.configured):
                raise
            auth.sign_in_interactive()
    except TenantChangedError as exc:
        log.warning("Set-up check: %s", exc)
        return Check(SIGN_IN, "Sign in", False, True, f"{exc}.",
                     "Two tenants are never mixed. Use 'Start fresh for this tenant' in the reminder RADAR shows, "
                     "or sign in with an account of the original tenant.")
    except Exception as exc:  # noqa: BLE001 - whatever the sign-in libraries raise, it is explained to the user
        what, todo = explain_auth(str(exc), kind)
        log.warning("Set-up check: sign-in failed (%s)", exc)
        return Check(SIGN_IN, "Sign in", False, True, what, todo)
    log.info("Set-up check: signed in as %s", auth.account)
    return Check(SIGN_IN, "Sign in", True, True, f"signed in as {auth.account or 'your account'}")


def probe(graph: Any, account: str = "", kind: str = "", on_result: Callable[[Check], None] | None = None) -> list[Check]:
    """Try each thing RADAR reads, with the smallest possible request."""
    out = []
    for key, title, path, params, required, needed_for in PROBES:
        try:
            graph.get(path, params)
            check = Check(key, title, True, required, "readable")
            log.info("Set-up check: %s readable", title.lower())
        except GraphError as exc:
            what, todo = explain_graph(exc, title, account, kind, needed_for)
            if not required:
                todo = f"RADAR works without it, but not {needed_for}. " + todo
            check = Check(key, title, False, required, what, todo)
            log.warning("Set-up check: %s not readable (%s %s)", title.lower(), exc.status, exc.code)
        except Exception as exc:  # noqa: BLE001 - no network, sign-in lost in between ...
            check = Check(key, title, False, required, f"{title}: could not be reached ({type(exc).__name__}).",
                          "Check the internet connection and check again.")
            log.warning("Set-up check: %s failed (%s)", title.lower(), exc)
        out.append(check)
        if on_result:
            on_result(check)
    check = report_check(graph)
    out.append(check)
    if on_result:
        on_result(check)
    return out


def report_check(graph: Any) -> Check:
    """Can users report an MFA prompt they did not start? A tenant setting, off unless somebody switched it on -
    and until it is on, RADAR's check for such reports has nothing to find and stays inactive."""
    title, steps, needed_for = tenant_settings.REPORT_TITLE, tenant_settings.REPORT_ENABLE_STEPS, tenant_settings.REPORT_NEEDED_FOR
    try:
        state, scope = tenant_settings.report_suspicious_activity(graph)
    except GraphError as exc:
        log.warning("Set-up check: tenant setting '%s' not readable (%s %s)", title, exc.status, exc.code)
        if exc.status in (401, 403):
            return Check(REPORT, title, False, False,
                         f"{title}: this sign-in is not allowed to read the setting (it needs Policy.Read.All).",
                         f"RADAR works without it and keeps {needed_for} active, but cannot tell whether your users "
                         f"are able to report a prompt. Look it up yourself. {steps}")
        return Check(REPORT, title, False, False, f"{title}: Microsoft Graph answered {exc.status} ({exc.code or 'error'}).",
                     "Check again in a moment.")
    except Exception as exc:  # noqa: BLE001
        log.warning("Set-up check: tenant setting '%s' failed (%s)", title, exc)
        return Check(REPORT, title, False, False, f"{title}: could not be reached ({type(exc).__name__}).",
                     "Check the internet connection and check again.")
    log.info("Set-up check: tenant setting '%s' is %s%s", title, state, f" ({scope})" if scope else "")
    if state == tenant_settings.ENABLED and scope == "group":
        return Check(REPORT, title, True, False, "switched on for a group - only its members can report an MFA prompt")
    if state == tenant_settings.ENABLED:
        return Check(REPORT, title, True, False, "switched on for all users")
    return Check(REPORT, title, False, False,
                 f"{title}: switched off in this organisation - users cannot report an MFA prompt they did not start.",
                 f"RADAR works without it, but {needed_for} stays inactive until it is switched on. {steps}")


def working(checks: list[Check]) -> bool:
    """Everything RADAR cannot do without is there."""
    return bool(checks) and all(c.ok for c in checks if c.required)


def first_problem(checks: list[Check]) -> Check | None:
    """The problem to show: the first thing in the way, else the first optional thing that is missing."""
    return next((c for c in checks if not c.ok and c.required), None) or next((c for c in checks if not c.ok), None)
