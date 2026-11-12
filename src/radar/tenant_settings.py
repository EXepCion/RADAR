"""Settings of the tenant that decide whether a check can ever fire.

"Report suspicious activity" (Entra ID > Authentication methods > Settings) lets users report an MFA prompt they
did not start, in Microsoft Authenticator or on the phone. Only then does Entra write the audit entry RADAR's check
"MFA prompt reported by the user" looks for. "Microsoft managed" means off.
"""
from __future__ import annotations

from typing import Any

ENABLED, OFF, UNKNOWN = "enabled", "off", "unknown"
REPORT_TITLE = "Report suspicious activity"
REPORT_ENABLE_STEPS = ("To switch it on: Entra admin center (entra.microsoft.com) > Entra ID > Authentication methods > "
                       "Settings > Report suspicious activity > Enabled ('Microsoft managed' means off) > All users > Save.")
REPORT_NEEDED_FOR = "the check 'MFA prompt reported by the user'"


def report_suspicious_activity(graph: Any) -> tuple[str, str]:
    """(ENABLED or OFF, 'all' or 'group' or '') as set in the tenant. Raises what the Graph client raises when the
    policy cannot be read (it needs Policy.Read.All, which not every sign-in identity has)."""
    policy = graph.get("/beta/policies/authenticationMethodsPolicy") or {}
    settings = policy.get("reportSuspiciousActivitySettings") or {}
    if str(settings.get("state") or "default").lower() != "enabled":
        return OFF, ""  # 'default' (Microsoft managed) and 'disabled' are both off
    target = settings.get("includeTarget") or {}
    everyone = str(target.get("id") or "all_users").lower() == "all_users"
    return ENABLED, "all" if everyone else "group"
