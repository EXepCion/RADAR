"""Example drop-in plugin for RADAR.

To activate: save as %LOCALAPPDATA%\\RADAR\\plugins\\risky_users.py (any name not starting
with "_"), then use tray menu  Functions > Reload plugins  and enable it under Functions.

This one lists users that Entra ID Protection currently rates as high risk.
Needs Graph permission IdentityRiskyUser.Read.All (Global Reader / Security Reader can read it, but
the client used for sign-in must have that permission consented - see README "Authentication").
"""
from radar.plugin_api import Finding, Plugin, PluginContext, Rule, Severity

RISKY_USERS_URL = "https://portal.azure.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskyUsers"


class RiskyUsersPlugin(Plugin):
    id = "risky_users"                      # stable id, used as key in config.json
    name = "Risky users (ID Protection)"    # text in the tray menu
    description = "Alerts on users currently at high/medium risk in Entra ID Protection."
    default_enabled = False                 # start disabled; toggle it in the tray
    default_interval_minutes = 30
    permissions = ["IdentityRiskyUser.Read.All"]
    default_settings = {"levels": ["high"]}  # editable in config.json -> plugins.risky_users.settings
    rules = [                                # optional sub-toggles shown in the plugin's submenu
        Rule("at_risk", "Users at risk"),
        Rule("compromised", "Confirmed compromised users"),
    ]

    def run(self, ctx: PluginContext) -> list[Finding]:
        findings = []
        levels = {lvl.lower() for lvl in ctx.settings.get("levels", ["high"])}
        for user in ctx.graph.get_all("/v1.0/identityProtection/riskyUsers",
                                      {"$filter": "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"}):
            state = user.get("riskState")
            rule = "compromised" if state == "confirmedCompromised" else "at_risk"
            if not ctx.rule_enabled(rule) or (rule == "at_risk" and user.get("riskLevel") not in levels):
                continue
            upn = user.get("userPrincipalName", user["id"])
            findings.append(Finding(
                # same key = same reminder; include riskLastUpdatedDateTime so a new risk event re-alerts
                key=f"riskyuser|{user['id']}|{user.get('riskLastUpdatedDateTime', '')}",
                rule_id=rule,
                severity=Severity.HIGH,
                title=f"{'Compromised' if rule == 'compromised' else 'High-risk'} user: {upn}",
                summary=f"{upn} is {state} (risk level {user.get('riskLevel')}, {user.get('riskDetail')}).",
                fields={"User": upn, "Risk level": str(user.get("riskLevel")), "Risk state": str(state)},
                recommendation="Investigate the user's recent sign-ins; reset password and revoke sessions if needed.",
                links=[("Open risky users", RISKY_USERS_URL)],
            ))
        ctx.set_status(f"{len(findings)} risky user(s)")
        return findings
