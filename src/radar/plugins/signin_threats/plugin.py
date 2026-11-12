"""Sign-in threat detection plugin: incremental ingestion of tenant sign-ins + detection rules."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from ... import tenant_settings
from ...graph import GraphError
from ...plugin_api import Finding, Plugin, PluginContext, Rule
from . import apps, indicators, netintel, overview, rules
from .accounts import AccountDirectory, sync_directory
from .asnames import AsnNameResolver
from .history import SignInHistory
from .models import AccountChange, SignIn, graph_time, parse_time
from .rules import RULES, RuleContext

EVENT_TYPES = ("interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity")


DATA_AS_OF = "data_as_of"  # state key: start of the last complete scan


class SignInThreatsPlugin(Plugin):
    id = "signin_threats"
    name = "Sign-in threat detection"
    description = ("Pulls every Entra ID sign-in of the tenant (interactive and non-interactive), looks for attack "
                   "patterns and ranks each finding with a context-based risk score.")
    version = "2.0"
    entry_id_field = "Sign-in ID"
    default_enabled = True
    default_interval_minutes = 10
    permissions = ["AuditLog.Read.All", "Directory.Read.All (role: Global Reader, Reports Reader or Security Reader)"]
    rules = [r.meta for r in RULES] + [
        Rule("app_signins", "App sign-ins (service principals)",
             "Apps signing in with their own secret: new country, new credential, failing credentials"),
    ]
    default_settings = {
        "api_version": "beta",
        "event_types": ["interactiveUser", "nonInteractiveUser"],
        "baseline_days": 30,  # Entra keeps sign-in logs for 30 days
        "initial_lookback_hours": 24,
        "non_interactive_initial_hours": 2,
        "non_interactive_max_catchup_hours": 6,
        "overlap_minutes": 20,
        "interactive_overlap_minutes": 60,
        "retention_days": 30,
        # 3 h covers the 60-min window rules. Raise to ~26 if you enable include_non_interactive
        # for impossible_travel / new_country (they look back up to 24 h).
        "non_interactive_retention_hours": 3,
        "max_pages_per_run": 400,
        "ignore_users": [],
        "ignore_ips": [],
        "trusted_ips": [],
        "trust_named_locations": True,
        "risky_signin": {"min_risk_level": "medium", "include_remediated": True, "include_failed": False},
        "password_spray": {"window_minutes": 60, "min_distinct_users": 5},
        "distributed_attack": {"window_hours": 72, "min_failures": 8, "min_distinct_ips": 6},
        "brute_force": {"window_minutes": 60, "min_failures": 10},
        "mfa_fatigue": {"window_minutes": 60, "min_denials": 3},
        "impossible_travel": {"min_distance_km": 500, "max_speed_kmh": 900, "lookback_hours": 24,
                              "ignore_phone_networks": True,
                              "ignore_same_device": True, "ignore_same_country": True,
                              "include_non_interactive": False},
        "new_country": {"min_baseline_signins": 5, "allowed_countries": [], "include_non_interactive": False},
        "new_country_background": {"min_baseline_signins": 5},
        # a disabled account refused this often within the window is reported once a week
        "account_state": {"disabled_attempts_window_hours": 3, "disabled_attempts_min": 10},
        "legacy_auth": {"allowed_users": []},
        # {"scanner@contoso.com": ["198.51.100.10", "203.0.113.0/28"]}: any successful sign-in of the account
        # from another IP raises a High alert; legacy auth from the pinned IPs counts as expected.
        "pinned_accounts": {"accounts": {}},
        "device_code": {"allowed_users": []},
        # account context (roles, MFA exclusions from Conditional Access, state), refreshed from Entra ID
        "account_sync_hours": 12,
        # emergency access accounts (UPN patterns and/or group object ids): any sign-in raises an alert
        "breakglass_accounts": [],
        "breakglass_groups": [],
        "mfa_exempt_watch": {"min_failures": 3, "window_hours": 24, "seed_accounts_per_run": 40},
        "mfa_exposure_report": {"unused_days": 90, "password_max_days": 365},
        "session_theft": {"lookback_hours": 24},
        # MFA-method / password changes (directory audit) judged by where they were made and what signs in after
        "mfa_change": {"lookback_hours": 24, "include_guests": False, "new_account_days": 7},
        # fresh MFA through a hosting network (AiTM proxy) / session moving networks right after a fresh MFA
        "aitm_replay": {"window_minutes": 180},
        # addresses another finding proved to be an attacker's count against every sign-in from them, to any
        # account, for this many days (indicators.py)
        "hostile_indicators": {"enabled": True, "days": 7},
        # several accounts with an odd sign-in (past the password, outside their usual surroundings) within the
        # window, all from one network new to the tenant / a hosting or VPN network, or with one never-seen client
        "signin_wave": {"window_hours": 6, "min_accounts": 4},
        "password_not_completed": {"settle_minutes": 15, "window_hours": 3},
        # a user reported an MFA prompt as not theirs: the audit entries that say so (by name), how close in time the
        # failed sign-in must be to count as the one that caused the prompt, and how long to wait for it
        "mfa_report": {"activities": ["Suspicious activity reported"], "lookback_hours": 24,
                       "match_seconds_before": 180, "match_seconds_after": 60, "wait_minutes": 120,
                       "setting_check_hours": 24},
        "attack_tooling": {"min_failures": 3},
        "new_shared_ip": {"min_accounts": 2, "new_ip_hours": 24},
        # Risk scoring: trusted_asns lower nothing but stop "VPN/hosting" points (e.g. your own ZTNA/VPN
        # provider); extra_asns adds networks: {"64500": ["My VPN provider", "vpn"]} (vpn|hosting|bulletproof|cloud);
        # suspicious_user_agents: null = built-in list, or your own list of regexes.
        # lookup_asn_names: classify unlisted networks by their registered name via RIPEstat (sends AS numbers only).
        "scoring": {"trusted_asns": [], "extra_asns": {}, "suspicious_user_agents": None, "lookup_asn_names": True},
    }

    #: rule id -> a short note shown behind the rule's name in the menu (why it is inactive, what cannot be verified)
    rule_notes: dict[str, str] = {}

    # ---------------------------------------------------------------- run
    def run(self, ctx: PluginContext) -> list[Finding]:
        if "rule_notes" not in self.__dict__:
            self.rule_notes = {}
        s = ctx.settings
        history = SignInHistory(ctx.data_dir / "signins.db")
        try:
            if history.was_reset:
                ctx.log.warning("Sign-in history schema upgraded: re-importing the baseline")
                for event_type in EVENT_TYPES:
                    ctx.state.delete(f"checkpoint:{event_type}")
            now = ctx.now()
            self._extend_baseline(ctx, history, now)
            # a refresh asked for by the user reads everything again, so that all shown data has the same age
            full, self._full_refresh = getattr(self, "_full_refresh", False), False
            self._account_sync_error = ""
            accounts = self._accounts(ctx, now, max_age=timedelta(0) if full else None)
            learning = self._seed_patterns(ctx, history, accounts, now)
            fetched, new = 0, []
            for event_type in self._event_types(s):
                n, fresh = self._ingest(ctx, history, event_type, now)
                fetched += n
                new.extend(fresh)
            self._refresh_incomplete(ctx, history, now)
            report_off = self._report_setting(ctx, now, force=full) == tenant_settings.OFF
            self._ingest_changes(ctx, history, now, reports=ctx.rule_enabled("mfa_report") and not report_off)
            history.purge(now - timedelta(days=float(s.get("retention_days", 30))),
                          now - timedelta(hours=float(s.get("non_interactive_retention_hours", 3))))

            scoring = s.get("scoring") if isinstance(s.get("scoring"), dict) else {}
            resolver = AsnNameResolver(ctx.state, enabled=bool(scoring.get("lookup_asn_names", True)))
            rc = RuleContext.build(new, history, s, now, enabled_rules=ctx.enabled_rules, asn_resolver=resolver,
                                   accounts=accounts)
            rc.learning = frozenset(learning)
            findings: list[Finding] = []
            for rule in RULES:
                if not ctx.rule_enabled(rule.meta.id) or (rule.meta.id == "mfa_report" and report_off) \
                        or rule.meta.id == "hostile_reuse":
                    continue
                try:
                    findings.extend(rule.evaluate(rc))
                except Exception:
                    ctx.log.exception("Rule %s failed", rule.meta.id)
            try:  # what these findings prove about attacker addresses is remembered and used from here on
                marked = indicators.apply(rc, findings, reuse=ctx.rule_enabled("hostile_reuse"))
                if marked:
                    ctx.log.info("%d attacker address(es) remembered: %s", len({m.value for m in marked}),
                                 ", ".join(sorted({f"{m.value} ({m.source})" for m in marked}))[:300])
            except Exception:
                ctx.log.exception("Attacker addresses could not be worked out")
            resolver.save()
            if ctx.rule_enabled("app_signins"):
                findings.extend(self._app_signins(ctx, history, now))
            ctx.state.set(DATA_AS_OF, now.isoformat())  # the sign-in history is complete up to here
            status = f"{fetched:,} sign-ins fetched, {len(new):,} new, {len(findings)} finding(s)"
            ctx.log.info(status + f" (history {history.count():,})")
            ctx.set_status(status)
            return findings
        finally:
            history.close()

    def _extend_baseline(self, ctx: PluginContext, history: SignInHistory, now: datetime) -> None:
        """If baseline_days was raised, fetch the missing older interactive sign-ins once (never treated as new)."""
        if ctx.state.get("checkpoint:interactiveUser") is None:
            return  # first run imports the full baseline anyway
        want = now - timedelta(days=min(30.0, float(ctx.settings.get("baseline_days", 30))))
        have = parse_time(ctx.state.get("baseline_from:interactiveUser") or "") if ctx.state.get(
            "baseline_from:interactiveUser") else history.oldest()
        if have is None or want >= have - timedelta(hours=1):
            return
        api = "beta" if str(ctx.settings.get("api_version", "beta")).lower() == "beta" else "v1.0"
        flt = f"createdDateTime ge {graph_time(want)} and createdDateTime le {graph_time(have)}"
        if api == "beta":
            flt += " and signInEventTypes/any(t: t eq 'interactiveUser')"
        ctx.set_status(f"Extending baseline back to {want.astimezone():%d.%m.}...")
        added = 0
        for page in ctx.graph.get_pages(f"/{api}/auditLogs/signIns", {"$filter": flt, "$top": "1000"},
                                        max_pages=int(ctx.settings.get("max_pages_per_run", 400))):
            ctx.check_cancelled()
            added += len(history.add([SignIn.from_graph(r, "interactiveUser") for r in page]))
        ctx.state.set("baseline_from:interactiveUser", want.isoformat())
        ctx.log.info("Baseline extended back to %s: %d older interactive sign-ins added", graph_time(want), added)

    @staticmethod
    def _event_types(s: dict) -> list[str]:
        if str(s.get("api_version", "beta")).lower() != "beta":
            return ["interactiveUser"]  # v1.0 only returns interactive sign-ins
        types = [t for t in s.get("event_types", []) if t in EVENT_TYPES]
        return types or ["interactiveUser"]

    def _ingest(self, ctx: PluginContext, history: SignInHistory, event_type: str,
                now: datetime) -> tuple[int, list[SignIn]]:
        s = ctx.settings
        api = "beta" if str(s.get("api_version", "beta")).lower() == "beta" else "v1.0"
        key = f"checkpoint:{event_type}"
        checkpoint = ctx.state.get(key)
        interactive = event_type == "interactiveUser"
        if checkpoint is None:
            back = (timedelta(days=float(s.get("baseline_days", 7))) if interactive
                    else timedelta(hours=float(s.get("non_interactive_initial_hours", 2))))
            since = now - back
            new_cutoff: datetime | None = now - timedelta(hours=float(s.get("initial_lookback_hours", 24)))
        else:
            # Interactive records are re-read for an hour: Entra may replace a preliminary result (e.g. 50097 ->
            # 50074) after a while, and the rules that judge MFA outcomes need the final one. Cheap (few rows).
            overlap = (s.get("interactive_overlap_minutes", 60) if interactive else s.get("overlap_minutes", 20))
            since = parse_time(checkpoint) - timedelta(minutes=float(overlap))
            new_cutoff = None
            if not interactive:
                floor = now - timedelta(hours=float(s.get("non_interactive_max_catchup_hours", 6)))
                if since < floor:
                    ctx.log.warning("Skipping %s sign-ins older than %s (catch-up limit)", event_type, floor)
                    since = floor

        flt = f"createdDateTime ge {graph_time(since)}"
        if api == "beta":
            flt += f" and signInEventTypes/any(t: t eq '{event_type}')"
        params = {"$filter": flt, "$top": "1000"}
        ctx.set_status(f"Fetching {event_type} sign-ins since {since.astimezone():%d.%m. %H:%M}...")

        newest = parse_time(checkpoint) if checkpoint else None
        fetched, fresh = 0, []
        for page in ctx.graph.get_pages(f"/{api}/auditLogs/signIns", params,
                                        max_pages=int(s.get("max_pages_per_run", 400))):
            ctx.check_cancelled()
            rows = [SignIn.from_graph(r, event_type) for r in page]
            fetched += len(rows)
            inserted = history.add(rows)
            fresh.extend(x for x in inserted if new_cutoff is None or x.created >= new_cutoff)
            for r in rows:
                if newest is None or r.created > newest:
                    newest = r.created
            if fetched and fetched % 5000 < len(rows):
                ctx.set_status(f"Fetching {event_type} sign-ins... {fetched:,}")
        ctx.state.set(key, (newest or now).isoformat())
        ctx.log.info("%s: fetched %d since %s, %d new", event_type, fetched, graph_time(since), len(fresh))
        return fetched, fresh

    # ------------------------------------------------------- log entries
    def fetch_entry(self, ctx: PluginContext, evidence_row: dict[str, str]) -> dict[str, Any] | None:
        """The full Graph sign-in record behind an evidence row.

        A filter on a +-2 min window with the event type returns in ~2 s; GET /signIns/{id} takes ~40 s
        and does not find non-interactive sign-ins.
        """
        signin_id = evidence_row.get(self.entry_id_field) or ""
        if not signin_id:
            return None
        created, event = evidence_row.get("_created"), evidence_row.get("_event")
        if not created:
            history = SignInHistory(ctx.data_dir / "signins.db")
            try:
                known = history.get(signin_id)
            finally:
                history.close()
            if known:
                created, event = known.created.isoformat(), known.event_type
        if created:
            row = self._lookup(ctx, signin_id, datetime.fromisoformat(created), event or "")
            if row:
                return row
        try:
            return ctx.graph.get(f"/beta/auditLogs/signIns/{signin_id}")
        except Exception:
            return None

    @staticmethod
    def _lookup(ctx: PluginContext, signin_id: str, when: datetime, event: str) -> dict[str, Any] | None:
        """One sign-in by id via a +-2 min filter (fast; the time of a completed record may shift a few seconds)."""
        flt = (f"createdDateTime ge {graph_time(when - timedelta(minutes=2))} and "
               f"createdDateTime le {graph_time(when + timedelta(minutes=2))} and id eq '{signin_id}'")
        if event:
            flt += f" and signInEventTypes/any(t: t eq '{event}')"
        rows = ctx.graph.get("/beta/auditLogs/signIns", {"$filter": flt}).get("value", [])
        return rows[0] if rows else None

    def _app_signins(self, ctx: PluginContext, history: SignInHistory, now: datetime) -> list[Finding]:
        """Service-principal sign-ins: judged against each app's baseline (see apps.py); errors never block the scan."""
        store = apps.AppStore(history.conn)
        key = "checkpoint:servicePrincipal"
        checkpoint = ctx.state.get(key)
        since = (parse_time(checkpoint) - timedelta(minutes=float(ctx.settings.get("overlap_minutes", 20))) if checkpoint
                 else now - timedelta(hours=float(ctx.settings.get("app_initial_hours", 24))))
        flt = f"createdDateTime ge {graph_time(since)} and signInEventTypes/any(t: t eq 'servicePrincipal')"
        rows: list[apps.AppSignIn] = []
        try:
            try:
                pages = list(ctx.graph.get_pages("/beta/auditLogs/signIns", {"$filter": flt, "$top": "1000",
                                                                             "$select": apps.SELECT}, max_pages=200))
            except GraphError as exc:
                if exc.status != 400:
                    raise
                pages = list(ctx.graph.get_pages("/beta/auditLogs/signIns", {"$filter": flt, "$top": "1000"},
                                                 max_pages=200))
            for page in pages:
                rows.extend(apps.AppSignIn.from_graph(r) for r in page)
        except Exception as exc:
            ctx.log.warning("App sign-ins not readable: %s", exc)
            return []
        fresh = store.new_rows(rows)
        findings = apps.app_findings(store, fresh, now)
        store.purge(now)
        newest = max((r.created for r in rows), default=None)
        ctx.state.set(key, (newest or now).isoformat())
        ctx.log.info("App sign-ins: %d fetched, %d new, %d finding(s)", len(rows), len(fresh), len(findings))
        return findings

    # Directory-audit sources of MFA-method / password changes (see AccountChange).
    CHANGE_FILTERS = ("loggedByService eq 'Authentication Methods'",
                      "loggedByService eq 'Self-service Password Management'",
                      "activityDisplayName eq 'Reset user password'",
                      # MFA methods that Core Directory logs (not in the Authentication Methods log)
                      "(activityDisplayName eq 'Add passwordless phone sign-in credential' or "
                      "activityDisplayName eq 'Add Passkey (device-bound)' or "
                      "activityDisplayName eq 'Add Windows Hello for Business credential' or "
                      "activityDisplayName eq 'Delete passwordless phone sign-in credential')")

    def _report_setting(self, ctx: PluginContext, now: datetime, force: bool = False) -> str:
        """Is 'Report suspicious activity' on in the tenant? (enabled / off / unknown; asked once a day.) While it
        is off nobody can report a prompt: the mfa_report rule is left out and the menu says why. When the setting
        cannot be read with this sign-in (it needs Policy.Read.All) the rule stays active."""
        if not ctx.rule_enabled("mfa_report"):
            self.rule_notes.pop("mfa_report", None)
            return tenant_settings.UNKNOWN
        cfg = ctx.settings.get("mfa_report") if isinstance(ctx.settings.get("mfa_report"), dict) else {}
        try:
            cached = json.loads(ctx.state.get("report_setting") or "{}")
        except (TypeError, ValueError):
            cached = {}
        fresh = cached.get("checked") and now - parse_time(cached["checked"]) < timedelta(
            hours=float(cfg.get("setting_check_hours", 24)))
        if force or not fresh:
            try:
                state, scope = tenant_settings.report_suspicious_activity(ctx.graph)
            except GraphError as exc:
                # not allowed to read it: unknown. Anything else (throttling ...): what was known before stays
                denied = exc.status in (401, 403)
                state = tenant_settings.UNKNOWN if denied else cached.get("state", tenant_settings.UNKNOWN)
                scope = "" if denied else cached.get("scope", "")
            except Exception:  # noqa: BLE001 - no network: nothing learned
                state, scope = cached.get("state", tenant_settings.UNKNOWN), cached.get("scope", "")
            if state != cached.get("state"):
                ctx.log.info("Tenant setting 'Report suspicious activity': %s%s", state, f" ({scope})" if scope else "")
            cached = {"state": state, "scope": scope, "checked": now.isoformat()}
            ctx.state.set("report_setting", json.dumps(cached))
        state = cached.get("state", tenant_settings.UNKNOWN)
        note = {tenant_settings.OFF: "inactive: 'Report suspicious activity' is off in Entra",
                tenant_settings.UNKNOWN: "cannot verify the Entra setting"}.get(
                    state, "on for a group only" if cached.get("scope") == "group" else "")
        if note:
            self.rule_notes["mfa_report"] = note
        else:
            self.rule_notes.pop("mfa_report", None)
        return state

    def _ingest_changes(self, ctx: PluginContext, history: SignInHistory, now: datetime, reports: bool = False) -> None:
        """Fetch MFA-method and password changes for the mfa_change rule (first run: the whole baseline), and the
        reports of MFA prompts for the mfa_report rule."""
        changes_wanted = ctx.rule_enabled("mfa_change")
        if not changes_wanted and not reports:
            return
        cfg = ctx.settings.get("mfa_report") if isinstance(ctx.settings.get("mfa_report"), dict) else {}
        names = [str(n) for n in (cfg.get("activities") or ["Suspicious activity reported"]) if "'" not in str(n)]
        report_names = {n.lower() for n in names} if reports else set()
        checkpoint = ctx.state.get("checkpoint:changes")  # time of the last fetch; audit events arrive late
        since = (parse_time(checkpoint) - timedelta(minutes=60) if checkpoint
                 else now - timedelta(days=min(30.0, float(ctx.settings.get("baseline_days", 30)))))
        wanted = [(flt, since) for flt in (self.CHANGE_FILTERS if changes_wanted else ())]
        if report_names:
            # the first time this is read (also after an update): what was reported within the rule's window
            first = not ctx.state.get("checkpoint:reports")
            wanted.append(("(" + " or ".join(f"activityDisplayName eq '{n}'" for n in names) + ")",
                           min(since, now - timedelta(hours=float(cfg.get("lookback_hours", 24)))) if first else since))
        audits: list[dict] = []
        try:
            for flt, start in wanted:
                for page in ctx.graph.get_pages("/v1.0/auditLogs/directoryAudits",
                                                {"$filter": f"activityDateTime ge {graph_time(start)} and {flt}",
                                                 "$top": "999"}, max_pages=50):
                    ctx.check_cancelled()
                    audits.extend(page)
        except Exception as exc:  # the sign-in rules must not depend on the audit log
            ctx.log.warning("Could not read MFA/password changes from the audit log: %s", exc)
            return
        if report_names:
            ctx.state.set("checkpoint:reports", now.isoformat())
        audits.sort(key=lambda a: a.get("activityDateTime") or "")
        # "User registered security info" does not name the method; the preceding "started" event does
        started: dict[str, tuple[datetime, str]] = {}
        changes = []
        for a in audits:
            if (a.get("activityDisplayName") or "").strip().lower() in report_names:
                report = AccountChange.from_report(a)
                if report:
                    changes.append(report)
                continue
            if (a.get("activityDisplayName") or "").lower() == "user started security info registration":
                method = next((str(d.get("value")) for d in a.get("additionalDetails") or []
                               if isinstance(d, dict) and d.get("key") == "AuthenticationMethod"), "")
                uid = next((t.get("id") for t in a.get("targetResources") or [] if t.get("id")), "")
                if uid and method:
                    started[uid] = (parse_time(a["activityDateTime"]), method)
                continue
            prior = started.get(next((t.get("id") for t in a.get("targetResources") or [] if t.get("id")), ""))
            method = prior[1] if prior and parse_time(a["activityDateTime"]) - prior[0] < timedelta(minutes=30) else ""
            change = AccountChange.from_audit(a, method)
            if change:
                changes.append(change)
        added = history.add_changes(changes)  # duplicates from the overlap are ignored
        ctx.state.set("checkpoint:changes", now.isoformat())
        if added:
            ctx.log.info("%d MFA-method / password change(s) recorded", added)

    def _refresh_incomplete(self, ctx: PluginContext, history: SignInHistory, now: datetime) -> None:
        """Re-read preliminary records (no UPN/network yet) until Entra has completed them.

        Without this an MFA interrupt of the user himself stays 'unknown network' and can look like an attacker
        who got past the password (error 50074 from the user's own computer is logged first without ASN/UPN).
        """
        if str(ctx.settings.get("api_version", "beta")).lower() != "beta":
            return
        hours = float(ctx.settings.get("refresh_incomplete_hours", 6))
        rows = history.incomplete(now - timedelta(hours=hours), limit=int(ctx.settings.get("refresh_incomplete_max", 10)))
        before = history.enriched
        for s in rows:
            ctx.check_cancelled()
            try:
                raw = self._lookup(ctx, s.id, s.created, s.event_type)
            except Exception as exc:  # never let this block the scan
                ctx.log.debug("Re-reading sign-in %s failed: %s", s.id, exc)
                continue
            if raw:
                history.add([SignIn.from_graph(raw, s.event_type)])
        if rows:
            ctx.log.info("Re-read %d incomplete sign-in record(s), %d completed by Entra since", len(rows),
                         history.enriched - before)

    # ---------------------------------------------------------- rescore
    def reevaluate(self, ctx: PluginContext, hours: int) -> list[Finding]:
        """Run the enabled rules again over the stored history of the last ``hours`` (no Graph calls)."""
        s = ctx.settings
        history = SignInHistory(ctx.data_dir / "signins.db")
        try:
            now = ctx.now()
            recent = history.query(now - timedelta(hours=hours), now)
            scoring = s.get("scoring") if isinstance(s.get("scoring"), dict) else {}
            resolver = AsnNameResolver(ctx.state, enabled=bool(scoring.get("lookup_asn_names", True)))
            rc = RuleContext.build(recent, history, s, now, enabled_rules=ctx.enabled_rules, asn_resolver=resolver,
                                   accounts=AccountDirectory.load(ctx.data_dir / "accounts.json"))
            findings: list[Finding] = []
            for rule in RULES:
                if ctx.rule_enabled(rule.meta.id):
                    try:
                        findings.extend(rule.evaluate(rc))
                    except Exception:
                        ctx.log.exception("Rule %s failed", rule.meta.id)
            resolver.save()
            return findings
        finally:
            history.close()

    # ---------------------------------------------------- live overview
    def ongoing(self, ctx: PluginContext, hours: float = 72) -> "overview.AttackOverview":
        """Password attacks running in the last ``hours`` - from the local history, independent of reminders."""
        history = SignInHistory(ctx.data_dir / "signins.db")
        try:
            scoring = ctx.settings.get("scoring") if isinstance(ctx.settings.get("scoring"), dict) else {}
            # the overview names every attacking network (parallel lookups, see AsnNameResolver.prefetch)
            resolver = AsnNameResolver(ctx.state, enabled=bool(scoring.get("lookup_asn_names", True)), budget=200)
            rc = RuleContext.build([], history, ctx.settings, ctx.now(), enabled_rules=ctx.enabled_rules,
                                   asn_resolver=resolver, accounts=AccountDirectory.load(ctx.data_dir / "accounts.json"))
            result = overview.ongoing_attacks(rc, hours)
            resolver.save()
            return result
        finally:
            history.close()

    # ------------------------------------------------------------ offices
    def office_suggestions(self, ctx: PluginContext, days: int = 30, min_users: int = 4, limit: int = 12) -> list[dict]:
        """Addresses many different people sign in from that are no office yet - most likely offices (or a VPN
        exit). For the first set-up of the offices; read from the local history only."""
        from . import offices
        from .rules import IpMatcher

        path = ctx.data_dir / "signins.db"
        if not path.exists():
            return []
        known = IpMatcher(offices.trusted_map(ctx.settings))
        history = SignInHistory(path)
        try:
            since = (ctx.now() - timedelta(days=days)).timestamp()
            rows = history.conn.execute(
                "SELECT ip, COUNT(DISTINCT user_id) AS users, COUNT(*) AS n, MAX(data) FROM signins "
                "WHERE error_code=0 AND ts>=? AND ip<>'' AND user_id<>'' GROUP BY ip HAVING users>=? "
                "ORDER BY users DESC LIMIT 60", (since, min_users)).fetchall()
        finally:
            history.close()
        out = []
        for ip, users, n, sample in rows:
            if ip in known:
                continue
            s = SignIn.from_json(sample)
            info = netintel.asn_info(s.asn, None)
            out.append({"ip": ip, "users": users, "signins": n, "city": s.city, "country": s.country,
                        "lat": s.lat, "lon": s.lon, "network": f"{info[0]} ({info[1]})" if info else ""})
            if len(out) >= limit:
                break
        return out

    def host_suggestions(self, ctx: PluginContext, days: int = 30) -> list[dict]:
        """Machines that look like virtual desktops / shared hosts and are not configured yet (local history only)."""
        from . import hosts, presence

        path = ctx.data_dir / "signins.db"
        if not path.exists():
            return []
        history = SignInHistory(path)
        try:
            now = ctx.now()
            rc = RuleContext.build([], history, ctx.settings, now)
            rows = history.query(now - timedelta(days=days), now, success=True)
            return hosts.suggest(rows, ctx.settings, lambda s: rc.trusted_label(s) if rc.trusted(s) else None,
                                 lambda s: presence.device_class(s) == presence.SERVICE, rc.assessor.extra_asns)
        finally:
            history.close()

    # ------------------------------------------------- age of the data / refresh on demand
    def request_full_refresh(self) -> None:
        """The next scan also re-reads the accounts (normally only every ``account_sync_hours``): after it, sign-ins
        and account data are from the same moment. Used by the Refresh buttons of the live windows."""
        self._full_refresh = True

    def data_as_of(self, ctx: PluginContext) -> datetime | None:
        """Moment up to which ALL local data is current: the older of 'sign-in history read' and 'accounts read'.
        None = nothing has been read yet."""
        stamps = []
        try:
            stamps.append(parse_time(ctx.state.get(DATA_AS_OF)) if ctx.state.get(DATA_AS_OF) else None)
        except ValueError:
            stamps.append(None)
        stamps.append(AccountDirectory.load(ctx.data_dir / "accounts.json").synced_at)
        return None if None in stamps else min(stamps)

    def refresh_error(self) -> str:
        """Why the accounts could not be re-read in the last scan ('' = they were, or it was not their turn)."""
        return getattr(self, "_account_sync_error", "")

    def exposure_report(self, ctx: PluginContext) -> Finding | None:
        """The MFA exposure report on demand (same rule as the weekly reminder, which may be switched off).

        Built from the local data without touching the network, so a window can show it at once; the caller refreshes
        the data in the background (request_full_refresh + a scan) and builds it again. None = no account without
        MFA, or no account data yet."""
        history = SignInHistory(ctx.data_dir / "signins.db")
        try:
            now = ctx.now()
            accounts = AccountDirectory.load(ctx.data_dir / "accounts.json")
            rc = RuleContext.build([], history, ctx.settings, now, accounts=accounts)
            found = rules.mfa_exposure_report(rc)
        finally:
            history.close()
        if not found:
            return None
        f = found[0]
        f.key = "mfaexposure|on-demand"
        as_of = self.data_as_of(ctx)
        f.fields = {"Data as of": as_of.astimezone().strftime("%Y-%m-%d %H:%M") if as_of else "unknown", **f.fields}
        return f

    # ---------------------------------------------------------- accounts
    def _accounts(self, ctx: PluginContext, now: datetime, max_age: timedelta | None = None) -> AccountDirectory:
        """Account directory, refreshed every ``account_sync_hours`` (or when older than ``max_age``); the last good
        copy is kept on errors (the error is remembered in ``_account_sync_error``)."""
        path = ctx.data_dir / "accounts.json"
        directory = AccountDirectory.load(path)
        if max_age is None:
            max_age = timedelta(hours=float(ctx.settings.get("account_sync_hours", 12)))
        groups = [str(g) for g in ctx.settings.get("breakglass_groups", []) or []]
        if directory.synced_at and now - directory.synced_at < max_age and directory.licenses_synced \
                and sorted(groups) == sorted(directory.breakglass_groups):
            return directory
        try:
            ctx.set_status("Reading accounts, roles and MFA exclusions...")
            fresh = sync_directory(ctx.graph, now, groups)
            fresh.save(path)
            return fresh
        except Exception as exc:  # e.g. throttling: keep working with the previous snapshot
            ctx.log.warning("Account sync failed (%s); using the snapshot from %s", exc, directory.synced_at)
            self._account_sync_error = str(exc).splitlines()[0][:160] if str(exc) else type(exc).__name__
            return directory

    def _seed_patterns(self, ctx: PluginContext, history: SignInHistory, accounts: AccountDirectory,
                       now: datetime) -> set[str]:
        """Learn the 30-day pattern of MFA-excluded accounts once, including their background sign-ins.

        Only a few hours of non-interactive sign-ins are kept locally, but service accounts and shared mailboxes
        mostly sign in non-interactively - without seeding, everything they normally do would look new.
        """
        seeded = ctx.state.get("seeded_patterns", {}) or {}
        todo = [a for a in accounts.mfa_excluded() if a.user_id not in seeded and a.enabled]
        if not todo:
            return set()
        budget = int((ctx.settings.get("mfa_exempt_watch") or {}).get("seed_accounts_per_run", 10))
        since = graph_time(now - timedelta(days=30))
        for acct in todo[:budget]:
            ctx.check_cancelled()
            ctx.set_status(f"Learning the pattern of {acct.upn}...")
            base = (f"createdDateTime ge {since} and userId eq '{acct.user_id}' and "
                    f"signInEventTypes/any(t: t eq 'nonInteractiveUser')")
            added = 0
            try:
                for flt in (base + " and status/errorCode eq 0", base):
                    try:
                        for page in ctx.graph.get_pages("/beta/auditLogs/signIns", {"$filter": flt, "$top": "1000"},
                                                        max_pages=1):
                            added += len(history.add([SignIn.from_graph(r, "nonInteractiveUser") for r in page]))
                        break
                    except Exception as exc:  # the status filter may not be supported
                        if flt != base:
                            continue
                        raise exc
            except Exception as exc:
                ctx.log.warning("Could not seed the pattern of %s: %s", acct.upn, exc)
                continue
            seeded[acct.user_id] = now.isoformat()
            ctx.log.info("Seeded pattern of %s with %d background sign-ins", acct.upn, added)
        ctx.state.set("seeded_patterns", seeded)
        return {a.user_id for a in todo if a.user_id not in seeded}  # still learning
