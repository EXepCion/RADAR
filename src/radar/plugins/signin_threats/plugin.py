"""Sign-in threat detection plugin: incremental ingestion of tenant sign-ins + detection rules."""
from __future__ import annotations

from ... import timefmt
import dataclasses
import json
from datetime import datetime, timedelta
from typing import Any, Iterator

from ... import tenant_settings
from ...graph import GraphError, page_cut
from ...plugin_api import Finding, Plugin, PluginContext, Rule, StagedState
from . import apps, enrolment, indicators, netintel, overview, registrations, rules
from .accounts import AccountDirectory, sync_directory
from .asnames import AsnNameResolver
from .history import SignInHistory
from .models import AccountChange, SignIn, graph_time, parse_time
from .rules import RULES, RuleContext

ENROLMENT_STATE = "enrolments"  # sign-ins of the enrolment service: proven ones, and those still waiting
REGISTRATION_STATE = "registrations"  # sign-ins to the registration service still waiting for their audit entry

EVENT_TYPES = ("interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity")


DATA_AS_OF = "data_as_of"  # state key: start of the last complete scan
RULE_FAILURES = "rule_failures"  # state key: rule id -> scans in a row the rule failed in
RULE_GIVE_UP = 3  # ... from this many on, a scan is complete without it (it is still tried, and the user is told)


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
        # After the PC was off: the first scan reads the last hours at once (non_interactive_max_catchup_hours), the
        # scans after it read what lies before, newest first, backlog_pages_per_run pages (of 1000) each time - up
        # to non_interactive_backlog_days back (0 = what is older than the catch-up hours is skipped).
        "non_interactive_max_catchup_hours": 6,
        "non_interactive_backlog_days": 7,
        "backlog_pages_per_run": 30,
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
        # app_server_min_accounts: an application (not Microsoft's own) that signs in for this many accounts from
        # one cloud / hosting network is its own server there, not a device abroad (0 = never assume that)
        "new_country_background": {"min_baseline_signins": 5, "app_server_min_accounts": 3},
        # a sign-in by hand from a network, address, device and client the account never used, in a known country
        "unfamiliar_signin": {"min_history_days": 7},
        # an admin role switched on (PIM), judged by where the account signed in from in the minutes before
        "role_activation": {"lookback_hours": 24, "minutes_before": 90},
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
        # network_min_accounts: a network from which the passwords of this many accounts were guessed at and nobody
        # ever signed in counts against what gets past a password from it (0 = off)
        "hostile_indicators": {"enabled": True, "days": 7, "network_min_accounts": 3},
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
        # corporate_types: what only a device of the organisation can have, in the directory's enrollmentType or
        # among its physical id marks ("DEP" = Apple's automated device enrolment, "ZTDID" = Windows Autopilot);
        # wait_minutes: how long the proof may take to show up
        "device_enrolment": {"corporate_types": list(enrolment.CORPORATE_TYPES), "wait_minutes": 30},
    }

    #: rule id -> a short note shown behind the rule's name in the menu (why it is inactive, what cannot be verified)
    rule_notes: dict[str, str] = {}

    # ---------------------------------------------------------------- run
    def run(self, ctx: PluginContext) -> list[Finding]:
        """One scan. Nothing it reads is lost when it is stopped, crashes or fails: the sign-ins it stores wait as
        "unjudged" and its bookmarks are held back (StagedState) until the findings are in the alert store
        (``ctx.when_delivered``). A scan that could not judge everything commits nothing - the next one reads
        from the same place and judges what waits, again and again until it works."""
        # (kept either way: network names looked up, and how often each rule failed - a scan that is not complete
        # must still count, or a rule that always fails would hold every scan back for good)
        staged = StagedState(ctx.state, direct=("asn_names", RULE_FAILURES))
        inner = dataclasses.replace(ctx, state=staged)  # (the same lists: incomplete, what waits for delivery)
        judged: list[str] = []
        apps_seen: list[tuple[str, float]] = []
        findings = self._scan(inner, judged, apps_seen)
        if ctx.incomplete:
            ctx.log.warning("The scan could not judge everything (%s): nothing is ticked off, the next scan judges it again",
                            "; ".join(ctx.incomplete)[:300])
            return findings
        path = ctx.data_dir / "signins.db"

        def done() -> None:
            history = SignInHistory(path)
            try:
                history.judged(judged)
                if apps_seen:
                    apps.AppStore(history.conn).remember(apps_seen)
            finally:
                history.close()
            staged.commit()

        ctx.when_delivered(done)
        return findings

    def _scan(self, ctx: PluginContext, judged: list[str], apps_seen: list[tuple[str, float]]) -> list[Finding]:
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
            owed = {t for t in self._event_types(s) if ctx.state.get(f"backlog:{t}")}  # from scans before this one
            for event_type in self._event_types(s):
                n, fresh = self._ingest(ctx, history, event_type, now)
                fetched += n
                new.extend(fresh)
            for event_type in sorted(owed):
                n, fresh = self._work_backlog(ctx, history, event_type, now)
                fetched += n
                new.extend(fresh)
            self._refresh_incomplete(ctx, history, now)
            report_off = self._report_setting(ctx, now, force=full) == tenant_settings.OFF
            self._ingest_changes(ctx, history, now, reports=ctx.rule_enabled("mfa_report") and not report_off)
            # what is judged: everything stored and not judged yet - this scan's new sign-ins, and what a scan
            # before this one stored and did not get to (it was stopped, it failed)
            keys, new = history.pending()
            judged.extend(keys)

            settled = self._settle_enrolments(ctx, history, new, now)
            new = settled.new
            scoring = s.get("scoring") if isinstance(s.get("scoring"), dict) else {}
            resolver = AsnNameResolver(ctx.state, enabled=bool(scoring.get("lookup_asn_names", True)))
            # sign-ins to the registration service wait until it is known what they were (registrations.py)
            named = self._registrations(ctx, history, new, now)
            there = {x.id for x in new}
            new = [x for x in new if x.id not in named.hold] + [x for x in named.release if x.id not in there]
            rc = RuleContext.build(new, history, s, now, enabled_rules=ctx.enabled_rules, asn_resolver=resolver,
                                   accounts=accounts, excluded=set(settled.excluded) | named.hold)
            rc.learning = frozenset(learning)
            rc.enrolments = settled.records
            rc.registrations = named.matches
            findings: list[Finding] = []
            before = ctx.state.get(RULE_FAILURES)
            failures = {k: int(v) for k, v in before.items() if ctx.rule_enabled(k)} if isinstance(before, dict) else {}
            for rule in RULES:
                if not ctx.rule_enabled(rule.meta.id) or (rule.meta.id == "mfa_report" and report_off) \
                        or rule.meta.id == "hostile_reuse":
                    continue
                try:
                    findings.extend(rule.evaluate(rc))
                    failures.pop(rule.meta.id, None)
                except Exception as exc:
                    ctx.log.exception("Rule %s failed", rule.meta.id)
                    failures[rule.meta.id] = failures.get(rule.meta.id, 0) + 1
                    if failures[rule.meta.id] >= RULE_GIVE_UP:  # it failed in the scans before too: the rest goes on
                        ctx.failing.append(f"the check '{rule.meta.name}' ({type(exc).__name__}: {exc})"[:200])
                    else:
                        ctx.incomplete.append(f"the rule '{rule.meta.name}' ({rule.meta.id}) failed: {type(exc).__name__}: {exc}"[:200])
            if failures != (before if isinstance(before, dict) else {}):
                ctx.state.set(RULE_FAILURES, failures)
            if ctx.failing:
                ctx.log.warning("Judged without what keeps failing: %s", "; ".join(ctx.failing)[:300])
            try:  # what these findings prove about attacker addresses is remembered and used from here on
                marked = indicators.apply(rc, findings, reuse=ctx.rule_enabled("hostile_reuse"))
                if marked:
                    ctx.log.info("%d attacker address(es) remembered: %s", len({m.value for m in marked}),
                                 ", ".join(sorted({f"{m.value} ({m.source})" for m in marked}))[:300])
            except Exception:
                ctx.log.exception("Attacker addresses could not be worked out")
            findings = rules.fold_same_signin(findings)  # one sign-in, one alert
            resolver.save()
            if ctx.rule_enabled("app_signins"):
                findings.extend(self._app_signins(ctx, history, now, apps_seen))
            ctx.state.set(DATA_AS_OF, now.isoformat())  # the sign-in history is complete up to here
            # (cleared after the rules: a background record read late is judged before it goes; what still waits
            # to be judged is never cleared)
            history.purge(now - timedelta(days=float(s.get("retention_days", 30))),
                          now - timedelta(hours=float(s.get("non_interactive_retention_hours", 3))))
            self._compact(ctx, history, now)
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
        added, oldest, cut = 0, None, False
        for page in ctx.graph.get_pages(f"/{api}/auditLogs/signIns", {"$filter": flt, "$top": "1000"},
                                        max_pages=int(ctx.settings.get("max_pages_per_run", 400))):
            ctx.check_cancelled()
            rows = [SignIn.from_graph(r, "interactiveUser") for r in page]
            added += len(history.add(rows))
            for r in rows:
                if oldest is None or r.created < oldest:
                    oldest = r.created
            cut = cut or page_cut(page)
        # newest first: a read the page limit cut short is complete from its oldest sign-in on - the next scan goes on
        # from there (the second it lies in is asked for again)
        reached = (oldest + timedelta(seconds=1)) if cut and oldest is not None else want
        ctx.state.set("baseline_from:interactiveUser", reached.isoformat())
        ctx.log.info("Baseline extended back to %s: %d older interactive sign-ins added%s", graph_time(reached), added,
                     f" (back to {graph_time(want)} in the scans after this one)" if reached != want else "")

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
                    self._note_backlog(ctx, event_type, since, floor, now)
                    since = floor

        flt = f"createdDateTime ge {graph_time(since)}"
        if api == "beta":
            flt += f" and signInEventTypes/any(t: t eq '{event_type}')"
        params = {"$filter": flt, "$top": "1000"}
        ctx.set_status(f"Fetching {event_type} sign-ins since {timefmt.stamp(since)}...")

        newest = parse_time(checkpoint) if checkpoint else None
        fetched, fresh, oldest, cut = 0, [], None, False
        for page in ctx.graph.get_pages(f"/{api}/auditLogs/signIns", params,
                                        max_pages=int(s.get("max_pages_per_run", 400))):
            ctx.check_cancelled()
            rows = [SignIn.from_graph(r, event_type) for r in page]
            fetched += len(rows)
            inserted = history.add(rows, unjudged=True, since=new_cutoff)  # (older: the baseline, nothing to judge)
            fresh.extend(x for x in inserted if new_cutoff is None or x.created >= new_cutoff)
            for r in rows:
                if newest is None or r.created > newest:
                    newest = r.created
                if oldest is None or r.created < oldest:
                    oldest = r.created
            cut = cut or page_cut(page)
            if fetched and fetched % 5000 < len(rows):
                ctx.set_status(f"Fetching {event_type} sign-ins... {fetched:,}")
        if cut and oldest is not None:
            # Graph lists the newest first: what the page limit left unread lies between ``since`` and the oldest one
            # read. It is owed, like the hours RADAR was not running, and read by the scans after this one. (Of a first
            # run only what is to be judged: the baseline before it is completed by _extend_baseline - up to there.)
            start = since if new_cutoff is None else max(since, new_cutoff)
            if start < oldest:
                self._note_backlog(ctx, event_type, start, oldest + timedelta(seconds=1), now,
                                   why="more than one scan reads at once")
                if new_cutoff is not None and interactive:
                    ctx.state.set("baseline_from:interactiveUser", start.isoformat())
        ctx.state.set(key, (newest or now).isoformat())
        ctx.log.info("%s: fetched %d since %s, %d new", event_type, fetched, graph_time(since), len(fresh))
        return fetched, fresh

    # ------------------------------------------------- sign-ins read afterwards (RADAR was off, or too many at once)
    def _note_backlog(self, ctx: PluginContext, event_type: str, start: datetime, end: datetime, now: datetime,
                      why: str = "while RADAR was not running") -> None:
        """Sign-ins a scan did not read - RADAR was not running for longer than it reads at once, or there were more
        than a scan reads (``why``): remember them as owed. The scans after this one read them (``_owed_pages``), so
        a scan stays quick and nothing is left out."""
        days = float(ctx.settings.get("non_interactive_backlog_days", 7))
        start = max(start, now - timedelta(days=days))
        if days <= 0 or start >= end:
            ctx.log.warning("Skipping %s sign-ins older than %s (catch-up limit)", event_type, end)
            return
        key = f"backlog:{event_type}"
        ctx.state.set(key, list(ctx.state.get(key) or []) + [[start.isoformat(), end.isoformat()]])
        ctx.log.info("%s sign-ins from %s to %s (%s) are read in the scans after this one",
                     event_type, graph_time(start), graph_time(end), why)

    def _owed_pages(self, ctx: PluginContext, event_type: str, now: datetime,
                    api: str | None = None) -> Iterator[list[dict[str, Any]]]:
        """The pages of a portion of the sign-ins owed from earlier scans (see _note_backlog): the newest gap first,
        within it from its end backwards, ``backlog_pages_per_run`` pages per scan. What is still owed is noted once
        the portion is read. ``api``: the Graph version to ask (default: the one the settings name)."""
        s = ctx.settings
        key = f"backlog:{event_type}"
        owed = ctx.state.get(key)
        if not owed:
            return
        api = api or ("beta" if str(s.get("api_version", "beta")).lower() == "beta" else "v1.0")
        pending = [list(p) for p in owed if isinstance(p, (list, tuple)) and len(p) == 2]
        budget = max(1, int(s.get("backlog_pages_per_run", 30)))
        oldest_wanted = now - timedelta(days=float(s.get("non_interactive_backlog_days", 7)))
        while pending and budget > 0:
            start, end = max(parse_time(pending[-1][0]), oldest_wanted), parse_time(pending[-1][1])
            if start >= end:
                pending.pop()
                continue
            ctx.set_status(f"Reading {event_type} sign-ins not read yet ({timefmt.stamp(start)} - {timefmt.stamp(end)})...")
            flt = f"createdDateTime ge {graph_time(start)} and createdDateTime le {graph_time(end)}"
            params = {"$filter": flt, "$top": "1000"}
            if api == "beta":  # (v1.0 lists the interactive sign-ins only, newest first as well)
                params.update({"$filter": flt + f" and signInEventTypes/any(t: t eq '{event_type}')",
                               "$orderby": "createdDateTime desc"})
            pages, oldest = 0, None
            for page in ctx.graph.get_pages(f"/{api}/auditLogs/signIns", params):
                ctx.check_cancelled()
                pages += 1
                for r in page:
                    created = parse_time(r["createdDateTime"])
                    if oldest is None or created < oldest:
                        oldest = created
                yield page
                if pages >= budget:
                    break  # this scan's portion; the rest is read by the next one
            # the portion was used up: there may be more before the oldest one read (the second it lies in is
            # asked for again; what is already stored is not counted twice)
            more = pages >= budget and oldest is not None
            budget -= max(1, pages)
            new_end = (oldest + timedelta(seconds=1)) if more else start
            if more and start < new_end < end:
                pending[-1] = [start.isoformat(), new_end.isoformat()]
                break
            pending.pop()
        ctx.state.set(key, pending)

    def _work_backlog(self, ctx: PluginContext, history: SignInHistory, event_type: str,
                      now: datetime) -> tuple[int, list[SignIn]]:
        """Read a portion of the sign-ins owed from earlier scans (see _owed_pages). What is read is kept and judged
        like any other new sign-in."""
        fetched, fresh = 0, []
        for page in self._owed_pages(ctx, event_type, now):
            rows = [SignIn.from_graph(r, event_type) for r in page]
            fetched += len(rows)
            fresh.extend(history.add(rows, unjudged=True))
        pending = ctx.state.get(f"backlog:{event_type}")
        ctx.log.info("%s: %d sign-in(s) read afterwards, %d new%s", event_type, fetched, len(fresh),
                     f"; still owed: {len(pending)} period(s)" if pending else "; nothing owed any more")
        return fetched, fresh

    def _compact(self, ctx: PluginContext, history: Any, now: datetime) -> None:
        """Once a week: let the history give back the room of what it purged (background sign-ins are stored by the
        thousand and deleted hours later; the file never shrinks by itself)."""
        last = ctx.state.get("compacted_at")
        if last and now - parse_time(last) < timedelta(days=7):
            return
        ctx.state.set("compacted_at", now.isoformat())
        try:
            freed = history.compact()
        except Exception:  # noqa: BLE001 - housekeeping must never cost a scan
            ctx.log.warning("The sign-in history could not be compacted", exc_info=True)
            return
        if freed:
            ctx.log.info("Sign-in history compacted: %.0f MB given back", freed / 1e6)

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

    def _app_signins(self, ctx: PluginContext, history: SignInHistory, now: datetime,
                     seen: list[tuple[str, float]] | None = None) -> list[Finding]:
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
            oldest = min((r.created for r in rows), default=None)
            # what earlier scans left unread (a portion of it; see _note_backlog)
            for page in self._owed_pages(ctx, "servicePrincipal", now, api="beta"):
                rows.extend(apps.AppSignIn.from_graph(r) for r in page)
        except Exception as exc:
            ctx.log.warning("App sign-ins not readable: %s", exc)
            return []
        if oldest is not None and any(page_cut(p) for p in pages) and since < oldest:
            # newest first: what the page limit left unread lies before the oldest one read - owed to the next scans
            self._note_backlog(ctx, "servicePrincipal", since, oldest + timedelta(seconds=1), now,
                               why="more than one scan reads at once")
        # (ticked off as seen only when their findings are delivered - see run)
        fresh = store.new_rows(rows, remember=seen is None)
        if seen is not None:
            seen.extend((r.id, r.created.timestamp()) for r in fresh)
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

    # An eligible admin role switched on (see the role_activation rule).
    ROLE_FILTER = "activityDisplayName eq 'Add member to role completed (PIM activation)'"

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
        roles_wanted = ctx.rule_enabled("role_activation")
        if not changes_wanted and not reports and not roles_wanted:
            return
        cfg = ctx.settings.get("mfa_report") if isinstance(ctx.settings.get("mfa_report"), dict) else {}
        names = [str(n) for n in (cfg.get("activities") or ["Suspicious activity reported"]) if "'" not in str(n)]
        report_names = {n.lower() for n in names} if reports else set()
        checkpoint = ctx.state.get("checkpoint:changes")  # time of the last fetch; audit events arrive late
        since = (parse_time(checkpoint) - timedelta(minutes=60) if checkpoint
                 else now - timedelta(days=min(30.0, float(ctx.settings.get("baseline_days", 30)))))
        wanted = [(flt, since) for flt in (self.CHANGE_FILTERS if changes_wanted else ())]
        if roles_wanted:
            # the first time (also after an update): what the rule looks back on, not the whole baseline
            cfg_roles = ctx.settings.get("role_activation") if isinstance(ctx.settings.get("role_activation"), dict) else {}
            first = not ctx.state.get("checkpoint:roles")
            wanted.append((self.ROLE_FILTER, max(now - timedelta(hours=float(cfg_roles.get("lookback_hours", 24))),
                                                 now - timedelta(days=30)) if first else since))
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
        if roles_wanted:
            ctx.state.set("checkpoint:roles", now.isoformat())
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
            ctx.log.info("%d account event(s) recorded (MFA methods, passwords, reported prompts, role activations)", added)

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

    @staticmethod
    def _directory_device(ctx: PluginContext, device_id: str) -> dict | None:
        """The directory's record of a device (what says whether it is the organisation's own), or None."""
        if not enrolment.GUID.match(device_id):
            return None
        data = ctx.graph.get("/v1.0/devices", {"$filter": f"deviceId eq '{device_id}'",
                                               "$select": enrolment.DEVICE_SELECT})
        values = (data or {}).get("value") or []
        return values[0] if values else None

    # ----------------------------------------------------- registrations
    def _registrations(self, ctx: PluginContext, history: SignInHistory, new: list[SignIn],
                       now: datetime) -> "registrations.Outcome":
        """What the sign-ins to the device registration service were, by the audit log (see registrations.py).
        The audit log is only asked while there is such a sign-in."""
        if not ctx.rule_enabled("sensitive_app"):
            return registrations.Outcome()

        def entries(since: datetime) -> list[dict]:
            found: list[dict] = []
            for page in ctx.graph.get_pages(
                    "/v1.0/auditLogs/directoryAudits",
                    {"$filter": f"activityDateTime ge {graph_time(since)} and loggedByService eq 'Device Registration Service'",
                     "$top": "999"}, max_pages=5):
                found.extend(page)
            return found

        cfg = ctx.settings.get(enrolment.RULE_ID) if isinstance(ctx.settings.get(enrolment.RULE_ID), dict) else {}
        types = [str(t) for t in (cfg.get("corporate_types") or enrolment.CORPORATE_TYPES)]
        try:
            wait = timedelta(minutes=max(1.0, float(cfg.get("wait_minutes", 30))))
        except (TypeError, ValueError):
            wait = registrations.WAIT
        try:
            state = ctx.state.get(REGISTRATION_STATE)
            out = registrations.settle(new, history, state if isinstance(state, dict) else {}, now, entries,
                                       lambda device_id: self._directory_device(ctx, device_id), types, wait)
            if out.state != (state or {}):
                ctx.state.set(REGISTRATION_STATE, out.state)
            return out
        except Exception:  # never let this stop the scan
            ctx.log.exception("Device registrations could not be matched with the audit log")
            return registrations.Outcome()

    # -------------------------------------------------------- enrolments
    def _settle_enrolments(self, ctx: PluginContext, history: SignInHistory, new: list[SignIn],
                           now: datetime) -> "enrolment.Outcome":
        """Sign-ins of the device enrolment service: a record when the device they produced proves a corporate
        enrolment, held back while that may still show up, judged like any other otherwise (see enrolment.py).
        The audit log and the directory are only asked while such a sign-in is waiting."""
        unchanged = enrolment.Outcome(new, set(), {})
        if not ctx.rule_enabled(enrolment.RULE_ID):
            return unchanged
        cfg = ctx.settings.get(enrolment.RULE_ID) if isinstance(ctx.settings.get(enrolment.RULE_ID), dict) else {}
        types = [str(t) for t in (cfg.get("corporate_types") or enrolment.CORPORATE_TYPES)]
        try:
            wait = timedelta(minutes=max(1.0, float(cfg.get("wait_minutes", 30))))
        except (TypeError, ValueError):
            wait = enrolment.WAIT

        def registrations(since: datetime) -> list[dict]:
            found: list[dict] = []
            for page in ctx.graph.get_pages(
                    "/v1.0/auditLogs/directoryAudits",
                    {"$filter": f"activityDateTime ge {graph_time(since)} and activityDisplayName eq 'Register device'",
                     "$top": "999"}, max_pages=5):
                found.extend(page)
            return found

        def device(device_id: str) -> dict | None:
            return self._directory_device(ctx, device_id)

        try:
            state = ctx.state.get(ENROLMENT_STATE)
            out = enrolment.settle(new, history, state if isinstance(state, dict) else {}, now, registrations, device,
                                   types, wait)
            if out.state != state:
                ctx.state.set(ENROLMENT_STATE, out.state)
            if out.records:
                ctx.log.info("%d corporate device enrolment(s) recognised: their sign-ins are not judged", len(out.records))
            return out
        except Exception:  # never let this stop the scan: everything is judged as usual
            ctx.log.exception("Device enrolments could not be worked out")
            return unchanged

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
            known = ctx.state.get(ENROLMENT_STATE) if ctx.rule_enabled(enrolment.RULE_ID) else None
            known = known if isinstance(known, dict) else {}
            rc = RuleContext.build(recent, history, s, now, enabled_rules=ctx.enabled_rules, asn_resolver=resolver,
                                   accounts=AccountDirectory.load(ctx.data_dir / "accounts.json"),
                                   excluded=set(known.get("explained") or {}) | set(known.get("held") or {}))
            findings: list[Finding] = []
            for rule in RULES:
                if ctx.rule_enabled(rule.meta.id):
                    try:
                        findings.extend(rule.evaluate(rc))
                    except Exception:
                        ctx.log.exception("Rule %s failed", rule.meta.id)
            resolver.save()
            return rules.fold_same_signin(findings)
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
        f.fields = {"Data as of": timefmt.sortable(as_of) if as_of else "unknown", **f.fields}
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
            try:
                fresh.save(path)
            except OSError as exc:  # (the file stayed in use): what was read is used all the same
                ctx.log.warning("Accounts read, but not saved (%s): this scan uses them, the next one reads them again", exc)
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
