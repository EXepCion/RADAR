"""A bookmark only moves when what was read up to it is in the alert store. A scan that is stopped, crashes or fails
after it has stored sign-ins must not lose them: the next scan judges them - and it never gives up on them."""
import threading
from datetime import datetime, timedelta, timezone

import pytest

from radar.config import ConfigManager
from radar.plugin_api import OperationCancelled
from radar.plugin_manager import PluginManager
from radar.plugins.directory_audit import DirectoryAuditPlugin
from radar.plugins.signin_threats import SignInThreatsPlugin, rules
from radar.store import Store

from conftest import T0, make_signin

NOW = datetime.now(timezone.utc)


def manager(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "plugins",
                       stop_event=threading.Event())
    pm.discover()
    return pm


def raw(i, minutes_ago, **kw):
    d = {"id": f"id{i}", "createdDateTime": (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z"),
         "userId": f"u{i}", "userPrincipalName": f"user{i}@contoso.com", "ipAddress": "203.0.113.9",
         "status": {"errorCode": 50126}, "location": {"countryOrRegion": "CA"}, "clientAppUsed": "Browser",
         "isInteractive": True}
    d.update(kw)
    return d


SPRAY = [raw(i, 30 + i) for i in range(6)]   # six accounts, one address, wrong passwords: a password spray


class Graph:
    def __init__(self, interactive, fail_after_pages=None):
        self.interactive, self.fail_after_pages = interactive, fail_after_pages

    def get_pages(self, path, params=None, max_pages=None):
        if "interactiveUser" in params["$filter"] and "nonInteractiveUser" not in params["$filter"]:
            for n, page in enumerate(self.interactive):
                if self.fail_after_pages is not None and n >= self.fail_after_pages:
                    raise RuntimeError("the connection dropped")
                yield page

    def get(self, path, params=None):
        return {"value": []}


def scan(pm, graph, defer=False):
    ctx = pm.build_context("signin_threats", defer=defer)
    ctx.graph = graph
    return ctx, SignInThreatsPlugin().run(ctx)


def spray_found(findings):
    return [f.rule_id for f in findings if f.rule_id == "password_spray"]


def test_a_test_that_undoes_its_patches_still_never_touches_the_installed_radar(monkeypatch):
    """(It happened: ``monkeypatch.undo()`` also undid the test's own data folder.)"""
    import os
    from pathlib import Path

    from radar import paths

    monkeypatch.undo()
    real = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "RADAR"
    assert os.environ.get("RADAR_HOME") and paths.data_dir().resolve() != real.resolve()


def test_what_a_scan_writes_is_held_back_until_it_is_delivered_except_what_it_only_looked_up():
    from radar.plugin_api import PluginState, StagedState

    real = PluginState(Store(":memory:"), "x")
    real.set("old", 1)
    staged = StagedState(real, direct=("asn_names",))
    staged.set("checkpoint", "t1")
    staged.delete("old")
    staged.set("asn_names", {"64500": "Example"})
    assert staged.get("checkpoint") == "t1" and staged.get("old") is None            # the scan sees what it wrote
    assert real.get("checkpoint") is None and real.get("old") == 1                   # nothing moved yet
    assert real.get("asn_names") == {"64500": "Example"}                           # a looked-up name is kept at once
    staged.commit()
    assert real.get("checkpoint") == "t1" and real.get("old") is None


# -------------------------------------------------------------------------------- the history
def test_stored_sign_ins_wait_to_be_judged_until_that_is_confirmed(history):
    a, b = make_signin(0, id="A", asn=812), make_signin(1, id="B", asn=812, interactive=False)
    history.add([a, b], unjudged=True)
    history.add([make_signin(2, id="C", asn=812)])                        # (stored for the baseline: nothing to judge)
    keys, waiting = history.pending()
    assert sorted(s.id for s in waiting) == ["A", "B"]
    # what waits is not cleared with the old background sign-ins
    history.purge(T0 - timedelta(days=30), T0 + timedelta(hours=1))
    assert sorted(s.id for s in history.pending()[1]) == ["A", "B"]
    history.judged(keys)
    assert history.pending() == ([], [])
    history.purge(T0 - timedelta(days=30), T0 + timedelta(hours=1))
    assert history.get("B") is None and history.get("A") is not None       # judged: cleared like any other


def test_forgetting_what_a_sign_in_brought_twice_takes_it_out_once(history):
    own = [make_signin(-10, id="O1", asn=812, country="CA"), make_signin(-5, id="O2", asn=812, country="CA")]
    history.add(own)
    history.forget([own[0]])
    history.forget([own[0]])                                               # a scan that ran again
    assert history.user_asns("u1", T0 + timedelta(days=1)) == {812}        # the user's other sign-in still counts


# --------------------------------------------------------------- the sign-in scan, interrupted
def test_a_scan_stopped_after_storing_is_judged_by_the_next_one(tmp_path, monkeypatch):
    pm = manager(tmp_path)

    def stopped(*_a, **_k):
        raise OperationCancelled()

    with monkeypatch.context() as m:                                       # RADAR is closed right after the reading
        m.setattr(SignInThreatsPlugin, "_ingest_changes", stopped)
        with pytest.raises(OperationCancelled):
            scan(pm, Graph([SPRAY]))
    ctx, findings = scan(pm, Graph([SPRAY]))                               # Entra returns the same again: nothing "new"
    assert spray_found(findings) == ["password_spray"]
    _ctx, again = scan(pm, Graph([SPRAY]))
    assert spray_found(again) == []                                        # ... and once only


def test_a_scan_that_fails_in_the_middle_of_reading_loses_nothing(tmp_path):
    pm = manager(tmp_path)
    with pytest.raises(RuntimeError):
        scan(pm, Graph([SPRAY[:3], SPRAY[3:]], fail_after_pages=1))         # the first page is stored, then it breaks
    ctx, findings = scan(pm, Graph([SPRAY[:3], SPRAY[3:]]))
    assert spray_found(findings) == ["password_spray"]                     # all six, the three of before among them


def test_the_bookmark_moves_only_when_the_findings_were_delivered(tmp_path):
    pm = manager(tmp_path)
    ctx, findings = scan(pm, Graph([SPRAY]), defer=True)                   # the app takes the findings ...
    assert spray_found(findings) == ["password_spray"]
    assert ctx.state.get("checkpoint:interactiveUser") is None             # ... and until it has stored them: nothing moved
    ctx, findings = scan(pm, Graph([SPRAY]), defer=True)                   # (it never did - it was closed)
    assert spray_found(findings) == ["password_spray"]                     # the next scan says it again
    ctx.delivered()
    assert ctx.state.get("checkpoint:interactiveUser")
    _ctx, after = scan(pm, Graph([SPRAY]), defer=True)
    assert spray_found(after) == []


def test_a_rule_that_fails_keeps_the_scan_open(tmp_path, monkeypatch):
    """Never give up: what a rule could not judge is judged again by the next scan, and the scan says it is incomplete."""
    pm = manager(tmp_path)

    def broken(_rc):
        raise ValueError("a bug")

    from radar.plugins.signin_threats import plugin as plugin_module

    patched = [rules.RuleDef(rd.meta, broken) if rd.meta.id == "password_spray" else rd for rd in rules.RULES]
    with monkeypatch.context() as m:
        m.setattr(plugin_module, "RULES", patched)
        ctx, findings = scan(pm, Graph([SPRAY]))
        assert spray_found(findings) == [] and any("password_spray" in p for p in ctx.incomplete)
        assert ctx.state.get("checkpoint:interactiveUser") is None
    ctx, findings = scan(pm, Graph([SPRAY]))
    assert spray_found(findings) == ["password_spray"] and ctx.incomplete == []


def test_the_plugin_manager_commits_for_callers_that_do_not_deliver_themselves(tmp_path):
    pm = manager(tmp_path)
    pm._graph_factory = lambda: Graph([SPRAY])
    assert spray_found(pm.run("signin_threats")) == ["password_spray"]
    assert spray_found(pm.run("signin_threats")) == []                      # committed at once


def test_the_plugin_manager_holds_the_commit_back_for_a_caller_that_delivers(tmp_path):
    pm2 = manager(tmp_path)
    pm2._graph_factory = lambda: Graph([SPRAY])
    assert spray_found(pm2.run("signin_threats", defer=True)) == ["password_spray"]
    assert spray_found(pm2.run("signin_threats", defer=True)) == ["password_spray"]   # not delivered: said again
    pm2.delivered("signin_threats")
    assert spray_found(pm2.run("signin_threats", defer=True)) == []


# ------------------------------------------------------------------------- the audit watch
def audit_entry(i, minutes_ago):
    return {"id": f"a{i}", "activityDateTime": (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "activityDisplayName": "Add member to role", "category": "RoleManagement", "result": "success",
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com", "id": "admin-id"}}, "correlationId": f"c{i}",
            "targetResources": [{"type": "User", "id": "u9", "userPrincipalName": "eve@contoso.com",
                                 "modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": '"Global Administrator"'}]}]}


class AuditGraph:
    def __init__(self, events):
        self.events = events

    def get_all(self, path, params=None, max_pages=None):
        yield from self.events

    def get(self, path, params=None):
        raise RuntimeError(path)


def audit_scan(pm, defer=False):
    ctx = pm.build_context("directory_audit", defer=defer)
    ctx.graph = AuditGraph([audit_entry(1, 120)])                           # two hours old: outside the re-read overlap
    return ctx, DirectoryAuditPlugin().run(ctx)


def test_the_audit_watch_reads_again_what_was_not_delivered(tmp_path, monkeypatch):
    pm = manager(tmp_path)

    def broken(*_a, **_k):
        raise RuntimeError("lookup failed")

    with monkeypatch.context() as m:                                        # fails after the entries were read
        m.setattr(DirectoryAuditPlugin, "_add_app_origins", broken)
        with pytest.raises(RuntimeError):
            audit_scan(pm)
    ctx, findings = audit_scan(pm, defer=True)
    assert [f.rule_id for f in findings if f.rule_id == "role_assignment"] == ["role_assignment"]
    assert ctx.state.get("checkpoint") is None                              # not delivered yet
    ctx.delivered()
    assert ctx.state.get("checkpoint")
