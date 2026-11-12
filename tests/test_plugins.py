import json
import threading
from pathlib import Path

from radar.config import ConfigManager
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import SignInThreatsPlugin
from radar.plugins.signin_threats.models import SignIn
from radar.store import Store

GOOD_PLUGIN = '''
from radar.plugin_api import Plugin, Rule, Finding, Severity

class Hello(Plugin):
    id = "hello"
    name = "Hello plugin"
    default_enabled = False
    rules = [Rule("r1", "Rule one"), Rule("r2", "Rule two", default_enabled=False)]
    default_settings = {"greeting": "hi"}

    def run(self, ctx):
        return [Finding(key="hello|1", title=ctx.settings["greeting"], severity=Severity.LOW,
                        summary=",".join(sorted(ctx.enabled_rules)))]
'''


def manager(tmp_path, plugins: dict[str, str]):
    user_dir = tmp_path / "plugins"
    user_dir.mkdir()
    for name, code in plugins.items():
        (user_dir / name).write_text(code, encoding="utf-8")
    cfg = ConfigManager(tmp_path / "config.json")
    cfg.set("general", "allowed_user_plugins", value=list(plugins))  # the user said yes to each
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=user_dir,
                       stop_event=threading.Event())
    pm.discover()
    return pm, cfg


def test_builtin_and_user_plugins_load_and_broken_plugin_is_isolated(tmp_path):
    pm, cfg = manager(tmp_path, {"hello.py": GOOD_PLUGIN, "broken.py": "raise RuntimeError('boom')",
                                 "_ignored.py": "raise SystemExit"})
    assert {"signin_threats", "directory_audit", "hello"} <= set(pm.runtimes)
    assert len(pm.load_errors) == 1 and "boom" in pm.load_errors[0].error
    data = json.loads((tmp_path / "config.json").read_text())
    assert data["plugins"]["hello"] == {"enabled": False, "interval_minutes": 15,
                                        "rules": {"r1": True, "r2": False}, "settings": {"greeting": "hi"}}
    assert data["plugins"]["signin_threats"]["enabled"] is True
    assert data["plugins"]["directory_audit"]["enabled"] is False


def test_shipped_template_plugin_loads(tmp_path):
    template = Path(__file__).resolve().parents[1] / "templates" / "example_plugin.py"
    pm, _ = manager(tmp_path, {"risky_users.py": template.read_text(encoding="utf-8")})
    assert not pm.load_errors
    assert pm.get("risky_users").plugin.rules[0].id == "at_risk"


def test_toggle_plugin_and_rules_persist_and_reach_context(tmp_path):
    pm, cfg = manager(tmp_path, {"hello.py": GOOD_PLUGIN})
    pm.set_enabled("hello", True)
    pm.set_rule_enabled("hello", "r2", True)
    pm.set_rule_enabled("hello", "r1", False)
    assert ConfigManager(tmp_path / "config.json").get("plugins", "hello", "enabled") is True
    findings = pm.run("hello")
    assert findings[0].summary == "r2"
    assert pm.get("hello").last_findings == 1


def test_config_keeps_user_values_and_adds_new_defaults(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"general": {"play_sound": False}}), encoding="utf-8")
    cfg = ConfigManager(path)
    assert cfg.get("general", "play_sound") is False
    assert cfg.get("general", "tick_seconds") == 30
    assert cfg.get("auth", "authority").startswith("https://login.microsoftonline.com/")  # a default that was added


def test_invalid_config_is_backed_up(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    cfg = ConfigManager(path)
    assert cfg.get("general", "paused") is False
    assert list(tmp_path.glob("config.invalid-*.json"))


class FakeGraph:
    def __init__(self, pages_by_type):
        self.pages_by_type = pages_by_type
        self.calls = []

    def get_pages(self, path, params=None, max_pages=None):
        self.calls.append(params["$filter"])
        for et, pages in self.pages_by_type.items():
            if et in params["$filter"]:
                yield from pages


def _raw(i, minutes_ago, now, **kw):
    from datetime import timedelta
    d = {"id": f"id{i}", "createdDateTime": (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z"),
         "userId": "u1", "userPrincipalName": "Alice@contoso.com", "ipAddress": "203.0.113.9",
         "status": {"errorCode": 50126}, "location": {"countryOrRegion": "CA"}, "clientAppUsed": "Browser",
         "isInteractive": True}
    d.update(kw)
    return d


def test_signin_plugin_first_run_baseline_then_incremental(tmp_path):
    from datetime import datetime, timezone

    pm, cfg = manager(tmp_path, {})
    now = datetime.now(timezone.utc)
    spray = [_raw(i, 30 + i, now, userId=f"u{i}", userPrincipalName=f"user{i}@contoso.com") for i in range(6)]
    old = [_raw(100 + i, 60 * 48 + i, now, userId=f"u{i}") for i in range(6)]  # 2 days old: baseline only
    fake = FakeGraph({"interactiveUser": [spray + old], "nonInteractiveUser": [[]]})
    ctx = pm.build_context("signin_threats")
    ctx.graph = fake
    findings = SignInThreatsPlugin().run(ctx)
    assert [f.rule_id for f in findings] == ["password_spray"]
    assert ctx.state.get("checkpoint:interactiveUser")
    assert len([c for c in fake.calls if "signInEventTypes" in c and "servicePrincipal" not in c]) == 2
    assert len([c for c in fake.calls if "'servicePrincipal'" in c]) == 1  # app sign-ins
    assert len([c for c in fake.calls if c.startswith("activityDateTime")]) == 4  # MFA/password change audits

    # second run: same data again -> nothing new, no findings
    ctx2 = pm.build_context("signin_threats")
    ctx2.graph = FakeGraph({"interactiveUser": [spray], "nonInteractiveUser": [[]]})
    assert SignInThreatsPlugin().run(ctx2) == []


def test_preliminary_records_are_re_read_until_entra_completes_them(tmp_path):
    from datetime import datetime, timezone

    from radar.plugins.signin_threats.history import SignInHistory

    pm, _ = manager(tmp_path, {})
    now = datetime.now(timezone.utc)
    prelim = _raw(1, 20, now, userPrincipalName=None, location={}, status={"errorCode": 50074})
    final = dict(prelim, userPrincipalName="Alice@contoso.com", autonomousSystemNumber=55430,
                 location={"city": "Singapore", "countryOrRegion": "SG"})

    class Graph(FakeGraph):
        def __init__(self, record):
            super().__init__({"interactiveUser": [[prelim]], "nonInteractiveUser": [[]]})
            self.record, self.lookups = record, []

        def get(self, path, params=None):
            self.lookups.append(params["$filter"])
            return {"value": [self.record]}

    ctx = pm.build_context("signin_threats")
    ctx.graph = Graph(prelim)  # Entra has not completed it yet
    SignInThreatsPlugin().run(ctx)
    assert len(ctx.graph.lookups) == 1 and "id eq 'id1'" in ctx.graph.lookups[0]
    ctx = pm.build_context("signin_threats")
    ctx.graph = Graph(final)
    SignInThreatsPlugin().run(ctx)
    h = SignInHistory(ctx.data_dir / "signins.db")
    stored = h.get("id1")
    assert (stored.upn, stored.asn, stored.country) == ("alice@contoso.com", 55430, "SG")
    h.close()
    ctx = pm.build_context("signin_threats")
    ctx.graph = Graph(final)
    SignInThreatsPlugin().run(ctx)
    assert ctx.graph.lookups == []  # complete now: no more re-reads


def test_fetch_entry_uses_fast_time_window_query(tmp_path):
    pm, _ = manager(tmp_path, {})
    calls = []

    class Graph:
        def get(self, path, params=None):
            calls.append((path, params))
            return {"value": [{"id": "abc", "userPrincipalName": "x@contoso.com"}]}

    ctx = pm.build_context("signin_threats")
    ctx.graph = Graph()
    row = {"Sign-in ID": "abc", "_created": "2026-11-09T10:00:00+00:00", "_event": "nonInteractiveUser"}
    assert SignInThreatsPlugin().fetch_entry(ctx, row)["id"] == "abc"
    path, params = calls[0]
    assert path == "/beta/auditLogs/signIns"
    flt = params["$filter"]
    assert "createdDateTime ge 2026-11-09T09:58:00Z" in flt and "createdDateTime le 2026-11-09T10:02:00Z" in flt
    assert "id eq 'abc'" in flt and "t eq 'nonInteractiveUser'" in flt


def test_signin_model_parses_graph_record():
    s = SignIn.from_graph({
        "id": "x", "createdDateTime": "2026-11-09T10:11:12.1234567Z", "userPrincipalName": "Bob@Contoso.com",
        "status": {"errorCode": 0}, "location": {"city": "Toronto", "countryOrRegion": "ca",
                                                   "geoCoordinates": {"latitude": 43.7, "longitude": -79.4}},
        "riskEventTypes_v2": ["none"], "isInteractive": False,
    }, "nonInteractiveUser")
    assert s.upn == "bob@contoso.com" and s.country == "CA" and s.success and not s.interactive
    assert s.risk_events == []
    assert SignIn.from_json(s.to_json()) == s
