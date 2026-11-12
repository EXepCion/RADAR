"""One tenant per installation, the token only for Microsoft Graph, plugins only when allowed, old alerts removed."""
import base64
import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from radar import tenant
from radar.alerts import AlertCenter
from radar.auth import AuthManager, TenantChangedError
from radar.config import ConfigManager
from radar.graph import GraphClient, GraphError
from radar.plugin_api import Finding, Severity
from radar.plugin_manager import PluginManager
from radar.store import Store

T1 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
T2 = "11111111-2222-3333-4444-555555555555"


def token_for(tid: str, upn: str = "admin@contoso.com") -> dict:
    body = base64.urlsafe_b64encode(json.dumps({"tid": tid, "upn": upn}).encode()).decode().rstrip("=")
    return {"access_token": f"x.{body}.y", "expires_in": 3600}


# ------------------------------------------------------------------ tenant
def test_the_first_tenant_is_adopted_and_another_one_is_turned_away(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    assert tenant.known(cfg) == "" and tenant.allows(cfg, T1.upper()) and tenant.known(cfg) == T1
    assert tenant.allows(cfg, T1) and not tenant.allows(cfg, T2) and tenant.known(cfg) == T1
    assert tenant.allows(cfg, "")  # a token without tenant claim decides nothing

    auth = AuthManager(cfg, tmp_path / "cache.bin", tenant_guard=lambda tid: tenant.allows(cfg, tid))
    assert auth._accept(token_for(T1)) and auth.state == "ok" and auth.tenant_id == T1
    with pytest.raises(TenantChangedError) as caught:
        auth._accept(token_for(T2, "admin@fabrikam.com"))
    assert "another tenant" in str(caught.value) and T2 in str(caught.value)
    assert auth.state == "other_tenant" and auth.other_tenant == T2 and auth.account == "admin@fabrikam.com"
    assert auth._token is None  # nothing can be read with it
    assert auth._accept(token_for(T1)) and auth.state == "ok" and auth.other_tenant is None  # back in the own tenant


def test_fresh_start_moves_the_stored_data_into_the_archive(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    tenant.allows(cfg, T1)
    (tmp_path / "radar.db").write_text("alerts")
    (tmp_path / "plugin-data" / "signin_threats").mkdir(parents=True)
    (tmp_path / "plugin-data" / "signin_threats" / "signins.db").write_text("history")
    (tmp_path / "token_cache.bin").write_text("token")
    assert tenant.apply_pending(cfg, tmp_path, tmp_path / "config.json") is None  # nothing asked for: nothing happens
    assert (tmp_path / "radar.db").exists()

    name = tenant.request_fresh_start(cfg, T2.upper(), now=datetime(2030, 1, 2, 3, 4, 5))
    assert name == f"{T1}-20300102-030405" and tenant.pending(cfg) == T2
    target = tenant.apply_pending(ConfigManager(tmp_path / "config.json"), tmp_path, tmp_path / "config.json")
    assert target == tmp_path / "archive" / name
    assert (target / "radar.db").read_text() == "alerts"
    assert (target / "plugin-data" / "signin_threats" / "signins.db").read_text() == "history"
    assert (target / "config.json").exists()
    assert not (tmp_path / "radar.db").exists() and not (tmp_path / "plugin-data").exists()
    assert (tmp_path / "token_cache.bin").exists() and (tmp_path / "config.json").exists()  # sign-in and settings stay
    after = ConfigManager(tmp_path / "config.json")
    assert tenant.known(after) == T2 and tenant.pending(after) == "" and tenant.allows(after, T2) and not tenant.allows(after, T1)


def test_fresh_start_waits_when_a_file_is_in_use(tmp_path, monkeypatch):
    cfg = ConfigManager(tmp_path / "config.json")
    tenant.allows(cfg, T1)
    (tmp_path / "radar.db").write_text("alerts")
    tenant.request_fresh_start(cfg, T2)
    monkeypatch.setattr("pathlib.Path.rename", lambda self, target: (_ for _ in ()).throw(PermissionError("in use")))
    assert tenant.apply_pending(cfg, tmp_path, wait=0) is None
    assert tenant.known(cfg) == T1 and tenant.pending(cfg) == T2  # still the old tenant's data: tried again next start


# ------------------------------------------------------------------- graph
def test_the_token_is_only_sent_to_microsoft_graph():
    sent = []

    class Session:
        headers: dict = {}

        def get(self, url, params=None, timeout=None, headers=None):
            sent.append((url, headers["Authorization"]))
            nxt = {"@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=2"} if "skiptoken" not in url else {}
            return SimpleNamespace(status_code=200, json=lambda: {"value": [1], **nxt}, headers={}, text="")

    g = GraphClient(SimpleNamespace(get_token=lambda force_refresh=False: "secret"), threading.Event())
    g._session = Session()
    assert list(g.get_all("/v1.0/users")) == [1, 1] and len(sent) == 2 and sent[1][0].endswith("skiptoken=2")
    assert GraphClient._url("v1.0/me") == "https://graph.microsoft.com/v1.0/me"
    for bad in ("https://evil.example/v1.0/users", "http://graph.microsoft.com/v1.0/users",
                "https://graph.microsoft.com.evil.example/x", "https://graph.microsoft.com@evil.example/x",
                "https://user:pw@graph.microsoft.com/x", "https://graph.microsoft.com:8443/x", "ftp://graph.microsoft.com/x"):
        with pytest.raises(GraphError) as caught:
            g.get(bad)
        assert caught.value.code == "untrusted_url", bad
    assert len(sent) == 2  # nothing left the program


# ----------------------------------------------------------------- plugins
MARKER_PLUGIN = '''
from pathlib import Path
Path(r"{marker}").write_text("ran")
from radar.plugin_api import Plugin
class P(Plugin):
    id = "marked"
    def run(self, ctx):
        return []
'''


def test_a_user_plugin_is_not_even_imported_before_it_is_allowed(tmp_path):
    user_dir = tmp_path / "plugins"
    user_dir.mkdir()
    marker = tmp_path / "marker.txt"
    (user_dir / "marked.py").write_text(MARKER_PLUGIN.format(marker=marker), encoding="utf-8")
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=user_dir, stop_event=threading.Event())
    pm.discover()
    assert pm.unapproved == ["marked.py"] and "marked" not in pm.runtimes and not pm.load_errors
    assert not marker.exists()  # its code did not run
    pm.allow_user_plugin("marked.py")
    pm.discover()
    assert pm.unapproved == [] and "marked" in pm.runtimes and marker.read_text() == "ran"
    assert cfg.get("general", "allowed_user_plugins") == ["marked.py"]


# --------------------------------------------------------------- retention
def test_old_dismissed_alerts_are_removed_and_open_ones_stay():
    from radar.app import App

    now = datetime.now(timezone.utc)
    center = AlertCenter(Store(":memory:"))

    for key in ("old-dismissed", "old-open", "recent-dismissed"):
        center.ingest("p", [Finding(key=key, title=key, severity=Severity.MEDIUM, summary="s")])
    ids = {row["key"].split(":")[-1]: row["id"] for row in center._store.query("SELECT id, key FROM alerts")}
    center.dismiss([ids["old-dismissed"], ids["recent-dismissed"]])
    old = (now - timedelta(days=120)).isoformat()
    center._store.execute("UPDATE alerts SET last_seen=? WHERE id IN (?,?)", (old, ids["old-dismissed"], ids["old-open"]))

    app = SimpleNamespace(alerts=center, cfg=SimpleNamespace(get=lambda *a, default=None: 90),
                          ui_call=lambda *a: None, _refresh_history_if_open=lambda: None)
    assert App.purge_old_alerts(app) == 1
    left = {row["key"].split(":")[-1] for row in center._store.query("SELECT key FROM alerts")}
    assert left == {"old-open", "recent-dismissed"}
    assert App.purge_old_alerts(app) == 0
