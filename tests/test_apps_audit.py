"""App sign-ins (service principals) and the audit watches."""
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from radar import chains
from radar.alerts import AlertCenter
from radar.config import ConfigManager
from radar.plugin_api import Finding, Severity
from radar.plugin_manager import PluginManager
from radar.plugins.signin_threats import apps
from radar.plugins.signin_threats.apps import AppSignIn, AppStore, app_findings
from radar.plugins.signin_threats.models import AccountChange
from radar.store import Store

T = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def sp(i, hours, app="Cronofy", sp_id="sp1", ip="3.120.0.5", country="DE", code=0, key="k1"):
    return AppSignIn(id=f"{sp_id}-{i}-{hours}", created=T + timedelta(hours=hours), sp_id=sp_id, app=app, ip=ip,
                     country=country, error_code=code, key_id=key,
                     failure_reason="Invalid client secret provided." if code else "")


def store_with_baseline(days=5):
    s = AppStore(sqlite3.connect(":memory:"))
    s.learn([sp(i, -24 * days + i) for i in range(20)])
    return s


def test_stable_app_is_quiet_and_new_country_is_medium():
    s = store_with_baseline()
    assert app_findings(s, [sp(1, 0), sp(2, 0.1)], T) == []
    out = app_findings(s, [sp(3, 1, ip="45.9.9.9", country="US")], T + timedelta(hours=1))
    assert len(out) == 1 and out[0].severity == Severity.MEDIUM and "new country" in out[0].title
    assert out[0].subjects == ["app:cronofy"]


def test_new_credential_and_new_range_and_learning_period():
    s = store_with_baseline()
    out = {f.key.split("|")[0]: f for f in app_findings(s, [sp(1, 0, key="k2"), sp(2, 0, ip="3.121.7.7")], T)}
    assert out["appkey"].severity == Severity.LOW and "new credential" in out["appkey"].title
    assert out["appnet"].severity == Severity.INFO
    young = AppStore(sqlite3.connect(":memory:"))
    young.learn([sp(i, -24 + i) for i in range(5)])  # seen for one day only: still learning
    assert app_findings(young, [sp(9, 0, country="US", ip="45.9.9.9")], T) == []


def test_failing_credential_low_versus_guessing_from_new_ips_medium():
    vpn = AppStore(sqlite3.connect(":memory:"))  # never succeeded (VPN_Branch_Office)
    fails = [sp(i, i / 60, app="VPN_Branch_Office", sp_id="vpn", ip="192.0.2.181", country="", code=7000215)
             for i in range(60)]
    f = app_findings(vpn, fails, T + timedelta(hours=1))[0]
    assert f.severity == Severity.LOW and "credential failing" in f.title and "invalid client secret (60)" in f.title
    assert "has not signed in successfully at all" in f.summary
    s = store_with_baseline()
    tries = [sp(i, i / 60, ip=f"91.200.{i}.1", country="RU", code=7000215) for i in range(60)]
    g = app_findings(s, tries, T + timedelta(hours=1))[0]
    assert g.severity == Severity.MEDIUM and g.title.startswith("Someone is trying the credentials of app Cronofy")


def test_overlapping_fetch_is_processed_once():
    s = AppStore(sqlite3.connect(":memory:"))
    rows = [sp(1, 0), sp(2, 0)]
    assert len(s.new_rows(rows)) == 2 and s.new_rows(rows + [sp(3, 0)]) == [sp(3, 0)]


def test_core_directory_mfa_events_are_changes():
    a = {"id": "x1", "activityDateTime": "2026-11-09T10:00:00Z", "activityDisplayName": "Add Passkey (device-bound)",
         "result": "success", "resultReason": "",
         "initiatedBy": {"user": {"id": "u1", "userPrincipalName": "bill.m@contoso.com"}},
         "targetResources": [{"id": "u1", "type": "User", "userPrincipalName": "bill.m@contoso.com"}]}
    c = AccountChange.from_audit(a)
    assert (c.kind, c.by_admin) == ("method_added", False)
    a["activityDisplayName"] = "Add Windows Hello for Business credential"
    assert AccountChange.from_audit(a).points == 5


# --------------------------------------------------------------- directory audit
def _audit(i, activity, who, category="UserManagement", targets=None, app=False):
    by = {"app": {"displayName": who}} if app else {"user": {"userPrincipalName": who, "id": "admin-id"}}
    return {"id": f"d{i}", "activityDateTime": f"2026-11-0{3 + i % 3}T10:{i:02d}:00Z", "activityDisplayName": activity,
            "category": category, "result": "success", "initiatedBy": by, "correlationId": f"c{i}",
            "targetResources": targets or []}


class Graph:
    def __init__(self, events, policies=()):
        self.events, self.policies = events, list(policies)

    def get_all(self, path, params=None, max_pages=None):
        yield from self.events

    def get(self, path, params=None):
        if path == "/v1.0/identity/conditionalAccess/policies":
            return {"value": self.policies}
        if path.startswith("/v1.0/groups/"):
            return {"displayName": "Travel exceptions"}
        raise RuntimeError(path)


def run_audit(tmp_path, events, policies=()):
    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: Graph(events, policies), user_dir=tmp_path / "x",
                       stop_event=threading.Event())
    pm.discover()
    return pm.run("directory_audit")


def test_new_audit_watches(tmp_path):
    user = [{"type": "User", "id": "u9", "userPrincipalName": "eve@contoso.com"}]
    events = [_audit(i, "Read BitLocker key", "arthur@contoso.com", "KeyManagement") for i in (1, 4, 7, 10, 13)]
    events += [_audit(5, "Read BitLocker key", "karen@contoso.com", "KeyManagement"),
               _audit(6, "Register device", "eve@contoso.com", "Device",
                      [{"type": "Device", "displayName": "iPad Pro"}]),
               _audit(7, "Update StsRefreshTokenValidFrom Timestamp", "brian@contoso.com", targets=user),
               _audit(8, "User has elevated their access to User Access Administrator for their Azure Resources",
                      "admin@contoso.com", "AzureRBACRoleManagementElevateAccess"),
               _audit(9, "Add owner to application", "Ops Automation", "ApplicationManagement", app=True)]
    out = run_audit(tmp_path, events)
    by = {f.title: f for f in out}
    bulk = next(f for f in out if f.rule_id == "sensitive_reads" and "arthur" in f.title)
    single = next(f for f in out if f.rule_id == "sensitive_reads" and "karen" in f.title)
    assert bulk.severity == Severity.MEDIUM and single.severity == Severity.INFO
    dev = next(f for f in out if f.rule_id == "device_registration")
    assert dev.signal == "device_registered" and dev.score == 30 and dev.subjects == ["eve@contoso.com"]
    rev = next(f for f in out if f.rule_id == "session_revocations")
    assert rev.signal == "sessions_revoked" and rev.subjects == ["eve@contoso.com"]
    assert next(f for f in out if f.rule_id == "elevate_access").severity == Severity.HIGH
    owner = next(f for f in out if f.rule_id == "app_owner_change")
    assert owner.score == 40 and owner.severity == Severity.LOW  # "Ops Automation" not configured as automation here
    assert by


def test_member_added_to_group_excluded_from_any_ca_policy(tmp_path):
    policy = {"id": "p1", "displayName": "Block outside EU", "state": "enabled",
              "grantControls": {"builtInControls": ["block"]},
              "conditions": {"users": {"includeUsers": ["All"], "excludeGroups": ["g-travel"]}}}
    add = _audit(1, "Add member to group", "admin@contoso.com", "GroupManagement",
                 [{"type": "User", "userPrincipalName": "eve@contoso.com"}, {"type": "Group", "id": "g-travel"}])
    f = next(f for f in run_audit(tmp_path, [add], [policy]) if f.rule_id == "mfa_exclusion_change")
    assert f.score == 60 and f.fields["Excluded from"] == "Block outside EU"
    assert f.title == "Added to CA exclusion group Travel exceptions: eve@contoso.com"


def test_revoked_sessions_mark_a_chain_as_handled():
    ac = AlertCenter(Store(":memory:"))
    when = datetime.now(timezone.utc)
    ac.ingest("signin_threats", [
        Finding(key="pwok", rule_id="password_not_completed", severity=Severity.MEDIUM, score=60,
                title="pw", occurred_at=when - timedelta(days=2), fields={"User": "eve@contoso.com"}),
        Finding(key="mfa", rule_id="mfa_change", severity=Severity.LOW, score=30, title="mfa",
                occurred_at=when - timedelta(days=1), fields={"User": "eve@contoso.com"})])
    ac.ingest("directory_audit", [Finding(key="rev", rule_id="session_revocations", severity=Severity.INFO, score=0,
                                          signal="sessions_revoked", subjects=["eve@contoso.com"], title="revoked",
                                          occurred_at=when - timedelta(hours=2))])
    f = chains.chain_findings(ac.since(when - timedelta(days=10)), when)[0]
    assert "Sessions revoked" in f.fields and any("handled" in r for _, r in f.factors) and f.score == 69 - 15


def test_app_select_fields_cover_the_model():
    for name in ("servicePrincipalId", "servicePrincipalCredentialKeyId", "ipAddress", "status", "location"):
        assert name in apps.SELECT
