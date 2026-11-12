"""A habitual personal VPN on an unmanaged PC with MFA passed: known behaviour, not an intruder."""
from datetime import timedelta

from radar.alerts import AlertCenter
from radar.plugin_api import Finding, Severity
from radar.plugins import directory_audit as da
from radar.plugins.signin_threats import rules
from radar.plugins.signin_threats.rules import RuleContext
from radar.plugins.signin_threats.scoring import LABEL_HABITUAL_VPN, LABEL_VPN
from radar.store import Store

from conftest import T0, make_signin

VPN = dict(ip="198.51.100.152", asn=212238, country="CA", city="Toronto")
OFFICE = dict(ip="203.0.113.166", asn=577, country="CA", city="Toronto", device_id="laptop", trust_type="Azure AD joined",
              compliant=True, os="Windows10", browser="Edge 18.26200")


def habit(history, days=20):
    """Weeks of the user's own Firefox-on-Windows sessions through the VPN, plus the office laptop."""
    rows = []
    for d in range(days):
        rows.append(make_signin(-60 * 24 * (d + 1), os="Windows10", browser=f"Firefox {150 + d % 5}.0", **VPN))
        rows.append(make_signin(-60 * 24 * (d + 1) + 30, **OFFICE))
    history.add(rows)


def flagged(**kw):
    base = dict(os="Windows10", browser="Firefox 159.0", app="One Outlook Web", risk_during="medium",
                risk_state="remediated", risk_events=["anonymizedIPAddress"],
                auth_methods=["Passwordless phone sign-in", "Previously satisfied"],
                auth_requirement="multiFactorAuthentication")
    base.update(VPN)
    base.update(kw)
    return make_signin(0, **base)


def run(history, s):
    history.add([s])
    return rules.risky_signin(RuleContext.build([s], history, {}, T0 + timedelta(hours=1)))


def test_habitual_vpn_with_known_client_is_low(history):
    habit(history)
    out = run(history, flagged())
    assert len(out) == 1 and out[0].severity == Severity.LOW
    assert LABEL_HABITUAL_VPN in out[0].title
    texts = " ".join(r for _, r in out[0].factors)
    assert "Habitual network of the user" in texts and "Known client of the user (Windows, Firefox)" in texts
    assert "Passwordless sign-in" in texts


def test_attacker_on_same_vpn_with_new_client_and_password_is_high(history):
    habit(history)
    s = flagged(os="Linux", browser="Chrome 131.0", risk_state="atRisk", auth_methods=["Password"],
                auth_requirement="singleFactorAuthentication", password_ok=True, user_id="u1")
    out = run(history, s)
    assert out[0].severity >= Severity.MEDIUM
    texts = " ".join(r for _, r in out[0].factors)
    assert "Client never used by this user (Linux, Chrome)" in texts and "Password only" in texts


def test_first_time_vpn_is_not_habitual(history):
    history.add([make_signin(-60 * 24 * 5 - i, **OFFICE) for i in range(5)])
    out = run(history, flagged())
    assert LABEL_VPN in out[0].title and LABEL_HABITUAL_VPN not in out[0].title


def test_regular_vpn_user_across_different_vpn_networks(history):
    # alternating exits (Hydra is not in the ASN list, but Entra flags it as anonymous IP)
    rows = [make_signin(-60 * 24 * d, ip=f"89.37.173.{d}", asn=25369 if d % 2 else 212238, country="CA", city="Toronto",
                        os="Windows10", browser="Firefox 157.0", risk_events=["anonymizedIPAddress"])
            for d in (3, 10, 17, 24)]
    history.add(rows + [make_signin(-60 * 24 * 5, **OFFICE)])
    out = run(history, flagged(ip="198.51.100.122", asn=25369))
    texts = " ".join(r for _, r in out[0].factors)
    assert "regularly signs in through VPNs (4 earlier days" in texts
    assert LABEL_HABITUAL_VPN in out[0].title and out[0].severity <= Severity.LOW


def test_baseline_extension_fetches_gap_once(tmp_path):
    import threading

    from radar.config import ConfigManager
    from radar.plugin_manager import PluginManager
    from radar.plugins.signin_threats import SignInThreatsPlugin
    from radar.plugins.signin_threats.history import SignInHistory

    cfg = ConfigManager(tmp_path / "config.json")
    pm = PluginManager(cfg, Store(":memory:"), graph_factory=lambda: None, user_dir=tmp_path / "none",
                       stop_event=threading.Event())
    pm.discover()
    ctx = pm.build_context("signin_threats")
    calls = []

    class Graph:
        def get_pages(self, path, params=None, max_pages=None):
            calls.append(params["$filter"])
            yield [{"id": "old1", "createdDateTime": "2026-10-15T10:00:00Z", "userId": "u1", "status": {"errorCode": 0}}]

    ctx.graph = Graph()
    ctx.state.set("checkpoint:interactiveUser", T0.isoformat())
    h = SignInHistory(ctx.data_dir / "signins.db")
    h.add([make_signin(-60 * 24 * 7)])  # existing 7-day baseline
    plugin = SignInThreatsPlugin()
    plugin._extend_baseline(ctx, h, T0)
    assert len(calls) == 1 and "createdDateTime ge 2026-10-10" in calls[0] and "interactiveUser" in calls[0]
    assert h.get("old1") is not None
    plugin._extend_baseline(ctx, h, T0)  # already extended: no second fetch
    assert len(calls) == 1
    h.close()


def test_guest_invite_classification():
    audit = {"activityDisplayName": "Invite external user", "id": "a1", "activityDateTime": "2026-10-20T09:00:00Z",
             "initiatedBy": {"user": {"userPrincipalName": "lee.park@contoso.com"}},
             "targetResources": [{"id": "g1", "userPrincipalName": "lee.park1_gmail.com#EXT#@contoso.onmicrosoft.com"}]}
    assert da.guest_email(audit) == "lee.park1@gmail.com"
    f = da.DirectoryAuditPlugin._invite_finding(audit)
    assert f.severity == Severity.MEDIUM and f.score == 65 and "own private mailbox" in f.summary
    assert da.classify_invite("lee.park@contoso.com", "sam@fabrikam.com")[0] == 20
    assert da.classify_invite("lee.park@contoso.com", "someone@gmail.com")[0] == 50


def test_replace_assessment_can_lower_and_mute():
    ac = AlertCenter(Store(":memory:"))
    ac.ingest("p", [Finding(key="k", title="old", severity=Severity.MEDIUM, score=65)])
    before, after = ac.replace_assessment(Finding(key="k", title="new", severity=Severity.LOW, score=35))
    assert (before.score, after.score, after.severity, after.status) == (65, 35, Severity.LOW, "active")
    _, muted = ac.replace_assessment(Finding(key="k", title="newer", severity=Severity.INFO, score=10))
    assert muted.status == "muted" and ac.count_active() == 0
    assert ac.replace_assessment(Finding(key="unknown", title="x", severity=Severity.HIGH)) is None
