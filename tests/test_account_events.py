"""Account events for the live map's feed: one entry per real action, from the audit lines the watch reads anyway."""
from datetime import datetime, timedelta, timezone

from conftest import T0, make_signin

from radar import account_events as ae
from radar.mapview import data

NOW = datetime(2026, 11, 10, 16, 0, tzinfo=timezone.utc)
_n = [0]


def audit(minute, activity, *, target=None, by_user=None, by_app=None, result="success", reason="", props=(), details=(),
          extra_targets=()):
    _n[0] += 1
    return {
        "id": f"a{_n[0]}", "activityDateTime": (NOW - timedelta(hours=2) + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "activityDisplayName": activity, "result": result, "resultReason": reason,
        "initiatedBy": {"user": {"userPrincipalName": by_user, "id": "id-" + by_user.split("@")[0]} if by_user else None,
                        "app": {"displayName": by_app} if by_app else None},
        "targetResources": ([dict(target, modifiedProperties=[{"displayName": n, "oldValue": o, "newValue": v} for n, o, v in props])]
                            if target else []) + list(extra_targets),
        "additionalDetails": [{"key": k, "value": v} for k, v in details],
    }


def user(name, upn):
    return {"type": "User", "displayName": name, "userPrincipalName": upn, "id": "id-" + upn.split("@")[0]}


BEA = user("Bea", "bea@contoso.com")
ROLE = {"type": "Role", "displayName": "License Administrator", "id": "r1"}


def test_one_entry_per_real_action():
    events = ae.normalise([
        # a self-service password reset writes four lines; a failed attempt earlier is an entry of its own
        audit(0, "Self-service password reset flow activity progress", target=BEA, by_user="bea@contoso.com", result="failure",
              reason="Password reset is not enabled for this user."),
        audit(20, "User started password reset", target=BEA, by_user="bea@contoso.com"),
        audit(21, "Self-service password reset flow activity progress", target=BEA, by_user="bea@contoso.com"),
        audit(22, "Reset password (self-service)", target=BEA, by_user="bea@contoso.com", reason="Successfully completed reset."),
        audit(22, "Reset user password", target=dict(BEA, displayName=None), by_app="Microsoft password reset service"),
        audit(23, "Change user password", target=dict(BEA, displayName=None), by_app="ConnectSyncProvisioning_SRV1"),
        audit(23, "Update PasswordProfile", target=BEA, by_app="x"),                       # not a user's doing: left out
        audit(24, "Update device local administrator password", target={"type": "Device", "displayName": "PC-1"}),
        # registering an MFA method: three lines
        audit(30, "User started security info registration", target=BEA, by_user="bea@contoso.com"),
        audit(31, "User registered security info", target=BEA, by_user="bea@contoso.com", reason="User registered Passkey"),
        audit(31, "User registered all required security info", target=BEA, by_user="bea@contoso.com"),
        # a PIM activation: five lines, and its expiry later
        audit(40, "Add member to role requested (PIM activation)", target=ROLE, by_user="bea@contoso.com", extra_targets=[BEA]),
        audit(40, "Add member to role completed (PIM activation)", target=ROLE, by_user="bea@contoso.com", extra_targets=[BEA],
              reason="assign a licence"),
        audit(40, "Add member to role", target=dict(BEA, displayName=None), by_app="MS-PIM",
              props=[("Role.DisplayName", None, '"License Administrator"')]),
        audit(100, "Remove member from role (PIM activation expired)", target=ROLE, by_app="MS-PIM", extra_targets=[BEA]),
        audit(100, "Remove member from role", target=dict(BEA, displayName=None), by_app="MS-PIM",
              props=[("Role.DisplayName", '"License Administrator"', None)]),
        # a permanent assignment by a person is an entry
        audit(50, "Add member to role", target=user("Cy", "cy@contoso.com"), by_user="admin@contoso.com",
              props=[("Role.DisplayName", None, '"Global Administrator"')]),
        # a device: registered + added (the failed duplicate "add" is nothing), and one deleted
        audit(60, "Register device", target={"type": "Device", "displayName": "DESKTOP-1"}, by_user="bea@contoso.com",
              details=[("Device Trust Type", "Azure AD join"), ("Device OS", "Unknown")]),
        audit(60, "Add device", target={"type": "Device", "displayName": "DESKTOP-1"}, by_app="Device Registration Service"),
        audit(61, "Add device", target={"type": "Device", "displayName": "DESKTOP-1"}, by_app="Device Registration Service", result="failure"),
        audit(62, "Hard Delete device", target={"type": "Device", "displayName": "Old-PC"}, by_app="Microsoft Online Services Garbage Collector"),
        # an account disabled: "Disable account" and an "Update user" that says the same
        audit(70, "Disable account", target=user(None, "info@contoso.com"), by_user="admin@contoso.com", props=[("AccountEnabled", "[true]", "[false]")]),
        audit(70, "Update user", target=user(None, "info@contoso.com"), by_user="admin@contoso.com", props=[("AccountEnabled", "[true]", "[false]")]),
        audit(71, "Update user", target=BEA, by_user="admin@contoso.com", props=[("Department", "a", "b")]),  # nothing shown
        audit(72, "Add user", target=user(None, "x_gmail.com#EXT#@contoso.onmicrosoft.com"), by_user="admin@contoso.com",
              props=[("CreationType", "[]", '["Invitation"]')]),
    ])
    got = [(e["title"], e["who"], e["failed"]) for e in events]
    assert got == [
        ("Self-service password reset failed", "Bea", True),
        ("Password reset (self-service)", "Bea", False),
        ("MFA method registered", "Bea", False),
        ("Admin role activated: License Administrator", "Bea", False),
        ("Admin role assigned: Global Administrator", "Cy", False),
        ("Device registered", "DESKTOP-1", False),
        ("Device removed for good", "Old-PC", False),
        ("Account disabled", "info@contoso.com", False),
        ("Guest account created", "x_gmail.com#EXT#@contoso.onmicrosoft.com", False),
    ]
    by_title = {e["title"]: e for e in events}
    assert by_title["MFA method registered"]["detail"] == "User registered Passkey"
    assert by_title["Admin role activated: License Administrator"]["detail"] == "assign a licence"
    assert by_title["Device registered"]["detail"] == "Azure AD join" and by_title["Device registered"]["upn"] == "bea@contoso.com"
    assert by_title["Device registered"]["user_id"] == "id-bea"          # the person who registered it
    assert by_title["Device removed for good"]["detail"] == "automatic cleanup"
    assert by_title["Self-service password reset failed"]["detail"].startswith("Password reset is not enabled")
    assert ae.collapse(events) == events                                  # stable: collapsing again changes nothing


def test_file_keeps_a_week_and_takes_the_same_lines_twice(tmp_path):
    path = tmp_path / "x" / ae.FILE
    assert ae.load(path) == []
    first = ae.normalise([audit(0, "Reset password (self-service)", target=BEA, by_user="bea@contoso.com"),
                          audit(0, "Reset user password", target=dict(BEA, displayName=None), by_app="Microsoft password reset service")])
    assert len(ae.merge(path, first, NOW)) == 1
    # the next run reads the last half hour again - and only one of the two lines this time
    again = ae.normalise([audit(0, "Reset user password", target=dict(BEA, displayName=None), by_app="Microsoft password reset service")])
    again[0]["ts"] = first[0]["ts"]
    assert [e["title"] for e in ae.merge(path, again, NOW)] == ["Password reset (self-service)"]
    assert len(ae.merge(path, [], NOW + timedelta(days=6))) == 1
    assert ae.merge(path, [], NOW + timedelta(days=8)) == []              # older than a week: gone
    assert "_group" not in ae.public(first[0]) and ae.public(first[0])["title"] == "Password reset (self-service)"


def test_account_events_are_in_the_maps_feed(history):
    history.add([make_signin(10, user_id="id-bea", upn="bea@contoso.com", user_name="Bea", ip="203.0.113.5", asn=812,
                             device_id="d1", device_name="LT-1", os="Windows10", managed=True, compliant=True)])
    now = T0 + timedelta(minutes=30)
    recent = {"id": "a1", "ts": (now - timedelta(hours=3)).isoformat(), "kind": "mfa", "title": "MFA method registered", "who": "Bea",
              "upn": "bea@contoso.com", "user_id": "id-bea", "by": "bea@contoso.com", "detail": "User registered Passkey", "failed": False}
    old = dict(recent, id="a2", ts=(now - timedelta(hours=30)).isoformat(), title="Password changed")
    settings = {"offices": [{"name": "Toronto office", "city": "Toronto", "country": "CA", "ips": ["203.0.113.5"]}]}
    snap = data.build_snapshot(history, settings, None, now, account_events=[recent, old])
    acct = [e for e in snap["events"] if e["kind"] == "account"]
    assert [(e["title"], e["what"], e["who"], e["detail"]) for e in acct] == [("MFA method registered", "mfa", "Bea", "User registered Passkey")]
    assert acct[0]["user"] == "id-bea" and acct[0]["place"] == "office:Toronto office"  # links to the person on the map
    assert snap["events"] == sorted(snap["events"], key=lambda e: e["ts"], reverse=True)
    assert [e for e in data.build_snapshot(history, settings, None, now)["events"] if e["kind"] == "account"] == []
    # a busy hour of sign-ins does not push the day's account events out of the list
    history.add([make_signin(20 + i / 10, user_id=f"u{i}", upn=f"p{i}@contoso.com", user_name=f"P{i}", ip="203.0.113.5", asn=812,
                             device_id=f"dev{i}", device_name=f"LT-{i}", os="Windows10", managed=True, compliant=True)
                 for i in range(data.MAX_EVENTS + 20)])
    snap = data.build_snapshot(history, settings, None, now, account_events=[recent])
    assert len(snap["events"]) == data.MAX_EVENTS + 1 and snap["events"][-1]["kind"] == "account"
