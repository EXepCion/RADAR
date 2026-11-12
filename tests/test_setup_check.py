"""Set-up: sign-in and permission problems are explained in the set-up window, with a way to check again."""
import tkinter as tk
from types import SimpleNamespace

import pytest

from radar import identity, setup_check
from radar.auth import AuthRequiredError
from radar.graph import GraphError
from radar.setup_check import Check

APP = "11111111-2222-3333-4444-555555555555"


class Graph:
    """Answers each read with success or the given error."""

    def __init__(self, errors=None):
        self.errors = errors or {}
        self.asked = []

    def get(self, path, params=None):
        self.asked.append(path)
        for part, error in self.errors.items():
            if part in path:
                raise error
        return {"value": []}


def test_everything_readable_means_working():
    seen = []
    checks = setup_check.probe(Graph(), "me@contoso.com", identity.AZURE_CLI, on_result=seen.append)
    assert [c.key for c in checks] == ["signins", "audit", "directory", "policies"] and all(c.ok for c in checks)
    assert seen == checks and setup_check.working(checks) and setup_check.first_problem(checks) is None
    assert [k for k, _ in setup_check.STEPS] == ["signin", "signins", "audit", "directory", "policies"]


def test_missing_role_is_explained_with_what_to_do():
    denied = GraphError(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
    checks = setup_check.probe(Graph({"signIns": denied, "directoryAudits": denied}), "me@contoso.com", identity.AZURE_CLI)
    assert not setup_check.working(checks)
    problem = setup_check.first_problem(checks)
    assert problem.key == "signins" and problem.detail == "Sign-in log: me@contoso.com is not allowed to read it."
    assert "Global Reader, Security Reader or Reports Reader" in problem.hint and "few minutes" in problem.hint
    assert "admin consent" not in problem.hint  # that part is only for an app registration of one's own
    own = setup_check.probe(Graph({"signIns": denied}), "me@contoso.com", identity.OWN)[0]
    assert "AuditLog.Read.All" in own.hint and "admin consent" in own.hint
    assert [c.ok for c in checks] == [False, False, True, True]  # the other reads are still tried


def test_missing_licence_and_optional_reads():
    no_licence = GraphError(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                            "Neither tenant is B2C or tenant doesn't have premium license")
    licence = setup_check.probe(Graph({"signIns": no_licence}), "me@contoso.com", identity.AZURE_CLI)[0]
    assert "no Microsoft Entra ID P1 or P2 licence" in licence.detail and "role" not in licence.hint.lower()
    # Conditional Access policies are not required: RADAR works, and says what is missing
    denied = GraphError(403, "AccessDenied", "nope")
    checks = setup_check.probe(Graph({"conditionalAccess": denied}), "me@contoso.com", identity.AZURE_CLI)
    assert setup_check.working(checks)
    missing = setup_check.first_problem(checks)
    assert missing.key == "policies" and missing.hint.startswith("RADAR works without it, but not the MFA exposure report")
    # no network at all
    class Offline(Graph):
        def get(self, path, params=None):
            raise OSError("no route")
    assert "could not be reached" in setup_check.probe(Offline(), "x", "")[0].detail


def test_sign_in_step_and_its_explanations():
    class Auth:
        configured, account = True, "me@contoso.com"

        def __init__(self, silent_error=None, prompt_error=None):
            self.silent_error, self.prompt_error, self.prompted = silent_error, prompt_error, 0

        def get_token(self):
            if self.silent_error:
                raise AuthRequiredError(self.silent_error)
            return "token"

        def sign_in_interactive(self):
            self.prompted += 1
            if self.prompt_error:
                raise AuthRequiredError(self.prompt_error)
            return self.account

    ok = setup_check.sign_in(Auth(), identity.AZURE_CLI)
    assert ok.ok and ok.detail == "signed in as me@contoso.com"
    asked = Auth(silent_error="No cached account and no Windows account available.")
    assert setup_check.sign_in(asked, identity.AZURE_CLI).ok and asked.prompted == 1  # silent failed: the prompt was shown
    blocked = setup_check.sign_in(Auth("x", "AADSTS53003: Access has been blocked by Conditional Access policies."), identity.AZURE_CLI)
    assert not blocked.ok and blocked.detail == "Sign-in was blocked by a Conditional Access policy." and "app registration" in blocked.hint
    assert setup_check.explain_auth("AADSTS65001: The user or administrator has not consented")[1].startswith("An administrator has to grant")
    assert setup_check.explain_auth("AADSTS700016: Application with identifier 'x' was not found")[0].startswith("This application ID is not known")
    assert setup_check.explain_auth("broker_error: User canceled the flow.")[0] == "The sign-in was cancelled."
    unknown = setup_check.explain_auth("something odd", identity.AZURE_CLI)
    assert unknown[0] == "Sign-in failed: something odd" and "does not work in every organisation" in unknown[1]


@pytest.fixture(scope="module")
def root():
    from radar.ui import theme

    try:
        r = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - no desktop available
        pytest.skip(f"no Tk display: {exc}")
    r.withdraw()
    theme.init(r)
    yield r
    r.destroy()


class FakeApp:
    def __init__(self, auth=None):
        self.auth_settings = auth or {"client_id": ""}
        self.cfg = SimpleNamespace(get=lambda *path, default=None: self.auth_settings if path == ("auth",) else default)
        self.applied, self.runs, self.links = [], [], []

    def apply_identity(self, values):
        self.applied.append(values)
        self.auth_settings = dict(values)

    def run_setup_check(self, win, other_account=False):
        self.runs.append(other_account)

    def open_link(self, url):
        self.links.append(url)


def test_setup_window_checks_the_choice_and_shows_each_step(root):
    from radar.ui import setup as ui

    app = FakeApp()
    win = ui.SetupWindow(root, app)
    root.update()
    try:
        assert win.kind.get() == identity.OWN and not win.busy
        win.client.set("nonsense")
        win.start()
        assert app.applied == [] and app.runs == [] and "application (client) ID" in win.headline.cget("text")
        win.client.set(APP)
        win.tenant.set("contoso.com")
        win.start()
        assert app.applied == [{"client_id": APP, "authority": "https://login.microsoftonline.com/contoso.com"}]
        assert app.runs == [False] and win.busy and str(win.check_btn.cget("state")) == "disabled"
        assert win.rows["signin"][0].cget("text") == ui.MARK[ui.RUNNING]
        win.start()  # a second click while it runs does nothing
        assert app.runs == [False]
        # the steps come in: signed in, the sign-in log is refused
        win.step_done(Check("signin", "Sign in", True, True, "signed in as me@contoso.com"))
        assert win.rows["signin"][0].cget("text") == ui.MARK[ui.OK] and win.rows["signins"][0].cget("text") == ui.MARK[ui.RUNNING]
        refused = Check("signins", "Sign-in log", False, True, "Sign-in log: me@contoso.com is not allowed to read it.", "Needs a role.")
        win.step_done(refused)
        win.finished([Check("signin", "Sign in", True), refused, Check("audit", "Audit log", True),
                      Check("directory", "Accounts", True), Check("policies", "CA", True, False)])
        assert not win.busy and win.check_btn.cget("text") == "Check again" and str(win.check_btn.cget("state")) == "normal"
        assert win.headline.cget("text") == ui.NOT_YET + " Sign-in log: me@contoso.com is not allowed to read it."
        assert win.hint.cget("text") == "Needs a role." and win.rows["signins"][0].cget("text") == ui.MARK[ui.FAILED]
        # checked again (nothing to save: the choice is the same) - now everything is readable
        win.start()
        assert app.runs == [False, False] and win.rows["signins"][0].cget("text") == ui.MARK[ui.WAITING]
        win.finished([Check(k, t, True, k != "policies", "readable") for k, t in setup_check.STEPS])
        assert win.headline.cget("text") == ui.WORKING and win.close_btn.cget("text") == "Done"
        # sign-in failed: the reads were never tried and say so
        win.start(other_account=True)
        assert app.runs[-1] is True
        win.finished([Check("signin", "Sign in", False, True, "The sign-in was cancelled.", "Check again.")])
        assert win.rows["audit"][1].cget("text") == "not checked" and "cancelled" in win.headline.cget("text")
    finally:
        win.top.destroy()


def test_setup_window_shows_the_current_choice_and_can_run_at_once(root):
    from radar.ui import setup as ui

    app = FakeApp(identity.check(identity.AZURE_CLI)[0])
    win = ui.SetupWindow(root, app, run_now=True)
    try:
        assert win.kind.get() == identity.AZURE_CLI and str(win.client_entry.cget("state")) == "disabled"
        end = __import__("time").monotonic() + 2
        while not app.runs and __import__("time").monotonic() < end:
            root.update()
        assert app.runs == [False] and app.applied == []  # checked without saving anything
        # one optional thing missing: working, and the window says what is missing
        missing = Check("policies", "Conditional Access policies", False, False, "Conditional Access policies: not allowed.", "RADAR works without it.")
        win.finished([Check(k, t, True, True, "readable") for k, t in setup_check.STEPS[:4]] + [missing])
        assert win.headline.cget("text").startswith(ui.WORKING_PARTLY) and "notification area" in win.hint.cget("text")
    finally:
        win.top.destroy()
