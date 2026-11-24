import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from radar.plugins.signin_threats.history import SignInHistory  # noqa: E402
from radar.plugins.signin_threats.models import SignIn  # noqa: E402

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def _patient_tk():
    """Windows now and then fails to start Tk when many windows were opened and closed in one process ("Can't
    find a usable init.tcl" / "tk.tcl"); the fixtures of the window tests would skip them for it - silently. Try again."""
    import time
    import tkinter

    class Tk(tkinter.Tk):
        def __init__(self, *args, **kw):
            for attempt in range(6):
                try:
                    super().__init__(*args, **kw)
                    return
                except tkinter.TclError as exc:
                    if "Can't find a usable" not in str(exc) or attempt == 5:  # (init.tcl or tk.tcl)
                        raise
                    time.sleep(0.3)

    tkinter.Tk = Tk


_patient_tk()
_counter = [0]


def make_signin(minutes: float = 0, **kw) -> SignIn:
    _counter[0] += 1
    defaults = dict(id=f"s{_counter[0]}", created=T0 + timedelta(minutes=minutes), user_id="u1",
                    upn="alice@contoso.com", ip="198.51.100.10", country="CA", city="Toronto",
                    lat=43.65, lon=-79.38, app="Office 365", client_app="Browser", interactive=True)
    defaults.update(kw)
    return SignIn(**defaults)


@pytest.fixture
def history():
    h = SignInHistory(":memory:")
    yield h
    h.close()


@pytest.fixture(scope="session", autouse=True)
def _never_the_real_home(tmp_path_factory):
    """The whole test run has a data folder of its own. The per-test one below is set with ``monkeypatch`` - which a
    test can undo (``monkeypatch.undo()`` undoes everything, this included); without this fallback RADAR_HOME would
    then be unset and the test would read and write the data of the RADAR installed on this PC."""
    import os

    before = os.environ.get("RADAR_HOME")
    os.environ["RADAR_HOME"] = str(tmp_path_factory.mktemp("radar-home"))
    yield
    if before is None:
        os.environ.pop("RADAR_HOME", None)
    else:
        os.environ["RADAR_HOME"] = before


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch, _never_the_real_home):
    monkeypatch.setenv("RADAR_HOME", str(tmp_path / "home"))
    yield


@pytest.fixture(autouse=True)
def _no_animations():
    """Windows appear in their final state (layout tests measure positions); animation tests switch it on."""
    from radar.ui import theme

    theme.set_animations(False)
    yield
    theme.set_animations(False)


@pytest.fixture(autouse=True)
def _no_dialogs(monkeypatch):
    """Nothing waits for an answer in a test: what goes with a dismissal is not taken along unless a test says so."""
    from radar.app import App

    monkeypatch.setattr(App, "ask_companions", lambda self, extra, parent=None: False)
    yield
