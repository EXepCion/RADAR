import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from radar.plugins.signin_threats.history import SignInHistory  # noqa: E402
from radar.plugins.signin_threats.models import SignIn  # noqa: E402

T0 = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
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


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_HOME", str(tmp_path / "home"))
    yield


@pytest.fixture(autouse=True)
def _no_animations():
    """Windows appear in their final state (layout tests measure positions); animation tests switch it on."""
    from radar.ui import theme

    theme.set_animations(False)
    yield
    theme.set_animations(False)
