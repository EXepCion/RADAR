"""Which application RADAR signs in as: chosen once, nothing is read before that."""
import pytest

from radar import identity
from radar.auth import AuthManager, AuthRequiredError
from radar.config import AZURE_CLI_CLIENT_ID, ConfigManager

APP = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_a_new_installation_has_no_identity_and_does_not_sign_in(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    assert cfg.get("auth", "client_id") == ""  # no default: not the Azure CLI id either
    assert identity.current(cfg.get("auth")) == (identity.UNSET, "", "")
    auth = AuthManager(cfg, tmp_path / "cache.bin")
    assert not auth.configured
    with pytest.raises(AuthRequiredError):
        auth.get_token()  # (no Microsoft library call is made: there is no client to make it with)
    assert auth.state == "setup"
    with pytest.raises(AuthRequiredError):
        auth.sign_in_interactive()
    auth.use_windows_account()  # harmless without a client


def test_choices_are_checked_and_turned_into_settings():
    values, problem = identity.check(identity.AZURE_CLI)
    assert problem == "" and values == {"client_id": AZURE_CLI_CLIENT_ID, "authority": identity.SHARED_AUTHORITY}
    values, problem = identity.check(identity.OWN, " {" + APP.upper() + "} ", TENANT)
    assert problem == "" and values == {"client_id": APP, "authority": f"https://login.microsoftonline.com/{TENANT}"}
    assert identity.check(identity.OWN, APP, "Contoso.com")[0]["authority"] == "https://login.microsoftonline.com/contoso.com"
    assert "application (client) ID" in identity.check(identity.OWN, "my app", TENANT)[1]
    assert "tenant" in identity.check(identity.OWN, APP, "")[1]
    assert "tenant" in identity.check(identity.OWN, APP, "not a domain")[1]
    assert "Azure CLI" in identity.check(identity.OWN, AZURE_CLI_CLIENT_ID, TENANT)[1]  # that id belongs to the other choice
    assert identity.check("something else")[1]


def test_current_choice_is_read_back_from_the_settings(tmp_path):
    cfg = ConfigManager(tmp_path / "config.json")
    for key, value in identity.check(identity.OWN, APP, TENANT)[0].items():
        cfg.set("auth", key, value=value)
    assert identity.current(cfg.get("auth")) == (identity.OWN, APP, TENANT)
    auth = AuthManager(cfg, tmp_path / "cache.bin")
    assert auth.configured
    for key, value in identity.check(identity.AZURE_CLI)[0].items():
        cfg.set("auth", key, value=value)
    assert identity.current(cfg.get("auth")) == (identity.AZURE_CLI, AZURE_CLI_CLIENT_ID, "")
    assert identity.LABELS[identity.AZURE_CLI] == "Azure CLI (quick start)"
    auth.state = "ok"
    auth.reset()
    assert auth.state == "unknown"
