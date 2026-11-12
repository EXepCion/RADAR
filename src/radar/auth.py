"""Token acquisition with MSAL and the Windows Web Account Manager (WAM) broker.

Silent order: cached account -> Windows (primary refresh token) account via the broker.
Interactive sign-in only happens when the user asks for it from the tray menu.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

import msal

from . import dpapi
from .config import ConfigManager

log = logging.getLogger(__name__)


class AuthRequiredError(Exception):
    """No token can be obtained silently; the user has to sign in."""


class _PersistentCache(msal.SerializableTokenCache):
    """MSAL token cache stored DPAPI-encrypted on disk."""

    def __init__(self, path: Path):
        super().__init__()
        self._path = Path(path)
        try:
            if self._path.exists():
                self.deserialize(dpapi.unprotect(self._path.read_bytes()).decode("utf-8"))
        except Exception:  # corrupt or from another user/machine: start fresh
            log.warning("Token cache unreadable, starting with an empty cache", exc_info=True)

    def persist(self) -> None:
        if not self.has_state_changed:
            return
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_bytes(dpapi.protect(self.serialize().encode("utf-8")))
            tmp.replace(self._path)
            self.has_state_changed = False
        except Exception:
            log.warning("Could not persist token cache", exc_info=True)

    def wipe(self) -> None:
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass


def _jwt_claims(token: str) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def describe_error(result: dict | None) -> str:
    if not result:
        return "No cached account and no Windows account available."
    desc = str(result.get("error_description") or "").strip()
    first = desc.splitlines()[0] if desc else ""
    return f"{result.get('error', 'error')}: {first}".strip(": ")


class TenantChangedError(AuthRequiredError):
    """The sign-in leads to another tenant than the one the stored data belongs to (radar.tenant)."""


class AuthManager:
    def __init__(self, cfg: ConfigManager, cache_path: Path, tenant_guard: Callable[[str], bool] | None = None):
        self._cfg = cfg
        self._tenant_guard = tenant_guard  # may this tenant's data be read into this installation?
        self.other_tenant: str | None = None  # the tenant of a sign-in that was turned away
        self._lock = threading.RLock()
        self._cache = _PersistentCache(cache_path)
        self._app: msal.PublicClientApplication | None = None
        self._app_key: tuple | None = None
        self._token: tuple[str, float] | None = None  # (access token, expires_at epoch)
        self.account: str | None = None
        self.tenant_id: str | None = None
        self.state = "unknown"  # unknown | ok | required | setup | other_tenant
        self.last_error: str | None = None

    # ------------------------------------------------------------ helpers
    def _settings(self) -> dict[str, Any]:
        return self._cfg.get("auth", default={}) or {}

    @property
    def configured(self) -> bool:
        """Has it been chosen which application RADAR signs in as? (radar.identity)"""
        return bool(str(self._settings().get("client_id") or "").strip())

    def reset(self) -> None:
        """The sign-in identity changed: forget the client and its token; the next call signs in afresh."""
        with self._lock:
            self._app = self._app_key = self._token = None
            self.state = "unknown"
            self.last_error = None

    @property
    def broker_enabled(self) -> bool:
        return bool(self._settings().get("use_broker", True))

    def _get_app(self) -> msal.PublicClientApplication:
        s = self._settings()
        key = (s.get("client_id"), s.get("authority"), bool(s.get("use_broker", True)))
        if self._app is None or key != self._app_key:
            self._app = msal.PublicClientApplication(
                s["client_id"],
                authority=s.get("authority") or "https://login.microsoftonline.com/organizations",
                token_cache=self._cache,
                enable_broker_on_windows=bool(s.get("use_broker", True)),
            )
            self._app_key = key
            self._token = None
        return self._app

    def _scopes(self) -> list[str]:
        return list(self._settings().get("scopes") or ["https://graph.microsoft.com/.default"])

    def _accept(self, result: dict) -> str:
        token = result["access_token"]
        claims = _jwt_claims(token)
        account = ((result.get("id_token_claims") or {}).get("preferred_username")
                   or claims.get("upn") or claims.get("unique_name") or self.account)
        tenant = claims.get("tid") or ""
        if tenant and self._tenant_guard is not None and not self._tenant_guard(tenant):
            # the token is not kept: nothing of the other tenant is read into this installation's data
            self._token = None
            self.account, self.other_tenant = account, tenant
            if self.state != "other_tenant":
                log.warning("Signed in as %s, but tenant %s is not the one the stored data belongs to", account, tenant)
            self.state = "other_tenant"
            self.last_error = (f"{account or 'this account'} belongs to another tenant ({tenant}) than the data "
                               f"RADAR has stored")
            self._cache.persist()
            raise TenantChangedError(self.last_error)
        self.other_tenant = None
        self._token = (token, time.time() + float(result.get("expires_in") or 3000))
        self.account = account
        self.tenant_id = tenant or self.tenant_id
        if self.state != "ok":
            log.info("Signed in as %s (tenant %s)", self.account, self.tenant_id)
        self.state = "ok"
        self.last_error = None
        self._cache.persist()
        return token

    # ---------------------------------------------------------------- api
    def get_token(self, force_refresh: bool = False) -> str:
        """Return a Graph access token without any UI, or raise AuthRequiredError."""
        with self._lock:
            if not self.configured:
                self.state = "setup"
                self.last_error = "it has not been chosen yet how RADAR signs in"
                raise AuthRequiredError(self.last_error)
            if not force_refresh and self._token and self._token[1] - 300 > time.time():
                return self._token[0]
            app = self._get_app()
            scopes = self._scopes()
            wanted = (self._settings().get("account") or "").strip()
            result: dict | None = None
            accounts = app.get_accounts(username=wanted) if wanted else app.get_accounts()
            if accounts:
                result = app.acquire_token_silent_with_error(scopes, account=accounts[0], force_refresh=force_refresh)
            if not (result and "access_token" in result) and not wanted and self.broker_enabled:
                # Signs in silently with the account that is logged on to Windows (PRT via WAM).
                result = app.acquire_token_interactive(
                    scopes, prompt="none", parent_window_handle=app.CONSOLE_WINDOW_HANDLE)
            if result and "access_token" in result:
                return self._accept(result)
            self.state = "required"
            self.last_error = describe_error(result)
            self._token = None
            self._cache.persist()
            log.warning("Silent token acquisition failed: %s", self.last_error)
            raise AuthRequiredError(self.last_error)

    def sign_in_interactive(self, select_account: bool = False) -> str:
        """Show the Windows/Entra sign-in UI. Returns the signed-in user name."""
        with self._lock:
            if not self.configured:
                raise AuthRequiredError("it has not been chosen yet how RADAR signs in")
            app = self._get_app()
            wanted = (self._settings().get("account") or "").strip()
            kwargs: dict[str, Any] = {"prompt": "select_account" if select_account else None}
            if wanted and not select_account:
                kwargs["login_hint"] = wanted
            if self.broker_enabled:
                kwargs["parent_window_handle"] = app.CONSOLE_WINDOW_HANDLE
            else:
                kwargs["timeout"] = 600
            result = app.acquire_token_interactive(self._scopes(), **kwargs)
            if not (result and "access_token" in result):
                self.last_error = describe_error(result)
                raise AuthRequiredError(self.last_error)
            try:
                self._accept(result)
            finally:  # also when it is another tenant's account: it stays the chosen one until the user decides
                if select_account and self.account:
                    self._cfg.set("auth", "account", value=self.account)
            return self.account or ""

    def use_windows_account(self) -> None:
        """Forget any explicitly chosen account and fall back to the Windows account."""
        with self._lock:
            if self.configured:
                app = self._get_app()
                for acct in app.get_accounts():
                    app.remove_account(acct)
            self._cache.persist()
            self._cfg.set("auth", "account", value="")
            self._token = None
            self.account = None
            self.state = "unknown"

    @property
    def using_explicit_account(self) -> bool:
        return bool((self._settings().get("account") or "").strip())
