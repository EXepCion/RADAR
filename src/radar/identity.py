"""Which application RADAR signs in as.

To ask Microsoft Graph for data a program needs an application identity. RADAR has none of its own (it is not a
service, nobody runs a shared registration for it), so the person installing it chooses once:

* **own** - an app registration of their organisation (recommended): RADAR shows up in the sign-in logs under the
  name they gave it and can be allowed or blocked like any other application;
* **azure_cli** - the public client id of Microsoft's Azure CLI (quick start): no set-up, but RADAR then appears as
  "Microsoft Azure CLI", fails where that is blocked, and Microsoft may change what the identity can do.

Until the choice is made RADAR does not sign in at all. Pure functions on the settings; no UI, no network.
"""
from __future__ import annotations

import re
from typing import Any

from .config import AZURE_CLI_CLIENT_ID

UNSET, OWN, AZURE_CLI = "unset", "own", "azure_cli"
SHARED_AUTHORITY = "https://login.microsoftonline.com/organizations"
HELP_URL = "https://github.com/EXepCion/RADAR#signing-in"
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
LABELS = {UNSET: "not chosen yet", OWN: "own app registration", AZURE_CLI: "Azure CLI (quick start)"}


def current(auth: dict[str, Any]) -> tuple[str, str, str]:
    """(kind, application id, tenant) from the ``auth`` settings."""
    client = str(auth.get("client_id") or "").strip()
    if not client:
        return UNSET, "", ""
    authority = str(auth.get("authority") or "").rstrip("/")
    tenant = authority.rsplit("/", 1)[-1] if authority else ""
    if client.lower() == AZURE_CLI_CLIENT_ID:
        return AZURE_CLI, client, ""
    return OWN, client, "" if tenant in ("organizations", "common") else tenant


def check(kind: str, client_id: str = "", tenant: str = "") -> tuple[dict[str, str], str]:
    """The ``auth`` values for this choice, or what is wrong with it: ({"client_id": ..., "authority": ...}, "")
    or ({}, "message")."""
    if kind == AZURE_CLI:
        return {"client_id": AZURE_CLI_CLIENT_ID, "authority": SHARED_AUTHORITY}, ""
    if kind != OWN:
        return {}, "Choose one of the two ways."
    client_id, tenant = client_id.strip().strip("{}"), tenant.strip().strip("{}")
    if not _GUID.match(client_id):
        return {}, "The application (client) ID looks like 00000000-0000-0000-0000-000000000000."
    if client_id.lower() == AZURE_CLI_CLIENT_ID:
        return {}, "That is the ID of Microsoft's Azure CLI - choose the quick start for it, or enter your own application's ID."
    if not (_GUID.match(tenant) or _DOMAIN.match(tenant)):
        return {}, "Enter your directory (tenant) ID or a domain of your organisation, e.g. contoso.com."
    return {"client_id": client_id.lower(), "authority": f"https://login.microsoftonline.com/{tenant.lower()}"}, ""
