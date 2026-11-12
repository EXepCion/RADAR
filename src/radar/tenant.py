"""One installation, one tenant: the stored data (alerts, sign-in history, baselines, checkpoints) belongs to the
tenant it was read from, and is never mixed with another one.

The tenant of the first successful sign-in is remembered (``general.data_tenant``). A later sign-in to a different
tenant gets no token to work with (``allows`` says no; nothing is read or stored). The user can then sign in with an
account of the original tenant again - or start fresh: the stored data is moved to ``archive/<tenant>-<date>`` in the
data folder, RADAR restarts and builds new baselines for the new tenant. Settings stay (a copy goes into the
archive); offices and exceptions are per tenant and should be looked through afterwards.
"""
from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

STORED = ("plugin-data", "radar.db", "radar.db-wal", "radar.db-shm")  # what belongs to a tenant (the folder first)


def known(cfg: Any) -> str:
    return str(cfg.get("general", "data_tenant", default="") or "").strip().lower()


def allows(cfg: Any, tenant_id: str) -> bool:
    """May data of this tenant be read into this installation? The first tenant seen is adopted."""
    tenant_id = str(tenant_id or "").strip().lower()
    if not tenant_id:
        return True
    mine = known(cfg)
    if not mine:
        cfg.set("general", "data_tenant", value=tenant_id)
        log.info("The stored data belongs to tenant %s from now on", tenant_id)
        return True
    return mine == tenant_id


def request_fresh_start(cfg: Any, tenant_id: str, now: datetime | None = None) -> str:
    """Note that the next start archives the stored data and continues with ``tenant_id``. Returns the archive name."""
    name = f"{known(cfg) or 'unknown'}-{(now or datetime.now()).strftime('%Y%m%d-%H%M%S')}"
    cfg.set("general", "start_fresh_archive", value=name)
    cfg.set("general", "start_fresh_for", value=str(tenant_id).strip().lower())
    return name


def pending(cfg: Any) -> str:
    return str(cfg.get("general", "start_fresh_for", default="") or "").strip().lower()


def apply_pending(cfg: Any, data_dir: Path, config_path: Path | None = None, wait: float = 10.0) -> Path | None:
    """At start, before anything is opened: carry out a requested fresh start. Returns the archive folder, or None
    when nothing was requested or a file is still in use (then nothing changes for this run and it is tried again
    at the next start - the old tenant's data stays guarded meanwhile)."""
    tenant_id = pending(cfg)
    if not tenant_id:
        return None
    name = str(cfg.get("general", "start_fresh_archive", default="") or "") or f"unknown-{datetime.now():%Y%m%d-%H%M%S}"
    target = Path(data_dir) / "archive" / name
    target.mkdir(parents=True, exist_ok=True)
    for item in STORED:
        source = Path(data_dir) / item
        if not source.exists():
            continue
        deadline = time.monotonic() + wait
        while True:
            try:
                source.rename(target / item)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    log.error("Fresh start not possible yet: %s is in use (%s). Close the live map and start RADAR "
                              "again.", source, exc)
                    return None
                time.sleep(0.5)
    if config_path is not None and Path(config_path).exists():
        try:
            shutil.copy2(config_path, target / "config.json")
        except OSError:
            log.warning("The settings could not be copied into the archive", exc_info=True)
    cfg.set("general", "data_tenant", value=tenant_id)
    cfg.set("general", "start_fresh_for", value="")
    cfg.set("general", "start_fresh_archive", value="")
    log.info("Fresh start for tenant %s: the previous data is in %s", tenant_id, target)
    return target
