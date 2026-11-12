"""Virtual desktops and shared hosts: machines people work ON from somewhere else (Citrix, Azure Virtual Desktop,
terminal servers, jump hosts).

A sign-in from such a machine carries the machine's device name and the address of the data centre or office it
runs in - not the place of the person, who sits in front of another device. Without knowing them, the app puts
remote people "in the office" (a Citrix host there) or sees "travel" to an Azure region.

Settings (``plugins.signin_threats.settings``)::

    "virtual_desktops": [
      {"match": "TOR-CTX-*",        "label": "Citrix"},                 # device name, shell wildcards, any case
      {"match": "cloud-vm-01",   "label": "Azure virtual machine"},
      {"match": "20.50.10.0/28",  "label": "AVD outbound addresses"}  # for hosts that send no device name
    ]

Edited in the tray under Settings > Virtual desktops..., which also proposes candidates found in the sign-ins
(``suggest``): Windows / Mac machines several people use at the same time, and managed machines that live in a
cloud data centre.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any, Callable, Iterable

from . import netintel
from .models import SignIn

_MOBILE = re.compile(r"ios|iphone|ipad|android", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"[{}]|^(desktop|laptop|unknown)$", re.IGNORECASE)  # redacted or meaningless names
CLOUD = {"cloud", "hosting"}
BUCKET_SECONDS = 1800


def _is_network(text: str) -> bool:
    try:
        ipaddress.ip_network(text.strip(), strict=False)
        return True
    except ValueError:
        return False


def load(settings: dict) -> list[dict[str, str]]:
    out = []
    for item in settings.get("virtual_desktops") or []:
        if isinstance(item, str):
            item = {"match": item}
        match = str((item or {}).get("match") or "").strip()
        if match:
            out.append({"match": match, "label": str(item.get("label") or "").strip()})
    return out


class HostMatcher:
    """Is a sign-in from a configured virtual desktop / shared host?"""

    def __init__(self, entries: Iterable[dict[str, str]]):
        self._names: list[tuple[str, str]] = []
        self._nets: list[tuple[Any, str]] = []
        for e in entries or []:
            match, label = e["match"], e.get("label") or "virtual desktop"
            if _is_network(match):
                self._nets.append((ipaddress.ip_network(match, strict=False), label))
            else:
                self._names.append((match.lower(), label))

    def __bool__(self) -> bool:
        return bool(self._names or self._nets)

    def label(self, s: SignIn) -> str | None:
        """What the host is ('Citrix', ...), or None if the sign-in is not from a configured host."""
        name = (s.device_name or "").lower()
        if name:
            for pattern, label in self._names:
                if fnmatch.fnmatchcase(name, pattern):
                    return label
        if self._nets and s.ip:
            try:
                addr = ipaddress.ip_address(s.ip)
            except ValueError:
                return None
            for net, label in self._nets:
                if addr.version == net.version and addr in net:
                    return label
        return None

    def __contains__(self, s: SignIn) -> bool:
        return self.label(s) is not None


def matcher(settings: dict) -> HostMatcher:
    return HostMatcher(load(settings))


def validate(entries: list[dict[str, str]]) -> list[str]:
    problems, seen = [], set()
    for e in entries:
        match = (e.get("match") or "").strip()
        if not match:
            problems.append("Every entry needs a device name, a name pattern or an IP range.")
            continue
        if match.lower() in seen:
            problems.append(f"'{match}' is listed twice.")
        seen.add(match.lower())
        if match.strip("*?") == "" or (not _is_network(match) and len(match.replace("*", "").replace("?", "")) < 3):
            problems.append(f"'{match}' would match almost every device - use a longer name or pattern.")
        if re.fullmatch(r"[0-9a-fA-F:./]+", match) and any(c in match for c in ".:") and not _is_network(match):
            problems.append(f"'{match}' looks like an IP address but is not a valid one (examples: 20.50.10.4, 20.50.10.0/28).")
    return problems


def save_into(settings: dict, entries: list[dict[str, str]]) -> dict:
    out = dict(settings)
    out["virtual_desktops"] = [{"match": e["match"].strip(), "label": (e.get("label") or "").strip()} for e in entries]
    return out


def guess_label(name: str, cloud: str) -> str:
    """A first idea of what a candidate is, from its name and where it runs (the user can change it)."""
    low = name.lower()
    if re.search(r"(^|[-_])(cx|ctx|citrix|xa|xd|vda)([-_]|\d|$)", low):
        return "Citrix"
    if re.search(r"(^|[-_])(avd|wvd|vdi|w365|cpc)([-_]|\d|$)", low):
        return "Azure Virtual Desktop"
    if cloud:
        return f"{cloud.split('/')[-1].strip()} virtual machine"
    if re.search(r"(^|[-_])(ts|rds|rdsh|jump|bastion|term)([-_]|\d|$)", low):
        return "Terminal server"
    return "Shared host"


def suggest(signins: Iterable[SignIn], settings: dict, office_label: Callable[[SignIn], str | None],
            is_service: Callable[[SignIn], bool], extra_asns: dict | None = None, min_users: int = 3) -> list[dict[str, Any]]:
    """Machines that look like virtual desktops or shared hosts and are not configured yet.

    - several accounts on one Windows / Mac machine AT THE SAME TIME (within half an hour): a session host - on a
      shared physical PC people take turns
    - a managed machine most of whose sign-ins come from a cloud / hosting network: it lives in a data centre

    ``office_label(s)`` names the office a sign-in came from (None if it did not). Phones and tablets (model names
    like "iPhone" are shared by many people) and redacted names are ignored."""
    known = matcher(settings)
    devices: dict[str, dict[str, Any]] = {}
    for s in signins:
        name = (s.device_name or "").strip()
        if not (s.success and s.user_id and name) or _MOBILE.search(s.os or "") or _PLACEHOLDER.search(name) or is_service(s):
            continue
        d = devices.setdefault(name, {"users": set(), "buckets": defaultdict(set), "n": 0, "cloud": Counter(), "where": Counter(),
                                      "cloud_n": 0, "sample": s})
        d["users"].add(s.user_id)
        d["buckets"][int(s.created.timestamp() // BUCKET_SECONDS)].add(s.user_id)
        d["n"] += 1
        info = netintel.asn_info(s.asn, extra_asns)
        office = office_label(s)
        if office:
            d["where"][office] += 1
        elif info and info[1].lower() in CLOUD:
            d["cloud_n"] += 1
            d["cloud"][info[0]] += 1
            d["where"][f"{info[0]}" + (f", {s.city}" if s.city else "")] += 1
        else:
            d["where"][", ".join(p for p in (s.city, s.country) if p) or "unknown"] += 1
    out = []
    for name, d in devices.items():
        if d["sample"] in known:
            continue
        users, together = len(d["users"]), max(len(u) for u in d["buckets"].values())
        in_cloud = d["cloud_n"] >= 0.5 * d["n"]
        if users >= min_users and together >= 2:
            why = f"{users} accounts, up to {together} at the same time"
        elif in_cloud and bool(s_managed(d["sample"])):
            why = "a managed machine that signs in from a cloud data centre"
        else:
            continue
        cloud = d["cloud"].most_common(1)[0][0] if in_cloud and d["cloud"] else ""
        out.append({"name": name, "users": users, "together": together, "signins": d["n"],
                    "where": d["where"].most_common(1)[0][0], "why": why, "label": guess_label(name, cloud)})
    return sorted(out, key=lambda c: (-c["users"], c["name"].lower()))


def s_managed(s: SignIn) -> bool:
    return bool(s.device_id and (s.compliant or s.managed or "joined" in (s.trust_type or "").lower()))
