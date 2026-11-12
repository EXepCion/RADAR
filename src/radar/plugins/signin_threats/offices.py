"""Offices: named sites with their public IP addresses / ranges.

An office is what makes a sign-in "from a company network": its IPs are trusted by the detection rules (the
location of such a sign-in is certain, attempts from it are not attacks) and the live map shows it as a place.

Settings (``plugins.signin_threats.settings``)::

    "offices": [
      {"name": "CA office", "city": "Toronto", "country": "CA", "hq": true, "ips": ["203.0.113.5", "198.51.100.0/28"]},
      {"name": "UK office", "city": "London", "country": "GB", "ips": ["192.0.2.7"], "lat": 51.51, "lon": -0.13}
    ]

``lat``/``lon`` are optional (default: where Entra locates the sign-ins from the office). Exactly one office can be
the headquarters. Edited in the tray under Settings > Offices...

Before this structure existed, offices were entries of ``trusted_ips`` with a label such as
``"CA office (HQ Toronto)"``. Those are still understood (``load`` derives offices from the labels) until the offices
are saved once from the editor. ``trusted_ips`` remains for trusted addresses that are not an office.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

_LABEL = re.compile(r"^(?P<name>.*?)\s*\((?P<inner>[^()]*)\)\s*$")
_HQ = re.compile(r"\b(HQ|headquarters?|head office)\b[\s,:-]*", re.IGNORECASE)


@dataclass
class Office:
    name: str
    city: str = ""
    country: str = ""
    hq: bool = False
    ips: list[str] = field(default_factory=list)
    lat: float | None = None
    lon: float | None = None

    @property
    def place(self) -> str:
        """'Toronto, CA' - where the office is, for display next to its name."""
        return ", ".join(p for p in (self.city, self.country) if p)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "city": self.city, "country": self.country, "hq": self.hq,
                               "ips": list(self.ips)}
        if self.lat is not None and self.lon is not None:
            out["lat"], out["lon"] = self.lat, self.lon
        return out


def _number(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_label(label: str) -> tuple[str, str, bool]:
    """('CA office', 'Toronto', True) from the old trusted-IP label 'CA office (HQ Toronto)'."""
    label = (label or "").strip()
    m = _LABEL.match(label)
    name, inner = (m.group("name").strip(), m.group("inner").strip()) if m else (label, "")
    hq = bool(_HQ.search(inner) or _HQ.search(name))
    city = _HQ.sub("", inner).strip(" ,-")
    name = _HQ.sub("", name).strip(" ,-") or label
    return name, city, hq


def trusted_dict(settings: dict) -> dict[str, str]:
    """``trusted_ips`` as {ip_or_range: label} (it may be stored as a plain list)."""
    trusted = settings.get("trusted_ips") or {}
    return dict(trusted) if isinstance(trusted, dict) else {str(t): "" for t in trusted}


def derive(settings: dict) -> list[Office]:
    """Offices from labelled ``trusted_ips`` entries (the format before ``offices`` existed)."""
    by_label: dict[str, list[str]] = {}
    for ip, label in trusted_dict(settings).items():
        if str(label or "").strip():
            by_label.setdefault(str(label).strip(), []).append(str(ip))
    out = []
    for label, ips in by_label.items():
        name, city, hq = parse_label(label)
        out.append(Office(name=name, city=city, hq=hq, ips=ips))
    return out


def load(settings: dict) -> list[Office]:
    """The configured offices; derived from the old labels while ``offices`` has never been saved."""
    raw = settings.get("offices")
    if raw is None:
        return derive(settings)
    out = []
    for item in raw or []:
        if not isinstance(item, dict) or not str(item.get("name") or "").strip():
            continue
        out.append(Office(name=str(item["name"]).strip(), city=str(item.get("city") or "").strip(),
                          country=str(item.get("country") or "").strip().upper(), hq=bool(item.get("hq")),
                          ips=[str(i).strip() for i in item.get("ips") or [] if str(i).strip()],
                          lat=_number(item.get("lat")), lon=_number(item.get("lon"))))
    return out


def configured(settings: dict) -> bool:
    """Have the offices been saved in the new structure (and not only derived from old labels)?"""
    return settings.get("offices") is not None


def trusted_map(settings: dict) -> dict[str, str]:
    """Every trusted address / range with its label: the office IPs (label = office name) plus ``trusted_ips``.
    This is what the detection rules match sign-ins against."""
    out = trusted_dict(settings)
    if configured(settings):
        for office in load(settings):
            for ip in office.ips:
                out[ip] = office.name
    return out


def by_name(settings: dict) -> dict[str, Office]:
    """Offices by the label the rules give their sign-ins (the office name; the old full label while derived)."""
    if configured(settings):
        return {o.name: o for o in load(settings)}
    out = {}
    for label in {str(v).strip() for v in trusted_dict(settings).values() if str(v or "").strip()}:
        name, city, hq = parse_label(label)
        out[label] = Office(name=name, city=city, hq=hq)
    return out


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]


def _internal(net: "ipaddress._BaseNetwork") -> bool:
    """An address inside the office network (never what Entra sees)."""
    return any(net.version == i.version and net.subnet_of(i) for i in _INTERNAL)


def validate(offices: list[Office]) -> list[str]:
    """Problems that must be fixed before saving ([] = fine)."""
    problems: list[str] = []
    names: set[str] = set()
    seen: dict[str, str] = {}
    for office in offices:
        name = office.name.strip()
        if not name:
            problems.append("Every office needs a name.")
            continue
        if name.lower() in names:
            problems.append(f"Two offices are called '{name}'.")
        names.add(name.lower())
        if not office.ips:
            problems.append(f"{name}: add at least one IP address or range - without it nobody is ever seen there.")
        for ip in office.ips:
            try:
                net = ipaddress.ip_network(ip, strict=False)
            except ValueError:
                problems.append(f"{name}: '{ip}' is not an IP address or range (examples: 203.0.113.5, 198.51.100.0/28).")
                continue
            if _internal(net):
                problems.append(f"{name}: {ip} is a private address. Entra sees the public address of the office.")
            if net.version == 4 and net.prefixlen < 16 or net.version == 6 and net.prefixlen < 32:
                problems.append(f"{name}: {ip} is a very large range - sign-ins from all of it would count as 'in the office'.")
            if str(net) in seen and seen[str(net)] != name:
                problems.append(f"{ip} is listed for both {seen[str(net)]} and {name}.")
            seen[str(net)] = name
        if (office.lat is None) != (office.lon is None):
            problems.append(f"{name}: give both latitude and longitude, or neither.")
        elif office.lat is not None and not (-90 <= office.lat <= 90 and -180 <= office.lon <= 180):
            problems.append(f"{name}: latitude must be between -90 and 90, longitude between -180 and 180.")
    if sum(1 for o in offices if o.hq) > 1:
        problems.append("Only one office can be the headquarters.")
    return problems


def save_into(settings: dict, offices: list[Office]) -> dict:
    """New settings with ``offices`` stored; office addresses leave ``trusted_ips`` (other trusted IPs stay)."""
    out = dict(settings)
    out["offices"] = [o.to_dict() for o in offices]
    old_office_labels = {str(v).strip() for v in trusted_dict(settings).values() if str(v or "").strip()} \
        if not configured(settings) else set()
    office_ips = {ip for o in offices for ip in o.ips}
    out["trusted_ips"] = {ip: label for ip, label in trusted_dict(settings).items()
                          if ip not in office_ips and str(label or "").strip() not in old_office_labels}
    return out
