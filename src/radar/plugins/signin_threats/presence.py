"""Where a person is, judged by the most trustworthy evidence - not by the most recent sign-in.

Every sign-in is classified twice:

- device:  work computer (managed / compliant / joined Windows or Mac) - the anchor for "where someone works";
           managed mobile; unmanaged (registered-only, or a device that did not identify itself);
           service (a cloud service acting on the user's behalf - its address says nothing about the user)
- network: office, isp (a normal access network), mobile (carrier), hidden (VPN, relay, hosting, cloud)

and ranked (1 = best):

  1 office            any real device on an office address                          -> the office, certain
                      (unless it only runs in the background while another computer is in use: see ``choose``)
  2 city              work computer on a normal network                             -> the city
  3 city (fair)       managed mobile on a network the person's computer also uses   -> the city
  4 city, unconfirmed unmanaged / unidentified device on a normal network           -> the city, flagged
  5 country           a phone on a network of its own, or any device on a carrier   -> only the country
  6 hidden            VPN / relay / hosting                                         -> place unknown

``choose`` takes the best-ranked evidence among the sign-ins of the last ``HOLD`` before the newest one: an active
work computer renews its sign-in about hourly, so a phone on mobile data does not pull someone out of the office
while the computer's office sign-in is younger than that - and wins once the computer has been silent for longer.

Pure functions; used by the live map (the detection rules do not use this yet).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Iterable

from . import netintel
from .models import SignIn

HOLD = timedelta(minutes=60)
WORK_COMPUTER, MANAGED_MOBILE, UNMANAGED, SERVICE = "work computer", "managed mobile", "unmanaged device", "service"
VIRTUAL = "virtual desktop"  # a configured virtual desktop / shared host (see hosts.py): the person sits elsewhere
OFFICE, ISP, MOBILE, HIDDEN = "office", "isp", "mobile", "hidden"
P_OFFICE, P_CITY, P_UNCONFIRMED, P_COUNTRY, P_HIDDEN = "office", "city", "city_unconfirmed", "country", "hidden"
JOINED = {"azure ad joined", "hybrid azure ad joined", "microsoft entra joined", "microsoft entra hybrid joined"}
HIDDEN_CATEGORIES = {"vpn", "proxy", "relay", "hosting", "cloud", "bulletproof", "anonymizer", "tor"}
_MOBILE_OS = re.compile(r"ios|iphone|ipad|android", re.IGNORECASE)
_COMPUTER_OS = re.compile(r"windows|mac|linux|chrome ?os", re.IGNORECASE)
#: network names that mean "mobile carrier" (names of incumbents that also sell fixed lines are not listed)
_CARRIER = re.compile(r"\b(mobile|wireless|cellular|cellco|cell|lte|gsm|t-mobile|telefonica o2|jio|airtel)\b", re.IGNORECASE)
AsnNames = Callable[[int | None], str | None]
_ROOM_APP = re.compile(r"teams rooms|skype room system", re.IGNORECASE)  # Microsoft's room-system client


def is_room(account: Any, upn: str, signins: Iterable[SignIn], patterns: Iterable[str] = ()) -> bool:
    """Is this account a meeting room (a room system signed in with a resource account), not a person?

    Decided by data, not by lists of makers or naming habits:
    1. Entra: the account holds a Teams Rooms licence (``AccountInfo.room``, read with the accounts)
    2. the sign-ins: the client app is Microsoft's room-system app
    3. the setting ``room_accounts`` (UPN patterns with wildcards) for anything else, e.g. unlicensed room PCs"""
    import fnmatch

    if account is not None and getattr(account, "room", False):
        return True
    upn = (upn or "").lower()
    if any(fnmatch.fnmatchcase(upn, str(p).strip().lower()) for p in patterns or [] if str(p).strip()):
        return True
    return any(_ROOM_APP.search(s.app or "") for s in signins)


def is_mobile_os(s: SignIn) -> bool:
    return bool(_MOBILE_OS.search(s.os or ""))


def device_class(s: SignIn) -> str:
    """Work computer / managed mobile / unmanaged device / service."""
    if s.ms_backend or (s.client_credential or "none").lower() not in ("", "none"):
        return SERVICE  # a server presenting its own credential, on behalf of the user
    managed = bool(s.compliant or s.managed or (s.trust_type or "").lower() in JOINED)
    if not managed or not s.device_id:
        return UNMANAGED
    return MANAGED_MOBILE if is_mobile_os(s) else WORK_COMPUTER


def device_label(s: SignIn) -> str:
    """'Work computer LT-TOR-00101', 'Managed phone (iOS)', 'Unidentified device (Windows / Firefox)' ..."""
    cls = device_class(s)
    what = s.device_name or " / ".join(p for p in (s.os, s.browser) if p)
    if cls == WORK_COMPUTER:
        return f"Work computer {what}".strip()
    if cls == MANAGED_MOBILE:
        return f"Managed phone or tablet {what}".strip()
    if cls == SERVICE:
        return f"Service on the user's behalf ({s.app})" if s.app else "Service on the user's behalf"
    kind = "Registered, unmanaged device" if s.device_id else "Unidentified device"
    return f"{kind} ({what})" if what else kind


def prefix(ip: str) -> str:
    """The network an address belongs to for 'same Wi-Fi' purposes: IPv4 /24, IPv6 /64."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 64}", strict=False))


def network_class(s: SignIn, trusted: bool, extra_asns: dict | None = None, asn_names: AsnNames | None = None) -> str:
    if trusted:
        return OFFICE
    info = netintel.asn_info(s.asn, extra_asns)
    if info and info[1].lower() in HIDDEN_CATEGORIES:
        return HIDDEN
    name = info[0] if info else (asn_names(s.asn) if asn_names else None)
    if name and _CARRIER.search(name):
        return MOBILE
    return ISP


@dataclass
class Evidence:
    signin: SignIn
    device: str
    network: str
    rank: int
    precision: str

    @property
    def flagged(self) -> bool:
        """The device is unmanaged or did not identify itself."""
        return self.device == UNMANAGED


def assess(s: SignIn, trusted: bool, computer_nets: set[str], extra_asns: dict | None = None,
           asn_names: AsnNames | None = None, virtual: bool = False) -> Evidence | None:
    """Evidence value of one successful sign-in; None for services and - with ``virtual`` - for sign-ins from a
    virtual desktop or shared host (neither is evidence of where the person is).
    ``computer_nets``: networks (see ``prefix``) the person's computers have used - a phone on one of them is on
    Wi-Fi there, a phone anywhere else is taken to be on mobile data."""
    device = device_class(s)
    if device == SERVICE or virtual:
        return None
    network = network_class(s, trusted, extra_asns, asn_names)
    if network == OFFICE:
        return Evidence(s, device, network, 1, P_OFFICE)
    if network == HIDDEN:
        return Evidence(s, device, network, 6, P_HIDDEN)
    phone = is_mobile_os(s)
    if network == MOBILE or (phone and prefix(s.ip) not in computer_nets):
        return Evidence(s, device, network, 5, P_COUNTRY)
    if device == WORK_COMPUTER:
        return Evidence(s, device, network, 2, P_CITY)
    if device == MANAGED_MOBILE:
        return Evidence(s, device, network, 3, P_CITY)
    return Evidence(s, device, network, 4, P_UNCONFIRMED)


def computer_networks(signins: Iterable[SignIn], is_trusted: Callable[[SignIn], bool]) -> set[str]:
    """Non-office networks on which a person's computers (managed or not) signed in: their Wi-Fi at home etc."""
    out = set()
    for s in signins:
        if s.success and not is_mobile_os(s) and _COMPUTER_OS.search(s.os or "") and device_class(s) != SERVICE \
                and not is_trusted(s):
            net = prefix(s.ip)
            if net:
                out.add(net)
    return out


SAME_MOMENT = timedelta(minutes=20)  # sign-ins of one device this close together are the same moment


def device_key(s: SignIn) -> str:
    """Identifies a device across sign-ins (its id, or what little an unidentified device tells)."""
    return s.device_id or f"{s.os}|{(s.browser or '').split(' ')[0]}|{s.device_name}"


def current_per_device(evidence: list[Evidence]) -> list[Evidence]:
    """One piece of evidence per device: where it is NOW. A device is in one place - when the laptop signs in from
    home, its office sign-in of 50 minutes ago no longer counts. Sign-ins of the same moment (apps of one device
    take different network paths: direct, via a proxy) are settled by the better rank."""
    by_device: dict[str, list[Evidence]] = {}
    for e in evidence:
        by_device.setdefault(device_key(e.signin), []).append(e)
    out = []
    for items in by_device.values():
        newest = max(e.signin.created for e in items)
        moment = [e for e in items if e.signin.created >= newest - SAME_MOMENT]
        out.append(min(moment, key=lambda e: (e.rank, -e.signin.created.timestamp())))
    return out


ATTENDED = timedelta(hours=16)  # a computer somebody signed in to by hand this recently is "in use" (a working day)


def choose(evidence: list[Evidence], hold: timedelta = HOLD,
           hands_on: dict[str, Any] | None = None) -> tuple[Evidence | None, Evidence | None]:
    """(the evidence that decides the position, the last locatable evidence if that one hides the place).

    Each device counts with where it is now (``current_per_device``). Between devices, only those seen in the last
    ``hold`` before the newest count; among them the best rank wins, the newest within a rank - so a phone on
    mobile data does not pull someone out of the office while the computer there is still active.

    ``hands_on`` (device key -> time of its last INTERACTIVE sign-in): a person is where the computer is they are
    using, not where another machine keeps running. If one of the person's computers was signed in to by hand
    within ``ATTENDED`` and another was not (an office PC or Mac left on, syncing in the background), the unattended
    one does not count - even when it sits in an office. Phones never claim this (an app on a phone asking for a
    sign-in does not move the person out of the office)."""
    if not evidence:
        return None, None
    devices = current_per_device(evidence)
    newest = max(e.signin.created for e in devices)
    pool = [e for e in devices if e.signin.created >= newest - hold]
    if hands_on:
        def attended(e: Evidence) -> bool:
            last = hands_on.get(device_key(e.signin))
            return last is not None and newest - last <= ATTENDED

        computers = [e for e in pool if not is_mobile_os(e.signin)]
        in_use = [e for e in computers if attended(e) and e.precision != P_HIDDEN]
        if in_use and len(in_use) < len(computers):
            pool = in_use + [e for e in pool if is_mobile_os(e.signin)]
    best = min(pool, key=lambda e: (e.rank, -e.signin.created.timestamp()))
    fallback = None
    if best.precision == P_HIDDEN:
        located = [e for e in evidence if e.precision != P_HIDDEN]
        fallback = max(located, key=lambda e: e.signin.created) if located else None
    return best, fallback


def describe(e: Evidence, office: str = "") -> str:
    """One sentence for the person panel: what the position is based on."""
    where = {OFFICE: f"on the office network{f' ({office})' if office else ''}", ISP: "on a normal internet connection",
             MOBILE: "on a mobile network", HIDDEN: "behind a VPN, relay or cloud network - place unknown"}
    if e.precision == P_COUNTRY and e.network != MOBILE:
        return f"{device_label(e.signin)} on a network of its own (mobile data or foreign Wi-Fi)"
    return f"{device_label(e.signin)} {where.get(e.network, '')}".strip()


def summary(e: Evidence) -> dict[str, Any]:
    return {"device": e.device, "network": e.network, "rank": e.rank, "precision": e.precision, "flagged": e.flagged}
