"""Sign-ins made on a machine whose place is not the person's place.

Where a sign-in comes from is where the person is - unless it was made on a machine the person works on from
somewhere else, or on one that only asked for a token on their behalf. Then the address, the country and the
network are the machine's:

- a virtual desktop or shared host listed in the settings (hosts.py)
- a machine in a cloud data centre: a device whose sign-ins (practically) all come from cloud and hosting networks,
  learned from the activity record - with enough sign-ins, and seen there for longer than a device needs to count as
  the account's own (scoring.FAMILIAR_AFTER_HOURS): a device that turned up in a data centre an hour ago is a
  stranger's as likely as not
- a machine reached by remote desktop: the sign-in came with a remote desktop token, or the machine started signing
  in right after the account's remote desktop client connected from another device
- the machine that asked for a device code: a device-code sign-in names the device that APPROVED the code (its id,
  its management, its sign-in token) but carries the address of the machine that asked for it - and so do the tokens
  that machine was given. One event, judged by the device_code rule.

The rules that place the person pass such sign-ins over (impossible travel, new country ...), the baselines learn no
country from them, and they make no network the account's usual one (scoring.py). Everything here is read once per
run of the rules - a few queries, none per sign-in.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from . import netintel, presence
from .models import SignIn

if TYPE_CHECKING:  # pragma: no cover
    from .rules import RuleContext

#: networks a machine lives in
CLOUD_CATEGORIES = ("cloud", "hosting")
#: a device lives in a cloud data centre when this share of its sign-ins come from cloud / hosting networks ...
CLOUD_SHARE = 0.95
#: ... out of at least this many (a laptop behind a cloud-hosted gateway comes from there most of the time, not always)
CLOUD_MIN_SIGNINS = 20
#: a machine reached by remote desktop starts signing in this soon after the client connected
REMOTE_DESKTOP_WINDOW = timedelta(minutes=3)
REMOTE_DESKTOP_TOKEN = "remotedesktoptoken"  # incomingTokenType of a sign-in on the machine that was connected to

# what the machine is, in words that fit into a sentence
VIRTUAL_DESKTOP = "a virtual desktop"
IN_A_CLOUD = "a machine in a cloud data centre"
REMOTE_DESKTOP = "a machine reached by remote desktop"
DEVICE_CODE = "the machine that asked for a device code"


def _net(ip: str) -> str:
    """IPv6 -> its /64 (privacy addresses rotate inside it); IPv4 stays as is."""
    try:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if ipaddress.ip_address(ip).version == 6 else ip
    except ValueError:
        return ip


class Machines:
    """Which sign-ins were made on such a machine, for one run of the rules. What it needs is read in three passes,
    the first time it is asked: the activity record per device, the stored sign-ins that mention a remote desktop or
    a device code, and the runs of activity that began with a remote desktop token. Beyond that only the accounts
    that ever used such a machine are looked at."""

    def __init__(self, rc: "RuleContext"):
        self.rc = rc
        self._ready = False
        self._allowed: Any = None   # the device_code rule's allowed accounts
        self._devices: dict[str, tuple[datetime, int, int]] = {}  # device id -> (first seen, cloud, all sign-ins)
        self._resident: set[str] = set()                           # devices that live in a cloud data centre
        self._users: set[str] = set()                              # accounts that used such a machine
        self._anyone = False                                       # (a host known by its address: any account)
        self._clients: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)  # remote desktop clients
        self._targets: dict[str, list[tuple[tuple[str, str], datetime, datetime]]] = defaultdict(list)  # token runs
        self._codes: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)    # device-code sign-ins
        self._runs: dict[str, dict[tuple[str, str], list[tuple[datetime, datetime]]]] = {}
        self._judged: dict[str, list[tuple[SignIn, datetime, datetime, int, str]]] = {}
        self._networks: dict[str, dict[int, tuple[datetime | None, int]]] = {}
        self._only_machines: dict[int, set[str]] = {}
        self._signins: dict[str, list[tuple[datetime, str, bool]]] = {}

    # ------------------------------------------------------------ one sign-in
    def label(self, s: SignIn, begin: datetime | None = None) -> str:
        """What the sign-in was made on when its place is not the person's ('' when it is the person's place).
        ``begin``: when its run of activity began, if the caller has it (the first sign-in of a run)."""
        host = self.rc.virtual_hosts.label(s) if self.rc.virtual_hosts else None
        if host:
            return VIRTUAL_DESKTOP if host.lower() == "virtual desktop" else f"{VIRTUAL_DESKTOP} ({host})"
        if self.device_code(s):
            return DEVICE_CODE
        if self.remote_desktop(s, begin):
            return REMOTE_DESKTOP
        if self.in_cloud(s):
            return IN_A_CLOUD
        return ""

    def device_code(self, s: SignIn) -> bool:
        """The device-code sign-in itself, or a token it issued: the same application at the same address, after a
        device-code sign-in of the account (a refresh keeps the transfer method for as long as the grant lives).
        Only where the device_code rule judges the event: for an account on its allowed list, or with the rule
        switched off, nobody else would - so there it is a sign-in like any other, and every rule looks at it."""
        if not self._rule_judges(s):
            return False
        if s.auth_protocol.lower() == "devicecode":
            return s.success
        if s.transfer_method.lower() != "devicecodeflow" or not s.user_id:
            return False
        self._load()
        net = _net(s.ip)
        return any(app == s.app_id and where == net and when <= s.created for when, app, where in self._codes.get(s.user_id, ()))

    def _rule_judges(self, s: SignIn) -> bool:
        """Does the device_code rule judge this account's device-code sign-ins?"""
        if self._allowed is None:
            from .rules import UserMatcher
            self._allowed = UserMatcher(self.rc.cfg("device_code").get("allowed_users", []))
        return self.rc.rule_on("device_code") and s.upn not in self._allowed

    def remote_desktop(self, s: SignIn, begin: datetime | None = None) -> bool:
        if s.incoming_token.lower() == REMOTE_DESKTOP_TOKEN:
            return True
        self._load()
        if not s.user_id or (s.user_id not in self._clients and s.user_id not in self._targets):
            return False
        key = (presence.device_key(s), s.ip)
        if any(k == key and first <= s.created <= last for k, first, last in self._targets.get(s.user_id, ())):
            return True  # its run began with a remote desktop token
        if s.user_id not in self._clients or not s.device_id or presence.is_mobile_os(s):
            return False  # (a phone is no machine anybody connects to)
        if begin is None:
            begin = next((b for b, e in self._user_runs(s.user_id).get(key, ()) if b <= s.created <= e), s.created)
        # the client connected from ANOTHER device at ANOTHER address shortly before this machine began
        return any(device != s.device_id and ip != s.ip and when <= begin <= when + REMOTE_DESKTOP_WINDOW
                   for when, device, ip in self._clients[s.user_id])

    def in_cloud(self, s: SignIn) -> bool:
        if not (s.device_id and self._cloud(s.asn)):
            return False  # (a machine in a data centre that signs in from anywhere else: nothing to pass over)
        self._load()
        return s.device_id in self._resident

    # ------------------------------------------------------------ read once per run
    def _cloud(self, asn: int | None) -> bool:
        if not asn or asn in self.rc.assessor.trusted_asns:
            return False
        known = netintel.asn_info(asn, self.rc.assessor.extra_asns)
        return bool(known) and known[1].lower() in CLOUD_CATEGORIES

    def _load(self) -> None:
        if self._ready:
            return
        self._ready = True
        rc, since = self.rc, self.rc.now - timedelta(days=31)
        hosts = rc.virtual_hosts
        users_of: dict[str, set[str]] = defaultdict(set)
        devices: dict[str, list] = {}
        listed: dict[str, bool] = {}  # device name -> a configured host?
        for device, user_id, asn, name, n, first in rc.history.device_users():
            users_of[device].add(user_id)
            if hosts and name:
                if name not in listed:
                    listed[name] = bool(hosts.label(SignIn(id="", created=first, device_name=name)))
                if listed[name]:
                    self._users.add(user_id)
            if device and "|" not in device:  # a device with an id
                d = devices.setdefault(device, [first, 0, 0])
                d[0], d[2] = min(d[0], first), d[2] + n
                if self._cloud(asn):
                    d[1] += n
        self._devices = {device: (d[0], d[1], d[2]) for device, d in devices.items()}
        # (judged with what is known now: the first hours of a machine that has lived there since are its own too)
        cut = rc.now - rc.assessor.familiar_after
        self._resident = {device for device, (first, cloud, total) in self._devices.items()
                          if total >= CLOUD_MIN_SIGNINS and cloud >= CLOUD_SHARE * total and first <= cut}
        for device in self._resident:
            self._users |= users_of[device]
        for s in rc.history.machine_marks(netintel.REMOTE_DESKTOP_RESOURCES, since):
            if not s.user_id:
                continue
            if s.resource_id in netintel.REMOTE_DESKTOP_RESOURCES:
                self._clients[s.user_id].append((s.created, s.device_id, s.ip))
            elif s.interactive and s.auth_protocol.lower() == "devicecode":
                self._codes[s.user_id].append((s.created, s.app_id, _net(s.ip)))
            self._users.add(s.user_id)  # (or a sign-in with a remote desktop token)
        for o, first, last, _n in rc.history.activity_mentioning("remoteDesktopToken", since):
            if o.user_id and o.incoming_token.lower() == REMOTE_DESKTOP_TOKEN:
                self._targets[o.user_id].append(((presence.device_key(o), o.ip), first, last))
                self._users.add(o.user_id)
        self._anyone = bool(hosts) and hosts.by_address

    def concerned(self, user_id: str) -> bool:
        """Did the account ever use such a machine? (Accounts that did not are not looked at any further.)"""
        self._load()
        return self._anyone or user_id in self._users

    def _user_runs(self, user_id: str) -> dict[tuple[str, str], list[tuple[datetime, datetime]]]:
        if user_id not in self._runs:
            runs: dict[tuple[str, str], list] = defaultdict(list)
            for o, first, last, _n in self.rc.runs(user_id):
                runs[(presence.device_key(o), o.ip)].append((first, last))
            self._runs[user_id] = runs
        return self._runs[user_id]

    # ------------------------------------------------------------ what the account learns
    def runs(self, user_id: str) -> list[tuple[SignIn, datetime, datetime, int, str]]:
        """The account's runs of activity (RuleContext.runs), each with what it was made on ('' = the person)."""
        if user_id not in self._judged:
            mine = self.concerned(user_id)
            self._judged[user_id] = [(o, b, e, n, self.label(o, b) if mine else "") for o, b, e, n in self.rc.runs(user_id)]
        return self._judged[user_id]

    def countries(self, user_id: str, before: datetime) -> set[str]:
        """The countries the account knows only through such machines (its runs that began before ``before``)."""
        if not self.concerned(user_id):
            return set()
        person, machine = set(), set()
        for o, b, _e, _n, label in self.runs(user_id):
            if o.country and b < before:
                (machine if label else person).add(o.country)
        return machine - person

    def signins(self, user_id: str, before: datetime, interactive_only: bool) -> Counter:
        """How many of the account's stored successful sign-ins before ``before`` were made on such machines, per
        country (what SignInHistory.user_countries counts). Only the sign-ins at the machines' addresses are read."""
        if not self.concerned(user_id):
            return Counter()
        if user_id not in self._signins:
            spans = [(o.ip, b, e) for o, b, e, _n, label in self.runs(user_id) if label and o.ip]
            found = self.rc.history.signins_at(user_id, {ip for ip, _b, _e in spans}, min((b for _ip, b, _e in spans), default=self.rc.now),
                                               max((e for _ip, _b, e in spans), default=self.rc.now)) if spans else []
            self._signins[user_id] = [(s.created, s.country, s.interactive) for s in found if s.country and self.label(s)]
        return Counter(country for when, country, by_hand in self._signins[user_id]
                       if when < before and (by_hand or not interactive_only))

    def first_in_country(self, user_id: str, country: str) -> datetime | None:
        """When the account was first in a country - not counting such machines (None: never)."""
        person, machine = None, False
        for o, b, _e, _n, label in self.runs(user_id) if self.concerned(user_id) else ():
            if o.country == country:
                if label:
                    machine = True
                elif person is None or b < person:
                    person = b
        return person if machine else self.rc.history.first_use(user_id, "country", country)

    def networks(self, user_id: str) -> dict[int, tuple[datetime | None, int]]:
        """The networks the account used on such a machine: what it did on each of them otherwise - (first use,
        sign-ins), (None, 0) when nothing. Networks it never used on such a machine are not listed."""
        if not self.concerned(user_id):
            return {}
        if user_id not in self._networks:
            touched: set[int] = set()
            other: dict[int, list] = {}
            for o, b, _e, n, label in self.runs(user_id):
                if not o.asn:
                    continue
                if label:
                    touched.add(o.asn)
                else:
                    use = other.setdefault(o.asn, [b, 0])
                    use[0], use[1] = min(use[0], b), use[1] + n
            self._networks[user_id] = {asn: (other[asn][0], other[asn][1]) if asn in other else (None, 0) for asn in touched}
        return self._networks[user_id]

    def colleagues(self, asn: int, before: datetime, user_id: str) -> int:
        """How many other accounts used a network before ``before`` - not counting those that used it only on such
        a machine (eight people on one virtual machine do not make its cloud a network people work from)."""
        if asn not in self._only_machines:
            self._load()
            use: dict[str, set[bool]] = defaultdict(set)
            users = self.rc.history.asn_users(asn, self.rc.now)
            for o, b in self.rc.history.network_runs(asn, users if self._anyone else users & self._users):
                use[o.user_id].add(bool(self.label(o, b)))
            self._only_machines[asn] = {u for u, kinds in use.items() if kinds == {True}}
        return len(self.rc.history.asn_users(asn, before) - self._only_machines[asn] - {user_id})
