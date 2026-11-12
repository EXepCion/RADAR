"""What the live map shows, computed from the local sign-in history (no network access).

- people: everyone with a successful sign-in in the last ``hours``, at the place the best evidence points to
  (see ``signin_threats/presence.py``: office > work computer > phone on known Wi-Fi > unmanaged device >
  country only > hidden) - not simply at the place of the latest sign-in
- places: offices (certain) and cities (IP geolocation - approximate); the map shows one marker per place with
  the number of people and expands it on a click. A person of whom only a phone on mobile data is seen (its
  address tells the country at best) is put at the best guess: where the work computer was last, else the usual
  place outside the office, else where the phone's network is located - and marked as a guess
- attacks: failed passwords from networks the account does not use (the same filter as the attack overview),
  grouped by source and target place; "past the password" = the password step succeeded from such a network
- events: the newest sign-ins and attempts for the feed
"""
from __future__ import annotations

import dataclasses
import math
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import median
from typing import Any, Callable

from ..plugins.signin_threats import hosts, netintel, offices, presence
from ..plugins.signin_threats.accounts import AccountDirectory
from ..plugins.signin_threats.history import SignInHistory
from ..plugins.signin_threats.models import SignIn
from ..plugins.signin_threats.presence import Evidence
from ..plugins.signin_threats.rules import FAILED_PASSWORD_CODES, RuleContext
from . import cities

MAX_EVENTS = 80
ACCOUNT_EVENT_HOURS = 24  # how far back password / MFA / device / account / role events stay in the feed
MAX_HOPS = 10
SESSION_GAP = timedelta(hours=4)  # no sign-in for this long ends a stay: the device was off, asleep or offline
IMPOSSIBLE_KMH = 1000.0  # faster than an airliner between two geolocated sign-ins
TRAIL_RANKS = (1, 2, 3)  # evidence good enough to be a stop on the movement trail
SAME_MOMENT = timedelta(minutes=30)  # two addresses of one device this close together are in use at the same time
DISAGREE_KM = 50.0     # ... and located further apart than this: at least one of the two locations is wrong
COMMUTE_KM = 150.0     # a person lives within this distance of an office they go to
LAST_LOCATED_DAYS = 7  # how far back "where this person was last located" may lie for a best guess
AsnNames = Callable[[int | None], str | None]


def _iso(dt: datetime | None) -> str:
    return dt.isoformat() if dt else ""


def distance_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance between two (lat, lon) points."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(h)))


class Places:
    """Offices, cities and countries, each with one position on the map."""

    def __init__(self, rc: RuleContext):
        self.rc = rc
        self.items: dict[str, dict[str, Any]] = {}
        self.offices = offices.by_name(rc.settings)
        self._office_points: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self._office_cities: dict[str, dict[tuple[str, str], int]] = defaultdict(lambda: defaultdict(int))
        self._country_points: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self._city_points: dict[tuple[str, str], list[tuple[float, float]]] = defaultdict(list)
        for office in offices.load(rc.settings):  # every configured office is on the map, also when nobody is in
            self.items[f"office:{office.name}"] = self._office_item(f"office:{office.name}", office, office.name)

    @staticmethod
    def _office_item(key: str, office: Any, label: str) -> dict[str, Any]:
        return {"key": key, "kind": "office", "label": office.name if office else label,
                "city": office.city if office else "", "country": office.country if office else "",
                "hq": bool(office and office.hq), "ips": len(office.ips) if office else 0,
                "lat": office.lat if office else None, "lon": office.lon if office else None,
                "fixed": bool(office and office.lat is not None), "configured": office is not None}

    def office_key(self, s: SignIn) -> str:
        """'office:<name>' of a sign-in from an office address (as ``key`` names it), without recording anything."""
        label = self.rc.trusted_label(s)
        office = self.offices.get(label)
        return f"office:{office.name if office else label}"

    def anchor(self, key: str) -> tuple[float, float] | None:
        """Where an office is, for judging distances: its coordinates or its city (set in the Offices window). An
        office known only by where Entra locates its address is no anchor - that location may itself be wrong."""
        item = self.items.get(key)
        if not item:
            return None
        if item["fixed"]:
            return item["lat"], item["lon"]
        if item["city"]:
            return self.city_position(item["city"], item["country"]) or cities.locate(item["city"], item["country"])
        return None

    def learn_office(self, s: SignIn) -> None:
        """An earlier sign-in from an office: tells where Entra locates its address (the office is also drawn when
        nobody is signed in there right now)."""
        if self.rc.trusted(s):
            self.key(s)

    @staticmethod
    def _norm(text: str) -> str:
        """'São Paulo' == 'Sao Paulo' == 'SAO PAULO' (Entra writes city names without accents)."""
        import unicodedata

        plain = unicodedata.normalize("NFKD", text or "")
        return "".join(c for c in plain if not unicodedata.combining(c)).strip().lower()

    def learn_cities(self, signins: Any) -> None:
        """Where cities are, learned from the sign-ins themselves: Entra names city AND coordinates for every
        located address, so every city anybody signed in from is known - no built-in list of places."""
        for s in signins:
            if s.city and s.lat is not None and s.lon is not None:
                self._city_points[(self._norm(s.city), (s.country or "").upper())].append((s.lat, s.lon))

    def city_position(self, city: str, country: str) -> tuple[float, float] | None:
        """Coordinates of a city as seen in the sign-ins (same country preferred; 'UK' and 'GB' are the same)."""
        name, cc = self._norm(city), {"UK": "GB"}.get((country or "").upper(), (country or "").upper())
        if not name:
            return None
        points = self._city_points.get((name, cc))
        if not points:
            same = [(k, v) for k, v in self._city_points.items() if k[0] == name]
            points = max(same, key=lambda kv: len(kv[1]))[1] if same else None
        if not points:
            return None
        return round(median(p[0] for p in points), 3), round(median(p[1] for p in points), 3)

    def key(self, s: SignIn, precision: str = "") -> str:
        """Place of a sign-in: 'office:<name>', 'city:<city>|<country>', 'country:<CC>' or '' (no usable location).
        ``precision`` = presence.P_COUNTRY places it at country level only."""
        if self.rc.trusted(s):
            label = self.rc.trusted_label(s)
            office = self.offices.get(label)
            key = f"office:{office.name if office else label}"
            if s.lat is not None and s.lon is not None:
                self._office_points[key].append((s.lat, s.lon))
                self._office_cities[key][(s.city, s.country)] += 1
            if key not in self.items:
                self.items[key] = self._office_item(key, office, label)
            return key
        if precision == presence.P_COUNTRY:
            if not s.country:
                return ""
            key = f"country:{s.country}"
            if s.lat is not None and s.lon is not None:
                self._country_points[key].append((s.lat, s.lon))
            self.items.setdefault(key, {"key": key, "kind": "country", "label": s.country, "country": s.country,
                                        "lat": None, "lon": None})
            return key
        if s.lat is None or s.lon is None:
            return ""
        key = f"city:{s.city or '?'}|{s.country}"
        if key not in self.items:
            label = ", ".join(p for p in (s.city, s.country) if p) or "unknown place"
            self.items[key] = {"key": key, "kind": "city", "label": label, "lat": round(s.lat, 3), "lon": round(s.lon, 3)}
        return key

    def finish(self) -> dict[str, dict[str, Any]]:
        """Offices without a configured position get the median position of the sign-ins seen from them (and, without
        a configured city, the city Entra names most often). Countries get a fallback position (the page puts them
        in the middle of the country when it knows the country). Places never located are dropped."""
        # Position of an office, best source first: the coordinates set in the Offices window; the city set there,
        # located through sign-ins other people made from that city; where Entra locates the office's own address
        # (IP geolocation - can be far off: a provider's hub instead of the office).
        for key, item in self.items.items():
            if item["kind"] != "office":
                continue
            points = self._office_points.get(key) or []
            entra = (round(median(p[0] for p in points), 3), round(median(p[1] for p in points), 3)) if points else None
            if points:
                (city, country), _n = max(self._office_cities[key].items(), key=lambda kv: kv[1])
                item["entra_city"] = ", ".join(p for p in (city, country) if p)
            if item["fixed"]:
                item["position"] = "set by hand"
            else:
                # the configured city: where sign-ins from that city were located, else the offline index of towns
                by_city = (self.city_position(item["city"], item["country"]) or cities.locate(item["city"], item["country"])
                           or (cities.locate(item["city"]) if not item["country"] else None)) if item["city"] else None
                if by_city:
                    item["lat"], item["lon"], item["position"] = by_city[0], by_city[1], "city"
                    if entra and distance_km(by_city, entra) > 100:
                        item["position_note"] = (f"Entra locates this office's address in {item.get('entra_city') or 'another place'}, "
                                                 f"{distance_km(by_city, entra):,.0f} km away; shown in {item['city']} as configured.")
                elif entra:
                    item["lat"], item["lon"], item["position"] = entra[0], entra[1], "address"
                    if item["city"] and self._norm(item["city"]) != self._norm((item.get("entra_city") or "").split(",")[0]):
                        item["position_note"] = (f"The city '{item['city']}'" + (f" in {item['country']}" if item["country"] else "")
                                                 + " is not known to the map (check the spelling and the country code); shown "
                                                 f"where Entra locates the office's address ({item.get('entra_city') or 'unknown'}). "
                                                 "Or set coordinates in Settings > Offices.")
            if not item["city"] and points:
                (city, country), _n = max(self._office_cities[key].items(), key=lambda kv: kv[1])
                item["city"], item["country"] = city, item["country"] or country
        for key, points in self._country_points.items():
            self.items[key]["lat"] = round(median(p[0] for p in points), 3)
            self.items[key]["lon"] = round(median(p[1] for p in points), 3)
        return {k: v for k, v in self.items.items() if v["lat"] is not None}


def account_tags(accounts: AccountDirectory | None, user_id: str) -> list[str]:
    acct = accounts.get(user_id) if accounts else None
    if not acct:
        return []
    tags = []
    if acct.breakglass:
        tags.append("break-glass")
    if acct.roles or acct.pim_roles:
        tags.append("admin")
    if acct.mfa_excluded:
        tags.append("MFA excluded")
    elif acct.mfa_gap:
        tags.append("no MFA")
    return tags


def _foreign(rc: RuleContext, user_id: str, start: datetime) -> tuple[list[SignIn], list[SignIn]]:
    """(failed passwords, sign-ins that got past the password) from networks the account does not use."""
    attempts = rc.keep(rc.history.query(start, rc.now, user_id=user_id))
    familiar = rc.history.user_asns(user_id, start) | {s.asn for s in attempts if s.success and s.asn and s.device_id}
    foreign = [s for s in attempts if not s.success and not rc.trusted(s) and (not s.asn or s.asn not in familiar)]
    return ([s for s in foreign if s.error_code in FAILED_PASSWORD_CODES],
            [s for s in foreign if s.password_ok and s.error_code not in FAILED_PASSWORD_CODES])


def activity_points(history: SignInHistory, start: datetime, end: datetime, user_id: str | None = None) -> list[SignIn]:
    """The activity record as sign-ins: for every run of activity one at its begin, one per hour while it lasted
    and one at its end (same device, address and place). They stand in for the background sign-ins the app has
    purged, so that "active until 18:51" is true also for days whose background sign-ins are gone."""
    out = []
    for s, first, last, _n in history.activity(start, end, user_id):
        stamps, at = [first], first + timedelta(hours=1)
        while at < last:
            stamps.append(at)
            at += timedelta(hours=1)
        if last > first:
            stamps.append(last)
        for i, stamp in enumerate(stamps):
            if start <= stamp <= end:
                out.append(dataclasses.replace(s, id=f"activity:{s.id}:{i}", created=stamp, interactive=False))
    return out


def address_corrections(rows: list[SignIn], rc: RuleContext, places: Places) -> dict[str, dict[str, SignIn]]:
    """Addresses whose location Entra gets wrong, found by cross-checking each device against itself.

    A device on a home or mobile connection often shows two addresses of the same provider at the same time (IPv4
    and IPv6, or the path a cloud service sees). When Entra locates them more than DISAGREE_KM apart, one location
    is wrong - typically the provider's hub instead of the customer's town - and it is not always the same kind of
    address. The office the person goes to decides: of the two, the location within commuting distance of such an
    office is right. Nothing is decided when both or neither are (travelling, fully remote, never in an office).

    Returns {user id: {network of the wrongly located address (see presence.prefix): a sign-in from the right one}}."""
    offices_of: dict[str, set[str]] = defaultdict(set)
    per_device: dict[tuple[str, str], list[SignIn]] = defaultdict(list)
    for s in rows:
        if not s.user_id or not s.success:
            continue
        if rc.trusted(s):
            offices_of[s.user_id].add(places.office_key(s))
        elif s.device_id and s.lat is not None and s.lon is not None and s.asn and s.ip:
            per_device[(s.user_id, s.device_id)].append(s)
    anchors: dict[str, tuple[float, float] | None] = {}
    out: dict[str, dict[str, SignIn]] = defaultdict(dict)
    for (user_id, _device), items in per_device.items():
        mine = []
        for key in offices_of.get(user_id, ()):
            if key not in anchors:
                anchors[key] = places.anchor(key)
            if anchors[key]:
                mine.append(anchors[key])
        if not mine or len({s.ip for s in items}) < 2:
            continue

        def commutable(s: SignIn) -> bool:
            return any(distance_km((s.lat, s.lon), a) <= COMMUTE_KM for a in mine)

        items.sort(key=lambda s: s.created)
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                if b.created - a.created > SAME_MOMENT:
                    break
                if a.ip == b.ip or a.asn != b.asn or distance_km((a.lat, a.lon), (b.lat, b.lon)) <= DISAGREE_KM:
                    continue
                near_a, near_b = commutable(a), commutable(b)
                if near_a != near_b:
                    good, bad = (a, b) if near_a else (b, a)
                    out[user_id][presence.prefix(bad.ip)] = good
    return out


class Assessor:
    """Evidence value of sign-ins for one snapshot (knows the networks each person's computers use)."""

    def __init__(self, rc: RuleContext, baseline: list[SignIn], asn_names: AsnNames | None):
        self.rc, self.asn_names = rc, asn_names
        per_user: dict[str, list[SignIn]] = defaultdict(list)
        for s in baseline:
            per_user[s.user_id].append(s)
        self.rows = per_user
        self.hosts = hosts.matcher(rc.settings)
        self.computer_nets = {u: presence.computer_networks([s for s in rows if s not in self.hosts], rc.trusted)
                              for u, rows in per_user.items()}

    def guess(self, e: Evidence, places: "Places", since: datetime) -> tuple[str, str]:
        """Best guess of the place of a person of whom only a phone outside known networks is seen (its address
        tells the country at best). Returns (place key, why) - ('', '') if there is nothing to go by.

        1. the work computer was seen at a place outside the office in the last hours -> still there (lid closed)
        2. else the place where the person's computer is most often outside the office (home), if it is in the
           country the phone is in - e.g. someone who left the office and is on the way or at home
        3. else where the phone's own address is located (travelling, or no computer known)"""
        phone = e.signin
        days: dict[str, set] = defaultdict(set)
        latest: tuple[SignIn, str] | None = None
        for s in sorted(self.rows.get(phone.user_id, []), key=lambda x: x.created):
            ev = self.assess(s)
            if ev is None or ev.device != presence.WORK_COMPUTER or ev.rank not in (1, 2):
                continue
            key = places.key(s)
            if key:
                days[key].add(s.created.date())
                latest = (s, key)
        if latest and latest[0].created >= since and not latest[1].startswith("office:"):
            return latest[1], f"where the work computer was last seen ({latest[0].created.astimezone():%H:%M})"
        homes = sorted((k for k in days if k.startswith("city:") and k.rsplit("|", 1)[-1] == phone.country),
                       key=lambda k: len(days[k]), reverse=True)
        if homes:
            return homes[0], "the place where the work computer is most often outside the office"
        key = places.key(phone)
        return (key, "where the phone's network is located") if key else ("", "")

    def assess(self, s: SignIn) -> Evidence | None:
        return presence.assess(s, self.rc.trusted(s), self.computer_nets.get(s.user_id, set()),
                               self.rc.assessor.extra_asns, self.asn_names, virtual=s in self.hosts)

    def host(self, s: SignIn) -> str:
        """'Citrix TOR-CTX-01 (in CA office)' if the sign-in is from a virtual desktop / shared host, else ''."""
        label = self.hosts.label(s)
        if label is None:
            return ""
        where = self.rc.trusted_label(s) if self.rc.trusted(s) else ", ".join(p for p in (s.city, s.country) if p)
        return f"{label} {s.device_name or s.ip}".strip() + (f" (in {where})" if where else "")

    def office_of(self, e: Evidence) -> str:
        return self.rc.trusted_label(e.signin) if e.network == presence.OFFICE else ""


def is_guest(acct: Any, s: SignIn | None) -> bool:
    """A guest account (invited from outside): by the directory, by the sign-in, or by the '#EXT#' in its name."""
    upn = ((acct.upn if acct else "") or (s.upn if s else "") or "").lower()
    return ((acct is not None and (acct.user_type or "").lower() == "guest")
            or (s is not None and (s.user_type or "").lower() == "guest") or "#ext#" in upn)


def build_snapshot(history: SignInHistory, settings: dict, accounts: AccountDirectory | None, now: datetime,
                   hours: float = 4, attack_hours: float = 1, as_of: datetime | None = None,
                   asn_names: AsnNames | None = None, include_offline: bool = False,
                   account_events: list[dict] | None = None) -> dict[str, Any]:
    """``include_offline``: also list the known accounts that are NOT signed in, each at the place it was last
    located in the retention time (the map's "Not signed in" switch; costs a pass over the activity record)."""
    rc = RuleContext.build([], history, settings, now, accounts=accounts)
    places = Places(rc)
    start = now - timedelta(hours=hours)
    window = [s for s in rc.keep(history.query(start, now, success=True)) if s.user_id]
    # background sign-ins older than a few hours are purged: the activity record says who was still active when
    window = sorted(window + rc.keep(activity_points(history, start, now)), key=lambda s: s.created)
    # the networks people's computers used in the last 30 days (interactive sign-ins) and in the window (all)
    baseline = [s for s in history.query(now - timedelta(days=30), start, success=True, interactive_only=True) if s.user_id]
    places.learn_cities(s for s in baseline + window if not rc.trusted(s))
    for s in baseline:
        places.learn_office(s)
    assessor = Assessor(rc, baseline + window, asn_names)
    corrections = address_corrections(baseline + window, rc, places)

    evidence: dict[str, list[Evidence]] = defaultdict(list)
    interactive: dict[str, SignIn] = {}
    on_host: dict[str, SignIn] = {}  # latest sign-in on a virtual desktop per person
    # when each device was last signed in to by hand (interactive sign-ins are kept 30 days)
    hands_on: dict[str, dict[str, datetime]] = defaultdict(dict)
    for s in baseline + window:
        if s.interactive and presence.device_class(s) != presence.SERVICE and s not in assessor.hosts:
            key = presence.device_key(s)
            if key not in hands_on[s.user_id] or s.created > hands_on[s.user_id][key]:
                hands_on[s.user_id][key] = s.created
    for s in window:
        e = assessor.assess(s)
        if e is None:
            if s in assessor.hosts:
                on_host[s.user_id] = s
            continue  # a service acting for the user, or a virtual desktop: no evidence of where the user is
        evidence[s.user_id].append(e)
        if s.interactive:
            interactive[s.user_id] = s  # rows come ordered by time

    def network(s: SignIn) -> str:
        info = netintel.asn_info(s.asn, rc.assessor.extra_asns)
        if info:
            return f"{info[0]} ({info[1]})"
        name = asn_names(s.asn) if asn_names else None
        return name or (f"AS{s.asn}" if s.asn else "unknown network")

    # ---- people: the place the best evidence points to
    people: list[dict[str, Any]] = []
    unlocated: list[dict[str, Any]] = []
    rooms: list[dict[str, Any]] = []  # meeting rooms: signed in, but not people
    place_of: dict[str, str] = {}
    room_patterns = settings.get("room_accounts") or []
    last_signin: dict[str, SignIn] = {}  # of people whose place is hidden: the sign-in that hides it
    shown_by: dict[str, SignIn] = {}     # the sign-in each person's place on the map comes from
    for user_id, items in evidence.items():
        best, fallback = presence.choose(items, hands_on=hands_on.get(user_id))
        if best is None:
            continue
        used = fallback if best.precision == presence.P_HIDDEN and fallback else best
        why = fixed = ""
        if used.precision == presence.P_HIDDEN:
            key = ""
        elif used.precision == presence.P_COUNTRY:  # only a phone on a network of its own: the best guess
            key, why = assessor.guess(used, places, start)
        else:
            # the device's other address says where it really is (Entra locates this one at the provider's hub)
            right = corrections.get(user_id, {}).get(presence.prefix(used.signin.ip))
            key = places.key(right or used.signin)
            if right is not None and key:
                fixed = (f"where this device's other address is located - Entra places {used.signin.ip} in "
                       f"{used.signin.city or 'another town'}, {distance_km((right.lat, right.lon), (used.signin.lat, used.signin.lon)):,.0f} km "
                       f"away, the provider's hub rather than the person's place")
        s = best.signin
        shown_by[user_id] = s
        acct = accounts.get(user_id) if accounts else None
        tags = account_tags(accounts, user_id)
        if best.precision == presence.P_HIDDEN:
            tags.append("VPN / proxy")
        if best.flagged:
            tags.append("unmanaged device")
        others: list[str] = []
        for e in presence.current_per_device(items):  # other devices of the person, active elsewhere right now
            if e is best or e.signin.created < s.created - presence.HOLD or e.precision == best.precision \
                    or presence.device_key(e.signin) == presence.device_key(s):
                continue
            text = presence.describe(e, assessor.office_of(e))
            if text not in others:
                others.append(text)
        person = {
            "id": user_id, "name": (acct.display_name if acct else "") or s.user_name or s.upn or user_id,
            "upn": s.upn or (acct.upn if acct else ""), "place": key, "seen": _iso(s.created),
            "how": presence.describe(best, assessor.office_of(best)),
            "guess": why, "corrected": fixed,
            "precision": "guess" if best.precision == presence.P_COUNTRY else best.precision,
            "device": best.device, "flagged": best.flagged, "tags": tags,
            "also": ([f"Working on {assessor.host(on_host[user_id])}"] if user_id in on_host else []) + others[:3],
            "fallback": bool(fallback and best.precision == presence.P_HIDDEN), "guest": is_guest(acct, s),
        }
        if presence.is_room(acct, person["upn"], (e.signin for e in items), room_patterns):
            if key:
                place_of[user_id] = key
                rooms.append({k: person[k] for k in ("id", "name", "upn", "place", "seen", "how")})
            continue  # a meeting room is not a person: listed with its office, not counted or drawn as one
        if key:
            place_of[user_id] = key
            people.append(person)
        else:
            last_signin[user_id] = s
            unlocated.append(person)

    for user_id, s in on_host.items():  # seen only on a virtual desktop: signed in, but where is unknown
        if user_id in evidence:
            continue
        acct = accounts.get(user_id) if accounts else None
        unlocated.append({
            "id": user_id, "name": (acct.display_name if acct else "") or s.user_name or s.upn or user_id,
            "upn": s.upn or (acct.upn if acct else ""), "place": "", "seen": _iso(s.created),
            "how": f"Only seen on {assessor.host(s)} - that says where the machine runs, not where the person is",
            "guess": "", "precision": "virtual", "device": presence.VIRTUAL, "flagged": False,
            "tags": account_tags(accounts, user_id), "also": [], "fallback": False, "guest": is_guest(acct, s)})

    # Active right now, but only through something that hides the place (a cloud machine, a VPN, a virtual desktop):
    # the best guess is that the person still is where they were last located - shown as a guess, with how long ago.
    for person in list(unlocated):
        since = now - timedelta(days=LAST_LOCATED_DAYS)
        earlier = sorted(list(rc.keep(history.query(since, now, user_id=person["id"], success=True, interactive_only=True)))
                         + rc.keep(activity_points(history, since, now, person["id"])), key=lambda s: s.created, reverse=True)
        for s in earlier:
            e = assessor.assess(s)
            if e is None or e.rank > 4:
                continue  # a service, a virtual desktop, a phone on mobile data, a VPN: no place either
            right = corrections.get(person["id"], {}).get(presence.prefix(s.ip)) if not rc.trusted(s) else None
            key = places.key(right or s)
            if not key:
                continue
            person.update(place=key, precision="guess", located=_iso(s.created),
                          guess="where this person was last located; now only " + (
                              "on a virtual desktop" if person["precision"] == "virtual" else "behind a cloud network or VPN"))
            place_of[person["id"]] = key
            unlocated.remove(person)
            people.append(person)
            break
        else:
            # Never located on a normal network: the last address used to sign in is all there is. It belongs to
            # the network the person comes through (named from the network lookup), so the person is put at that
            # network's exit - as a guess that says what it is.
            s = last_signin.get(person["id"])
            key = places.key(s) if s is not None and not rc.trusted(s) else ""
            if key:
                person.update(place=key, precision="guess", exit=True,
                              guess=(f"at the exit of the network this account signs in through: {network(s)}, last address "
                                     f"{s.ip}. The person may be somewhere else - no sign-in from a normal network is on record"))
                place_of[person["id"]] = key
                unlocated.remove(person)
                people.append(person)

    # ---- accounts that are not signed in (only when asked for): each at the place it was last located
    offline: list[dict[str, Any]] = []
    if include_offline:
        present = set(evidence) | set(on_host)
        since = now - timedelta(days=30)
        earlier: dict[str, list[SignIn]] = defaultdict(list)
        for s in baseline:
            earlier[s.user_id].append(s)
        for s, _first, last, _n in history.activity(since, start):
            earlier[s.user_id].append(dataclasses.replace(s, id=f"activity:{s.id}", created=last, interactive=False))
        for user_id, rows in earlier.items():
            if user_id in present:
                continue
            acct = accounts.get(user_id) if accounts else None
            if accounts and (acct is None or not acct.enabled):
                continue  # deleted or disabled meanwhile: not a "known account" any more
            rows = rc.keep(rows)
            if not rows or presence.is_room(acct, (acct.upn if acct else rows[-1].upn), rows, room_patterns):
                continue
            for s in sorted(rows, key=lambda x: x.created, reverse=True):
                e = assessor.assess(s)
                if e is None or e.rank > 4:
                    continue
                right = corrections.get(user_id, {}).get(presence.prefix(s.ip)) if not rc.trusted(s) else None
                key = places.key(right or s)
                if not key:
                    continue
                offline.append({
                    "id": user_id, "name": (acct.display_name if acct else "") or s.user_name or s.upn or user_id,
                    "upn": s.upn or (acct.upn if acct else ""), "place": key, "seen": _iso(s.created),
                    "how": "Not signed in - last seen here: " + presence.describe(e, assessor.office_of(e)),
                    "tags": account_tags(accounts, user_id), "precision": "offline", "offline": True, "absent": True,
                    "flagged": False, "unusual": False, "guess": "", "also": [], "guest": is_guest(acct, s)})
                break

    # ---- attacks: every account with a failure in the window, filtered like the attack overview
    a_start = now - timedelta(hours=attack_hours)
    failing = {s.user_id for s in rc.keep(history.query(a_start, now, success=False)) if s.user_id}
    groups: dict[tuple, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    attacked: dict[str, int] = defaultdict(int)
    target_of: dict[str, tuple[str, SignIn]] = {}  # attacked account -> (place the attack is drawn at, an attempt)
    attempts_total = breaches_total = 0
    for user_id in sorted(failing):
        failed, past = _foreign(rc, user_id, a_start)
        if not failed and not past:
            continue
        target_place = place_of.get(user_id, "")
        if not target_place:  # not on the map right now: draw the attack at the place the account was last seen
            for s in reversed(history.query(now - timedelta(days=30), now, user_id=user_id, success=True)):
                e = presence.assess(s, rc.trusted(s), set(), rc.assessor.extra_asns, asn_names)
                if e is not None and e.precision != presence.P_HIDDEN:
                    target_place = places.key(s)
                    if target_place:
                        break
        target_of[user_id] = (target_place, (failed + past)[-1])
        for s, breach in [(s, False) for s in failed] + [(s, True) for s in past]:
            attempts_total += 1
            breaches_total += breach
            attacked[user_id] += 1
            who = s.upn or user_id
            source = ", ".join(p for p in (s.city, s.country) if p) or "unknown place"
            events.append({"ts": _iso(s.created), "kind": "breach" if breach else "attack", "user": user_id, "who": who,
                           "sid": s.id,
                           "ip": s.ip, "source": source, "network": network(s), "code": s.error_code,
                           "reason": s.failure_reason, "place": target_place})
            if s.lat is None or s.lon is None or not target_place:
                continue
            g = groups.setdefault((round(s.lat, 1), round(s.lon, 1), target_place, breach), {
                "lat": round(s.lat, 2), "lon": round(s.lon, 2), "source": source, "to": target_place, "breach": breach,
                "count": 0, "last": "", "ips": set(), "networks": set(), "targets": set(), "users": set()})
            g["count"] += 1
            g["last"] = max(g["last"], _iso(s.created))
            g["ips"].add(s.ip)
            g["networks"].add(network(s))
            g["targets"].add(who)
            g["users"].add(user_id)

    located = places.finish()
    unlocated += [p for p in people if p["place"] not in located]
    people = [p for p in people if p["place"] in located]
    for p in unlocated:
        p["place"] = ""
    for p in people + unlocated:
        if attacked.get(p["id"]):
            p["tags"].insert(0, "under attack")
        p["unusual"] = bool(attacked.get(p["id"]) or p["precision"] == presence.P_HIDDEN or "no MFA" in p["tags"])
    rooms = [r for r in rooms if r["place"] in located]
    on_map = {p["id"]: p["place"] for p in people}
    for user_id, s in interactive.items():  # the feed shows a person once, with the latest interactive sign-in
        if user_id in on_map and presence.device_class(s) != presence.SERVICE:
            events.append({"ts": _iso(s.created), "kind": "signin", "user": user_id, "place": on_map[user_id],
                           "sid": s.id,
                           "who": s.user_name or s.upn, "app": s.app,
                           "device": s.device_name or " ".join(p for p in (s.os, s.browser) if p)})
    # A person who turned up at a place WITHOUT signing in by hand there (a phone or laptop coming online in the
    # background) gets a feed entry too - once, at the moment they were first seen there - so that every person
    # appearing or moving on the map has a line in the feed. Not for someone who was at that place already before
    # the feed's time (nothing new), and marked when it is a country the account was not seen in for 30 days.
    def spot(x: SignIn) -> tuple:
        return ("office", x.ip) if rc.trusted(x) else ("at", x.city or "", x.country or "")

    before: dict[str, set[tuple]] = defaultdict(set)      # where each account was shortly before the feed's time
    countries: dict[str, set[str]] = defaultdict(set)     # the countries each account was seen in, 30 days
    for x, _first, last, _n in history.activity(now - timedelta(days=30), start):
        if x.country:
            countries[x.user_id].add(x.country)
        if last >= start - SESSION_GAP:
            before[x.user_id].add(spot(x))
    for x in baseline:
        if x.country:
            countries[x.user_id].add(x.country)
        if x.created >= start - SESSION_GAP:
            before[x.user_id].add(spot(x))
    for user_id, place in on_map.items():
        s = shown_by.get(user_id)
        if s is None:
            continue
        here = spot(s)
        same = sorted((e.signin for e in evidence[user_id] if spot(e.signin) == here), key=lambda x: x.created)
        if not same or here in before[user_id] or any(x.interactive for x in same):
            continue  # was there already, or signed in by hand there (that sign-in is in the feed)
        first = same[0]
        events.append({"ts": _iso(first.created), "kind": "seen", "user": user_id, "place": place,
                       "sid": "" if first.id.startswith("activity:") else first.id,
                       "who": first.user_name or first.upn or (accounts.get(user_id).display_name if accounts and accounts.get(user_id) else user_id),
                       "app": first.app, "device": first.device_name or " ".join(p for p in (first.os, first.browser) if p),
                       "moved": bool(before[user_id]) or any(spot(e.signin) != here and e.signin.created < first.created
                                                             for e in evidence[user_id]),
                       "new_country": first.country if first.country and countries[user_id]
                       and first.country not in countries[user_id] else ""})
    # account events of the last day (password resets, MFA methods, devices, accounts, admin roles): read by the
    # tray app from the audit log, see radar.account_events
    day_ago = _iso(now - timedelta(hours=ACCOUNT_EVENT_HOURS))
    for ev in account_events or []:
        if ev.get("ts", "") < day_ago or ev.get("upn") in rc.ignore_users:
            continue
        events.append({"ts": ev["ts"], "kind": "account", "what": ev.get("kind", ""), "title": ev.get("title", ""),
                       "who": ev.get("who", ""), "upn": ev.get("upn", ""), "user": ev.get("user_id", ""),
                       "by": ev.get("by", ""), "detail": ev.get("detail", ""), "failed": bool(ev.get("failed")),
                       "place": on_map.get(ev.get("user_id", ""), "")})
    events.sort(key=lambda e: e["ts"], reverse=True)
    attacks = []
    for g in groups.values():
        if g["to"] in located:
            attacks.append({**g, "ips": sorted(g["ips"])[:20], "ip_count": len(g["ips"]),
                            "networks": sorted(g["networks"])[:6], "targets": sorted(g["targets"])[:10],
                            "users": sorted(g["users"])})
    counts: dict[str, int] = defaultdict(int)
    for p in people:
        counts[p["place"]] += 1
    room_counts: dict[str, int] = defaultdict(int)
    for r in rooms:
        room_counts[r["place"]] += 1
    used_places = set(on_map.values()) | {a["to"] for a in attacks}
    offline_places = {p["place"] for p in offline}
    # Known accounts that cannot be put on the map at all - so that the map's figures add up to the directory:
    # "silent" = no successful sign-in on record in the 30 days, "active" = signed in, but only through services,
    # shared servers, VPNs or cloud networks (nothing that tells a place). Guests are counted separately.
    unplaced = {"silent": 0, "silent_guests": 0, "active": 0, "active_guests": 0}
    if include_offline and accounts:
        placed = set(place_of) | {p["id"] for p in unlocated} | {p["id"] for p in offline} | {
            u for u, (place, _attempt) in target_of.items() if u not in on_map and place in located}
        in_window = {s.user_id for s in window}
        for acct in accounts.accounts.values():
            if not acct.enabled or acct.user_id in placed or acct.user_id in evidence or acct.user_id in on_host:
                continue
            rows = earlier.get(acct.user_id) or []
            if presence.is_room(acct, acct.upn, rows, room_patterns):
                continue
            kind = "active" if rows or acct.user_id in in_window else "silent"
            unplaced[kind + ("_guests" if is_guest(acct, None) else "")] += 1
    return {
        "as_of": _iso(as_of or now), "generated": _iso(now), "hours": hours, "attack_hours": attack_hours,
        "offices_configured": bool(offices.load(settings)),
        "host_suggestions": len(hosts.suggest(
            baseline + window, settings, lambda s: rc.trusted_label(s) if rc.trusted(s) else None,
            lambda s: presence.device_class(s) == presence.SERVICE, rc.assessor.extra_asns)),
        "places": [{**v, "count": counts.get(k, 0), "rooms": room_counts.get(k, 0)} for k, v in located.items()
                   if k in used_places or v.get("configured") or k in offline_places],
        "unplaced_offices": sorted(v["label"] for k, v in places.items.items() if v.get("configured") and k not in located),
        "rooms": sorted(rooms, key=lambda r: r["name"].lower()),
        "people": sorted(people, key=lambda p: p["name"].lower()),
        "unlocated": sorted(unlocated, key=lambda p: p["name"].lower()),
        "offline": sorted((p for p in offline if p["place"] in located and p["id"] not in on_map),
                          key=lambda p: p["name"].lower()),
        # attacked accounts that are not signed in: they get a marker of their own (where the account was last
        # seen), so that the arrows aimed at them end on something
        "absent_targets": sorted((
            {"id": user_id, "name": ((accounts.get(user_id).display_name if accounts and accounts.get(user_id) else "")
                                     or attempt.upn or user_id),
             "upn": attempt.upn or (accounts.get(user_id).upn if accounts and accounts.get(user_id) else ""),
             "place": place, "seen": max(_iso(a.created) for a in [attempt]), "attempts": attacked[user_id],
             "how": "Not signed in - the attacks are drawn where this account was last seen",
             "tags": ["under attack"] + account_tags(accounts, user_id), "precision": "absent", "absent": True,
             "flagged": False, "unusual": True, "guess": "", "also": [],
             "guest": is_guest(accounts.get(user_id) if accounts else None, attempt)}
            for user_id, (place, attempt) in target_of.items() if user_id not in on_map and place in located),
            key=lambda p: p["name"].lower()),
        "attacks": sorted(attacks, key=lambda a: a["last"]),
        # the newest sign-ins and attempts, plus ALL account events of the day: they are few and must not be pushed
        # out of the list by a busy hour of sign-ins
        "events": sorted([e for e in events if e["kind"] != "account"][:MAX_EVENTS] + [e for e in events if e["kind"] == "account"],
                         key=lambda e: e["ts"], reverse=True),
        "unplaced": unplaced,
        "stats": {"people": len(people) + len(unlocated),
                  "in_office": sum(1 for p in people if p["place"].startswith("office:")),
                  "guessed": sum(1 for p in people if p["precision"] == "guess"),
                  "unlocated": len(unlocated), "rooms": len(rooms), "attempts": attempts_total,
                  "breaches": breaches_total,
                  "accounts_attacked": len(attacked)},
    }


def person_detail(history: SignInHistory, settings: dict, accounts: AccountDirectory | None, now: datetime,
                  user_id: str, days: int = 30, asn_names: AsnNames | None = None) -> dict[str, Any]:
    """Devices and movement of one person (asked for when the person is clicked)."""
    rc = RuleContext.build([], history, settings, now, accounts=accounts)
    places = Places(rc)
    since = now - timedelta(days=days)
    rows = sorted(list(rc.keep(history.query(since, now, user_id=user_id, success=True)))
                  + rc.keep(activity_points(history, since, now, user_id)), key=lambda s: s.created)
    assessor = Assessor(rc, rows, asn_names)
    corrections = address_corrections(rows, rc, places).get(user_id, {})
    # computers the person signed in to by hand in this time; one that only ever runs in the background (an office
    # PC or Mac left on) would make the trail jump between it and the laptop in use
    in_use = {presence.device_key(s) for s in rows if s.interactive and presence.device_class(s) != presence.SERVICE
              and not presence.is_mobile_os(s) and s not in assessor.hosts}
    devices: dict[str, dict[str, Any]] = {}
    visits: list[dict[str, Any]] = []
    for s in rows:
        e = assessor.assess(s)
        if e is None:
            if s in assessor.hosts:  # a virtual desktop the person works on: listed, but no place
                host = s.device_name or s.ip
                devices[host] = {"name": host, "detail": assessor.host(s), "class": presence.VIRTUAL,
                                 "seen": _iso(s.created), "managed": True, "id": s.device_id,
                                 "known": bool(s.device_id and s.device_name)}
            continue  # (else) a service on the user's behalf: neither a device of the user nor a place
        name = s.device_name or " / ".join(p for p in (s.os, s.browser) if p) or "unknown device"
        state = ("compliant" if s.compliant else "managed" if s.managed else s.trust_type or
                 ("registered" if s.device_id else "did not identify itself"))
        devices[name] = {"name": name, "detail": " · ".join(p for p in (s.os, s.browser, state) if p), "class": e.device,
                         "seen": _iso(s.created), "managed": e.device != presence.UNMANAGED,
                         "id": s.device_id, "known": bool(s.device_id and s.device_name)}
        if e.rank not in TRAIL_RANKS:
            continue  # phones on mobile data, unmanaged devices and VPNs do not make a stop on the trail
        if in_use and not presence.is_mobile_os(s) and presence.device_key(s) not in in_use:
            continue  # a computer nobody signed in to by hand: it shows where the machine is, not the person
        key = places.key(s if rc.trusted(s) else corrections.get(presence.prefix(s.ip)) or s)
        if not key:
            continue
        # A stay lasts as long as sign-ins keep coming from the place. A silence of hours ends it - the laptop was
        # shut and taken home overnight - so "office yesterday" and "office today" are two stays, not one.
        if visits and visits[-1]["place"] == key and s.created - visits[-1]["_until"] <= SESSION_GAP:
            visits[-1]["until"], visits[-1]["_until"] = _iso(s.created), s.created
            visits[-1]["signins"] += not s.id.startswith("activity:")
            continue
        visits.append({"place": key, "when": _iso(s.created), "until": _iso(s.created), "_until": s.created,
                       "signins": int(not s.id.startswith("activity:")),
                       "how": presence.describe(e, assessor.office_of(e)), "hidden": False})
    located = places.finish()
    stops = []
    for v in visits:
        if v["place"] in located:
            place = located[v["place"]]
            if place["kind"] == "office":
                city, country = place.get("city", ""), place.get("country", "")
            else:  # 'city:<name>|<CC>'
                city, _sep, country = v["place"].split(":", 1)[1].rpartition("|")
            stops.append({**v, "label": place["label"], "lat": place["lat"], "lon": place["lon"], "bad": False,
                          "office": place["kind"] == "office",
                          # the time zone of the place: "yesterday 17:40" means yesterday THERE
                          "tz": cities.timezone(city, country, place["lat"], place["lon"])})

    def too_fast(a: dict, b: dict) -> tuple[bool, float]:
        hours = abs((datetime.fromisoformat(b["when"]) - datetime.fromisoformat(a["until"])).total_seconds()) / 3600
        km = distance_km((a["lat"], a["lon"]), (b["lat"], b["lon"]))
        return km > 500 and km / max(hours, 0.01) > IMPOSSIBLE_KMH, km

    # A person seen in an office is there for certain. A "city" that cannot be reached from the office in the time
    # between is not a trip but the address of a cloud service, relay or VPN the device talks through: leave it out.
    ignored = 0
    kept: list[dict] = []
    for i, stop in enumerate(stops):
        neighbours = [stops[j] for j in (i - 1, i + 1) if 0 <= j < len(stops)]
        if not stop["office"] and any(n["office"] and too_fast(*sorted((n, stop), key=lambda x: x["when"]))[0]
                                      for n in neighbours):
            ignored += 1
            continue
        if kept and kept[-1]["place"] == stop["place"] and \
                datetime.fromisoformat(stop["when"]) - datetime.fromisoformat(kept[-1]["until"]) <= SESSION_GAP:
            kept[-1]["until"] = stop["until"]
            kept[-1]["signins"] += stop["signins"]
            continue
        kept.append(stop)
    hops = []
    for hop in kept:
        hop.pop("_until", None)
        if hops:
            previous = hops[-1]
            fast, km = too_fast(previous, hop)
            hop["km"] = round(km)
            hop["bad"] = bool(fast)
            hop["same_place"] = hop["place"] == previous["place"]
            # how long nothing was seen before this stay began (the device was off, asleep, offline or on the way)
            hop["idle_minutes"] = round((datetime.fromisoformat(hop["when"]) - datetime.fromisoformat(previous["until"])).total_seconds() / 60)
        hops.append(hop)
    acct = accounts.get(user_id) if accounts else None
    last = rows[-1] if rows else None
    order = {presence.WORK_COMPUTER: 0, presence.MANAGED_MOBILE: 1, presence.UNMANAGED: 2, presence.VIRTUAL: 3}
    ranked = sorted(devices.values(), key=lambda d: d["seen"], reverse=True)
    return {
        "id": user_id, "name": (acct.display_name if acct else "") or (last.user_name if last else "") or user_id,
        "upn": (last.upn if last else "") or (acct.upn if acct else ""), "tags": account_tags(accounts, user_id),
        "devices": sorted(ranked, key=lambda d: order.get(d["class"], 3))[:12],
        "hops": hops[-MAX_HOPS:], "days": days, "ignored_places": ignored,
    }
