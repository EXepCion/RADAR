"""Where cities are: an offline index of the world's towns (GeoNames 'cities1000', CC BY 4.0, geonames.org).

Used to put an office at the city set in Settings > Offices when that city has never appeared in a sign-in. The
index ships with the app (``cities.tsv.gz``: name without accents, country code, latitude, longitude,
population); nothing is looked up online. Loaded on first use, in the map process only.
"""
from __future__ import annotations

import gzip
import unicodedata
from functools import lru_cache
from pathlib import Path

FILE = Path(__file__).with_name("cities.tsv.gz")
COUNTRY_ALIASES = {"UK": "GB"}  # what people write -> ISO code


def norm(text: str) -> str:
    """'São Paulo' == 'Sao Paulo' == 'SAO PAULO'."""
    plain = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in plain if not unicodedata.combining(c)).strip().lower()


@lru_cache(maxsize=1)
def _index() -> tuple[dict[tuple[str, str], tuple[float, float]], dict[str, tuple[float, float]]]:
    by_country: dict[tuple[str, str], tuple[float, float]] = {}
    largest: dict[str, tuple[float, float, int]] = {}
    try:
        with gzip.open(FILE, "rt", encoding="utf-8") as f:
            for line in f:
                name, cc, lat, lon, pop, tz = line.rstrip(chr(10)).split(chr(9))
                position = (float(lat), float(lon))
                by_country[(name, cc)] = position
                _ZONES[(name, cc)] = tz
                _BY_COUNTRY.setdefault(cc, []).append((position[0], position[1], tz))
                if name not in largest or int(pop) > largest[name][2]:
                    largest[name] = (position[0], position[1], int(pop))
    except OSError:
        pass
    return by_country, {k: (v[0], v[1]) for k, v in largest.items()}


_ZONES: dict[tuple[str, str], str] = {}                       # (town, country) -> IANA time zone
_BY_COUNTRY: dict[str, list[tuple[float, float, str]]] = {}   # country -> (lat, lon, zone) of its towns


def timezone(city: str, country: str, lat: float | None = None, lon: float | None = None) -> str:
    """IANA time zone ('Asia/Singapore') of a place: of the town of that name in the country, else of the nearest
    town of the country to the coordinates (countries with several zones), else ''."""
    _index()
    cc = (country or "").strip().upper()
    cc = COUNTRY_ALIASES.get(cc, cc)
    zone = _ZONES.get((norm(city), cc)) if city and cc else None
    if zone:
        return zone
    towns = _BY_COUNTRY.get(cc) or []
    if towns and lat is not None and lon is not None:
        return min(towns, key=lambda t: (t[0] - lat) ** 2 + (t[1] - lon) ** 2)[2]
    return towns[0][2] if towns and len({t[2] for t in towns}) == 1 else ""


def locate(city: str, country: str = "") -> tuple[float, float] | None:
    """(lat, lon) of a town; with a country the town in that country, without one the largest town of that name."""
    name = norm(city)
    if not name:
        return None
    by_country, largest = _index()
    cc = (country or "").strip().upper()
    cc = COUNTRY_ALIASES.get(cc, cc)
    if cc:
        return by_country.get((name, cc))
    return largest.get(name)
