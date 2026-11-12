"""Make RADAR's town index (src/radar/mapview/cities.tsv.gz) from the GeoNames file "cities1000".

    python packaging/build_cities.py [path to cities1000.txt or cities1000.zip]

Without a path the file is downloaded from https://download.geonames.org/export/dump/cities1000.zip.
GeoNames data is licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/), see THIRD-PARTY-NOTICES.md.

What is kept of each town: its name and its plain-ASCII name (lower case, accents removed), the country code,
latitude and longitude (rounded to 3 decimals), population and time zone. One line per (name, country) - the largest town of
that name wins - sorted by name and country, tab-separated, gzip-compressed without a time stamp (the same input
gives the same file).
"""
from __future__ import annotations

import gzip
import io
import sys
import unicodedata
import urllib.request
import zipfile
from pathlib import Path

SOURCE = "https://download.geonames.org/export/dump/cities1000.zip"
TARGET = Path(__file__).resolve().parents[1] / "src" / "radar" / "mapview" / "cities.tsv.gz"
TAB, NEWLINE = chr(9), chr(10)


def norm(text: str) -> str:
    plain = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in plain if not unicodedata.combining(c)).strip().lower()


def read(path: str | None) -> str:
    if path and not path.lower().endswith(".zip"):
        return Path(path).read_text(encoding="utf-8")
    raw = Path(path).read_bytes() if path else urllib.request.urlopen(SOURCE, timeout=120).read()  # noqa: S310
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return z.read("cities1000.txt").decode("utf-8")


def build(text: str) -> list[str]:
    towns: dict[tuple[str, str], tuple[int, str]] = {}
    for line in text.split(NEWLINE):
        col = line.split(TAB)
        if len(col) < 18:
            continue
        country, zone = col[8].strip().upper(), col[17].strip()
        try:
            lat, lon, population = float(col[4]), float(col[5]), int(col[14] or 0)
        except ValueError:
            continue
        if not country or not zone:
            continue
        for name in {norm(col[1]), norm(col[2])}:
            if not name or TAB in name:
                continue
            key = (name, country)
            if key not in towns or population > towns[key][0]:
                towns[key] = (population, TAB.join([name, country, str(round(lat, 3)), str(round(lon, 3)), str(population), zone]))
    return [towns[key][1] for key in sorted(towns)]


def main() -> int:
    lines = build(read(sys.argv[1] if len(sys.argv) > 1 else None))
    with open(TARGET, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as f:
        f.write((NEWLINE.join(lines) + NEWLINE).encode("utf-8"))
    print(f"{len(lines)} towns -> {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
