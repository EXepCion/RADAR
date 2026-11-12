# Third-party notices

RADAR itself is released under the MIT licence (see `LICENSE`). It includes, or is distributed together with, the
software and data listed here. Each stays under its own licence. The licence texts are in the folder `licenses`
(Apache ECharts, LGPL/GPL for pystray) and, for the Python packages, in the `*.dist-info` folders that ship with a
packaged RADAR.

## Included in this repository

| Component | Where | Licence | Source |
|---|---|---|---|
| Apache ECharts 4.9.0 (map and chart library), unmodified | `src/radar/mapview/static/echarts.min.js` | Apache License 2.0: `licenses/ECharts-LICENSE.txt`, `licenses/ECharts-NOTICE.txt` | https://echarts.apache.org |
| World map outline for ECharts | `src/radar/mapview/static/world.js` | Apache License 2.0 (distributed with Apache ECharts 4) | https://github.com/apache/echarts |
| Town index, derived from GeoNames "cities1000" (name, country, coordinates, time zone; reduced and re-packed) | `src/radar/mapview/cities.tsv.gz` | Creative Commons Attribution 4.0 International, https://creativecommons.org/licenses/by/4.0/ | https://www.geonames.org, file https://download.geonames.org/export/dump/cities1000.zip |

Apache ECharts: Copyright 2017-2020 The Apache Software Foundation. This product includes software developed at
The Apache Software Foundation (https://www.apache.org/). The ECharts licence file also lists the licences of the
components ECharts itself includes.

GeoNames: the town index is made from the GeoNames file "cities1000" (as downloaded in November 2026) by
`packaging/build_cities.py`, which changes it: only towns with their name (lower case, without accents), country
code, coordinates, population and time zone are kept, one line per name and country, sorted and compressed.
GeoNames does not endorse RADAR.

## Python packages RADAR depends on

Installed from PyPI when RADAR is installed from source, and shipped inside the packaged program.

| Package | Licence |
|---|---|
| msal, pymsalruntime (Microsoft Authentication Library and its Windows broker) | MIT |
| requests | Apache License 2.0 |
| urllib3, charset-normalizer, PyJWT, six | MIT |
| idna, pycparser | BSD 3-Clause |
| certifi | Mozilla Public License 2.0 |
| cryptography | Apache License 2.0 or BSD 3-Clause |
| cffi | MIT |
| Pillow | MIT-CMU (HPND) |
| sv-ttk (Sun Valley theme for tkinter) | MIT |
| pystray (tray icon) | GNU Lesser General Public License v3 |

**pystray and the LGPL.** pystray is used as a separate, unmodified library. In a packaged RADAR it is not packed
into the program: it is the folder `_internal\pystray` with plain `.py` files, which you can replace with another
version of pystray (same interface) without rebuilding anything. The complete source of RADAR and the
instructions to build it yourself are public as well. pystray's source is at
https://github.com/moses-palmer/pystray; the licence texts are `licenses/LGPL-3.0.txt` and `licenses/GPL-3.0.txt`.

## Python

A packaged RADAR includes the Python runtime and its standard library (Python Software Foundation License) with
Tcl/Tk (Tcl/Tk licence, BSD style).

## Not included

RADAR plays a reminder sound that is already on the PC (the Outlook reminder sound when Microsoft Office is
installed, else a Windows sound). No sound file ships with RADAR.
