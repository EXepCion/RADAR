"""Names for what the logs give as codes: a country for its two letters ('BR' -> 'Brazil').

Windows knows the names (in the language Windows is shown in); nothing is looked up anywhere else. Where it cannot
say - another system, an unknown code - the code itself is the name.
"""
from __future__ import annotations

import sys
from functools import lru_cache

GEO_FRIENDLYNAME = 8


@lru_cache(maxsize=512)
def country_name(code: str) -> str:
    code = str(code or "").strip()
    if len(code) != 2 or not code.isalpha() or sys.platform != "win32":
        return code
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(128)
        if ctypes.windll.kernel32.GetGeoInfoEx(ctypes.c_wchar_p(code.upper()), GEO_FRIENDLYNAME, buffer, len(buffer)) and buffer.value:
            return buffer.value
    except Exception:  # noqa: BLE001 - a name is a nicety
        pass
    return code
