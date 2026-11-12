"""Minimal Windows DPAPI wrapper (CurrentUser scope) used to encrypt the token cache at rest."""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

_ENTROPY = b"RADAR.token-cache.v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


if sys.platform == "win32":
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _sig = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.POINTER(_Blob), ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    _crypt32.CryptProtectData.argtypes = _sig
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_Blob), ctypes.POINTER(wintypes.LPWSTR),
                                            ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                                            wintypes.DWORD, ctypes.POINTER(_Blob)]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p


def _take(blob: _Blob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    src, _keep1 = _blob(data)
    ent, _keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not _crypt32.CryptProtectData(ctypes.byref(src), "RADAR", ctypes.byref(ent), None, None,
                                     _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _take(out)


def unprotect(data: bytes) -> bytes:
    src, _keep1 = _blob(data)
    ent, _keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None,
                                       _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _take(out)
