"""Is the disk RADAR keeps its data on encrypted?

RADAR stores the sign-in history of an organisation, its alerts and the names of accounts as plain files (only the
sign-in token is encrypted). On an encrypted disk that is fine; on one that is not, whoever gets hold of the PC can
read them. RADAR cannot encrypt the disk and does not refuse to work without it - it says what Windows reports: in
the set-up page, and with a reminder that can be switched off (``general.remind_disk_not_encrypted``).

What is asked is the shell property ``System.Volume.BitLockerProtection`` of the drive - the one Explorer takes its
drive icons from; it needs no administrator rights. It knows BitLocker and Windows device encryption (the same
thing). Other products, self-encrypting drives and the host of a virtual PC it does not see: then Windows says "off"
or nothing, and the reminder is there to be switched off.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

ENCRYPTED, NOT_ENCRYPTED, SUSPENDED, UNKNOWN = "encrypted", "not encrypted", "suspended", "unknown"
# the property's values, as its own list names them (IPropertyDescription::GetEnumTypeList): On, Off, Encrypting,
# Decrypting, Suspended, Locked, Not encryptable, Waiting for activation
_VALUES = {
    1: (ENCRYPTED, "BitLocker on"),
    2: (NOT_ENCRYPTED, "BitLocker off"),
    3: (ENCRYPTED, "being encrypted"),
    4: (NOT_ENCRYPTED, "being decrypted"),
    5: (SUSPENDED, "BitLocker suspended"),
    6: (ENCRYPTED, "BitLocker on, locked"),
    7: (UNKNOWN, "not a drive Windows can encrypt"),
    8: (NOT_ENCRYPTED, "encryption not activated"),
}
PROPERTY = "System.Volume.BitLockerProtection"
ALERT_KEY = "disk-not-encrypted"
SETTINGS_LINK = "radar://disk-settings"
FIRST_CHECK_AFTER = 30          # seconds after the start
CHECK_EVERY = 3600              # ... and then: it costs nothing, and a disk decrypted today is said today
SUSPENDED_FOR = timedelta(hours=24)   # Windows suspends protection by itself during some updates


@dataclass(frozen=True)
class Status:
    drive: str    # "C:" ('' = not a local drive)
    state: str    # ENCRYPTED, NOT_ENCRYPTED, SUSPENDED or UNKNOWN
    what: str     # what Windows says, in a few words


def judge(value: int | None) -> tuple[str, str]:
    return _VALUES.get(value, (UNKNOWN, "Windows does not say")) if isinstance(value, int) else (UNKNOWN, "Windows does not say")


def drive_of(path: str | os.PathLike) -> str:
    """'C:' for a folder on a local drive, '' for anything else (a network share)."""
    import ntpath

    drive = ntpath.splitdrive(ntpath.abspath(str(path)) if not str(path).startswith("\\\\") else str(path))[0]
    return drive.upper() if len(drive) == 2 and drive[1] == ":" else ""


def read(path: str | os.PathLike | Path, value_of: Callable[[str], int | None] | None = None) -> Status:
    """What Windows says about the drive ``path`` is on. Never raises: no answer is UNKNOWN."""
    drive = drive_of(path)
    if not drive:
        return Status("", UNKNOWN, "not a local drive")
    try:
        value = (value_of or protection_value)(drive)
    except Exception as exc:  # noqa: BLE001
        log.debug("disk encryption of %s could not be asked: %s", drive, exc)
        value = None
    return Status(drive, *judge(value))


def protection_value(drive: str) -> int | None:
    """The raw value of the property for 'C:' (None: Windows gives none). Windows only."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

    class PROPERTYKEY(ctypes.Structure):
        _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]

    ole32, shell32, propsys = ctypes.OleDLL("ole32"), ctypes.OleDLL("shell32"), ctypes.OleDLL("propsys")
    co_init = ctypes.windll.ole32.CoInitializeEx
    co_init.argtypes, co_init.restype = [ctypes.c_void_p, wintypes.DWORD], ctypes.c_long
    began = co_init(None, 0x2)  # apartment threaded; < 0: the thread already has COM in another mode - usable as it is
    try:
        iid = GUID()  # IShellItem2
        ole32.CLSIDFromString(ctypes.c_wchar_p("{7E9FB0D3-919F-4307-AB2E-9B1860310C93}"), ctypes.byref(iid))
        key = PROPERTYKEY()
        propsys.PSGetPropertyKeyFromName(ctypes.c_wchar_p(PROPERTY), ctypes.byref(key))
        item = ctypes.c_void_p()
        shell32.SHCreateItemFromParsingName.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        shell32.SHCreateItemFromParsingName(drive + "\\", None, ctypes.byref(iid), ctypes.byref(item))
        vtable = ctypes.cast(ctypes.cast(item, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
        method = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int))
        release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtable[2])
        try:
            number = ctypes.c_int()
            hr = method(vtable[16])(item, ctypes.byref(key), ctypes.byref(number))  # IShellItem2::GetInt32
            return number.value if hr == 0 else None  # (a drive without the property: no value)
        finally:
            release(item)
    finally:
        if began >= 0:
            ctypes.windll.ole32.CoUninitialize()


class Watch:
    """Decides when to look and whether a reminder is due. ``since``/``remember`` keep since when the protection is
    suspended (an ISO time, '' = it is not), so that a restart of RADAR does not start the day anew."""

    def __init__(self, read: Callable[[], Status], enabled: Callable[[], bool], since: Callable[[], str],
                 remember: Callable[[str], None], clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._read, self._enabled, self._since, self._remember = read, enabled, since, remember
        self._clock, self._now = clock, now
        self._next = clock() + FIRST_CHECK_AFTER

    def due(self) -> bool:
        return self._clock() >= self._next

    def check(self) -> tuple[Status, bool]:
        """Look now: what Windows says, and whether the user is to be reminded of it."""
        self._next = self._clock() + CHECK_EVERY
        status = self._read()
        lasting = False
        if status.state == SUSPENDED:
            started = self._started()
            if started is None:
                started = self._now()
                self._remember(started.isoformat())
            lasting = self._now() - started >= SUSPENDED_FOR
        elif self._since():
            self._remember("")
        return status, self._enabled() and (status.state == NOT_ENCRYPTED or lasting)

    def _started(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self._since()) if self._since() else None
        except ValueError:
            return None


def reminder(status: Status) -> tuple[str, str, str]:
    """Title, summary and recommendation of the reminder."""
    if status.state == SUSPENDED:
        title = "The encryption of the disk RADAR keeps its data on has been suspended for a day"
        state = "is encrypted, but its protection is suspended: the key lies open on the disk"
    else:
        title = "The disk RADAR keeps its data on is not encrypted"
        state = f"is not protected by BitLocker or Windows device encryption (Windows says: {status.what})"
    summary = (f"Drive {status.drive} {state}. RADAR keeps the sign-in history of your organisation, its alerts and the "
               "names of accounts there as plain files: whoever gets hold of this PC or its disk can read them.")
    recommendation = ("Turn on device encryption or BitLocker in Windows (resume it, if it is suspended). If the disk is "
                      "encrypted by something RADAR cannot see - another product, the host of a virtual PC -, switch this "
                      "reminder off: RADAR > Settings > Account and connection > Disk encryption.")
    return title, summary, recommendation


def edition() -> str:
    """Windows' EditionID ('Core' = Home, 'Professional', 'Enterprise' ...), '' when it cannot be read."""
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            return str(winreg.QueryValueEx(key, "EditionID")[0])
    except Exception:  # noqa: BLE001
        return ""


def settings_command(edition_id: str) -> list[str]:
    """Where Windows has the switch: Home has device encryption in Settings, the other editions BitLocker's own page."""
    if not edition_id or edition_id.startswith("Core"):
        return ["ms-settings:deviceencryption"]
    system = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "control.exe")
    return [system, "/name", "Microsoft.BitLockerDriveEncryption"]


def open_settings() -> None:
    import subprocess

    command = settings_command(edition())
    try:
        if len(command) == 1:
            os.startfile(command[0])  # type: ignore[attr-defined]  # noqa: S606
        else:
            subprocess.Popen(command, close_fds=True)  # noqa: S603
    except OSError:
        log.warning("The Windows encryption settings could not be opened", exc_info=True)
