"""Reminder sound that respects the Windows output state (mute / zero volume / no device).

The sound is played on the DEFAULT playback device and nowhere else - the device whose mute and volume are checked.
Windows' own "play a sound" call (PlaySound / the wave mapper) does not promise that: in a process that has been
running while the devices changed (office -> home) it played through another, unmuted device although the default
one was muted. So the default device is looked up, its state read, and the sound sent to exactly that device.

Uses the Core Audio API (IMMDeviceEnumerator -> default render endpoint -> IAudioEndpointVolume) and the waveOut
functions through plain ctypes calls, so no extra packages are needed.
"""
from __future__ import annotations

import ctypes
import logging
import os
import struct
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text: str) -> "_GUID":
        g = cls()
        ctypes.oledll.ole32.CLSIDFromString(text, ctypes.byref(g))
        return g


CLSID_MMDeviceEnumerator = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
IID_IMMDeviceEnumerator = "{A95664D2-9614-4F35-A746-DE8DB63617E6}"
IID_IAudioEndpointVolume = "{5CDF2C82-841E-4546-9722-0CF74078229A}"
CLSCTX_ALL = 0x17
E_RENDER, E_CONSOLE = 0, 0
COINIT_APARTMENTTHREADED = 0x2
RPC_E_CHANGED_MODE = -2147417850  # 0x80010106
E_NOTFOUND = -2147023728  # 0x80070490: no output device

# vtable slots (IUnknown = 0..2)
_ENUM_GET_DEFAULT_ENDPOINT = 4
_DEVICE_ACTIVATE = 3
_DEVICE_OPEN_PROPERTY_STORE = 4
_DEVICE_GET_ID = 5
_STORE_GET_VALUE = 5
_VOL_GET_MASTER_SCALAR = 9
_VOL_GET_MUTE = 15
_RELEASE = 2


def _vcall(ptr: ctypes.c_void_p, index: int, argtypes: list, *args) -> int:
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(vtbl[index])
    return fn(ptr, *args)


def _release(ptr: ctypes.c_void_p) -> None:
    if ptr:
        _vcall(ptr, _RELEASE, [])


class _PropertyKey(ctypes.Structure):
    _fields_ = [("fmtid", _GUID), ("pid", wintypes.DWORD)]


class _PropVariant(ctypes.Structure):
    _fields_ = [("vt", wintypes.USHORT), ("r1", wintypes.USHORT), ("r2", wintypes.USHORT), ("r3", wintypes.USHORT),
                ("ptr", ctypes.c_void_p), ("pad", ctypes.c_void_p)]


PKEY_FRIENDLY_NAME = ("{a45c254e-df1c-4efd-8020-67d146a850e0}", 14)


@dataclass(frozen=True)
class OutputState:
    available: bool  # False: no default output device, or the state could not be read
    muted: bool = False
    volume: float = 0.0  # 0.0 .. 1.0
    error: str = ""
    device: str = ""     # name of the default playback device, e.g. "Speakers (Realtek Audio)"
    device_id: str = ""  # its endpoint id (to send the sound to exactly this device)

    @property
    def silent(self) -> bool:
        """Nothing would be heard: no device, muted or volume at zero."""
        return (not self.available and not self.error) or self.muted or (self.available and self.volume < 0.01)

    def describe(self) -> str:
        if self.error:
            return "unknown"
        if not self.available:
            return "no output device"
        if self.muted:
            return "muted"
        return f"on, volume {round(self.volume * 100)}%"

    def describe_device(self, limit: int = 44) -> str:
        """The default device by name with its state, e.g. "Speakers (Realtek Audio): muted"."""
        name = self.device if len(self.device) <= limit else self.device[:limit - 1].rstrip() + "\u2026"
        return f"{name}: {self.describe()}" if name else self.describe()


def _device_id(device: ctypes.c_void_p) -> str:
    try:
        text = ctypes.c_void_p()
        if _vcall(device, _DEVICE_GET_ID, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(text)) < 0 or not text:
            return ""
        value = ctypes.wstring_at(text.value)
        ctypes.windll.ole32.CoTaskMemFree(text)
        return value
    except OSError:
        return ""


def _device_name(device: ctypes.c_void_p) -> str:
    store = ctypes.c_void_p()
    try:
        if _vcall(device, _DEVICE_OPEN_PROPERTY_STORE, [wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)], 0, ctypes.byref(store)) < 0:
            return ""
        key = _PropertyKey(_GUID.parse(PKEY_FRIENDLY_NAME[0]), PKEY_FRIENDLY_NAME[1])
        value = _PropVariant()
        if _vcall(store, _STORE_GET_VALUE, [ctypes.POINTER(_PropertyKey), ctypes.POINTER(_PropVariant)],
                  ctypes.byref(key), ctypes.byref(value)) < 0 or not value.ptr:
            return ""
        name = ctypes.wstring_at(value.ptr)
        ctypes.windll.ole32.PropVariantClear(ctypes.byref(value))
        return name
    except OSError:
        return ""
    finally:
        try:
            _release(store)
        except OSError:
            pass


def output_state() -> OutputState:
    """Mute/volume of the current default Windows playback device."""
    ole32 = ctypes.oledll.ole32
    hr = ctypes.windll.ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    must_uninit = hr in (0, 1)  # S_OK / S_FALSE; RPC_E_CHANGED_MODE means COM is already usable
    enum = ctypes.c_void_p()
    device = ctypes.c_void_p()
    volume = ctypes.c_void_p()
    try:
        ole32.CoCreateInstance(ctypes.byref(_GUID.parse(CLSID_MMDeviceEnumerator)), None, CLSCTX_ALL,
                               ctypes.byref(_GUID.parse(IID_IMMDeviceEnumerator)), ctypes.byref(enum))
        hr = _vcall(enum, _ENUM_GET_DEFAULT_ENDPOINT, [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)],
                    E_RENDER, E_CONSOLE, ctypes.byref(device))
        if hr == E_NOTFOUND:
            return OutputState(available=False)
        if hr < 0:
            return OutputState(available=False, error=f"GetDefaultAudioEndpoint 0x{hr & 0xFFFFFFFF:08X}")
        name, device_id = _device_name(device), _device_id(device)
        iid = _GUID.parse(IID_IAudioEndpointVolume)
        hr = _vcall(device, _DEVICE_ACTIVATE, [ctypes.POINTER(_GUID), wintypes.DWORD, ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_void_p)],
                    ctypes.byref(iid), CLSCTX_ALL, None, ctypes.byref(volume))
        if hr < 0:
            return OutputState(available=False, error=f"Activate 0x{hr & 0xFFFFFFFF:08X}", device=name, device_id=device_id)
        muted = wintypes.BOOL()
        level = ctypes.c_float()
        if _vcall(volume, _VOL_GET_MUTE, [ctypes.POINTER(wintypes.BOOL)], ctypes.byref(muted)) < 0:
            return OutputState(available=False, error="GetMute failed", device=name, device_id=device_id)
        if _vcall(volume, _VOL_GET_MASTER_SCALAR, [ctypes.POINTER(ctypes.c_float)], ctypes.byref(level)) < 0:
            return OutputState(available=False, error="GetMasterVolumeLevelScalar failed", device=name, device_id=device_id)
        return OutputState(available=True, muted=bool(muted.value), volume=float(level.value), device=name, device_id=device_id)
    except OSError as exc:
        return OutputState(available=False, error=str(exc))
    finally:
        for ptr in (volume, device, enum):
            try:
                _release(ptr)
            except OSError:
                pass
        if must_uninit:
            ctypes.windll.ole32.CoUninitialize()


def _reminder_sound_files() -> list[str]:
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft Office/root/Office16/REMINDER.WAV",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Office/root/Office16/REMINDER.WAV",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "Media/Windows Notify Calendar.wav",
    ]
    return [str(p) for p in candidates if p.exists()]


# ------------------------------------------------------------ playing on one device
_DRV_QUERY_ID, _DRV_QUERY_ID_SIZE = 0x0811, 0x0812  # DRV_QUERYFUNCTIONINSTANCEID(SIZE): a waveOut device's endpoint id
_WAVE_MAPPED = 0x0004  # let Windows convert the file's format for the device given (not: pick a device)
_WHDR_DONE = 0x1


class _WaveHdr(ctypes.Structure):
    _fields_ = [("lpData", ctypes.c_void_p), ("dwBufferLength", wintypes.DWORD), ("dwBytesRecorded", wintypes.DWORD),
                ("dwUser", ctypes.c_size_t), ("dwFlags", wintypes.DWORD), ("dwLoops", wintypes.DWORD),
                ("lpNext", ctypes.c_void_p), ("reserved", ctypes.c_size_t)]


def _winmm():
    winmm = ctypes.windll.winmm
    winmm.waveOutMessage.argtypes = [ctypes.c_size_t, wintypes.UINT, ctypes.c_size_t, ctypes.c_size_t]
    winmm.waveOutMessage.restype = wintypes.UINT
    winmm.waveOutOpen.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.UINT, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_size_t, wintypes.DWORD]
    for name in ("waveOutPrepareHeader", "waveOutWrite", "waveOutUnprepareHeader"):
        getattr(winmm, name).argtypes = [ctypes.c_void_p, ctypes.POINTER(_WaveHdr), wintypes.UINT]
    winmm.waveOutReset.argtypes = winmm.waveOutClose.argtypes = [ctypes.c_void_p]
    return winmm


def wave_device_for(endpoint_id: str) -> int | None:
    """The waveOut device number of this playback endpoint (None: not found)."""
    if not endpoint_id:
        return None
    winmm = _winmm()
    for index in range(winmm.waveOutGetNumDevs()):
        size = ctypes.c_size_t(0)
        if winmm.waveOutMessage(index, _DRV_QUERY_ID_SIZE, ctypes.addressof(size), 0) != 0 or not size.value:
            continue
        buffer = ctypes.create_unicode_buffer(size.value // ctypes.sizeof(ctypes.c_wchar) + 1)
        if winmm.waveOutMessage(index, _DRV_QUERY_ID, ctypes.addressof(buffer), size.value) == 0 \
                and buffer.value.lower() == endpoint_id.lower():
            return index
    return None


def read_wav(path: str) -> tuple[bytes, bytes]:
    """(format block, sound data) of a .wav file - any format Windows can play (also the compressed Outlook sound)."""
    raw = Path(path).read_bytes()
    if raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise ValueError("not a WAV file")
    fmt = data = b""
    pos = 12
    while pos + 8 <= len(raw):
        tag, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + size]
        if tag == b"fmt ":
            fmt = body
        elif tag == b"data":
            data = body
        pos += 8 + size + (size & 1)
    if len(fmt) < 16 or not data:
        raise ValueError("WAV file without format or data")
    if len(fmt) < 18:
        fmt += b"\x00\x00"  # WAVEFORMATEX wants the size of the extra bytes (none)
    return fmt, data


def _play_on(device: int, path: str) -> str:
    """Start playing the file on this waveOut device; the rest happens on a thread of its own. '' or what went wrong."""
    try:
        fmt, data = read_wav(path)
    except (OSError, ValueError) as exc:
        return f"sound file not readable ({exc})"
    winmm = _winmm()
    handle = ctypes.c_void_p()
    fmt_buffer = ctypes.create_string_buffer(fmt, len(fmt))
    code = winmm.waveOutOpen(ctypes.byref(handle), device, ctypes.addressof(fmt_buffer), 0, 0, _WAVE_MAPPED)
    if code != 0:
        return f"the device does not take the sound (waveOutOpen {code})"
    buffer = ctypes.create_string_buffer(data, len(data))
    header = _WaveHdr(lpData=ctypes.addressof(buffer), dwBufferLength=len(data))
    size = ctypes.sizeof(_WaveHdr)
    code = winmm.waveOutPrepareHeader(handle, ctypes.byref(header), size) or winmm.waveOutWrite(handle, ctypes.byref(header), size)
    if code != 0:
        winmm.waveOutClose(handle)
        return f"the sound could not be started (waveOut {code})"

    def finish(_keep=(buffer, fmt_buffer)) -> None:  # wait for the end, then give the device back (the sound data stays alive here)
        end = time.monotonic() + 15
        while not header.dwFlags & _WHDR_DONE and time.monotonic() < end:
            time.sleep(0.05)
        winmm.waveOutReset(handle)
        winmm.waveOutUnprepareHeader(handle, ctypes.byref(header), size)
        winmm.waveOutClose(handle)

    threading.Thread(target=finish, name="reminder-sound", daemon=True).start()
    return ""


def play_reminder(respect_mute: bool = True) -> tuple[bool, str]:
    """Play the reminder sound on the default playback device - and only there. Returns (played, reason)."""
    state = output_state()
    if not state.device_id and not state.error and not state.available:
        log.info("Reminder sound not played: no playback device")
        return False, "there is no playback device"
    if state.error and not state.device_id:
        time.sleep(0.4)  # the devices are just changing (docking, a headset connecting): look once more
        state = output_state()
    if respect_mute and state.silent:
        log.info("Reminder sound suppressed: %s", state.describe_device())
        return False, f"Windows audio is {state.describe()}" + (f" ({state.device})" if state.device else "")
    device = wave_device_for(state.device_id)
    if device is None:
        # Not played through "whatever Windows picks": that is how the sound ended up on a device that was not the
        # default one.
        log.warning("Reminder sound not played: the default playback device could not be addressed (%s)",
                    state.device or state.error or "unknown")
        return False, "the default playback device could not be addressed"
    candidates = _reminder_sound_files()
    problem = "no sound file found"
    for sound in candidates:
        problem = _play_on(device, sound)
        if not problem:
            log.info("Reminder sound played on %s", state.describe_device())
            return True, "played"
        log.debug("Reminder sound %s: %s", sound, problem)
    log.warning("Reminder sound not played on %s: %s", state.device or "the default device", problem)
    return False, problem
