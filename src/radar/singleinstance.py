"""One instance per user session. A second launch asks the running instance to show its reminders."""
from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes
from typing import Callable

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
_k32.CreateMutexW.restype = wintypes.HANDLE
_k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
_k32.CreateEventW.restype = wintypes.HANDLE
_k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
_k32.OpenEventW.restype = wintypes.HANDLE
_k32.SetEvent.argtypes = [wintypes.HANDLE]
_k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_k32.WaitForSingleObject.restype = wintypes.DWORD
_k32.CloseHandle.argtypes = [wintypes.HANDLE]

ERROR_ALREADY_EXISTS = 183
EVENT_MODIFY_STATE = 0x0002
WAIT_OBJECT_0 = 0


class SingleInstance:
    def __init__(self, name: str):
        self._mutex_name = f"Local\\{name}.instance"
        self._event_name = f"Local\\{name}.show"
        self._mutex = _k32.CreateMutexW(None, False, self._mutex_name)
        self.already_running = ctypes.get_last_error() == ERROR_ALREADY_EXISTS

    def close(self) -> None:
        if self._mutex:
            _k32.CloseHandle(self._mutex)
            self._mutex = None

    def signal_running_instance(self) -> bool:
        handle = _k32.OpenEventW(EVENT_MODIFY_STATE, False, self._event_name)
        if not handle:
            return False
        try:
            return bool(_k32.SetEvent(handle))
        finally:
            _k32.CloseHandle(handle)

    def listen(self, callback: Callable[[], None], stop_event: threading.Event) -> None:
        handle = _k32.CreateEventW(None, False, False, self._event_name)

        def _loop() -> None:
            while not stop_event.is_set():
                if _k32.WaitForSingleObject(handle, 1000) == WAIT_OBJECT_0:
                    callback()
            _k32.CloseHandle(handle)

        threading.Thread(target=_loop, name="instance-signal", daemon=True).start()
