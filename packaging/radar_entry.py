"""Entry point of the packaged RADAR.exe.

``RADAR.exe``            the tray app (same switches as ``python -m radar``)
``RADAR.exe --mapview``  the live map, started by the tray app as a process of its own
"""
import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--mapview":
        del sys.argv[1]
        from radar.mapview.__main__ import main as run_map

        run_map()
        return 0
    from radar.__main__ import main as run_app

    return run_app()


if __name__ == "__main__":
    sys.exit(main())
