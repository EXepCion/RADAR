"""What build this is. A released RADAR is built from the commit its version tag points at; anything else - a build
on a developer's PC, with or without changes that are not committed - carries the same version number and says so:
'1.0.8 (dev.abc1234+changes)'. The mark is written by packaging/prepare.py at build time (``_build.py``, not in the
repository); the version number itself stays what the release and the update check go by."""
from __future__ import annotations

from . import __version__

try:
    from ._build import BUILD  # type: ignore[import-not-found]  (written at build time)
except ImportError:  # run from the source tree
    BUILD = ""


def mark(version: str, tag: str, commit: str, changed: bool) -> str:
    """'' for the release (the commit carries the tag of this version and nothing was changed), else what it is
    built from. No commit known (no git): nothing is claimed."""
    if not commit:
        return ""
    if tag == f"v{version}" and not changed:
        return ""
    return f"dev.{commit}" + ("+changes" if changed else "")


def full_version(version: str = __version__, build: str | None = None) -> str:
    build = BUILD if build is None else build
    return f"{version} ({build})" if build else version
