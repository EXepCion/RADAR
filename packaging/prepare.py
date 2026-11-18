"""Before the build: draw the icon and write the version details Windows shows for RADAR.exe.

    python packaging/prepare.py      ->  packaging/build/radar.ico, packaging/build/version_info.txt
    prints the version number (for the build script)
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import radar  # noqa: E402
from radar.ui import icons  # noqa: E402

out = ROOT / "packaging" / "build"
out.mkdir(parents=True, exist_ok=True)
icons.save_ico(str(out / "radar.ico"))

parts = [int(p) for p in radar.__version__.split(".")[:3]]
numbers = tuple(parts + [0] * (4 - len(parts)))
(out / "version_info.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'The RADAR authors'),
      StringStruct('FileDescription', 'RADAR - {radar.APP_TAGLINE}'),
      StringStruct('FileVersion', '{radar.__version__}'),
      StringStruct('InternalName', 'RADAR'),
      StringStruct('LegalCopyright', 'MIT licence'),
      StringStruct('OriginalFilename', 'RADAR.exe'),
      StringStruct('ProductName', 'RADAR'),
      StringStruct('ProductVersion', '{radar.__version__}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")

def _git(*args: str) -> str:
    import subprocess

    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    except Exception:  # noqa: BLE001 - no git, no repository: the build claims nothing
        return ""


# What this build is made from (see radar/buildinfo.py): nothing for the release, else the commit.
from radar import buildinfo  # noqa: E402

tag = f"v{radar.__version__}"
build = buildinfo.mark(radar.__version__, tag if tag in _git("tag", "--points-at", "HEAD").split() else "",
                       _git("rev-parse", "--short", "HEAD"), bool(_git("status", "--porcelain", "--untracked-files=no")))
(ROOT / "src" / "radar" / "_build.py").write_text(
    f'"""Written by packaging/prepare.py at build time (not in the repository)."""\nBUILD = {build!r}\n', encoding="utf-8")
print(radar.__version__)
