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
print(radar.__version__)
