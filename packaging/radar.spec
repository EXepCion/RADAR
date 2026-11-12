# PyInstaller build description for RADAR (a folder build: RADAR.exe next to an _internal folder with plain files,
# so the bundled libraries can be looked at and replaced). Run through packaging/build.ps1.
import pathlib
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules, copy_metadata

ROOT = pathlib.Path(SPECPATH).parent
sys.path.insert(0, str(ROOT / "src"))
import radar  # noqa: E402  (the version number)

datas = collect_data_files("radar")            # the map page, map files and the town index
datas += collect_data_files("sv_ttk")          # the Windows 11 look for tkinter
datas += collect_data_files("pymsalruntime")
datas += [(str(ROOT / "templates" / "example_plugin.py"), "templates"),
          (str(ROOT / "LICENSE"), "."), (str(ROOT / "THIRD-PARTY-NOTICES.md"), "."), (str(ROOT / "README.md"), "."),
          (str(ROOT / "licenses" / "ECharts-LICENSE.txt"), "licenses"), (str(ROOT / "licenses" / "ECharts-NOTICE.txt"), "licenses"),
          (str(ROOT / "licenses" / "LGPL-3.0.txt"), "licenses"), (str(ROOT / "licenses" / "GPL-3.0.txt"), "licenses")]
for package in ("msal", "pymsalruntime", "pystray", "requests", "sv_ttk", "pillow", "certifi", "urllib3", "idna",
                "charset_normalizer", "cryptography", "PyJWT", "cffi", "pycparser"):
    try:
        datas += copy_metadata(package)        # each package's licence and metadata (*.dist-info)
    except Exception:                          # noqa: BLE001 - not installed under that name: nothing to copy
        pass
binaries = collect_dynamic_libs("pymsalruntime")
hidden = collect_submodules("radar") + ["pystray._win32", "PIL._tkinter_finder"]

a = Analysis(
    [str(ROOT / "packaging" / "radar_entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    excludes=["pytest", "_pytest", "PyInstaller", "pip", "setuptools", "wheel"],
    # pystray (LGPL) is not packed into the program's archive: it ships as plain .py files in _internal/pystray,
    # so it can be replaced by another version without rebuilding RADAR (see THIRD-PARTY-NOTICES.md)
    module_collection_mode={"pystray": "py"},
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RADAR",
    console=False,                             # a tray app: no console window
    icon=str(ROOT / "packaging" / "build" / "radar.ico"),
    version=str(ROOT / "packaging" / "build" / "version_info.txt"),
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="RADAR", upx=False)
