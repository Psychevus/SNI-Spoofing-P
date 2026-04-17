# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import importlib.util
import platform
import tomllib


ROOT = Path(globals().get("SPECPATH", Path.cwd())).resolve()
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
VERSION = PROJECT["version"]
ARCH = "windows-x64" if platform.machine().lower() in {"amd64", "x86_64"} else platform.machine().lower()
DIST_NAME = f"sni-spoofing-proxy-{VERSION}-{ARCH}"


def package_root(package_name):
    spec = importlib.util.find_spec(package_name)
    if spec is None or spec.origin is None:
        raise RuntimeError(f"Required package is not installed: {package_name}")
    return Path(spec.origin).resolve().parent


pydivert_root = package_root("pydivert")
windivert_root = pydivert_root / "windivert_dll"

windivert_binaries = [
    (str(windivert_root / "WinDivert64.dll"), "pydivert/windivert_dll"),
]

windivert_datas = [
    (str(windivert_root / "WinDivert64.sys"), "pydivert/windivert_dll"),
]

hidden_imports = [
    "pydivert",
    "pydivert.consts",
    "pydivert.packet",
    "pydivert.packet.header",
    "pydivert.packet.icmp",
    "pydivert.packet.ip",
    "pydivert.packet.tcp",
    "pydivert.packet.udp",
    "pydivert.service",
    "pydivert.util",
    "pydivert.windivert",
    "pydivert.windivert_dll",
    "pydivert.windivert_dll.structs",
]

a = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=windivert_binaries,
    datas=windivert_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pydivert.tests",
        "pytest",
        "test",
        "tests",
        "tkinter",
        "unittest.mock",
    ],
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sni-spoof",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=DIST_NAME,
)
