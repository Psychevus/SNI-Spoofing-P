from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"
SPEC = ROOT / "sni-spoofing-proxy.spec"


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def load_project() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]


def release_name(version: str) -> str:
    machine = platform.machine().lower()
    arch = "windows-x64" if machine in {"amd64", "x86_64"} else machine
    return f"sni-spoofing-proxy-{version}-{arch}"


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def clean_outputs(name: str) -> None:
    remove_path(DIST / name)
    remove_path(BUILD / "sni-spoofing-proxy")
    remove_path(DIST / f"{name}.zip")
    remove_path(DIST / f"{name}.zip.sha256")
    legacy_archive = (DIST / name).with_suffix(".zip")
    remove_path(legacy_archive)
    remove_path(legacy_archive.with_name(f"{legacy_archive.name}.sha256"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_required_files(release_dir: Path) -> None:
    for filename in ("config.json", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / filename, release_dir / filename)


def copy_windows_helpers(release_dir: Path) -> None:
    helper_dir = ROOT / "packaging" / "windows"
    if not helper_dir.exists():
        return
    for source in sorted(helper_dir.iterdir()):
        if source.is_file():
            shutil.copy2(source, release_dir / source.name)


def copy_third_party_licenses(release_dir: Path) -> None:
    try:
        dist = importlib.metadata.distribution("pydivert")
    except importlib.metadata.PackageNotFoundError:
        return

    licenses = []
    for item in dist.files or []:
        item_text = str(item).replace("\\", "/")
        if "/licenses/" in item_text or item_text.lower().endswith(("license", "authors")):
            source = Path(dist.locate_file(item))
            if source.is_file():
                licenses.append(source)

    if not licenses:
        return

    target_root = release_dir / "third_party_licenses" / "pydivert"
    target_root.mkdir(parents=True, exist_ok=True)
    for source in licenses:
        shutil.copy2(source, target_root / source.name)


def write_manifest(release_dir: Path, project: dict[str, object]) -> None:
    files = []
    for path in sorted(p for p in release_dir.rglob("*") if p.is_file()):
        files.append(
            {
                "path": path.relative_to(release_dir).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    manifest = {
        "name": project["name"],
        "version": project["version"],
        "built_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "pyinstaller": importlib.metadata.version("pyinstaller"),
        "pydivert": importlib.metadata.version("pydivert"),
        "entrypoint": "sni-spoof.exe",
        "uac_manifest": False,
        "run_requires_administrator": True,
        "files": files,
    }
    (release_dir / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def write_checksums(release_dir: Path) -> None:
    lines = []
    for path in sorted(p for p in release_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(release_dir).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    (release_dir / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_zip(release_dir: Path) -> Path:
    archive = release_dir.parent / f"{release_dir.name}.zip"
    remove_path(archive)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in release_dir.rglob("*") if p.is_file()):
            zf.write(path, path.relative_to(release_dir.parent))
    archive.with_name(f"{archive.name}.sha256").write_text(f"{sha256_file(archive)}  {archive.name}\n", encoding="utf-8")
    return archive


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Windows release bundle with PyInstaller.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip unit tests and dry-run validation.")
    parser.add_argument("--no-clean", action="store_true", help="Keep previous build artifacts.")
    parser.add_argument("--no-archive", action="store_true", help="Do not create a release ZIP archive.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project = load_project()
    name = release_name(str(project["version"]))
    release_dir = DIST / name

    if platform.system() != "Windows":
        raise SystemExit("Windows is required for a WinDivert release build.")
    if platform.architecture()[0] != "64bit":
        raise SystemExit("64-bit Python is required for pydivert and WinDivert.")
    if not SPEC.exists():
        raise SystemExit(f"Missing PyInstaller spec: {SPEC}")

    try:
        importlib.metadata.version("pyinstaller")
    except importlib.metadata.PackageNotFoundError as exc:
        raise SystemExit("PyInstaller is not installed. Run: python -m pip install -r requirements-build.txt") from exc

    if not args.no_clean:
        clean_outputs(name)

    if not args.skip_tests:
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"])
        run([sys.executable, "-B", "main.py", "--dry-run"])

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--workpath",
            str(BUILD / "sni-spoofing-proxy"),
            "--distpath",
            str(DIST),
            str(SPEC),
        ],
        env=env,
    )

    if not release_dir.exists():
        raise SystemExit(f"PyInstaller did not create the expected output folder: {release_dir}")

    copy_required_files(release_dir)
    copy_windows_helpers(release_dir)
    copy_third_party_licenses(release_dir)
    write_manifest(release_dir, project)
    write_checksums(release_dir)
    archive = None if args.no_archive else make_zip(release_dir)

    print()
    print(f"Release folder: {release_dir}")
    if archive:
        print(f"Release archive: {archive}")
        print(f"Archive checksum: {archive.with_name(f'{archive.name}.sha256')}")
    print(f"Executable: {release_dir / 'sni-spoof.exe'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
