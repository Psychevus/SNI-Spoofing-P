from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import AppConfig


SUPPORTED_BROWSERS = ("edge", "chrome", "brave")


@dataclass(frozen=True)
class BrowserLaunchPlan:
    executable: str
    args: list[str]
    user_data_dir: Path


def find_browser(browser: str = "auto") -> str:
    candidates = _browser_candidates(browser)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        expanded = os.path.expandvars(candidate)
        if Path(expanded).exists():
            return expanded
    raise RuntimeError(f"could not find a supported browser: {browser}")


def build_launch_plan(
    config: AppConfig,
    browser: str = "auto",
    url: str | None = None,
    user_data_dir: str | Path | None = None,
    proxy_mode: str = "pac",
) -> BrowserLaunchPlan:
    executable = find_browser(browser)
    profile_dir = Path(user_data_dir or Path(".runtime") / "browser-profile").resolve()
    start_url = url or f"https://{config.fake_sni}/"

    args = [
        executable,
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--new-window",
    ]
    if proxy_mode == "pac":
        if not config.control_enabled:
            raise RuntimeError("PAC browser launch requires the control server to be enabled")
        args.append(f"--proxy-pac-url=http://{config.control_host}:{config.control_port}/proxy.pac")
    elif proxy_mode == "server":
        args.append(f"--proxy-server=http://{config.listen_host}:{config.listen_port}")
    else:
        raise RuntimeError("browser proxy mode must be either 'pac' or 'server'")
    args.append(start_url)
    return BrowserLaunchPlan(executable=executable, args=args, user_data_dir=profile_dir)


def launch_browser(plan: BrowserLaunchPlan) -> int:
    plan.user_data_dir.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(plan.args)
    return process.pid


def _browser_candidates(browser: str) -> list[str]:
    if browser == "auto":
        names = ["edge", "chrome", "brave"]
    else:
        names = [browser]

    candidates: list[str] = []
    for name in names:
        if name == "edge":
            candidates.extend(
                [
                    "msedge",
                    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
                    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
                ]
            )
        elif name == "chrome":
            candidates.extend(
                [
                    "chrome",
                    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
                    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
                    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
                ]
            )
        elif name == "brave":
            candidates.extend(
                [
                    "brave",
                    "brave-browser",
                    r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
                    r"%ProgramFiles(x86)%\BraveSoftware\Brave-Browser\Application\brave.exe",
                    r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe",
                ]
            )
        else:
            candidates.append(name)
    return candidates
