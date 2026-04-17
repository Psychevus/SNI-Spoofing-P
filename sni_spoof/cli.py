from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .browser import build_launch_plan, launch_browser
from .config import AppConfig, ConfigError
from .config_store import delete_profile, list_profiles, profile_from_config, save_profile, show_profile
from .doctor import format_checks, has_failures, run_doctor
from .logging_utils import configure_logging
from .pac import generate_pac
from .proxy import SpoofingProxy
from .selftest import test_tunnel
from .wizard import run_wizard


def default_config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "config.json"
    return Path(__file__).resolve().parent.parent / "config.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sni-spoof",
        description="Run a local TCP proxy with controlled TLS SNI spoofing during connection setup.",
    )
    parser.add_argument("command", nargs="?", choices=("run", "doctor", "test-tunnel", "pac", "wizard", "profiles", "launch-browser"), default="run", help="Command to run.")
    parser.add_argument("--config", default=str(default_config_path()), help="Path to the JSON configuration file.")
    parser.add_argument("--profile", help="Named profile from the configuration file.")
    parser.add_argument("--listen-host", help="Local address to bind.")
    parser.add_argument("--listen-port", type=int, help="Local TCP port to bind.")
    parser.add_argument("--connect-ip", help="Remote IPv4 address to connect to.")
    parser.add_argument("--connect-port", type=int, help="Remote TCP port to connect to.")
    parser.add_argument("--fake-sni", help="Hostname to place in the injected TLS ClientHello.")
    parser.add_argument("--proxy-mode", choices=("http-connect", "http_connect", "raw"), help="Frontend mode to run.")
    parser.add_argument("--allowed-host", action="append", dest="allowed_hosts", help="Allowed CONNECT host. Can be repeated.")
    parser.add_argument("--allowed-ports", help="Comma-separated allowed CONNECT ports.")
    parser.add_argument("--auth-token", help="Optional proxy authentication token for HTTP CONNECT mode.")
    parser.add_argument("--interface-ipv4", help="Local IPv4 address to use instead of auto-detection.")
    parser.add_argument("--strict-local-only", dest="strict_local_only", action="store_true", default=None, help="Require loopback listener binding.")
    parser.add_argument("--allow-remote-bind", dest="strict_local_only", action="store_false", help="Allow non-loopback listener binding.")
    parser.add_argument("--require-auth-for-remote-bind", dest="require_auth_for_remote_bind", action="store_true", default=None, help="Require auth token when binding HTTP CONNECT remotely.")
    parser.add_argument("--no-require-auth-for-remote-bind", dest="require_auth_for_remote_bind", action="store_false", help="Allow remote HTTP CONNECT binding without auth.")
    parser.add_argument("--control-enabled", dest="control_enabled", action="store_true", default=None, help="Enable local control dashboard.")
    parser.add_argument("--control-disabled", dest="control_enabled", action="store_false", help="Disable local control dashboard.")
    parser.add_argument("--control-host", help="Control dashboard bind address.")
    parser.add_argument("--control-port", type=int, help="Control dashboard TCP port.")
    parser.add_argument("--connect-timeout", type=float, help="Seconds to wait for upstream TCP connection setup.")
    parser.add_argument("--idle-timeout", type=float, help="Seconds before an idle tunnel is closed.")
    parser.add_argument("--handshake-timeout", type=float, help="Seconds to wait for the injected packet acknowledgement.")
    parser.add_argument("--recv-buffer-size", type=int, help="Relay receive buffer size in bytes.")
    parser.add_argument("--backlog", type=int, help="Listen socket backlog.")
    parser.add_argument("--max-connect-header-bytes", type=int, help="Maximum HTTP CONNECT header size.")
    parser.add_argument("--max-active-connections", type=int, help="Maximum concurrent client connections.")
    parser.add_argument("--log-level", help="Python logging level.")
    parser.add_argument("--log-format", choices=("text", "json"), help="Log output format.")
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration and print the resolved runtime plan.")
    parser.add_argument("--test-host", help="Host to test through a running HTTP CONNECT proxy.")
    parser.add_argument("--test-path", default="/", help="HTTP path to request during test-tunnel.")
    parser.add_argument("--pac-output", help="Write generated PAC content to this path instead of stdout.")
    parser.add_argument("--show-profile", help="Show a profile from the configuration file.")
    parser.add_argument("--save-profile", help="Save the resolved runtime config as a named profile.")
    parser.add_argument("--delete-profile", help="Delete a named profile from the configuration file.")
    parser.add_argument("--browser", default="auto", help="Browser to launch: auto, edge, chrome, brave, or a browser executable.")
    parser.add_argument("--browser-url", help="URL to open in launch-browser mode.")
    parser.add_argument("--browser-profile-dir", help="Dedicated browser profile directory.")
    parser.add_argument("--browser-proxy-mode", choices=("pac", "server"), default="pac", help="Use PAC or direct proxy server arguments for browser launch.")
    return parser


def load_config(args: argparse.Namespace) -> AppConfig:
    config = AppConfig.load(args.config, args.profile)
    return config.with_overrides(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        connect_ip=args.connect_ip,
        connect_port=args.connect_port,
        fake_sni=args.fake_sni,
        proxy_mode=args.proxy_mode,
        allowed_hosts=args.allowed_hosts,
        allowed_ports=args.allowed_ports,
        auth_token=args.auth_token,
        interface_ipv4=args.interface_ipv4,
        strict_local_only=args.strict_local_only,
        require_auth_for_remote_bind=args.require_auth_for_remote_bind,
        control_enabled=args.control_enabled,
        control_host=args.control_host,
        control_port=args.control_port,
        connect_timeout=args.connect_timeout,
        idle_timeout=args.idle_timeout,
        handshake_timeout=args.handshake_timeout,
        recv_buffer_size=args.recv_buffer_size,
        backlog=args.backlog,
        max_connect_header_bytes=args.max_connect_header_bytes,
        max_active_connections=args.max_active_connections,
        log_level=args.log_level.upper() if args.log_level else None,
        log_format=args.log_format,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "wizard":
            run_wizard(args.config)
            return 0

        if args.command == "profiles" and args.delete_profile:
            delete_profile(args.config, args.delete_profile)
            print(f"Deleted profile: {args.delete_profile}")
            return 0

        if args.command == "profiles" and args.show_profile:
            print(json.dumps(show_profile(args.config, args.show_profile), indent=2, sort_keys=True))
            return 0

        if args.command == "profiles" and not args.save_profile:
            profiles = list_profiles(args.config)
            if not profiles:
                print("No profiles found.")
                return 0
            for name in sorted(profiles):
                print(name)
            return 0

        config = load_config(args)
        configure_logging(config.log_level, config.log_format)

        if args.command == "profiles" and args.save_profile:
            save_profile(args.config, args.save_profile, profile_from_config(config))
            print(f"Saved profile: {args.save_profile}")
            return 0

        if args.dry_run:
            print(json.dumps(config.public_summary(), indent=2, sort_keys=True))
            warnings = config.security_warnings()
            if warnings:
                print("\nSecurity warnings:")
                for warning in warnings:
                    print(f"- {warning}")
            return 0

        if args.command == "doctor":
            checks = run_doctor(config)
            print(format_checks(checks))
            return 1 if has_failures(checks) else 0

        if args.command == "test-tunnel":
            result = test_tunnel(config, args.test_host, args.test_path)
            status = "OK" if result.ok else "FAIL"
            print(f"[{status}] {result.detail} ({result.elapsed_ms} ms)")
            if result.response_preview:
                print("\nResponse preview:")
                print(result.response_preview[:1000])
            return 0 if result.ok else 1

        if args.command == "pac":
            pac = generate_pac(config)
            if args.pac_output:
                Path(args.pac_output).write_text(pac, encoding="utf-8")
                print(f"Wrote PAC file to {args.pac_output}")
            else:
                print(pac, end="")
            return 0

        if args.command == "launch-browser":
            plan = build_launch_plan(
                config,
                browser=args.browser,
                url=args.browser_url,
                user_data_dir=args.browser_profile_dir,
                proxy_mode=args.browser_proxy_mode,
            )
            pid = launch_browser(plan)
            print(f"Launched browser process {pid}")
            print(f"Profile directory: {plan.user_data_dir}")
            return 0

        asyncio.run(SpoofingProxy(config).serve())
        return 0
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        print(f"Runtime error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
