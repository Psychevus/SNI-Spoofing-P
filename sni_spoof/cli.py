from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import AppConfig, ConfigError
from .logging_utils import configure_logging
from .proxy import SpoofingProxy


def default_config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "config.json"
    return Path(__file__).resolve().parent.parent / "config.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sni-spoof",
        description="Run a local TCP proxy with controlled TLS SNI spoofing during connection setup.",
    )
    parser.add_argument("--config", default=str(default_config_path()), help="Path to the JSON configuration file.")
    parser.add_argument("--listen-host", help="Local address to bind.")
    parser.add_argument("--listen-port", type=int, help="Local TCP port to bind.")
    parser.add_argument("--connect-ip", help="Remote IPv4 address to connect to.")
    parser.add_argument("--connect-port", type=int, help="Remote TCP port to connect to.")
    parser.add_argument("--fake-sni", help="Hostname to place in the injected TLS ClientHello.")
    parser.add_argument("--interface-ipv4", help="Local IPv4 address to use instead of auto-detection.")
    parser.add_argument("--handshake-timeout", type=float, help="Seconds to wait for the injected packet acknowledgement.")
    parser.add_argument("--recv-buffer-size", type=int, help="Relay receive buffer size in bytes.")
    parser.add_argument("--backlog", type=int, help="Listen socket backlog.")
    parser.add_argument("--log-level", help="Python logging level.")
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration and print the resolved runtime plan.")
    return parser


def load_config(args: argparse.Namespace) -> AppConfig:
    config = AppConfig.load(args.config)
    return config.with_overrides(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        connect_ip=args.connect_ip,
        connect_port=args.connect_port,
        fake_sni=args.fake_sni,
        interface_ipv4=args.interface_ipv4,
        handshake_timeout=args.handshake_timeout,
        recv_buffer_size=args.recv_buffer_size,
        backlog=args.backlog,
        log_level=args.log_level.upper() if args.log_level else None,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args)
        configure_logging(config.log_level)
        if args.dry_run:
            print(json.dumps(config.public_summary(), indent=2, sort_keys=True))
            warnings = config.security_warnings()
            if warnings:
                print("\nSecurity warnings:")
                for warning in warnings:
                    print(f"- {warning}")
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
