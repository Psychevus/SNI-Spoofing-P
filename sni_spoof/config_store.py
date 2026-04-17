from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .config import AppConfig, ConfigError


PROFILE_KEYS = (
    "CONNECT_IP",
    "CONNECT_PORT",
    "FAKE_SNI",
    "ALLOWED_HOSTS",
    "ALLOWED_PORTS",
    "BYPASS_METHOD",
    "DATA_MODE",
)


def _profiles_ref(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.pop("profiles", data.get("PROFILES", {}))
    if not isinstance(profiles, dict):
        raise ConfigError("profiles must be a JSON object")
    data["PROFILES"] = profiles
    return profiles


def _normalize_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(profile)
    return {key: normalized[key] for key in PROFILE_KEYS if key in normalized}


def read_config_document(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")
    return data


def write_config_document(path: str | Path, data: Mapping[str, Any]) -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp_path.replace(config_path)


def list_profiles(path: str | Path) -> dict[str, Any]:
    data = read_config_document(path)
    return dict(_profiles_ref(data))


def show_profile(path: str | Path, name: str) -> dict[str, Any]:
    profiles = list_profiles(path)
    profile = profiles.get(name)
    if profile is None:
        raise ConfigError(f"profile not found: {name}")
    if not isinstance(profile, dict):
        raise ConfigError(f"profile must be a JSON object: {name}")
    return profile


def save_profile(path: str | Path, name: str, profile: Mapping[str, Any]) -> None:
    if not name:
        raise ConfigError("profile name must not be empty")
    data = read_config_document(path)
    profiles = _profiles_ref(data)
    profiles[name] = _normalize_profile(profile)
    write_config_document(path, data)


def delete_profile(path: str | Path, name: str) -> None:
    data = read_config_document(path)
    profiles = _profiles_ref(data)
    if name not in profiles:
        raise ConfigError(f"profile not found: {name}")
    del profiles[name]
    write_config_document(path, data)


def profile_from_config(config: AppConfig) -> dict[str, Any]:
    return {
        "CONNECT_IP": config.connect_ip,
        "CONNECT_PORT": config.connect_port,
        "FAKE_SNI": config.fake_sni,
        "ALLOWED_HOSTS": list(config.allowed_hosts),
        "ALLOWED_PORTS": list(config.allowed_ports),
        "BYPASS_METHOD": config.bypass_method,
        "DATA_MODE": config.data_mode,
    }


def base_config_document(config: AppConfig) -> dict[str, Any]:
    return {
        "LISTEN_HOST": config.listen_host,
        "LISTEN_PORT": config.listen_port,
        "PROXY_MODE": config.proxy_mode,
        "CONNECT_IP": config.connect_ip,
        "CONNECT_PORT": config.connect_port,
        "FAKE_SNI": config.fake_sni,
        "ALLOWED_HOSTS": list(config.allowed_hosts),
        "ALLOWED_PORTS": list(config.allowed_ports),
        "BYPASS_METHOD": config.bypass_method,
        "DATA_MODE": config.data_mode,
        "HANDSHAKE_TIMEOUT": config.handshake_timeout,
        "CONNECT_TIMEOUT": config.connect_timeout,
        "IDLE_TIMEOUT": config.idle_timeout,
        "RECV_BUFFER_SIZE": config.recv_buffer_size,
        "BACKLOG": config.backlog,
        "MAX_CONNECT_HEADER_BYTES": config.max_connect_header_bytes,
        "MAX_ACTIVE_CONNECTIONS": config.max_active_connections,
        "STRICT_LOCAL_ONLY": config.strict_local_only,
        "REQUIRE_AUTH_FOR_REMOTE_BIND": config.require_auth_for_remote_bind,
        "CONTROL_ENABLED": config.control_enabled,
        "CONTROL_HOST": config.control_host,
        "CONTROL_PORT": config.control_port,
        "LOG_LEVEL": config.log_level,
        "LOG_FORMAT": config.log_format,
        "PROFILES": {},
    }
