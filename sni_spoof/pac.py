from __future__ import annotations

import json

from .config import AppConfig
from .policy import pac_host_condition


def generate_pac(config: AppConfig) -> str:
    proxy = f"PROXY {config.listen_host}:{config.listen_port}"
    condition = pac_host_condition(config.allowed_hosts)
    allowed_ports = json.dumps(list(config.allowed_ports))

    return f"""function FindProxyForURL(url, host) {{
  host = host.toLowerCase();
  var allowedPorts = {allowed_ports};
  var scheme = url.substring(0, url.indexOf(":")).toLowerCase();
  var port = scheme === "https" ? 443 : 80;
  var explicitPort = url.match(/^\\w+:\\/\\/[^/:]+:(\\d+)/);
  if (explicitPort) {{
    port = parseInt(explicitPort[1], 10);
  }}
  if (({condition}) && allowedPorts.indexOf(port) !== -1) {{
    return "{proxy}";
  }}
  return "DIRECT";
}}
"""
