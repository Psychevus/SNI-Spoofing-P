# SNI Spoofing Proxy

A Windows-focused TCP proxy that injects a controlled TLS ClientHello during connection setup and then relays client traffic to a configured TLS endpoint.

The default runtime mode is an HTTP CONNECT proxy on `127.0.0.1:8080`, which makes it practical to use with browsers and command-line clients that support HTTPS proxy settings.

## Requirements

- Windows with administrator privileges
- Python 3.11+
- WinDivert support through `pydivert`

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Configuration

Edit `config.json` or override values from the command line.

```json
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": 8080,
  "PROXY_MODE": "http_connect",
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com",
  "ALLOWED_HOSTS": [
    "auth.vercel.com"
  ],
  "ALLOWED_PORTS": [
    443
  ],
  "BYPASS_METHOD": "wrong_seq",
  "DATA_MODE": "tls",
  "HANDSHAKE_TIMEOUT": 2.0,
  "CONNECT_TIMEOUT": 10.0,
  "IDLE_TIMEOUT": 300.0,
  "RECV_BUFFER_SIZE": 65575,
  "BACKLOG": 128,
  "MAX_CONNECT_HEADER_BYTES": 16384,
  "MAX_ACTIVE_CONNECTIONS": 256,
  "LOG_LEVEL": "INFO"
}
```

Security note: prefer `127.0.0.1` for `LISTEN_HOST` unless remote clients must connect to this proxy.

## Usage

Validate the configuration without starting WinDivert:

```powershell
python main.py --dry-run
```

Run the proxy:

```powershell
python main.py
```

Override common settings:

```powershell
python main.py --listen-host 127.0.0.1 --listen-port 8080 --fake-sni auth.vercel.com
```

The module entry point is also available:

```powershell
python -m sni_spoof --dry-run
```

## HTTP CONNECT Mode

The default mode accepts HTTP CONNECT requests and creates a spoofed upstream TCP tunnel. This is the recommended mode for normal use.

Quick test:

```powershell
curl.exe -vk -x http://127.0.0.1:8080 https://auth.vercel.com/
```

Expected runtime logs include:

- `Accepted client connection`
- `CONNECT auth.vercel.com:443 accepted`
- `Opening upstream connection`
- `Tunnel established`
- `Relay finished`

Configure browser HTTPS proxy settings to:

- Host: `127.0.0.1`
- Port: `8080`

`ALLOWED_HOSTS` and `ALLOWED_PORTS` are enforced before a tunnel is opened. This prevents the service from becoming a broad local forwarding proxy by accident.

Optional proxy authentication can be enabled with `AUTH_TOKEN` in `config.json` or with:

```powershell
python main.py --auth-token "change-this-token"
```

Then test with:

```powershell
curl.exe -vk -x http://127.0.0.1:8080 --proxy-header "Proxy-Authorization: Bearer change-this-token" https://auth.vercel.com/
```

## Raw TCP Mode

Raw mode keeps the lower-level relay behavior available for controlled tests:

```powershell
python main.py --proxy-mode raw --listen-port 40443
```

Then route one hostname to the raw listener:

```powershell
curl.exe -vk --connect-to auth.vercel.com:443:127.0.0.1:40443 https://auth.vercel.com/
```

Do not use raw mode as a browser HTTP proxy.

For deeper packet-level diagnostics:

```powershell
python main.py --log-level DEBUG
```

## Architecture

- `sni_spoof.config` loads legacy and modern JSON keys, validates values, and reports security warnings.
- `sni_spoof.cli` provides the command-line interface and dry-run mode.
- `sni_spoof.http_connect` parses and validates HTTP CONNECT requests.
- `sni_spoof.proxy` owns socket lifecycle, connection setup, fake handshake waiting, and bidirectional relay.
- `sni_spoof.injector` owns WinDivert packet processing and connection tracking.
- `sni_spoof.packets` builds and validates supported TLS packet templates.
- Legacy root modules remain as compatibility wrappers.

## Safety Checks

The application validates:

- TCP port ranges
- target IP format
- optional local interface IP format
- SNI hostname shape and IDNA normalization
- HTTP CONNECT host and port allowlists
- optional proxy authentication token
- CONNECT header size limits
- upstream connect and tunnel idle timeouts
- maximum active connection count
- supported data mode and bypass method
- relay buffer and backlog limits

Dry-run mode prints the resolved runtime plan and warns about risky choices such as binding to all interfaces.

## Testing

Run the unit tests that do not require WinDivert:

```powershell
python -B -m unittest discover -s tests
```

Run a configuration health check:

```powershell
python -B main.py --dry-run
```
