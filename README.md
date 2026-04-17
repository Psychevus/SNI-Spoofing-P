# SNI Spoofing Proxy

A Windows-focused TCP proxy that injects a controlled TLS ClientHello during connection setup and then relays client traffic to a configured TLS endpoint.

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
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com",
  "BYPASS_METHOD": "wrong_seq",
  "DATA_MODE": "tls",
  "HANDSHAKE_TIMEOUT": 2.0,
  "RECV_BUFFER_SIZE": 65575,
  "BACKLOG": 128,
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
python main.py --listen-host 127.0.0.1 --listen-port 40443 --fake-sni auth.vercel.com
```

The module entry point is also available:

```powershell
python -m sni_spoof --dry-run
```

## Architecture

- `sni_spoof.config` loads legacy and modern JSON keys, validates values, and reports security warnings.
- `sni_spoof.cli` provides the command-line interface and dry-run mode.
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
