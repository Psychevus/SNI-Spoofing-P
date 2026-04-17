# SNI Spoofing Proxy

This repository is a maintained fork of the original [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) project.

A Windows-first local proxy for controlled TLS SNI injection, HTTP CONNECT tunneling, browser routing, diagnostics, and safe operator workflows.

The project is designed to make SNI injection experiments easier to run, easier to verify, and harder to misconfigure. It starts with secure local-only defaults, includes a guided setup flow, exposes a small local dashboard, and keeps the packet injector isolated behind a clean proxy interface.

## Highlights

- Local HTTP CONNECT proxy for browsers, CLI tools, and PAC-based routing.
- WinDivert-backed fake ClientHello injection before the real TLS stream is relayed.
- Profile system for switching targets without editing code.
- Interactive setup wizard for first-time configuration.
- Doctor checks for Windows, administrator rights, Python packages, config validity, and network reachability.
- Local dashboard with health, metrics, event stream, and PAC endpoint.
- Strict security defaults: loopback binding, host allowlists, port controls, and optional remote-bind authentication.
- Focused test suite for configuration, tunnel behavior, policy checks, browser launch helpers, and relay flow.

## Requirements

- Windows 10 or newer.
- Python 3.11 or newer.
- Administrator PowerShell for WinDivert packet capture and injection.
- Dependencies from `requirements.txt`.
- A target endpoint you are authorized to test.

The injector depends on WinDivert through `pydivert`. Without administrator privileges, Windows will usually return `WinError 5: Access is denied`.

## Quick Start

Open PowerShell as Administrator:

```powershell
git clone https://github.com/YOUR-USER/YOUR-REPO.git
cd YOUR-REPO
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The examples below use `example.com` and `93.184.216.34` as placeholders. Replace them with the hostname and endpoint you are authorized to test.

Configure the target route:

```powershell
python main.py wizard
```

Run environment checks:

```powershell
python main.py doctor
```

Start the proxy:

```powershell
python main.py run --log-level DEBUG
```

In another terminal, send traffic through the local proxy:

```powershell
curl.exe -vk -x http://127.0.0.1:8080 https://example.com/
```

For a direct raw TCP listener instead of HTTP CONNECT:

```powershell
python main.py run --listen-host 127.0.0.1 --listen-port 40443 --proxy-mode raw
curl.exe -vk --connect-to example.com:443:127.0.0.1:40443 https://example.com/
```

## Browser Workflow

The simplest browser workflow is to launch an isolated browser profile with the proxy already configured:

```powershell
python main.py launch-browser --browser edge --browser-url https://example.com/
```

You can also configure a browser manually with the PAC URL:

```text
http://127.0.0.1:9090/proxy.pac
```

The PAC route only sends configured hostnames through the local proxy and lets unrelated traffic go direct.

## Dashboard

When the control server is enabled, the local dashboard listens on:

```text
http://127.0.0.1:9090/
```

Useful endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/` | Human-readable local status page |
| `/health` | Lightweight health check |
| `/metrics` | JSON counters and runtime state |
| `/events` | Recent structured events |
| `/proxy.pac` | PAC file for browser routing |

Keep the control server on loopback unless you have a specific operational reason to expose it.

## Commands

| Command | Description |
| --- | --- |
| `python main.py run` | Start the proxy and injector |
| `python main.py doctor` | Validate runtime, permissions, packages, config, and network reachability |
| `python main.py wizard` | Create or update configuration interactively |
| `python main.py profiles` | List available profiles |
| `python main.py profiles --show-profile <name>` | Inspect a profile |
| `python main.py profiles --save-profile <name>` | Save current runtime options as a profile |
| `python main.py profiles --delete-profile <name>` | Remove a profile |
| `python main.py pac` | Print the generated PAC file |
| `python main.py test-tunnel` | Run a local tunnel smoke test |
| `python main.py launch-browser` | Launch a browser with an isolated proxy profile |

Global options can be combined with commands. For example:

```powershell
python main.py --profile example-route --log-level DEBUG run
python main.py --connect-ip 93.184.216.34 --fake-sni example.com --allowed-host example.com --dry-run
```

## Configuration

Runtime defaults live in `config.json` and can be overridden with CLI flags. A compact configuration looks like this:

```json
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": 8080,
  "PROXY_MODE": "http_connect",
  "CONNECT_IP": "93.184.216.34",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "example.com",
  "ALLOWED_HOSTS": ["example.com"],
  "ALLOWED_PORTS": [443],
  "STRICT_LOCAL_ONLY": true,
  "CONTROL_ENABLED": true,
  "CONTROL_HOST": "127.0.0.1",
  "CONTROL_PORT": 9090,
  "LOG_LEVEL": "INFO",
  "PROFILES": {
    "example-route": {
      "CONNECT_IP": "93.184.216.34",
      "CONNECT_PORT": 443,
      "FAKE_SNI": "example.com",
      "ALLOWED_HOSTS": ["example.com"],
      "ALLOWED_PORTS": [443]
    }
  }
}
```

Recommended defaults:

- Use `127.0.0.1` for `LISTEN_HOST` during local use.
- Keep `STRICT_LOCAL_ONLY` enabled unless remote clients are required.
- Keep `ALLOWED_HOSTS` narrow.
- Use `doctor` after changing target, profile, host, or port settings.

## Profiles

Profiles make target switching predictable and repeatable:

```powershell
python main.py profiles
python main.py profiles --show-profile example-route
python main.py --profile example-route run
```

Save the current command-line configuration as a profile:

```powershell
python main.py --connect-ip 93.184.216.34 --fake-sni example.com --allowed-host example.com profiles --save-profile example-route
```

## Security Model

This tool is intentionally conservative by default.

- Local-only listener by default: `127.0.0.1`.
- Control dashboard bound to loopback by default.
- Host allowlist enforced for HTTP CONNECT requests.
- Optional auth token requirement when remote binding is enabled.
- Request header size limits for CONNECT parsing.
- Connection timeouts and capacity limits for predictable resource use.
- Structured warnings when configuration expands the exposed surface.

If you bind the proxy to `0.0.0.0`, treat it like an exposed network service. Restrict firewall rules, set an auth token where supported, and keep the host allowlist tight.

## Architecture

The package is organized around small, focused modules:

| Module | Responsibility |
| --- | --- |
| `sni_spoof.cli` | Command-line interface and runtime assembly |
| `sni_spoof.config` | Configuration model, validation, profiles, and security warnings |
| `sni_spoof.proxy` | Proxy lifecycle, client handling, injector coordination, and control server startup |
| `sni_spoof.injector` | WinDivert packet capture, TCP state tracking, and fake payload injection |
| `sni_spoof.http_connect` | HTTP CONNECT parsing and response helpers |
| `sni_spoof.policy` | Host and port access policy |
| `sni_spoof.relay` | Bidirectional stream relay helpers |
| `sni_spoof.control` | Local dashboard, metrics, events, and PAC serving |
| `sni_spoof.doctor` | Runtime diagnostics |
| `sni_spoof.wizard` | Guided configuration |
| `sni_spoof.browser` | Isolated browser launch support |

The proxy opens the upstream TCP connection, the injector observes the handshake, injects the fake ClientHello, waits for acknowledgement, and then the relay forwards the real client stream.

## Observability

Use debug logging while validating a target:

```powershell
python main.py run --log-level DEBUG
```

Useful log milestones:

- Proxy listener started.
- Client connection accepted.
- Upstream connection opened.
- Outbound SYN captured.
- Inbound SYN-ACK captured.
- Fake payload sent.
- Fake payload acknowledged.
- Relay started and finished.

For automation or external monitoring, use the dashboard JSON endpoints:

```powershell
curl.exe http://127.0.0.1:9090/health
curl.exe http://127.0.0.1:9090/metrics
curl.exe http://127.0.0.1:9090/events
```

## Troubleshooting

### `WinError 5: Access is denied`

Run PowerShell as Administrator. WinDivert needs elevated privileges to open the packet capture driver.

### `pydivert is not installed`

Activate the virtual environment and install dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### The proxy starts but no connections appear

Make sure the client is actually routed through the proxy. Use one of these:

```powershell
curl.exe -vk -x http://127.0.0.1:8080 https://example.com/
python main.py launch-browser --browser edge --browser-url https://example.com/
```

### The fake payload is not acknowledged

Check that `CONNECT_IP`, `CONNECT_PORT`, and local network interface selection are correct. Then rerun:

```powershell
python main.py doctor
python main.py run --log-level DEBUG
```

### Browser traffic still goes direct

Use the generated PAC URL or the browser launcher. Also confirm the hostname is present in `ALLOWED_HOSTS`.

## Testing

Run the test suite:

```powershell
python -m unittest discover -s tests
```

Run a syntax check:

```powershell
python -m compileall main.py sni_spoof tests
```

Validate configuration without starting the injector:

```powershell
python main.py --dry-run
```

## Release Build

Install build dependencies inside the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-build.txt
```

Build a release-ready Windows bundle:

```powershell
python tools\build_release.py
```

The builder runs tests, validates `--dry-run`, creates a PyInstaller one-folder executable, copies `config.json`, `README.md`, `LICENSE`, third-party notices, available third-party license files, writes `RELEASE_MANIFEST.json`, generates `SHA256SUMS.txt`, and creates a ZIP archive under `dist\`.

Expected outputs:

```text
dist\sni-spoofing-proxy-<version>-windows-x64\
dist\sni-spoofing-proxy-<version>-windows-x64.zip
dist\sni-spoofing-proxy-<version>-windows-x64.zip.sha256
```

Run the packaged executable from the release folder:

```powershell
cd dist\sni-spoofing-proxy-<version>-windows-x64
.\sni-spoof.exe --dry-run
.\sni-spoof.exe run --log-level DEBUG
```

Use an Administrator PowerShell for `run` because WinDivert requires elevated privileges. The bundle also includes `Start-SNI-Spoof-Admin.cmd` for a quick UAC-assisted launch while keeping normal console behavior for `--help`, `--dry-run`, `doctor`, `pac`, and profile commands.

### GitHub Actions

The repository includes a Windows release workflow at `.github/workflows/windows-release.yml`.

- Pull requests and pushes to `main` build the Windows x64 ZIP and upload it as a workflow artifact.
- Manual runs are available from the GitHub Actions tab through `workflow_dispatch`.
- Version tags such as `vX.Y.Z` build the same artifact and attach the ZIP plus `.sha256` file to a draft GitHub Release.

To publish a release from CI:

```powershell
git tag vX.Y.Z
git push origin vX.Y.Z
```

Review the generated draft release in GitHub before publishing it.

## Packaging

Install the project in editable mode:

```powershell
python -m pip install -e .
```

Then run it through the console script:

```powershell
sni-spoof --dry-run
sni-spoof run --log-level DEBUG
```

## Operational Notes

- Keep target configuration explicit and versioned.
- Prefer profiles over one-off command lines for repeated work.
- Run `doctor` after network, VPN, DNS, firewall, or target changes.
- Keep the proxy local unless remote clients are part of the plan.
- Use the dashboard for quick confirmation, not as a public service.

## Acknowledgements

Special thanks to [patterniha](https://github.com/patterniha) and the original [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) project for the initial idea and foundation. This fork builds on that work with a stronger operator experience, safer defaults, expanded diagnostics, and a more maintainable architecture.
