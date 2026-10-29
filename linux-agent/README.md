# Linux remote-assist agent (`sentineld`)

A Go daemon for headless Linux servers, the Linux counterpart of the Windows
`SentinelRemoteAssist`. It provides CLI or ticket-based enrollment, a Socket.IO control
channel, dormant per-session SSH access, and an IT-audit collector.

## Layout

```
sentineld/
├── cmd/sentineld/            CLI and daemon entry points
├── internal/config/          build/runtime constants and env overrides
├── internal/enroll/          credential and ticket enrollment
├── internal/controlchannel/  Socket.IO control channel and device identity
├── internal/hop1/            reverse SSH tunnel to the bastion
├── internal/xraytransport/   embedded xray-core (VLESS/REALITY)
├── internal/arpwatch/        ARP/neighbour discovery
└── internal/zkwrap/          payload wrapping helpers
systemd/                      service, socket, and timer units
etc/                          sudoers and sshd snippets
libexec/                      hop-2, self-update, ARP-sweep, and app-control helpers
```

## Build

Requires Go 1.25+ and Docker (for the pinned xray extraction).

```bash
cd sentineld
./internal/xraytransport/embedded/extract.sh   # pulls teddysun/xray:26.3.27
go build ./cmd/sentineld
go test ./...
```

The `xray` / `xray-arm64` binaries are gitignored and embedded with `go:embed`, so the
extract step is required before a build.

## Enrollment

```bash
# Interactive: prompts for the account email and password.
sudo ./sentineld enroll

# No-login: use an installer ticket minted by the dashboard.
sudo ./sentineld enroll --ticket <ticket>
```

State lives in `/var/lib/sentinel-ra`; configuration in `/etc/sentinel-ra`; the Hop-2
arm file in `/run/sentinel-ra`.

## systemd

Install the units from `systemd/`:

- `sentineld.service` — the daemon;
- `sentinel-enroll.service` — one-shot enrollment;
- `sentinel-hop2.socket` / `sentinel-hop2@.service` — dormant per-session access;
- `sentinel-hop2-reaper.service` / `.timer` — cleanup;
- `sentinel-timesync.service` — wait for a sane clock before TLS.

## Configuration

The server URL, REALITY credentials, node lists, and bastion pin are environment
variables:

```bash
SENTINEL_SERVER_URL=https://app.example.com
SENTINEL_BASTION_HOST=bastion.example.com
SENTINEL_BASTION_KNOWN_HOSTS='[bastion.example.com]:22022 ssh-ed25519 AAAA...'
SENTINEL_REALITY_NODES=203.0.113.10,203.0.113.11,203.0.113.12
SENTINEL_REALITY_SNIS=www.microsoft.com
SENTINEL_REALITY_PUBLIC_KEY=...
SENTINEL_REALITY_SHORT_ID=...
SENTINEL_REALITY_CONTROL_UUID=...
```

Empty REALITY values disable the tunnel; the daemon then uses a direct connection. See
[`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

The bastion server is **not** part of this repository. Point the agent at a compatible
bastion you operate.

## IT audit

```bash
sudo ./sentineld it-audit
```

Runs the built-in collector and writes a JSON report to stdout. Review the categories in
`cmd/sentineld` before running it on a production host.

## License

AGPL-3.0. See [`../LICENSE`](../LICENSE).
