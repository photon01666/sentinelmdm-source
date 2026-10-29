# SentinelMDM

A device-management platform for Android, with a browser dashboard and
optional remote-assistance agents for Windows and Linux.

SentinelMDM is built around a **device-owner Android agent**, a **administrator
web dashboard**, and a **self-hosted server**. No third-party control plane is required:
you run the server, you hold the keys, and the device data stays on infrastructure you
control.

> **Lawful use only.** The Android agent is a device-management tool. It can access
> location, SMS, call logs, contacts, camera, microphone, screen capture, and app usage,
> and it can lock or wipe a device. Deploy it only on devices you own or administer, or
> on devices whose user has given informed, documented consent. Covert surveillance is
> prohibited and is not a supported use of this project. See
> [`docs/ACCEPTABLE-USE.md`](docs/ACCEPTABLE-USE.md) and
> [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md).

---

## Repository layout

| Path | Component | Language | What it is |
| :--- | :--- | :--- | :--- |
| [`android-agent/`](android-agent/) | Android agent | Kotlin | Device-owner / system agent. Enrollment, telemetry, commands, policy, VPN transport, OTA. |
| [`android-client/`](android-client/) | Android client | Kotlin | Parent/administrator companion app. WebView dashboard, push notifications, three build flavors (public, admin, sub-users). |
| [`server/`](server/) | Control server | Node.js | Express + Socket.IO backend, SQLite/Postgres, web dashboard, billing hooks, APK/OTA distribution. |
| [`windows-agent/`](windows-agent/) | Windows remote assist | C# / .NET 8 | `SentinelRemoteAssist` (support sessions, hardening, EDR hooks) and `NukeAgent` (secure wipe). |
| [`linux-agent/`](linux-agent/) | Linux remote assist | Go | `sentineld` daemon: enrollment, control channel, SSH hop, IT-audit collector, systemd units. |

## Architecture

```
                      ┌──────────────────────────────────────────┐
                      │            server/ (Node.js)             │
                      │  Express API · Socket.IO · web dashboard │
                      │  SQLite/Postgres · Redis (optional)      │
                      └──────────────┬───────────────────────────┘
                                     │ HTTPS / WebSocket
             ┌───────────────────────┼────────────────────────┐
             │                       │                        │
   ┌─────────▼─────────┐   ┌─────────▼─────────┐   ┌──────────▼─────────┐
   │ android-agent/    │   │ android-client/   │   │ windows-agent/     │
   │ Device Owner      │   │ WebView + FCM     │   │ linux-agent/       │
   │ telemetry/control │   │ parent dashboard  │   │ SSH support tunnel │
   └───────────────────┘   └───────────────────┘   └────────────────────┘
```

- The Android agent connects to the server over Socket.IO. Where the network blocks
  direct connections, it can use a VLESS/REALITY transport carried by an embedded
  xray-core process, with optional relay/front-door fallbacks.
- Device payloads are encrypted before storage where the feature requires it; the
  server's encryption material is supplied at deploy time, never committed.
- The Windows and Linux agents establish reverse SSH support tunnels to a support
  endpoint that you operate. Both agents expose the endpoint, host key, and REALITY
  parameters as configuration.

## Scope

This repository is the application and agent source: the Android agent, the Android
client, the server, and the Windows/Linux remote-assist agents. Build prerequisites
and optional runtime assets are documented in [`docs/BUILDING.md`](docs/BUILDING.md).

### Not included in this repository

This is a source release, not the upstream operator's full production tree. The
following are intentionally excluded:

- `android-bastion/` — internal Android WebView wrapper for the operator's
  Tailscale-only support bastion.
- `ssh-bastion/` and `bastion-web.py` — the support-bastion service and its admin UI.
- Swarm/HA and Cloudflare deployment configuration — Traefik, Patroni/etcd/Redis HA,
  xray relays, cloudflared, and related provisioning scripts.

These are operational tooling for one hosted deployment, not part of the
device-management product. Nothing in them is required to build or run the components
listed above. The server's bastion bridge is configured through
`BASTION_INTERNAL_URL` and `BASTION_INTERNAL_KEY` (see [`.env.example`](.env.example))
and points at a support service you operate yourself.

## Requirements

| Component | Toolchain |
| :--- | :--- |
| `server/` | Node.js 24+, npm |
| `android-agent/` | JDK 17, Android SDK 34, Gradle 8.2 (wrapper included) |
| `android-client/` | JDK 17, Android SDK 34, Gradle 8.2 (wrapper included) |
| `windows-agent/` | .NET 8 SDK, Windows 10/11 |
| `linux-agent/` | Go 1.25+, Docker (for the pinned xray extraction step) |

### Binary prerequisites (not committed)

Some components embed third-party binaries. Supply them before a full build:

| Component | Missing file | How to obtain it |
| :--- | :--- | :--- |
| `android-agent/` | `app/src/main/jniLibs/arm64-v8a/libxray.so`, `libhev-socks5-tunnel.so` | Build from the pinned xray-core / hev-socks5-tunnel sources; see [`android-agent/native/`](android-agent/native/). |
| `linux-agent/` | `sentineld/internal/xraytransport/embedded/xray`, `xray-arm64` | Run `internal/xraytransport/embedded/extract.sh` (pulls the pinned `teddysun/xray` image). |
| `windows-agent/` | `rclone.exe`, `xray.exe`, `OpenSSH-Win64.zip` | Fetch the pinned upstream releases. The project builds without them; the full installer does not. |
| `android-client/` | `app/google-services.json` | Create a Firebase project and download your own config. |

## Quick start: server

```bash
cd server
npm ci

export ADMIN_PASS="$(openssl rand -hex 16)"      # required
export SESSION_SECRET="$(openssl rand -hex 32)"
export SERVER_ORIGIN="http://localhost:3000"

npm start
```

Open <http://localhost:3000> and sign in with `ADMIN_USER` / `ADMIN_PASS`.
See [`.env.example`](.env.example) for the full configuration surface.

## Build the agents

```bash
# Android agent — point it at your own server
cd android-agent
./gradlew assembleRelease \
  -PserverUrl=https://device.example.com \
  -PwebUrl=https://app.example.com

# Monitor app (choose a flavor: publicClient, adminClient, subUsersClient)
cd ../android-client
./gradlew assembleAdminClientRelease -PserverUrl=https://app.example.com

# Windows agent
cd ../windows-agent
dotnet build SentinelRemoteAssist/SentinelRemoteAssist.csproj -c Release

# Linux agent
cd ../linux-agent/sentineld
./internal/xraytransport/embedded/extract.sh
go build ./cmd/sentineld
```

Full details, including signing and privileged-permission notes, are in
[`docs/BUILDING.md`](docs/BUILDING.md).

## Configuration

- Android: Gradle properties / `SENTINEL_*` environment variables. See
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
- Server: environment variables or Docker secrets. See [`.env.example`](.env.example).
- Windows/Linux agents: `SENTINEL_*` environment variables; see the component READMEs.

Every endpoint in this repository defaults to `example.com`. Nothing points at the
upstream maintainers' infrastructure.

## Security

Please read [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) before deploying. In
particular:

- Device-owner provisioning requires physical access or a managed enrollment flow.
- Several agent features rely on `signature|privileged` permissions. A stock Android
  build cannot grant them; they require platform signing or a custom ROM integration.
- There are no default credentials. The server refuses to start without `ADMIN_PASS`.
- Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

Licensed under the **GNU Affero General Public License v3.0**. See [`LICENSE`](LICENSE).

Third-party components retain their own licenses; see
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
