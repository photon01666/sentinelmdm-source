# Architecture

## Trust boundaries

```
 device owner / operator
        │  (browser, HTTPS)
        ▼
 ┌──────────────┐        ┌─────────────────────────────┐
 │  server/     │◄──────►│  SQLite / Postgres / Redis  │
 │  Node.js     │        └─────────────────────────────┘
 └──────┬───────┘
        │ Socket.IO (TLS)
        │
 ┌──────▼───────┐   ┌──────────────────┐   ┌────────────────────┐
 │ android-agent/ │   │ android-client/ │   │ windows-agent/     │
 │ Device Owner │   │ parent WebView   │   │ linux-agent/       │
 └──────────────┘   └──────────────────┘   └─────────┬──────────┘
                                                     │ reverse SSH
                                                     ▼
                                            operator-run bastion
                                            (not in this repo)
```

- **Device → server** is initiated by the agent. The server never dials a device.
- **Remote assist** is initiated by the operator through the server; the Windows/Linux
  agent opens a reverse SSH tunnel to a bastion the operator controls.
- **Bastion** is deliberately out of scope. Its address, host key, and REALITY
  parameters are configuration, not code.

## Android agent (`android-agent/`)

A Kotlin application that runs as **Device Owner** (or as a platform-signed system app
on a custom ROM). Main pieces:

| Area | Responsibility |
| :--- | :--- |
| `Prefs.kt` | Persistent settings: server URLs, device id, transport ladder, policy knobs. |
| `TransportManager.kt` | Starts/stops the embedded xray-core process for VLESS/REALITY. |
| `SocketManager.kt` | Socket.IO connection, reconnect/backoff, relay and cellular fallbacks. |
| `MonitoringService.kt` | Foreground service: telemetry, location, app usage, security events. |
| `DeviceOwnerHelper.kt` | Device-owner policy, lock/wipe, app suspension, permission grants. |
| `SentinelVpnService.kt` | Optional always-on VPN / per-app routing. |
| `WebDashboardActivity.kt` | In-app WebView for the server dashboard. |

Transport ladder (configurable, `transport_mode`):

1. **REALITY** — VLESS over an embedded xray-core process, camouflaged as a normal TLS
   site. Chosen first in the default `stealth` mode.
2. **Relay** — an HTTP front door (for example a Cloudflare Worker) that proxies to the
   server.
3. **Direct** — plain Socket.IO/TLS to `SERVER_URL`.
4. **Cellular** — rebuild the connection over the mobile network.

## Android client (`android-client/`)

A thin WebView client for the parent/administrator dashboard, plus Firebase Cloud
Messaging for push. Three product flavors share the code:

- `publicClient` — parent login;
- `adminClient` — administrator login;
- `subUsersClient` — delegated sub-user login.

Each flavor's landing URL is a build-time `LOGIN_URL`, all derived from one
`serverUrl` property. FCM is optional: the Google Services plugin is applied only when
`google-services.json` is present.

## Server (`server/`)

Node.js 24, Express, Socket.IO, SQLite (default) or Postgres (HA), optional Redis
adapter. `server.js` is a legacy monolith that is **closed to new code**; new work goes
into modules:

| Directory | Responsibility |
| :--- | :--- |
| `routes/` | HTTP endpoints, one feature per module. |
| `helpers/` | Stateless helpers (auth, crypto, device queries, transport). |
| `workers/` | Background pollers and alerters. |
| `sockets/` | Socket.IO connection handling and per-device state. |
| `services/` | Domain services (commerce, notifications, APK variants). |
| `schema/` | Migrations and generated statements. |
| `public/` | Dashboard SPA served to browsers. |

Requests are authenticated with a session cookie; WebAuthn and TOTP are supported.
Passwords are stored as `bcrypt(PBKDF2-SHA256(password, salt))` so the plaintext never
reaches the hashing layer directly. The module layout is summarised above.

## Windows agent (`windows-agent/`)

.NET 8 WinForms application (`SentinelRemoteAssist`) plus a small wipe utility
(`NukeAgent`). It supports:

- account-linked or ticket-based enrollment;
- a control channel over Socket.IO;
- reverse SSH support tunnels (Hop-1 to the bastion, Hop-2 per session);
- endpoint hardening (AppLocker/WDAC, SRP, Windows Update control, EDR hooks);
- optional S3/R2 network drive via `rclone`.

`rclone.exe`, `xray.exe`, and the OpenSSH bundle are runtime assets and are **not**
committed. The project builds without them; the full installer does not.

## Linux agent (`linux-agent/`)

A Go daemon (`sentineld`) with systemd units:

- enrollment (`sentineld enroll`) and ticket-based no-login enrollment;
- control channel over Socket.IO;
- dormanted Hop-2 SSH access activated per session by systemd socket activation;
- an IT-audit collector (`sentineld it-audit`) covering 18 categories;
- helper scripts under `libexec/` for ARP sweep, app control, time sync, and self-update.

The pinned xray binary is embedded with `go:embed`; run
`internal/xraytransport/embedded/extract.sh` once before building.

## Data and secrets

- **SQLite** by default (`DB_PATH`); set `DATABASE_URL` for Postgres.
- **Redis** is optional and only needed for multi-replica Socket.IO.
- **Object storage** (R2/S3) holds database backups, OTA packages, and boot ISOs.
- Secrets are read from `/run/secrets/<name>` first, then from the environment. The
  repository contains no production secrets; every endpoint defaults to `example.com`.

## Deliberate constraints

- `server/server.js` must not grow. Moves are verbatim; new code goes in modules.
- The agents never store plaintext server credentials in the repository. Build-time
  values are supplied through Gradle properties or environment variables.
- The bastion, marketing site, GrapheneOS integration, desktop shell, simulator, and
  deployment stacks are separate systems with their own release cadence.
