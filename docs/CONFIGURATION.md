# Configuration

Everything in this repository ships with non-routable `example.com` defaults. Supply
your own values at build time or runtime; do not commit them.

## Android agent — Gradle properties

Pass with `-P<name>=<value>` or set the matching `SENTINEL_*` environment variable.

| Property | Environment variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `serverUrl` | `SENTINEL_SERVER_URL` | `https://device.example.com` | Socket.IO device endpoint. |
| `webUrl` | `SENTINEL_WEB_URL` | `https://app.example.com` | Web dashboard / login endpoint. |
| `relayUrl` | `SENTINEL_RELAY_URL` | empty | Optional relay front door. |
| `relayNodes` | `SENTINEL_RELAY_NODES` | empty | Comma-separated relay hosts. |
| `realityNodes` | `SENTINEL_REALITY_NODES` | empty | Comma-separated REALITY node IPv4s. |
| `realityNodesV6` | `SENTINEL_REALITY_NODES_V6` | empty | Index-aligned IPv6s. |
| `realitySni` | `SENTINEL_REALITY_SNI` | `www.microsoft.com` | Camouflage SNI(s), index-aligned. |
| `realityPublicKey` | `SENTINEL_REALITY_PUBLIC_KEY` | empty | REALITY `x25519` public key. |
| `realityShortId` | `SENTINEL_REALITY_SHORT_ID` | empty | REALITY short id. |
| `realityControlUuid` | `SENTINEL_REALITY_CONTROL_UUID` | empty | VLESS control-channel UUID. |
| `dashboardHosts` | `SENTINEL_DASHBOARD_HOSTS` | `example.com` | Hosts kept inside the in-app WebView. |
| `expectedSignerSha256` | `SENTINEL_EXPECTED_SIGNER_SHA256` | empty | Optional comma-separated OTA signer allow-list. Empty relies on Android's same-signer update rule. |
| `adminAgent` | — | `false` | Build the admin/sub-user variant. |

Generate REALITY material with:

```bash
xray x25519          # public/private key pair
xray uuid            # client UUID
openssl rand -hex 8  # short id
```

## Android client — Gradle properties

Only `serverUrl` / `SENTINEL_SERVER_URL` is required. Each flavor derives its landing
URL from it (`/login`, `/admin/login`, `/admin/subusers/login`).

## Server — environment variables

In Docker Swarm, a value in `/run/secrets/<name>` takes precedence over the environment
variable of the same purpose. See `server/config.js`.

### Core

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `3000` | HTTP listen port. |
| `ROLE` | `standalone` | `standalone`, `web`, or `worker`. |
| `SERVER_ORIGIN` | `http://localhost:3000` | Public origin used in links and WebAuthn. |
| `PUBLIC_SITE_URL` | `SERVER_ORIGIN` | Marketing/legal site base for links. |
| `PUBLIC_API_URL` | `PUBLIC_SITE_URL` | Public API base for callbacks. |
| `TRACKER_DOMAIN` | `localhost:3000` | Host used in outgoing email. |
| `DEVICE_HOST` | empty | Host that should redirect the web UI. |
| `DB_PATH` | `./tracker.db` | SQLite path. |
| `DATABASE_URL` | empty | Postgres URL; overrides SQLite. |

### Authentication and encryption

| Variable | Purpose |
| :--- | :--- |
| `ADMIN_USER` | Bootstrap administrator username. |
| `ADMIN_PASS` | Bootstrap administrator password. **Required.** |
| `SESSION_SECRET` | Session cookie signing secret. |
| `ENC_PASSPHRASE` | Passphrase for application-level payload encryption. |
| `SERVER_ENC_KEY_PEM` | Private key material for encrypted fields. |
| `HWID_KEY` | Hardware-id derivation key. |
| `TOTP_SECRET` | TOTP seed/encryption material. |
| `WEBAUTHN_RP_ID` | WebAuthn relying-party id (hostname). |
| `WEBAUTHN_ORIGIN` | WebAuthn origin. |
| `COOKIE_INSECURE` | Set for plain-HTTP local development only. |

Docker secret equivalents: `sentinel_admin_pass`, `sentinel_session_secret`,
`sentinel_enc_passphrase`, `sentinel_enc_private_key`, `sentinel_hwid_key`,
`sentinel_totp_secret`.

### Redis

| Variable | Purpose |
| :--- | :--- |
| `REDIS_URL` | Redis connection URL. |
| `REDIS_SENTINELS` | Comma-separated sentinel addresses. |
| `REDIS_MASTER_NAME` | Sentinel master group name. |

### Object storage

| Variable | Purpose |
| :--- | :--- |
| `R2_ENDPOINT` | S3-compatible endpoint for database backups. |
| `R2_BUCKET` | Backup bucket (default `sentinel-db`). |
| `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY` | Backup credentials. |
| `OTA_R2_ENDPOINT` | S3-compatible endpoint for OTA/ISO objects. |
| `OTA_R2_BUCKET` | OTA bucket (default `sentinelmdm-ota`). |
| `OTA_ACCESS_KEY_ID` / `OTA_SECRET_ACCESS_KEY` | OTA credentials. |
| `OTA_PUBLIC_URL` | Public base URL that serves OTA/ISO files. |

Docker secrets: `sentinel_litestream_key_id`, `sentinel_litestream_secret_key`,
`sentinel_ota_key_id`, `sentinel_ota_secret_key`.

### Billing (optional)

`STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET`,
`STRIPE_TEST_SECRET_KEY`, `STRIPE_TEST_PUBLISHABLE_KEY`, `STRIPE_TEST_WEBHOOK_SECRET`,
`STRIPE_TEST_MODE`, `STRIPE_TRIAL_DAYS`, `TRIAL_DAYS`, `TRIAL_DEVICE_LIMIT`,
`NOWPAYMENTS_API_KEY`, `NOWPAYMENTS_IPN_SECRET`.

Stripe prices are deployment-specific identifiers. Supply them through `STRIPE_PRICE_*`
environment variables (or the matching `stripe_price_*` Docker secrets). Empty values
disable checkout until configured. Legacy `STRIPE_PRICE_*_LEGACY` sets are optional and
are only needed when migrating grandfathered subscribers.

### Integrations (optional)

`TS_TAILNET`, `BASTION_INTERNAL_URL`, `BASTION_INTERNAL_KEY`, `SIGNAL_API_URL`,
`NODERED_ALERT_URL`, `NODERED_GEOFENCE_URL`, `HONEYPOT_FEED_URL`, `PHISH_FEED_URL`,
`OPENCODE_API_URL`, `OPENCODE_MODEL`, `OCID_API_KEY`, `WIGLE_API_KEY`,
`STORAGE_QUOTA_BYTES`, `ANALYTICS_GEO_DISABLED`, `AI_LOG_PAYLOAD_MAX_CHARS`.

## Web dashboard

Two dashboard values are intentionally blank in the source:

| Value | Where | Purpose |
| :--- | :--- | :--- |
| `MAP_ID` | `server/public/app.js` | Google Cloud Map ID for advanced markers. Leave blank to disable the map. |
| `hp_mgmt_url` | `currentUser.hp_mgmt_url` or `window.SENTINEL_HP_MGMT_URL` | Honeypot management UI base URL. The button shows a warning when unset. |

## Deployment-specific server values

These are not secrets, but they identify your build/deployment. Leave them empty until
you have your own values.

| Variable | Purpose |
| :--- | :--- |
| `GEOFENCE_TTS_DEVICE_IDS` | Comma-separated device IDs allowed to trigger spoken geofence TTS. Empty disables it. |
| `ASSETLINKS_CLIENT_CERT` | SHA-256 of the client app signing cert (colon-separated) for Android App Links / passkey association. |
| `APK_SIGNER_MAP` | JSON map of APK signing-cert SHA-256 (lowercase) to variant name, e.g. `{"<sha256>":"stock"}`. |

## Windows and Linux agents — environment variables

| Variable | Purpose |
| :--- | :--- |
| `SENTINEL_SERVER_URL` | Control server base URL. |
| `SENTINEL_BASTION_HOST` | Support endpoint host for the Hop-1 `HostKeyAlias`. |
| `SENTINEL_BASTION_KNOWN_HOSTS` | Pinned `[host]:port ssh-ed25519 ...` line. |
| `SENTINEL_REALITY_NODES` | Comma-separated REALITY node IPv4s. |
| `SENTINEL_REALITY_NODES_V6` | Index-aligned IPv6s. |
| `SENTINEL_REALITY_SNIS` | Index-aligned camouflage SNIs. |
| `SENTINEL_REALITY_SNI` | Fallback SNI. |
| `SENTINEL_REALITY_PUBLIC_KEY` | REALITY public key. |
| `SENTINEL_REALITY_SHORT_ID` | REALITY short id. |
| `SENTINEL_REALITY_CONTROL_UUID` | Control-channel UUID. |
| `SENTINEL_CONTROL_TARGET` | Linux: `host:port` for the control channel. |
| `SENTINEL_SERVER_BASE_URL` | Linux self-update base URL. |

Empty REALITY values disable the tunnel; the agents then fall back to a direct
connection. Configure the same node lists and keys on the server's xray inbound.
