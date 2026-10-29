# Server

Node.js control server for SentinelMDM: HTTP API, Socket.IO device channel, and the
browser dashboard.

## Layout

```
server.js            legacy monolith — CLOSED to new code (see ../docs/ARCHITECTURE.md)
config.js            env/secrets, storage clients, static configuration
bootstrap.js         startup and wiring
routes/              HTTP endpoints, one feature per module
helpers/             stateless helpers (auth, crypto, device queries, transport)
workers/             background pollers and alerters
sockets/             Socket.IO connection and per-device state
services/            domain services (commerce, notifications, APK variants)
schema/              migrations and generated statements
public/              dashboard SPA (HTML/CSS/JS)
templates/           email templates
```

> **Rule 0:** `server.js` must never grow. New routes, helpers, workers, statements,
> and migrations go into modules. `../docs/ARCHITECTURE.md` summarises the module layout.

## Run locally

```bash
npm ci

export ADMIN_PASS="$(openssl rand -hex 16)"
export SESSION_SECRET="$(openssl rand -hex 32)"
export SERVER_ORIGIN="http://localhost:3000"

npm start
```

Open <http://localhost:3000>. SQLite is used by default (`./tracker.db`); set
`DATABASE_URL` for Postgres. `Dockerfile` is provided; supply your own deployment configuration.

## Checks

```bash
npm run typecheck
node --check server.js
```

## Configuration

See [`../.env.example`](../.env.example) and
[`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md). Secrets are read from
`/run/secrets/<name>` first, then the environment.

## License

AGPL-3.0. See [`../LICENSE`](../LICENSE).
