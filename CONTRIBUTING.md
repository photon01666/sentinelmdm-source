# Contributing

Thanks for taking the time to contribute.

## Before you start

- Open an issue for non-trivial changes so the approach can be discussed first.
- Security issues go through [`SECURITY.md`](SECURITY.md), not the public issue tracker.
- By participating you agree to the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Development setup

Each component is independent; use the README in its directory.

| Component | Setup |
| :--- | :--- |
| `server/` | `cd server && npm ci` then `ADMIN_PASS=... npm start` |
| `android-agent/` | Android Studio or `./gradlew assembleDebug` with SDK 34 |
| `android-client/` | `./gradlew assembleDebug`; add your own `google-services.json` for FCM |
| `windows-agent/` | `dotnet build` with the .NET 8 SDK |
| `linux-agent/` | `cd linux-agent/sentineld && ./internal/xraytransport/embedded/extract.sh && go test ./...` |

## Tests and checks

Run the checks that apply to the component you touched:

```bash
# Server
cd server && npm run typecheck && node --check server.js

# Linux agent
cd linux-agent/sentineld && go vet ./... && go test ./...

# Windows agent
cd windows-agent && dotnet build -c Release

# Android (unit tests, if present)
cd android && ./gradlew testDebugUnitTest
```

## Coding guidelines

- Match the style of the surrounding file; do not reformat unrelated code.
- Keep changes focused. One logical change per pull request.
- Do not add new code to `server/server.js`. The file is a legacy monolith under
  decomposition; new routes, helpers, workers, statements, and migrations belong in
  `server/routes/`, `server/helpers/`, `server/workers/`, `server/statements.js`, or
  `server/schema/migrations.js`. See `docs/ARCHITECTURE.md` for the module layout.
- Comments should explain *why*, not restate *what*.
- Never commit credentials, keystores, tokens, customer data, or production hostnames.
  Use the `example.com` placeholders and environment variables already wired in.

## Commits and pull requests

- Write imperative commit subjects, e.g. `fix(agent): handle empty enrollment ticket`.
- Reference the issue in the pull request description.
- Describe how the change was tested, including device/OS versions where relevant.
- By submitting a pull request you agree to license your contribution under the
  project's AGPL-3.0 license.

## Reporting bugs

Include the component, version/commit, platform, reproduction steps, and relevant log
excerpts with secrets removed.
