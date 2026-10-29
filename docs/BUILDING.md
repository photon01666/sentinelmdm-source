# Building

Each component is built independently. None of the build outputs are committed.

## Android agent (`android-agent/`)

**Requirements:** JDK 17, Android SDK 34, Gradle 8.2 (wrapper included).

1. Create `android-agent/local.properties`:

   ```properties
   sdk.dir=/path/to/Android/Sdk

   # Release signing — omit for debug builds.
   KEYSTORE_PATH=/path/to/your.keystore
   KEYSTORE_PASSWORD=...
   KEY_ALIAS=...
   KEY_PASSWORD=...
   ```

2. Point the agent at your server and build:

   ```bash
   cd android-agent
   ./gradlew assembleRelease \
     -PserverUrl=https://device.example.com \
     -PwebUrl=https://app.example.com
   ```

   The output is `app/build/outputs/apk/release/SentinelMDM-<version>.apk`.

3. For the admin variant add `-PadminAgent`.

**Native libraries.** `app/src/main/jniLibs/arm64-v8a/libxray.so` and
`libhev-socks5-tunnel.so` are not committed. Build them from the pinned upstream
sources and place them there. Without them the app compiles but the REALITY transport
cannot start. See `android-agent/native/README-hev-socks5-tunnel.md`.

**Privileged permissions.** The manifest requests several
`signature|privileged` permissions. A normal install silently ignores them; a
Device-Owner install grants the rest through the Device Policy Controller. Full
system-level behaviour requires platform signing or a ROM integration.

## Android client (`android-client/`)

**Requirements:** JDK 17, Android SDK 34.

1. Create `android-client/local.properties` with `sdk.dir` and (optionally) the same
   signing keys.
2. For FCM, place your own `app/google-services.json`. The Google Services plugin is
   applied only when that file exists, so the project builds without it.
3. Build a flavor:

   ```bash
   ./gradlew assemblePublicClientRelease   -PserverUrl=https://app.example.com
   ./gradlew assembleAdminClientRelease    -PserverUrl=https://app.example.com
   ./gradlew assembleSubUsersClientRelease -PserverUrl=https://app.example.com
   ```

## Server (`server/`)

**Requirements:** Node.js 24+, npm.

```bash
cd server
npm ci
npm run typecheck          # optional, runs tsc over server + web UI

ADMIN_PASS="$(openssl rand -hex 16)" \
SESSION_SECRET="$(openssl rand -hex 32)" \
SERVER_ORIGIN="http://localhost:3000" \
npm start
```

The server refuses to start without `ADMIN_PASS`. SQLite is used by default
(`./tracker.db`); set `DATABASE_URL` to use Postgres. `Dockerfile` is provided for
container builds; supply your own deployment configuration.

## Windows agent (`windows-agent/`)

**Requirements:** .NET 8 SDK on Windows 10/11.

```powershell
cd windows-agent
dotnet build SentinelRemoteAssist/SentinelRemoteAssist.csproj -c Release
dotnet build NukeAgent/NukeAgent.csproj -c Release
```

Runtime assets (`rclone.exe`, `xray.exe`, `OpenSSH-Win64.zip`) are not committed. The
project builds without them; the full self-contained installer does not. Place them in
`SentinelRemoteAssist/` before packaging.

The agent's endpoint is read from `SENTINEL_SERVER_URL` at runtime (default
`https://app.example.com`). The support endpoint host/key and REALITY values are also
environment-driven; see [`CONFIGURATION.md`](CONFIGURATION.md).

## Linux agent (`linux-agent/`)

**Requirements:** Go 1.25+, Docker (for the pinned xray extraction).

```bash
cd linux-agent/sentineld
./internal/xraytransport/embedded/extract.sh    # pulls teddysun/xray:26.3.27
go build ./cmd/sentineld
go test ./...
```

The extracted `xray` / `xray-arm64` binaries are gitignored. They are embedded into the
daemon with `go:embed`, so the extract step is mandatory before `go build`.

## Reproducibility notes

- Android and .NET builds are not hermetic; pin your SDK and NuGet cache if you need
  byte-identical artifacts.
- `server/package-lock.json` and `linux-agent/sentineld/go.sum` are committed; use
  `npm ci` and `go mod verify`.
- The xray version is pinned in `extract.sh` and in the embedded package constants.
  Do not bump it without re-testing the transport.
