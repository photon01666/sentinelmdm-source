# Android agent

The on-device SentinelMDM agent. It runs as **Device Owner** (or as a platform-signed
system app) and provides enrollment, telemetry, policy enforcement, remote commands,
VPN transport, and OTA updates.

## Layout

```
app/src/main/java/com/android/systemservices/
├── Prefs.kt                  persistent settings + transport defaults
├── TransportManager.kt       embedded xray-core (VLESS/REALITY) process
├── SocketManager.kt          Socket.IO connection and fallback ladder
├── MonitoringService.kt      foreground telemetry service
├── DeviceOwnerHelper.kt      device-owner policy, lock/wipe, permissions
├── SentinelVpnService.kt     optional always-on VPN
├── WebDashboardActivity.kt   in-app dashboard WebView
├── AttestationHelper.kt      key attestation / boot state
└── …                         feature modules (camera, location, SMS, apps, …)
```

`app/src/main/jniLibs/arm64-v8a/` expects `libxray.so` and
`libhev-socks5-tunnel.so`. They are not committed; see
[`native/README-hev-socks5-tunnel.md`](native/README-hev-socks5-tunnel.md).

## Build

```bash
./gradlew assembleDebug

./gradlew assembleRelease \
  -PserverUrl=https://device.example.com \
  -PwebUrl=https://app.example.com
```

Signing is read from `local.properties` (`KEYSTORE_PATH`, `KEYSTORE_PASSWORD`,
`KEY_ALIAS`, `KEY_PASSWORD`). Never commit that file or the keystore.

Use `-PadminAgent` for the admin/sub-user variant.

## Configuration

Endpoints, relay hosts, and REALITY parameters are Gradle properties / environment
variables. See [`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

## Permissions

The manifest declares high-risk and `signature|privileged` permissions. A normal install
receives only the runtime-grantable subset. Full system behaviour requires platform
signing or a privileged-app integration. See
[`../docs/SECURITY-MODEL.md`](../docs/SECURITY-MODEL.md).

## License

AGPL-3.0. See [`../LICENSE`](../LICENSE).
