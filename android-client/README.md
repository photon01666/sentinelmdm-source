# Android client (parent / administrator)

A WebView companion app for the SentinelMDM dashboard, with optional Firebase Cloud
Messaging push notifications. It is a client only — all data lives on your server.

## Flavors

| Flavor | Application ID | Landing page |
| :--- | :--- | :--- |
| `publicClient` | `com.sentinelmdm.monitor` | `/login` |
| `adminClient` | `com.sentinelmdm.adminmonitor` | `/admin/login` |
| `subUsersClient` | `com.sentinelmdm.subusersmonitor` | `/admin/subusers/login` |

All three derive their URL from one `serverUrl` Gradle property.

## Build

```bash
./gradlew assemblePublicClientRelease   -PserverUrl=https://app.example.com
./gradlew assembleAdminClientRelease    -PserverUrl=https://app.example.com
./gradlew assembleSubUsersClientRelease -PserverUrl=https://app.example.com
```

Signing is read from `local.properties`; see the agent README.

## Firebase / push (optional)

Place your own `app/google-services.json`. The Google Services Gradle plugin is applied
only when the file exists, so the app builds without FCM. Setup notes live in
[`FCM-SETUP.md`](FCM-SETUP.md).

## License

AGPL-3.0. See [`../LICENSE`](../LICENSE).
