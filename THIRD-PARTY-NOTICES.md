# Third-party notices

SentinelMDM is licensed under AGPL-3.0. The components below are used under their own
licenses. This list covers the direct, notable dependencies; the authoritative version
inventory is in `server/package-lock.json`, `linux-agent/sentineld/go.sum`, each
`.csproj`, and the Gradle dependency graph.

## Server (`server/`)

| Component | License |
| :--- | :--- |
| Express | MIT |
| Socket.IO | MIT |
| better-sqlite3 | MIT |
| pg-promise / node-postgres | MIT |
| ioredis | MIT |
| @aws-sdk/client-s3 | Apache-2.0 |
| Stripe Node SDK | MIT |
| Nodemailer | MIT |
| bcryptjs | MIT |
| speakeasy | MIT |
| qrcode | MIT |
| @simplewebauthn/server | MIT |
| firebase-admin | Apache-2.0 |
| connect-redis / express-session | MIT |
| undici | MIT |
| Bootstrap 5.3.2 (web dashboard) | MIT |
| Bootstrap Icons 1.11.3 | MIT |
| zxcvbn 4.4.2 (password strength) | MIT |
| @yume-chan/adb (WebUSB ADB bundle) | MIT |
| @yume-chan fastboot bundle (ya-webadb) | MIT |

## Android agent (`android-agent/`)

| Component | License |
| :--- | :--- |
| Kotlin standard library / Kotlin Gradle plugin | Apache-2.0 |
| AndroidX, Material Components | Apache-2.0 |
| OkHttp | Apache-2.0 |
| socket.io-client-java | MIT |
| xray-core (`libxray.so`, embedded) | MPL-2.0 |
| hev-socks5-tunnel (`libhev-socks5-tunnel.so`, embedded) | see upstream |

The xray and hev-socks5-tunnel binaries are **not distributed in this repository**.
If you build and redistribute them, retain the upstream license and notices. MPL-2.0
requires that modifications to MPL-covered files be made available under MPL-2.0.

## Android client (`android-client/`)

AndroidX, Material Components, Firebase Cloud Messaging / Google Play Services (see
Google's terms), OkHttp, and socket.io-client-java. Firebase is optional and configured
with your own `google-services.json`.

## Windows agent (`windows-agent/`)

| Component | License |
| :--- | :--- |
| .NET 8 / System.* packages | MIT |
| SocketIOClient | MIT |
| rclone.exe (bundled at build time, not committed) | MIT |
| xray.exe (bundled at build time, not committed) | MPL-2.0 |
| OpenSSH for Windows (bundled at build time, not committed) | BSD |

## Linux agent (`linux-agent/`)

| Component | License |
| :--- | :--- |
| gorilla/websocket | BSD-3-Clause |
| golang.org/x/crypto | BSD-3-Clause |
| golang.org/x/sys | BSD-3-Clause |
| xray-core (embedded binary, extracted at build time) | MPL-2.0 |

## Fonts and icons

Any icon sets, fonts, or images shipped with the web dashboard or apps remain under
their respective licenses. Verify before redistributing a branded build.

## Reporting a missing notice

If you believe a third-party notice is missing or incorrect, open an issue or contact
the maintainers. This file is informational and does not replace the license text
shipped with each dependency.
