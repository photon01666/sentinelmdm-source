# libhev-socks5-tunnel.so — build provenance

Prebuilt tun2socks engine used by SentinelVpnService (open-WiFi auto-VPN). Built from source —
NOT a vendored third-party binary — so the supply chain is auditable.

- Upstream: https://github.com/heiher/hev-socks5-tunnel (MIT/Apache-2.0)
- Pinned commit: `eb5c7cec807e80d9b0fa41e19f4c72e6c56d34a7`
- NDK: r27c, APP_PLATFORM android-26, APP_ABI arm64-v8a, 16KB-page aligned.
- JNI bound to the app's own namespace via build defines (so the wrapper class lives in
  `com.android.systemservices`, no extra `hev.*` package):
  `APP_CFLAGS += -DPKGNAME=com/android/systemservices -DCLSNAME=TProxyNative`
- Wrapper: `com.android.systemservices.TProxyNative` (static natives
  `TProxyStartService(String,int)`, `TProxyStopService()`, `TProxyGetStats()`).

## Rebuild
```bash
git clone --depth 1 --recursive https://github.com/heiher/hev-socks5-tunnel   # checkout eb5c7cec807e80d9b0fa41e19f4c72e6c56d34a7
# Application.mk: APP_ABI := arm64-v8a ; APP_PLATFORM := android-26
#   APP_CFLAGS := -O3 -DPKGNAME=com/android/systemservices -DCLSNAME=TProxyNative
#   APP_SUPPORT_FLEXIBLE_PAGE_SIZES := true
ndk-build NDK_PROJECT_PATH=<proj> APP_BUILD_SCRIPT=<repo>/Android.mk NDK_APPLICATION_MK=<proj>/jni/Application.mk
# => libs/arm64-v8a/libhev-socks5-tunnel.so  →  app/src/main/jniLibs/arm64-v8a/
```
