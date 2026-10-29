package com.android.systemservices;

/**
 * JNI binding to {@code libhev-socks5-tunnel.so} — the tun2socks engine used by
 * {@link SentinelVpnService} for the open-WiFi auto-VPN.
 *
 * The native library's {@code JNI_OnLoad} resolves this exact class via
 * {@code FindClass("com/android/systemservices/TProxyNative")} and {@code RegisterNatives} onto the
 * static methods below — the library was compiled with
 * {@code -DPKGNAME=com/android/systemservices -DCLSNAME=TProxyNative} so no extra {@code hev.*}
 * package is needed. Build provenance: {@code native/README-hev-socks5-tunnel.md}.
 *
 * {@link #TProxyStartService} spawns a worker thread that reads the VpnService TUN {@code fd} and
 * proxies every packet through the SOCKS5 server declared in the YAML at {@code configPath} (our
 * local xray {@code socks-vpn} inbound on 127.0.0.1:10809). It is a no-op if already running.
 */
public final class TProxyNative {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private TProxyNative() {}

    public static native void TProxyStartService(String configPath, int fd);

    public static native void TProxyStopService();

    /** [tx_packets, tx_bytes, rx_packets, rx_bytes] — best-effort, may be empty before start. */
    public static native long[] TProxyGetStats();
}
