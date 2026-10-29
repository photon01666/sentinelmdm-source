using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace SentinelRemoteAssist;

/// <summary>
/// Builds the periodic status heartbeat that populates the dashboard's Device Overview card
/// (Session / Uptime / Network columns) for a remote_assist Windows device — mirrors the shape
/// the card already expects from a plaintext OR ZK-decrypted "device_status" payload (see
/// buildDeviceCard()'s isWindows branch in app.js; sessionState/uptimeSecs/network are read
/// generically there regardless of which platform sent them).
/// </summary>
internal static class DeviceStatusHelper
{
    // "Active" vs "idle" vs "away" thresholds — a reasonable Windows equivalent to Android's
    // motion-based classification, not an attempt to match it semantically.
    private const int ActiveThresholdSecs = 60;
    private const int IdleThresholdSecs = 600;

    public static object Build()
    {
        var idleSecs = GetIdleSeconds();
        var sessionState = idleSecs < ActiveThresholdSecs ? "active"
            : idleSecs < IdleThresholdSecs ? "idle" : "away";
        return new
        {
            sessionState,
            uptimeSecs = Environment.TickCount64 / 1000,
            idleSecs,
            network = BuildNetwork(),
        };
    }

    private static long GetIdleSeconds()
    {
        try
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref info)) return 0;
            // Both GetTickCount()-based (32-bit) — matches dwTime's epoch, wraps safely together.
            // Do NOT use TickCount64 here (uptimeSecs above is the right place for that).
            var idleMs = unchecked((uint)Environment.TickCount - info.dwTime);
            return idleMs / 1000;
        }
        catch
        {
            return 0;
        }
    }

    private static object BuildNetwork()
    {
        try
        {
            var active = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                         && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                .OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                .FirstOrDefault();
            if (active is null) return new { connection_type = "none" };
            if (active.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
            {
                var ssid = TryGetWifiSsid();
                return string.IsNullOrEmpty(ssid)
                    ? new { connection_type = "wifi" }
                    : (object)new { connection_type = "wifi", wifi_current = new { ssid } };
            }
            return new { connection_type = "ethernet" };
        }
        catch
        {
            return new { connection_type = "none" };
        }
    }

    // Same "netsh wlan show interfaces" idiom VpnManager.DetectOpenWifi() already uses for
    // security-type detection — a separate, minimal parse here just for the SSID line.
    private static string? TryGetWifiSsid()
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return null;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            using var reader = new StringReader(output);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                var trimmed = line.Trim();
                // "BSSID" also appears as its own line — doesn't start with "SSID", no collision.
                if (trimmed.StartsWith("SSID", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = trimmed.IndexOf(':');
                    if (idx > 0) return trimmed[(idx + 1)..].Trim();
                }
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }
}
