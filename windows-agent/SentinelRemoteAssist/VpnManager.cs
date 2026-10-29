using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace SentinelRemoteAssist;

internal sealed class VpnManager
{
    private static readonly string ConfigPath = Path.Combine(Config.SessionKeyDir, "vpn-config.json");
    private readonly XrayTransportManager _xray;

    private bool _enabled;
    private bool _force;
    private string? _egressUuid;
    private bool _xrayRunning;
    private System.Threading.Timer? _pollTimer;

    public VpnManager(XrayTransportManager xray) => _xray = xray;

    public event Action<bool, bool>? StatusChanged;

    public bool IsActive { get; private set; }

    public void ReceiveConfig(bool enabled, bool force, string? egressUuid)
    {
        _enabled = enabled;
        _force = force;
        _egressUuid = egressUuid;
        SavePrefs();
        Reevaluate();
    }

    public void SetXrayRunning(bool running)
    {
        _xrayRunning = running;
        Reevaluate();
    }

    public void Start()
    {
        LoadPrefs();
    }

    public void Stop()
    {
        _pollTimer?.Dispose();
        _pollTimer = null;
        if (IsActive) SetVpnActive(false);
    }

    private void Reevaluate()
    {
        var desired = _force && !string.IsNullOrEmpty(_egressUuid) && _xrayRunning;
        if (desired != IsActive)
        {
            SetVpnActive(desired);
        }
    }

    private void SetVpnActive(bool active)
    {
        IsActive = active;
        _xray.Reconfigure(active ? _egressUuid : null);
        SetSystemProxy(active);
        StatusChanged?.Invoke(IsActive, false);
    }

    private static void SetSystemProxy(bool enable)
    {
        try
        {
            var reg = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true);
            if (reg is null) return;
            if (enable)
            {
                reg.SetValue("ProxyEnable", 1);
                reg.SetValue("ProxyServer", $"socks=127.0.0.1:{XrayTransportManager.VpnSocksPort}");
            }
            else
            {
                reg.SetValue("ProxyEnable", 0);
            }
            reg.Close();
            _NotifyProxyChange();
        }
        catch
        {
        }
    }

    private static void _NotifyProxyChange()
    {
        const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        const int INTERNET_OPTION_REFRESH = 37;
        try
        {
            NativeMethods.InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            NativeMethods.InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch
        {
        }
    }

    private void SavePrefs()
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            var prefs = new { enabled = _enabled, force = _force, egressUuid = _egressUuid };
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(prefs));
        }
        catch
        {
        }
    }

    private void LoadPrefs()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return;
            var text = File.ReadAllText(ConfigPath);
            var doc = JsonDocument.Parse(text);
            _enabled = doc.RootElement.TryGetProperty("enabled", out var e) && e.GetBoolean();
            _force = doc.RootElement.TryGetProperty("force", out var f) && f.GetBoolean();
            _egressUuid = doc.RootElement.TryGetProperty("egressUuid", out var u) ? u.GetString() : null;
        }
        catch
        {
        }
    }

    private static class NativeMethods
    {
        [DllImport("wininet.dll", SetLastError = true)]
        internal static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    }
}
