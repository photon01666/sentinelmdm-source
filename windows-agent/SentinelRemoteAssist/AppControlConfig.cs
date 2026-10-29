using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Reads <c>endpoint-config.json</c> (written by the bastion-pushed provisioning script — see
/// the support service's _APPCONTROL_PROVISION_PS1) from <see cref="Config.AppControlDir"/>.
/// TunnelRunner only ever needs <see cref="Enabled"/>/<see cref="LocalPort"/> to decide whether to
/// add its conditional -L forward — it deliberately never reads the report token, keeping the
/// bearer secret out of a process whose whole job is an outbound reverse tunnel, not app-control
/// reporting (least privilege inside the process itself, not just across processes).
/// </summary>
internal static class AppControlConfig
{
    private static string ConfigPath => Path.Combine(Config.AppControlDir, "endpoint-config.json");

    public static bool TryLoad(out bool enabled, out int localPort)
    {
        enabled = false;
        localPort = 0;
        try
        {
            if (!File.Exists(ConfigPath)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(ConfigPath));
            var root = doc.RootElement;
            if (root.TryGetProperty("enabled", out var e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                enabled = e.GetBoolean();
            }
            if (root.TryGetProperty("localPort", out var p) && p.ValueKind == JsonValueKind.Number)
            {
                localPort = p.GetInt32();
            }
            return enabled && localPort > 0;
        }
        catch
        {
            // Missing/malformed config = app-control not active. Never let a bad config file
            // break the reverse tunnel itself — TunnelRunner just proceeds without the -L forward.
            enabled = false;
            localPort = 0;
            return false;
        }
    }
}
