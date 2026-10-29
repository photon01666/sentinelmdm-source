using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Reads the Windows Update Control half of the SHARED <c>endpoint-config.json</c> under
/// <see cref="Config.AppControlDir"/> — the same file <see cref="AppControlConfig"/> reads, just
/// different fields (<c>winupdate_enabled</c>/<c>winupdate_token</c> vs. <c>enabled</c>/
/// <c>token</c>). Two independent features share one provisioned directory/ACL/tunnel-forward
/// port rather than each standing up its own — see the doc comment on
/// <see cref="Config.AppControlDir"/> for why this directory exists at all (survives Remote
/// Assist's ephemeral wipe). TunnelRunner only ever needs <see cref="TryLoad"/>'s
/// enabled/localPort out — like AppControlConfig, it deliberately never reads the token.
/// </summary>
internal static class WinUpdateConfig
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
            if (root.TryGetProperty("winupdate_enabled", out var e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False)
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
            enabled = false;
            localPort = 0;
            return false;
        }
    }
}
