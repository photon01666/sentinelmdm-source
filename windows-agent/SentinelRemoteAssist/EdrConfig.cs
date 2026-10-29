using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Reads the EDR-watch half of the SHARED <c>endpoint-config.json</c> under
/// <see cref="Config.AppControlDir"/> — the same file <see cref="AppControlConfig"/> and
/// <see cref="WinUpdateConfig"/> read, just different fields (<c>edr_enabled</c>/<c>edr_token</c>
/// vs. <c>enabled</c>/<c>token</c> vs. <c>winupdate_enabled</c>/<c>winupdate_token</c>). Three
/// independent features share one provisioned directory/ACL/tunnel-forward port rather than each
/// standing up its own — see the doc comment on <see cref="Config.AppControlDir"/>. TunnelRunner
/// only ever needs <see cref="TryLoad"/>'s enabled/localPort out — like AppControlConfig and
/// WinUpdateConfig, it deliberately never reads the token.
/// </summary>
internal static class EdrConfig
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
            if (root.TryGetProperty("edr_enabled", out var e) && e.ValueKind is JsonValueKind.True or JsonValueKind.False)
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
