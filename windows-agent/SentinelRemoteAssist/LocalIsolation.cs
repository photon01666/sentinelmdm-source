using System.Diagnostics;
using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Local, zero-Hop-2-dependency network isolation trigger — the autonomous-response counterpart to
/// bastion-web.py's dashboard-triggered _EDR_ISOLATE_BLOCK_PS1/_EDR_ISOLATE_UNBLOCK_PS1. Used by
/// EdrWatcher.cs's autonomous response path (see the EDR feature plan's autonomous-action policy
/// table: a canary-file touch or confirmed mass-encryption pattern must isolate the host INSTANTLY,
/// without waiting on a dashboard round trip — the Hop-1 tunnel may not even be reachable at that
/// moment, sometimes *because* of the attack). Shells out to netsh.exe directly via Process.Start
/// (this codebase's existing external-process idiom everywhere else — no new COM interop).
///
/// Writes/reads the SAME isolation-block.json marker under Config.EdrDir that the bastion-side PS1
/// pair uses, so a status check from either side sees a consistent picture regardless of which path
/// triggered it. Deliberately simpler than the dashboard path's exact-state snapshot/restore:
/// Restore resets both firewall directions to Windows' "notconfigured" (out-of-box default) rather
/// than replaying an arbitrary prior state — acceptable for an emergency path whose whole point is
/// "cut the network NOW," not "preserve a bespoke firewall configuration."
///
/// Not yet called from anywhere — this is the Phase 2 primitive; Phase 3's canary-file/
/// mass-encryption detectors are the actual callers, per the plan's phased design.
/// </summary>
internal static class LocalIsolation
{
    private static string Dir => Config.EdrDir;
    private static string MarkerPath => Path.Combine(Dir, "isolation-block.json");
    private static string LogPath => Path.Combine(Dir, "logs", "watcher.log");

    // Same allow-list as _EDR_ISOLATE_BLOCK_PS1 in bastion-web.py — keep the two in lockstep.
    private static readonly string[] AllowPaths =
    {
        @"C:\ProgramData\SentinelRemoteAssist\Sentinel.exe",
        @"C:\Windows\System32\OpenSSH\ssh.exe",
        @"C:\ProgramData\SentinelRemoteAssist\OpenSSH-Win64\sshd.exe",
        @"C:\ProgramData\SentinelRemoteAssist\OpenSSH-Win64\sshd-session.exe",
        @"C:\ProgramData\SentinelRemoteAssist\xray\xray.exe",
    };

    // 2.0.0 — audit-gap fix (was: system-wide DNS allow on ports 53). An unrestricted DNS allow
    // leaves a DNS-tunneling exfiltration channel open for ANY process during isolation — the
    // "isolated but still leaking" shape. Scoping the allow to the Windows DNS Client service
    // (svchost.exe, the OS resolver) closes that: everything that resolves through the normal
    // Windows API path still works (the allowlisted tooling's ssh/xray name lookups ride the
    // same resolver), but a payload speaking raw DNS to its own resolver port from ITS OWN
    // process — the actual tunneling technique — is blocked. LocalIsolation's own allowlist
    // programs don't need a direct rule either: OpenSSH's Windows build resolves via the OS
    // resolver, not in-process. One allowed program path, one rule pair (matching the
    // program-scoped allow rules above), same delete names in Unblock.
    private static readonly string[] DnsResolverPaths =
    {
        @"C:\Windows\System32\svchost.exe",
    };

    public static bool IsIsolated()
    {
        try { return File.Exists(MarkerPath); }
        catch { return false; }
    }

    /// <summary>Isolates the host immediately. Best-effort and idempotent — a failure here is
    /// logged, never thrown, so a firewall-command hiccup can't take down the watcher process
    /// itself; calling it while already isolated is a no-op.</summary>
    public static bool Block(string reason)
    {
        try
        {
            if (IsIsolated()) return true;

            Directory.CreateDirectory(Dir);
            foreach (var exe in AllowPaths)
            {
                if (!File.Exists(exe)) continue;
                var name = Path.GetFileName(exe);
                RunNetsh($"advfirewall firewall add rule name=\"Sentinel-Isolation-{name}-Out\" dir=out program=\"{exe}\" action=allow");
                RunNetsh($"advfirewall firewall add rule name=\"Sentinel-Isolation-{name}-In\" dir=in program=\"{exe}\" action=allow");
            }
            foreach (var exe in DnsResolverPaths)
            {
                if (!File.Exists(exe)) continue;
                var name = Path.GetFileName(exe);
                RunNetsh($"advfirewall firewall add rule name=\"Sentinel-Isolation-DNS-Out-UDP-{name}\" dir=out protocol=UDP remoteport=53 program=\"{exe}\" action=allow");
                RunNetsh($"advfirewall firewall add rule name=\"Sentinel-Isolation-DNS-Out-TCP-{name}\" dir=out protocol=TCP remoteport=53 program=\"{exe}\" action=allow");
            }
            RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");

            var marker = JsonSerializer.Serialize(new { local = true, reason, blockedAt = DateTime.UtcNow.ToString("o") });
            File.WriteAllText(MarkerPath, marker);
            LogLine($"LOCAL ISOLATION triggered: {reason}");
            return true;
        }
        catch (Exception ex)
        {
            LogLine($"local isolation failed: {ex.Message}");
            return false;
        }
    }

    public static bool Unblock()
    {
        try
        {
            foreach (var exe in AllowPaths)
            {
                var name = Path.GetFileName(exe);
                RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-{name}-Out\"");
                RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-{name}-In\"");
            }
            foreach (var exe in DnsResolverPaths)
            {
                var name = Path.GetFileName(exe);
                RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-DNS-Out-UDP-{name}\"");
                RunNetsh($"advfirewall firewall delete rule name=\"Sentinel-Isolation-DNS-Out-TCP-{name}\"");
            }
            RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,notconfigured");

            try { File.Delete(MarkerPath); } catch { /* best-effort */ }
            LogLine("local isolation restored");
            return true;
        }
        catch (Exception ex)
        {
            LogLine($"local isolation restore failed: {ex.Message}");
            return false;
        }
    }

    private static void RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(10000);
        }
        catch (Exception ex)
        {
            LogLine($"netsh command failed ({args}): {ex.Message}");
        }
    }

    private static void LogLine(string s)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"{DateTime.Now:O}  {s}{Environment.NewLine}");
        }
        catch { /* best-effort */ }
    }
}
