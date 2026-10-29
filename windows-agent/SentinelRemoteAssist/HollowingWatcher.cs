using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Process-hollowing heuristic — Phase 4, the "no clean single Sysmon signal exists for this, say
/// so plainly" item from the EDR feature plan. Sysmon's CreateRemoteThread (Event 8, handled in
/// EdrWatcher.cs) is a noisy, hollowing-ADJACENT correlative signal at best. This is a genuinely
/// separate, independent check: periodically, for every running process, ask whether the memory
/// region backing that process's OWN main-module base address is still MEM_IMAGE (a normal
/// loader-mapped EXE file) — a classic "unmap + rewrite" hollowing technique (NtUnmapViewOfSection
/// then VirtualAllocEx/WriteProcessMemory over the same base address, the standard RunPE-style
/// pattern) replaces that with MEM_PRIVATE, since the new content is no longer backed by the
/// original mapped file. A secondary, softer signal: PAGE_EXECUTE_READWRITE at that same base — no
/// ordinary PE loader leaves the main executable's own base region RWX.
///
/// ⚠️ Honesty, matching the plan: this narrowly targets ONE hollowing technique (the classic
/// unmap+rewrite), not process injection in general (a DLL injected elsewhere in the address space,
/// or a technique that never touches the base region, is invisible to this specific check). It has
/// NOT been validated against a real hollowing PoC — only that the P/Invoke plumbing itself
/// compiles and runs without throwing against ordinary processes. Report-only, MEDIUM, allowlist-
/// tuned, rate-limited to one alert per process lifetime — never wired to autonomous action (same
/// posture CreateRemoteThread already has, for the same reason: too high a false-positive risk for
/// anything but a human-reviewed report).
/// </summary>
internal static class HollowingWatcher
{
    private static string LogPath => Path.Combine(Config.EdrDir, "logs", "watcher.log");
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(90);

    // Kept short and conservative, same doctrine as EdrWatcher.cs's LsassAllowedAccessors — an
    // over-broad allowlist is a bypass; a false positive here is "just" a MEDIUM report-only entry
    // an operator has to dismiss, a much cheaper failure mode. Own tooling (SentinelRemoteAssist
    // itself, bundled sshd/xray) is excluded via IsOwnToolingPath below, not this list.
    private static readonly HashSet<string> AllowlistedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "svchost.exe", "memcompression",
    };

    // Alerts once per (pid, process start time) — a legitimate false-positive shouldn't re-page
    // every 90s for the life of a long-running process, and a start-time-qualified key means a
    // genuinely NEW process reusing a recycled PID is still evaluated fresh.
    private static readonly HashSet<(int Pid, long StartTicks)> AlreadyReported = new();
    private static readonly object ReportedLock = new();
    private const int AlreadyReportedMaxEntries = 4000;

    public static void Start(EdrWatcher.WatchConfig cfg)
    {
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try { ScanOnce(cfg); }
                catch (Exception ex) { LogLine($"scan pass failed: {ex.Message}"); }
                await Task.Delay(ScanInterval).ConfigureAwait(false);
            }
            // ReSharper disable once FunctionNeverReturns
        });
    }

    private static void ScanOnce(EdrWatcher.WatchConfig cfg)
    {
        foreach (var proc in Process.GetProcesses())
        {
            using (proc)
            {
                try { EvaluateProcess(cfg, proc); }
                catch { /* best-effort per-process — one bad process must never abort the whole scan pass */ }
            }
        }
    }

    private static void EvaluateProcess(EdrWatcher.WatchConfig cfg, Process proc)
    {
        if (proc.Id <= 4) return; // System Idle Process (0) / System (4) — no user-mode image to check
        var name = proc.ProcessName;
        if (AllowlistedNames.Contains(name) || AllowlistedNames.Contains(name + ".exe")) return;

        string? imagePath;
        IntPtr baseAddress;
        DateTime startTime;
        try
        {
            imagePath = proc.MainModule?.FileName;
            baseAddress = proc.MainModule?.BaseAddress ?? IntPtr.Zero;
            startTime = proc.StartTime;
        }
        catch
        {
            // Access denied (protected/elevated process this SYSTEM watcher still can't touch, or a
            // cross-bitness query) or the process exited mid-query — not evaluable, skip silently.
            // This is the expected, common case for a meaningful slice of the process list.
            return;
        }
        if (string.IsNullOrEmpty(imagePath) || baseAddress == IntPtr.Zero) return;
        if (IsOwnToolingPath(imagePath)) return;

        var key = (proc.Id, startTime.Ticks);
        lock (ReportedLock) { if (AlreadyReported.Contains(key)) return; }

        var hProcess = Win32Native.OpenProcess(Win32Native.PROCESS_QUERY_INFORMATION | Win32Native.PROCESS_VM_READ, false, (uint)proc.Id);
        if (hProcess == IntPtr.Zero) return; // access denied — not evaluable, same as above
        try
        {
            var size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Win32Native.MEMORY_BASIC_INFORMATION>();
            var written = Win32Native.VirtualQueryEx(hProcess, baseAddress, out var mbi, size);
            if (written == IntPtr.Zero) return;
            if (mbi.State != Win32Native.MEM_COMMIT) return; // decommitted/free at the base — nothing to evaluate

            var notImageBacked = mbi.Type != Win32Native.MEM_IMAGE;
            var rwxAtBase = (mbi.Protect & Win32Native.PAGE_EXECUTE_READWRITE) != 0;
            if (!notImageBacked && !rwxAtBase) return; // normal, loader-mapped image — nothing to report

            lock (ReportedLock)
            {
                AlreadyReported.Add(key);
                if (AlreadyReported.Count > AlreadyReportedMaxEntries) AlreadyReported.Clear(); // simple bound, not TTL-precise — acceptable for a report-only dedup set
            }

            var reason = notImageBacked && rwxAtBase
                ? "main-module memory is not image-backed AND RWX at base — both hollowing indicators"
                : notImageBacked
                    ? "main-module memory is not image-backed (expected MEM_IMAGE, got private/mapped) — classic unmap+rewrite indicator"
                    : "main-module base region is RWX — no ordinary PE loader leaves the base image writable+executable";

            LogLine($"HOLLOWING INDICATOR pid={proc.Id} image={imagePath} reason={reason}");
            var report = new
            {
                label = cfg.Label,
                rule = "process_hollowing_indicator",
                severity = "medium",
                reason,
                time = DateTime.UtcNow.ToString("o"),
                image = imagePath,
                command_line = "",
                lineage_context = EdrWatcher.BuildLineageContextByPid(proc.Id),
                raw_xml = System.Text.Json.JsonSerializer.Serialize(new
                {
                    pid = proc.Id, memory_type = mbi.Type, memory_protect = mbi.Protect, memory_state = mbi.State,
                }),
            };
            try { EdrWatcher.SendOrQueueAsync(cfg, report).GetAwaiter().GetResult(); }
            catch (Exception ex) { LogLine($"hollowing report failed: {ex.Message}"); }
        }
        finally
        {
            Win32Native.CloseHandle(hProcess);
        }
    }

    private static bool IsOwnToolingPath(string imagePath) =>
        imagePath.Contains("SentinelRemoteAssist", StringComparison.OrdinalIgnoreCase);

    private static void LogLine(string s)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"{DateTime.Now:O}  [HollowingWatcher] {s}{Environment.NewLine}");
        }
        catch { /* best-effort */ }
    }
}
