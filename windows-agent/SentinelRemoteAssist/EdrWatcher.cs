using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace SentinelRemoteAssist;

/// <summary>
/// Continuous behavioral-telemetry watcher — entry point for the <c>--edr-watch</c> mode,
/// registered as its own SYSTEM AtStartup scheduled task by the bastion-pushed provisioning
/// script (see bastion-web.py's <c>_EDR_PROVISION_PS1</c>), separate from SentinelRemoteAssist's
/// own SetupRunner-managed tasks (see <see cref="Config.EdrDir"/>'s doc comment) — same pattern as
/// <see cref="AppControlWatcher"/>, which this class mirrors structurally.
///
/// Tails the <c>Microsoft-Windows-Sysmon/Operational</c> log (Sysmon is deployed by the same
/// provisioning script) via the real-time <see cref="EventLogWatcher"/> API and evaluates a small,
/// intentionally conservative rule set:
///   - Event 1 (ProcessCreate): process-lineage alerting (Office/script-host parent spawning a
///     shell, or any powershell/pwsh invocation carrying -enc/-EncodedCommand).
///   - Event 3 (NetworkConnect): captured as CONTEXT ONLY on the correlated process, never an
///     independent alert — high volume, low standalone signal.
///   - Event 8 (CreateRemoteThread): hollowing-adjacent, report-only, MEDIUM — Sysmon has no
///     single "hollowing detected" event; this is a noisy correlative approximation, not a
///     detector, and deliberately never triggers autonomous action.
///   - Event 10 (ProcessAccess): LSASS credential-dump detection — TargetImage=lsass.exe plus a
///     known-bad GrantedAccess mask, minus an allowlist of legitimate accessors.
///
/// Field-name mapping was cross-checked against Sysmon's documented schema but NOT independently
/// verified against a real live event on this fleet before this was written (same caveat
/// AppControlWatcher's doc comment carries for CodeIntegrity events) — every report always
/// includes the raw event XML as a fallback so a field-mapping issue found on the real first run
/// is fixable bastion-side without needing to re-trigger anything on the endpoint.
/// </summary>
internal static class EdrWatcher
{
    private const string LogName = "Microsoft-Windows-Sysmon/Operational";
    private const int ProcessCreateEventId = 1;
    private const int NetworkConnectEventId = 3;
    private const int CreateRemoteThreadEventId = 8;
    private const int ProcessAccessEventId = 10;
    // Phase 3 (anti-ransomware/canary attribution) — see HandleFileCreateAsync/RecentFileTouches.
    // Not consumed in Phase 1/2; added here rather than a second EventLogWatcher subscription so
    // there's only ever one live Sysmon subscription/catch-up pass for the whole process.
    private const int FileCreateEventId = 11;
    private const int DriverLoadEventId = 6;
    private const int RegistrySetValueEventId = 13;
    private const int FileDeleteEventId = 23;
    private const int ProcessTamperEventId = 25;
    // Phase 4/5 — Event 5 (ProcessTerminate): the killed-process leg of the EDR corridor. Sysmon
    // Event 5 has NO killer attribution in its schema (the terminating PID isn't emitted), so this
    // is victim-side only — see HandleProcessTerminateAsync.
    private const int ProcessTerminateEventId = 5;
    // Phase 6 (3.2.3) — Event 22 (DnsQuery): the DNS leg of the AiTM/phishing-proxy feed. Sysmon's
    // Event 3 DestinationHostname attribution is unreliable (Chrome/curl often log the v4 connect
    // with an empty hostname — found live 2026-08-14 on a CF Pages c2 host), and the server-side
    // PTR fallback can't help for CDN-fronted domains (no PTR on CF/Vercel edge IPs). The DNS
    // query ALWAYS carries the qname, so watching Event 22 closes that gap: the server matches
    // qname against the feed's c2_domains/PhishTank sets and blocks/sinkholes on a C2-tier match.
    private const int DnsQueryEventId = 22;

    private static string Dir => Config.EdrDir;
    private static string SharedConfigPath => Path.Combine(Config.AppControlDir, "endpoint-config.json");
    private static string WatcherStatePath => Path.Combine(Dir, "watcher-state.json");
    private static string OutboxDir => Path.Combine(Dir, "outbox");
    private static string LogPath => Path.Combine(Dir, "logs", "watcher.log");

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    internal sealed record WatchConfig(bool Enabled, int LocalPort, string Token, string Label);

    // Correlated-process context, keyed by Sysmon's ProcessGuid (stable per process lifetime,
    // unlike a bare PID which is reused). Capped/TTL'd below — this is a bounded in-memory buffer,
    // never persisted, never streamed on its own; it only ever rides along as context on an actual
    // alert (see BuildLineageContext).
    private sealed class ProcessContext
    {
        public required int Pid;
        public required string Image;
        public required string CommandLine;
        public required string ParentImage;
        public required string ParentCommandLine;
        public required string ParentProcessGuid;
        public required DateTime SeenUtc;
        public readonly List<string> NetworkConnections = new();
    }

    private static readonly ConcurrentDictionary<string, ProcessContext> ProcessCache = new();
    private const int ProcessCacheMaxEntries = 2000;
    private static readonly TimeSpan ProcessCacheTtl = TimeSpan.FromMinutes(15);

    // Phase 4/5 — watchdog-check ProcessGuid set. The SentinelRemoteAssist-Watchdog scheduled task
    // spawns `Sentinel.exe --watchdog-check` every 60s; it exits immediately after verifying the
    // main agent is alive. Without suppression, every exit fires Sysmon Event 5 →
    // agent_process_killed → ~10 false-positive alerts/hour. Sysmon Event 5 carries NO command-line,
    // so we tag the ProcessGuid from Event 1 (which DOES carry CommandLine) and skip the alert in
    // HandleProcessTerminateAsync. Bounded/TTL'd like the other concurrent buffers.
    private static readonly ConcurrentDictionary<string, DateTime> WatchdogCheckGuids = new();
    private const int WatchdogCheckGuidsMaxEntries = 100;
    private static readonly TimeSpan WatchdogCheckGuidsTtl = TimeSpan.FromMinutes(5);

    // Phase 4 — reverse PID->ProcessGuid index. HollowingWatcher.cs starts from Process.GetProcesses()
    // (bare PIDs, no ProcessGuid) but every other correlation buffer here is keyed by ProcessGuid
    // (stable per process lifetime; a PID alone is reused and would misattribute across process
    // churn) — this lets a PID-only caller still reach the same lineage context ProcessGuid-keyed
    // callers get. Same cap/TTL discipline as ProcessCache.
    private static readonly ConcurrentDictionary<int, (string ProcessGuid, DateTime SeenUtc)> PidToProcessGuid = new();
    private const int PidMapMaxEntries = 2000;

    // Phase 3 attribution buffer — "which process most recently touched this exact file path,"
    // keyed by the FULL PATH lowercased (not ProcessGuid — RansomwareGuard.cs needs to look this
    // up BY PATH when a canary/mass-modification trigger fires, it doesn't have a ProcessGuid to
    // start from). Populated from Sysmon Event 11 (FileCreate — despite the name, Sysmon fires this
    // for renames/overwrites too, which is exactly the ransomware-relevant case). This is the
    // structural Phase 1 -> Phase 3 dependency called out in the EDR feature plan: canary/
    // mass-modification response has NO reliable attribution at all if Sysmon isn't deployed/
    // healthy — RansomwareGuard's own doc comment covers the fallback behavior for that case.
    private static readonly ConcurrentDictionary<string, (string Image, int Pid, string ProcessGuid, DateTime SeenUtc)> RecentFileTouches = new();
    private const int FileTouchCacheMaxEntries = 5000;
    private static readonly TimeSpan FileTouchCacheTtl = TimeSpan.FromMinutes(5);

    // Office/script-host apps whose spawning a shell is itself a strong signal (the user's own
    // literal example: winword.exe -> cmd.exe -> powershell.exe with a base64 payload).
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    };
    private static readonly HashSet<string> SuspiciousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "rundll32.exe",
    };

    // Sigma-rule-style "known bad" LSASS GrantedAccess masks (Mimikatz/ProcDump-style credential
    // dumping combinations). Tunable — not exhaustive, and a real access mask can legitimately
    // vary by OS build. Cross-referenced against widely used public Sysmon LSASS-access detection
    // rules, not independently verified live on this fleet yet (see class doc comment).
    private static readonly HashSet<string> LsassBadAccessMasks = new(StringComparer.OrdinalIgnoreCase)
    {
        "0x1010", "0x1038", "0x1400", "0x1410", "0x1418", "0x142a", "0x143a", "0x1438", "0x1fffff",
    };
    // Known-legitimate LSASS accessors — AV/EDR engines, Task Manager's own "Create dump file",
    // crash reporting, and Windows' own service-control/session processes. Kept short and
    // conservative on purpose (an over-broad allowlist is a bypass; an under-broad one is a
    // false-positive risk this codebase treats as the safer failure mode for a report-only rule).
    private static readonly HashSet<string> LsassAllowedAccessors = new(StringComparer.OrdinalIgnoreCase)
    {
        "msmpeng.exe", "sensendr.exe", "senseir.exe", "werfault.exe", "taskmgr.exe",
        "csrss.exe", "services.exe", "wininit.exe", "lsass.exe",
    };
    // Core Windows processes that legitimately use CreateRemoteThread as part of normal
    // system operation — CSRSS (client/server runtime), DWM (desktop compositor), Winlogon
    // (logon UI), and Service Control Manager. Browsers' multi-process IPC and RGB/OEM
    // utilities also trigger this event routinely, but those are harder to enumerate
    // statically; the comment in HandleCreateRemoteThreadAsync explains why the remaining
    // noise is acceptable for a report-only/MEDIUM rule.
    private static readonly HashSet<string> CreateRemoteThreadAllowedSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe", "dwm.exe", "winlogon.exe", "svchost.exe", "services.exe", "smss.exe",
    };

    public static int Run()
    {
        // Single-watcher guard (found live 2026-08-14): the EDR provision path re-registers +
        // starts the SYSTEM --edr-watch task on every enable AND on every agent cutover that
        // re-provisions EDR, and a second fire while the first watcher is alive used to start a
        // duplicate process tailing the same Sysmon log — two watchers raced on
        // watcher-state.json/outbox and dropped events between them. Exit fast if one is running.
        if (!SingleInstance.TryAcquireEdrWatch())
        {
            LogLine("edr-watch already running — exiting (single-watcher guard)");
            return 0;
        }

        var cfg = LoadConfig();
        if (cfg is null || !cfg.Enabled)
        {
            LogLine("edr-watch not enabled for this endpoint — exiting (task will no-op until re-enabled)");
            return 0;
        }

        LogLine($"--edr-watch starting (pid {Environment.ProcessId}, label {cfg.Label}, port {cfg.LocalPort})");

        try
        {
            CatchUpAsync(cfg).GetAwaiter().GetResult();
            FlushOutboxAsync(cfg).GetAwaiter().GetResult();

            var query = new EventLogQuery(LogName, PathType.LogName,
                $"*[System[(EventID={ProcessCreateEventId} or EventID={NetworkConnectEventId} " +
                $"or EventID={CreateRemoteThreadEventId} or EventID={ProcessAccessEventId} " +
                $"or EventID={FileCreateEventId} or EventID={DriverLoadEventId} " +
                $"or EventID={RegistrySetValueEventId} or EventID={FileDeleteEventId} " +
                $"or EventID={ProcessTamperEventId} or EventID={ProcessTerminateEventId} " +
                $"or EventID={DnsQueryEventId})]]");
            using var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += (_, e) =>
            {
                try
                {
                    if (e.EventRecord is null) return;
                    using var record = e.EventRecord;
                    HandleEventAsync(cfg, record).GetAwaiter().GetResult();
                    if (record.RecordId is { } rid) SaveLastRecordId(rid);
                }
                catch (Exception ex)
                {
                    LogLine($"event handling error: {ex.Message}");
                }
            };
            watcher.Enabled = true;
            LogLine("live watch active");

            _ = Task.Run(async () =>
            {
                // sensor-health loop: Sysmon/Defender presence re-checked on the same 2-min cadence
                // as the outbox flush; reporting is rate-limited per hour so a chronic outage pages
                // once, not every tick. This is the "watcher watching the watcher" gap: a killed
                // Sysmon service (the classic first move of anything that wants its behavior hidden)
                // used to be indistinguishable from a quiet system — no events flow, no alert ever.
                var lastSysmonReport = DateTime.MinValue;
                var lastDefenderReport = DateTime.MinValue;
                var healthTicks = 0;
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(2)).ConfigureAwait(false);
                    try { await FlushOutboxAsync(cfg).ConfigureAwait(false); }
                    catch (Exception ex) { LogLine($"outbox flush error: {ex.Message}"); }
                    EvictStaleProcessContexts();
                    EvictStaleFileTouches();
                    EvictStaleAgentKillerCandidates();

                    // ~ every 6 ticks (12 min) — cheap `sc query`, plaintext output, no PS.
                    healthTicks++;
                    if (healthTicks % 6 != 0) continue;

                    var sysmonRunning = ServiceState("Sysmon64");
                    if (!sysmonRunning && DateTime.UtcNow - lastSysmonReport > TimeSpan.FromHours(1))
                    {
                        lastSysmonReport = DateTime.UtcNow;
                        await SendHealthReportAsync(cfg, "sysmon_sensor_down",
                            "Sysmon64 service is not running — EDR events have stopped flowing; a " +
                            "killed sensor is indistinguishable from a quiet system by design, so " +
                            "treat this as compromise-until-proven-otherwise").ConfigureAwait(false);
                    }

                    var defenderRunning = ServiceState("WinDefend");
                    if (!defenderRunning && DateTime.UtcNow - lastDefenderReport > TimeSpan.FromHours(1))
                    {
                        lastDefenderReport = DateTime.UtcNow;
                        await SendHealthReportAsync(cfg, "defender_disabled",
                            "Windows Defender (WinDefend) service is not running — malware commonly " +
                            "disables AV first; this is a HIGH-priority hygiene finding").ConfigureAwait(false);
                    }
                }
                // ReSharper disable once FunctionNeverReturns
            });

            // Phase 3 — anti-ransomware mass-modification detector + canary files, sharing this
            // same process/config/attribution buffer (see RansomwareGuard.cs's doc comment for why
            // it's not a separate --mode). Best-effort: a failure setting it up must never take
            // down the telemetry watcher above.
            try { RansomwareGuard.Start(cfg); }
            catch (Exception ex) { LogLine($"RansomwareGuard failed to start: {ex.Message}"); }

            // Phase 4 — process-hollowing heuristic, same best-effort/never-take-down-the-watcher
            // posture as RansomwareGuard above.
            try { HollowingWatcher.Start(cfg); }
            catch (Exception ex) { LogLine($"HollowingWatcher failed to start: {ex.Message}"); }

            Thread.Sleep(Timeout.Infinite);
            return 0;
        }
        catch (Exception ex)
        {
            LogLine($"fatal: {ex.Message}");
            return 1;
        }
    }

    private static WatchConfig? LoadConfig()
    {
        try
        {
            if (!File.Exists(SharedConfigPath)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(SharedConfigPath));
            var root = doc.RootElement;
            var enabled = root.TryGetProperty("edr_enabled", out var e) && e.ValueKind == JsonValueKind.True;
            var localPort = root.TryGetProperty("localPort", out var p) ? p.GetInt32() : 0;
            var token = root.TryGetProperty("edr_token", out var t) ? t.GetString() ?? "" : "";
            var label = root.TryGetProperty("label", out var l) ? l.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(label) || localPort <= 0) return null;
            return new WatchConfig(enabled, localPort, token, label);
        }
        catch
        {
            return null;
        }
    }

    private static async Task CatchUpAsync(WatchConfig cfg)
    {
        var lastId = LoadLastRecordId();
        if (lastId is null)
        {
            // First run — baseline to the current log tip rather than replaying Sysmon's entire
            // history (which may span months and would flood the first report burst with stale
            // events), same reasoning as AppControlWatcher's own first-run baseline.
            SaveLastRecordId(CurrentMaxRecordId());
            LogLine("catch-up: first run — baselined to current log tip, no backlog replay");
            return;
        }

        var query = new EventLogQuery(LogName, PathType.LogName,
            $"*[System[(EventID={ProcessCreateEventId} or EventID={NetworkConnectEventId} " +
            $"or EventID={CreateRemoteThreadEventId} or EventID={ProcessAccessEventId} " +
            $"or EventID={FileCreateEventId} or EventID={DriverLoadEventId} " +
            $"or EventID={RegistrySetValueEventId} or EventID={FileDeleteEventId} " +
            $"or EventID={ProcessTamperEventId} or EventID={ProcessTerminateEventId}) " +
            $"and EventRecordID > {lastId}]]");
        using var reader = new EventLogReader(query);

        var caughtUp = 0;
        long? highest = null;
        while (reader.ReadEvent() is { } record)
        {
            using (record)
            {
                await HandleEventAsync(cfg, record).ConfigureAwait(false);
                if (record.RecordId is { } rid) highest = highest is null ? rid : Math.Max(highest.Value, rid);
                caughtUp++;
            }
        }
        if (highest is not null) SaveLastRecordId(highest.Value);
        if (caughtUp > 0) LogLine($"catch-up: processed {caughtUp} backlog event(s)");
    }

    private static long CurrentMaxRecordId()
    {
        try
        {
            using var log = new EventLogReader(new EventLogQuery(LogName, PathType.LogName)
            {
                ReverseDirection = true,
            });
            using var newest = log.ReadEvent();
            return newest?.RecordId ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static long? LoadLastRecordId()
    {
        try
        {
            if (!File.Exists(WatcherStatePath)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(WatcherStatePath));
            if (doc.RootElement.TryGetProperty("lastRecordId", out var v) && v.ValueKind == JsonValueKind.Number)
            {
                return v.GetInt64();
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static void SaveLastRecordId(long recordId)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            var payload = JsonSerializer.Serialize(new { lastRecordId = recordId, savedAtUtc = DateTime.UtcNow });
            File.WriteAllText(WatcherStatePath, payload);
        }
        catch (Exception ex)
        {
            LogLine($"could not save watcher state: {ex.Message}");
        }
    }

    private static async Task HandleEventAsync(WatchConfig cfg, EventRecord record)
    {
        var eventId = record.Id;
        string rawXml;
        try { rawXml = record.ToXml(); }
        catch { rawXml = ""; }

        var fields = ParseDataFields(rawXml);

        switch (eventId)
        {
            case ProcessCreateEventId:
                await HandleProcessCreateAsync(cfg, record, fields, rawXml).ConfigureAwait(false);
                break;
            case NetworkConnectEventId:
                await HandleNetworkConnectAsync(cfg, fields).ConfigureAwait(false);
                break;
            case DnsQueryEventId:
                await HandleDnsQueryAsync(cfg, fields).ConfigureAwait(false);
                break;
            case CreateRemoteThreadEventId:
                await HandleCreateRemoteThreadAsync(cfg, record, fields, rawXml).ConfigureAwait(false);
                break;
            case ProcessAccessEventId:
                await HandleProcessAccessAsync(cfg, record, fields, rawXml).ConfigureAwait(false);
                break;
            case FileCreateEventId:
                HandleFileCreate(fields);
                break;
            case DriverLoadEventId:
                await HandleDriverLoadAsync(cfg, fields).ConfigureAwait(false);
                break;
            case RegistrySetValueEventId:
                await HandleRegistryEventAsync(cfg, fields).ConfigureAwait(false);
                break;
            case FileDeleteEventId:
                HandleFileDelete(fields);
                break;
            case ProcessTamperEventId:
                await HandleProcessTamperAsync(cfg, fields).ConfigureAwait(false);
                break;
            case ProcessTerminateEventId:
                await HandleProcessTerminateAsync(cfg, fields).ConfigureAwait(false);
                break;
        }
    }

    // Phase 3 — records "which process most recently touched this file" for RansomwareGuard.cs's
    // canary/mass-modification attribution. Never alerts on its own (Event 11 fires constantly for
    // completely ordinary activity); purely a rolling buffer TryGetRecentFileTouch reads from.
    private static void HandleFileCreate(Dictionary<string, string> fields)
    {
        var targetFilename = Field(fields, "TargetFilename");
        if (string.IsNullOrEmpty(targetFilename)) return;
        var image = Field(fields, "Image");
        var pidStr = Field(fields, "ProcessId");
        var pid = int.TryParse(pidStr, out var p) ? p : 0;
        var processGuid = Field(fields, "ProcessGuid");
        RecentFileTouches[targetFilename.ToLowerInvariant()] = (image, pid, processGuid, DateTime.UtcNow);
        if (RecentFileTouches.Count > FileTouchCacheMaxEntries) EvictStaleFileTouches(force: true);
    }

    /// <summary>Best-effort attribution lookup for RansomwareGuard.cs — "what process most
    /// recently (within <see cref="FileTouchCacheTtl"/>) touched this exact path, per Sysmon."
    /// Returns false if Sysmon never saw it (not deployed/healthy, or the touch predates the
    /// cache window) — callers must have a no-attribution fallback, see RansomwareGuard's doc
    /// comment for the policy (canary hits still isolate even without attribution; they just can't
    /// target a specific kill). <paramref name="processGuid"/> (Phase 4) lets the caller additionally
    /// pull full lineage/network context via <see cref="BuildLineageContext"/> — may be empty even
    /// when image/pid resolved, if Sysmon's Event 11 schema omitted it.</summary>
    internal static bool TryGetRecentFileTouch(string path, out string image, out int pid, out string processGuid)
    {
        image = ""; pid = 0; processGuid = "";
        if (string.IsNullOrEmpty(path)) return false;
        if (!RecentFileTouches.TryGetValue(path.ToLowerInvariant(), out var entry)) return false;
        if (DateTime.UtcNow - entry.SeenUtc > FileTouchCacheTtl) return false;
        image = entry.Image; pid = entry.Pid; processGuid = entry.ProcessGuid;
        return !string.IsNullOrEmpty(image) || pid > 0;
    }

    private static void EvictStaleFileTouches(bool force = false)
    {
        var cutoff = DateTime.UtcNow - FileTouchCacheTtl;
        foreach (var kv in RecentFileTouches)
        {
            if (kv.Value.SeenUtc < cutoff) RecentFileTouches.TryRemove(kv.Key, out _);
        }
        if (force && RecentFileTouches.Count > FileTouchCacheMaxEntries)
        {
            foreach (var kv in RecentFileTouches.OrderBy(k => k.Value.SeenUtc)
                         .Take(RecentFileTouches.Count - FileTouchCacheMaxEntries))
            {
                RecentFileTouches.TryRemove(kv.Key, out _);
            }
        }
    }

    private static async Task HandleProcessCreateAsync(WatchConfig cfg, EventRecord record,
        Dictionary<string, string> fields, string rawXml)
    {
        var processGuid = Field(fields, "ProcessGuid");
        var image = Field(fields, "Image");
        var commandLine = Field(fields, "CommandLine");
        var parentImage = Field(fields, "ParentImage");
        var parentCommandLine = Field(fields, "ParentCommandLine");
        var parentProcessGuid = Field(fields, "ParentProcessGuid");
        var pid = int.TryParse(Field(fields, "ProcessId"), out var pidVal) ? pidVal : 0;

        if (!string.IsNullOrEmpty(processGuid))
        {
            ProcessCache[processGuid] = new ProcessContext
            {
                Pid = pid,
                Image = image,
                CommandLine = commandLine,
                ParentImage = parentImage,
                ParentCommandLine = parentCommandLine,
                ParentProcessGuid = parentProcessGuid,
                SeenUtc = DateTime.UtcNow,
            };
            if (ProcessCache.Count > ProcessCacheMaxEntries) EvictStaleProcessContexts(force: true);

            if (pid > 0)
            {
                PidToProcessGuid[pid] = (processGuid, DateTime.UtcNow);
                if (PidToProcessGuid.Count > PidMapMaxEntries) EvictStalePidMap(force: true);
            }

            // Tag --watchdog-check processes so HandleProcessTerminateAsync can suppress the
            // false-positive agent_process_killed alert (Sysmon Event 5 lacks CommandLine).
            if (image != null && BaseName(image).Equals("Sentinel.exe", StringComparison.OrdinalIgnoreCase) &&
                commandLine != null && commandLine.Contains("--watchdog-check", StringComparison.OrdinalIgnoreCase))
            {
                WatchdogCheckGuids[processGuid] = DateTime.UtcNow;
                if (WatchdogCheckGuids.Count > WatchdogCheckGuidsMaxEntries)
                    EvictStaleWatchdogCheckGuids();
            }
        }

        // Known-benign SentinelRemoteAssist automation — mirrors the IT Mode Audit's own
        // established "known-benign baseline" doctrine (own exe/sshd/sentinel-support account never
        // counted as a finding). Every legitimate bastion-driven Hop-2 PowerShell call
        // (session_powershell/fleet_powershell's arbitrary-exec primitive, and every one-shot
        // feature script deployed via _appcontrol_run_ps1 — Telemetry block, WinUpdate, AppLocker
        // deploy, ARP scan, IT audit, EDR's own provisioning, ...) is spawned as a child of our own
        // bundled OpenSSH sshd-session.exe, and the -EncodedCommand ones would otherwise ALWAYS
        // match the encoded-powershell-command rule below — without this guard EDR pages on every
        // existing dashboard action as if it were a credential-dumping attack. Found live 2026-07-19
        // (a handful of manual test/diagnostic PowerShell calls paged Signal repeatedly).
        if (IsOwnToolingContext(parentImage, parentProcessGuid, Field(fields, "User"))) return;

        // System tool access detection — alert when a user tries to open tools that could
        // disable agent features (regedit, taskmgr, cmd, powershell). Agent runs as SYSTEM
        // so HKCU restrictions don't affect it, but we log the attempt as a security signal.
        var systemTools = new[] { "regedit.exe", "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "msconfig.exe", "services.exe" };
        var imageBase = BaseName(image);
        var parentBase = BaseName(parentImage);
        var user = Field(fields, "User");
        var isSystemTool = Array.Exists(systemTools, t => t.Equals(imageBase, StringComparison.OrdinalIgnoreCase));
        var isNonSystemUser = !string.IsNullOrEmpty(user) &&
            !user.EndsWith("\\SYSTEM", StringComparison.OrdinalIgnoreCase) &&
            !user.Contains("LocalSystem", StringComparison.OrdinalIgnoreCase);
        if (isSystemTool && isNonSystemUser)
        {
            var toolReport = new
            {
                label = cfg.Label,
                rule = "system_tool_access",
                severity = "medium",
                reason = $"User {user} launched {imageBase} — system tool access detected",
                time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
                process_guid = processGuid,
                image,
                command_line = commandLine,
                parent_image = parentImage,
                user,
                lineage_context = BuildLineageContext(processGuid),
                raw_xml = rawXml,
            };
            await SendOrQueueAsync(cfg, toolReport).ConfigureAwait(false);
        }

        // UAC elevation detection — alert when any process gets a full (elevated) token.
        // TokenElevationType=2 means Type 2 (full token) = UAC was approved.
        // On a locked-down machine the user shouldn't be elevating — alert the admin.
        var tokenElevation = Field(fields, "TokenElevationType");
        if (tokenElevation == "2" && isNonSystemUser)
        {
            var uacReport = new
            {
                label = cfg.Label,
                rule = "uac_elevation",
                severity = "high",
                reason = $"User {user} approved UAC elevation for {imageBase}",
                time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
                process_guid = processGuid,
                image,
                command_line = commandLine,
                parent_image = parentImage,
                user,
                lineage_context = BuildLineageContext(processGuid),
                raw_xml = rawXml,
            };
            await SendOrQueueAsync(cfg, uacReport).ConfigureAwait(false);
        }

        // Anti-recovery attack rules — the classic ransomware final moves. vssadmin/wbadmin/
        // diskshadow deleting shadow copies and bcdedit disabling boot recovery are near-zero-
        // false-positive signatures (no legitimate consumer software does either), so these are
        // HIGH report-only. Report-only, not autonomous: the damage is already done or imminent,
        // and an attacker-deleted shadow copy can't be un-deleted by a kill — the operator needs
        // to see it instantly instead. Sends immediately, before the generic lineage check below.
        var shadowDelete = ShadowCopyDeletionSignature(imageBase, commandLine);
        if (shadowDelete is not null)
        {
            var shadowReport = new
            {
                label = cfg.Label,
                rule = "shadow_copy_attack",
                severity = "high",
                reason = shadowDelete,
                time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
                process_guid = processGuid,
                image,
                command_line = commandLine,
                parent_image = parentImage,
                lineage_context = BuildLineageContext(processGuid),
                raw_xml = rawXml,
            };
            await SendOrQueueAsync(cfg, shadowReport).ConfigureAwait(false);
        }

        var isEncoded = ContainsEncodedFlag(commandLine);
        var isSuspiciousLineage = SuspiciousParents.Contains(parentBase) && SuspiciousChildren.Contains(imageBase);

        if (!isEncoded && !isSuspiciousLineage) return;

        var reason = isEncoded && isSuspiciousLineage
            ? "encoded-command-from-suspicious-parent"
            : isEncoded ? "encoded-powershell-command" : "script-host-spawned-by-office-app";

        var report = new
        {
            label = cfg.Label,
            rule = "process_lineage",
            severity = "high",
            reason,
            time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            process_guid = processGuid,
            image,
            command_line = commandLine,
            parent_image = parentImage,
            parent_command_line = parentCommandLine,
            raw_xml = rawXml,
        };
        await SendOrQueueAsync(cfg, report).ConfigureAwait(false);
    }

    // Event 3 (NetworkConnect) — previously context-only (buffered onto ProcessCache for
    // lineage_context). Audit gap closed: an outbound connection to a PUBLIC destination on a
    // NON-STANDARD port from a process that isn't known system/own tooling is now its own MEDIUM
    // alert (rule "unusual_outbound_connection") — the C2/beacon shape. Strict gates keep the
    // false-positive rate near zero on real desktops:
    //   - only outbound (SourcePort present, no local-listener rows)
    //   - destination must be a real public IP (not RFC1918/link-local/loopback/multicast)
    //   - port must NOT be in the common-egress set below (browsers/OS updates/services on
    //     80/443/53/123/853/587/etc. never alert)
    //   - image not own tooling and not a core system component (system processes talk on odd
    //     ports legitimately — SMB/NetBIOS/RPC — so svchost and friends are exempt)
    //   - one alert per (process, destination) — no re-paging on every packet of a long-lived
    //     session; dedup set bounded, TTL'd.
    private const int NetworkAlertMaxEntries = 1000;
    private static readonly ConcurrentDictionary<string, DateTime> NetworkAlerted = new();
    private static readonly TimeSpan NetworkAlertDedupTtl = TimeSpan.FromHours(6);
    // Phase 6 — AiTM/phishing-proxy intel feed. A bounded, feed-only (LOW, never pages by itself)
    // report of EVERY public-IP outbound destination INCLUDING browsers + common egress ports (443
    // etc.), which the existing "unusual_outbound_connection" MEDIUM rule deliberately never sees
    // (CommonEgressPorts/NetworkQuietImages skip). The server matches each destination against
    // threat-intel sets (EvilProxy/Tycoon/VoidProxy C2 + PhishTank domains/IPs/ASNs) and pages
    // only on a match — so the whole volume here is inert unless the feed flags it. Dedup is keyed
    // on image|destIp (NOT the process GUID — a per-run GUID would mint a fresh entry for the same
    // destination on every browser restart) so a busy desktop stays bounded.
    private const int NetworkFeedMaxEntries = 2000;
    private static readonly ConcurrentDictionary<string, DateTime> NetworkFeed = new();
    private static readonly TimeSpan NetworkFeedDedupTtl = TimeSpan.FromHours(6);
    private static readonly HashSet<int> CommonEgressPorts = new()
    {
        53, 80, 123, 443, 853, 993, 995, 587, 465, 25, 110, 143, 5228, 5229, 5222, 8080, 8443,
    };
    private static readonly HashSet<string> NetworkQuietImages = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe", "explorer.exe",
        "System", "lsm.exe", "fontdrvhost.exe", "dwm.exe", "taskhostw.exe", "SearchHost.exe",
        "SearchIndexer.exe", "MsMpEng.exe", "SenseIR.exe", "MsSense.exe", "WerFault.exe",
        "chrome.exe", "msedge.exe", "firefox.exe",          // browser connection pools
        "discord.exe", "slack.exe", "teams.exe",             // chat apps — multi-connection pools
        "tailscaled.exe", "tailscale-ipn.exe",               // WireGuard mesh — DERP/STUN on high ports
        "spotify.exe", "code.exe",                            // media + IDE — high-port connections
    };

    private static async Task HandleNetworkConnectAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var processGuid = Field(fields, "ProcessGuid");
        var image = Field(fields, "Image");
        var destIp = Field(fields, "DestinationIp");
        var destPort = int.TryParse(Field(fields, "DestinationPort"), out var dp) ? dp : 0;
        var isOutbound = !string.IsNullOrEmpty(Field(fields, "SourcePort"));
        // Sysmon Event 3 carries DestinationHostname when the connecting process resolved DNS
        // through a Sysmon-observed path (browsers always do; raw IP connects leave it empty).
        // Phase 6 domain tier: the server matches this against the feed's c2_domains/PhishTank
        // sets for the hosts-file sinkhole half of a phish block (IP half stays authoritative).
        var destHost = (Field(fields, "DestinationHostname") ?? "").Trim();
        if (string.IsNullOrEmpty(destHost) || !destHost.Contains('.')) destHost = "";

        if (!string.IsNullOrEmpty(processGuid))
        {
            if (!ProcessCache.TryGetValue(processGuid, out var ctx))
            {
                ctx = new ProcessContext
                {
                    Pid = 0,
                    Image = image,
                    CommandLine = "",
                    ParentImage = "",
                    ParentCommandLine = "",
                    ParentProcessGuid = "",
                    SeenUtc = DateTime.UtcNow,
                };
                ProcessCache[processGuid] = ctx;
                if (ProcessCache.Count > ProcessCacheMaxEntries) EvictStaleProcessContexts(force: true);
            }
            var dest = $"{destIp}:{destPort}";
            lock (ctx.NetworkConnections)
            {
                if (ctx.NetworkConnections.Count < 20) ctx.NetworkConnections.Add(dest);
            }
        }

        // Phase 6 — AiTM/phishing-proxy intel feed. Feed-only (LOW): every public outbound
        // destination regardless of image or port (so the browser->proxy-443 relay path is
        // covered). Volume is bounded by image|destIp dedup + entry cap; the server decides
        // whether any given destination is worth paging on. IsOwnToolingLineage gate stays —
        // own-tooling (Remote Assist's own tunnels/xray) and RFC1918 traffic must never ride
        // this feed. This block MUST run BEFORE the MEDIUM path's gates below: those early-return
        // on CommonEgressPorts (443/80/8080/8443 — exactly the AiTM proxy ports) and
        // NetworkQuietImages, which would starve the feed of the browser->proxy-443 traffic it
        // exists to cover. Found live 2026-08-14: the feed was placed after the CommonEgressPorts
        // return, so HTTPS connects never produced a single outbound_connection report.
        // IsFeedEligibleIp also accepts global IPv6 — v6-only hosted phishing pages
        // (Cloudflare Pages/Vercel/Netlify often publish AAAA-only) are covered via the
        // destination_domain tier, since the IP half is v4-only by design.
        if (!isOutbound || destPort <= 0 || IsOwnToolingLineage(image, processGuid)) return;
        if (!IsFeedEligibleIp(destIp)) return;
        var feedKey = $"{BaseName(image)}|{destIp}";
        if (NetworkFeed.TryGetValue(feedKey, out var feedLast) && DateTime.UtcNow - feedLast < NetworkFeedDedupTtl) return;
        NetworkFeed[feedKey] = DateTime.UtcNow;
        if (NetworkFeed.Count > NetworkFeedMaxEntries) NetworkFeed.Clear(); // simple bound

        var feedReport = new
        {
            label = cfg.Label,
            rule = "outbound_connection",
            severity = "low",
            time = DateTime.UtcNow.ToString("o"),
            image,
            destination_ip = destIp,
            destination_port = destPort,
            destination_domain = destHost,
            lineage_context = BuildLineageContext(processGuid),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, feedReport).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"network feed failed: {ex.Message}"); }

        if (!isOutbound || destPort <= 0) return;
        if (CommonEgressPorts.Contains(destPort)) return;
        if (!IsPublicIp(destIp)) return;
        if (NetworkQuietImages.Contains(BaseName(image))) return;
        if (IsOwnToolingLineage(image, processGuid)) return;
        if (string.IsNullOrEmpty(processGuid)) return;

        var dedupKey = $"{processGuid}|{destIp}:{destPort}";
        if (NetworkAlerted.TryGetValue(dedupKey, out var last) && DateTime.UtcNow - last < NetworkAlertDedupTtl) return;
        NetworkAlerted[dedupKey] = DateTime.UtcNow;
        if (NetworkAlerted.Count > NetworkAlertMaxEntries) NetworkAlerted.Clear(); // simple bound

        var report = new
        {
            label = cfg.Label,
            rule = "unusual_outbound_connection",
            severity = "medium",
            time = DateTime.UtcNow.ToString("o"),
            image,
            destination_ip = destIp,
            destination_port = destPort,
            lineage_context = BuildLineageContext(processGuid),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"network alert failed: {ex.Message}"); }
    }

    // Phase 6 (3.2.3) — Sysmon Event 22 (DnsQuery) leg of the AiTM/phishing-proxy feed. The DNS
    // qname ALWAYS carries the hostname, unlike Event 3's DestinationHostname (which browsers
    // often fail to attribute on the connect event). The server matches the qname against the
    // feed's c2_domains/PhishTank sets — this is what catches CDN-fronted phishing pages
    // (CF Pages/Vercel/Netlify): the edge IP isn't in the feed and has no PTR, but the DNS
    // query for the flagged hostname is unambiguous. Volume is bounded by image|qname dedup +
    // entry cap, same shape as the connection feed. Common/quiet images are skipped so system
    // resolver noise never rides the feed.
    private static async Task HandleDnsQueryAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var image = Field(fields, "Image");
        if (string.IsNullOrEmpty(image)) return;
        if (NetworkQuietImages.Contains(BaseName(image))) return;
        if (IsOwnToolingLineage(image, Field(fields, "ProcessGuid"))) return;

        var qname = (Field(fields, "QueryName") ?? "").Trim().TrimEnd('.');
        if (string.IsNullOrEmpty(qname) || !qname.Contains('.')) return;
        if (qname.Length > 253) return;
        // Skip raw-IP queries (some resolvers query "in-addr.arpa"/"ip6.arpa" or literal forms)
        if (System.Net.IPAddress.TryParse(qname, out _)) return;

        var feedKey = $"{BaseName(image)}|{qname}";
        if (NetworkFeed.TryGetValue(feedKey, out var feedLast) && DateTime.UtcNow - feedLast < NetworkFeedDedupTtl) return;
        NetworkFeed[feedKey] = DateTime.UtcNow;
        if (NetworkFeed.Count > NetworkFeedMaxEntries) NetworkFeed.Clear(); // simple bound

        var feedReport = new
        {
            label = cfg.Label,
            rule = "dns_query",
            severity = "low",
            time = DateTime.UtcNow.ToString("o"),
            image,
            destination_domain = qname,
            lineage_context = BuildLineageContext(Field(fields, "ProcessGuid")),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, feedReport).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"dns feed failed: {ex.Message}"); }
    }

    private static bool IsPublicIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var parsed)) return false;
        var bytes = parsed.GetAddressBytes();
        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (bytes[0] == 10) return false;
            if (bytes[0] == 127) return false;
            if (bytes[0] == 169 && bytes[1] == 254) return false; // link-local
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
            if (bytes[0] == 192 && bytes[1] == 168) return false;
            if (bytes[0] >= 224) return false; // multicast/reserved
            return true;
        }
        return false; // IPv6: skip — dual-stack noise, public-v4 rule covers the gap
    }

    // Feed-path counterpart to IsPublicIp: the LOW outbound_connection feed ALSO accepts global
    // IPv6 destinations, because many AiTM hosting fronts (Cloudflare Pages/Vercel/Netlify)
    // publish AAAA-only and the destination_domain tier is what matches those. Still excludes
    // loopback/link-local/ULA/multicast/mapped — RFC1918 and local chatter never ride the feed.
    private static bool IsFeedEligibleIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var parsed)) return false;
        if (parsed.IsIPv4MappedToIPv6) return IsPublicIp(parsed.MapToIPv4().ToString());
        if (parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return IsPublicIp(ip);
        if (parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return false;
        if (parsed.IsIPv6LinkLocal || parsed.IsIPv6Multicast) return false;
        var bytes = parsed.GetAddressBytes();
        // fc00::/7 ULA, fec0::/10 site-local, and ::/128 loopback are rejected here; embedded-v4
        // (::ffff:) is handled by the MapToIPv4 branch above.
        if (bytes[0] == 0xfc || bytes[0] == 0xfd) return false;           // ULA
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0) return false;  // fec0::/10 site-local
        return true;
    }

    // Event 6 (DriverLoad) — audit gap closed: the Sysmon config previously never captured
    // driver loads, so BYOVD/vulnerable-driver abuse (the standard Defender-disabling and
    // rootkit path) was invisible. Now: any driver loaded from OUTSIDE C:\Windows\ is a MEDIUM
    // report (rule "driver_load"). C:\Windows\ drivers are OS-signed baseline and are excluded
    // at the Sysmon config level too (belt and suspenders — the config exclude keeps log volume
    // down, this handler is the second gate). Report-only: a legit vendor driver (VPN, printer,
    // GPU) in Program Files triggers this on first install — never autonomous.
    private static readonly HashSet<string> ReportedDrivers = new(StringComparer.OrdinalIgnoreCase);
    private const int ReportedDriversMax = 500;

    private static async Task HandleDriverLoadAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var imageLoaded = Field(fields, "ImageLoaded");
        if (string.IsNullOrEmpty(imageLoaded)) return;
        if (imageLoaded.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase)) return;
        if (imageLoaded.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return;
        if (imageLoaded.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return; // system-loaded paged/nonpaged device drivers — baseline

        lock (ReportedDrivers)
        {
            if (ReportedDrivers.Contains(imageLoaded)) return;
            ReportedDrivers.Add(imageLoaded);
            if (ReportedDrivers.Count > ReportedDriversMax) ReportedDrivers.Clear(); // simple bound
        }

        var report = new
        {
            label = cfg.Label,
            rule = "driver_load",
            severity = "medium",
            time = DateTime.UtcNow.ToString("o"),
            image_loaded = imageLoaded,
            hashes = Field(fields, "Hashes"),
            signed = Field(fields, "Signed"),
            signature = Field(fields, "Signature"),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"driver alert failed: {ex.Message}"); }
    }

    // Event 13 (RegistryEvent SetValue) — audit gap closed: no registry monitoring existed, so
    // persistence (Run keys, service start, IFEO debugger hijack, Winlogon) and Defender-tamper
    // were invisible. HIGH, report-only (registry writes are too ambiguous for autonomous
    // action — a legit software installer writing a Run key must not kill+isolate). The Sysmon
    // config include-list keeps volume bounded to the persistence-relevant keys.
    private static readonly string[] PersistenceRegistryPaths =
    {
        @"CurrentVersion\Run",
        @"CurrentVersion\RunOnce",
        @"CurrentVersion\Policies\Explorer\Run",
        @"CurrentVersion\RunServices",
        @"CurrentVersion\Winlogon",
        @"Image File Execution Options",
        @"CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        @"Microsoft\Windows Defender",
    };
    private static readonly ConcurrentDictionary<string, DateTime> RegistryAlerted = new();
    private const int RegistryAlertMaxEntries = 1000;
    private static readonly TimeSpan RegistryAlertDedupTtl = TimeSpan.FromHours(1);

    private static async Task HandleRegistryEventAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var targetObject = Field(fields, "TargetObject");
        if (string.IsNullOrEmpty(targetObject)) return;
        if (!PersistenceRegistryPaths.Any(p => targetObject.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)) return;

        var image = Field(fields, "Image");
        if (IsOwnToolingContext(image, Field(fields, "ProcessGuid"), Field(fields, "User"))) return; // agent's own config writes never page
        // Known-benign updater self-registration (found live 2026-08-14 on the test VM AND the test device):
        // Microsoft Edge Update's self-update flow writes its Run keys during every update —
        // MicrosoftEdgeUpdateSetup_X86_<ver>.exe stages a copy under
        // %ProgramFiles(x86)%\Microsoft\Temp\EU<hex>.tmp\MicrosoftEdgeUpdate.exe and both the
        // staging copy and the setup exe legitimately touch CurrentVersion\Run. The temp path
        // looks exactly like a malware staging drop, so this is a standing false-positive class
        // (same doctrine as the NetworkQuietImages skip: legitimate vendor automation is
        // baseline, never a finding).
        var imagePath = image ?? "";
        if (imagePath.IndexOf("MicrosoftEdgeUpdate", StringComparison.OrdinalIgnoreCase) >= 0
            || imagePath.IndexOf(@"EdgeUpdate\Install\", StringComparison.OrdinalIgnoreCase) >= 0) return;
        var imageBase = BaseName(image);
        if (NetworkQuietImages.Contains(imageBase)) return; // svchost/service-host registry writes are routine

        var dedupKey = $"{imageBase}|{targetObject}";
        if (RegistryAlerted.TryGetValue(dedupKey, out var last) && DateTime.UtcNow - last < RegistryAlertDedupTtl) return;
        RegistryAlerted[dedupKey] = DateTime.UtcNow;
        if (RegistryAlerted.Count > RegistryAlertMaxEntries) RegistryAlerted.Clear();

        var report = new
        {
            label = cfg.Label,
            rule = "registry_persistence",
            severity = "high",
            time = DateTime.UtcNow.ToString("o"),
            image,
            target_object = targetObject,
            new_value = Field(fields, "NewValue"),
            lineage_context = BuildLineageContext(Field(fields, "ProcessGuid")),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"registry alert failed: {ex.Message}"); }
    }

    // Event 23 (FileDelete) — feeds the SAME attribution buffer as Event 11: encrypt-then-delete-
    // original ransomware shows up here, and RansomwareGuard's "deleted" canary trigger needs this
    // to know WHO deleted it. Never alerts on its own (deletes are routine).
    private static void HandleFileDelete(Dictionary<string, string> fields)
    {
        var targetFilename = Field(fields, "TargetFilename");
        if (string.IsNullOrEmpty(targetFilename)) return;
        var image = Field(fields, "Image");
        var pid = int.TryParse(Field(fields, "ProcessId"), out var p) ? p : 0;
        var processGuid = Field(fields, "ProcessGuid");
        RecentFileTouches[targetFilename.ToLowerInvariant()] = (image, pid, processGuid, DateTime.UtcNow);
        if (RecentFileTouches.Count > FileTouchCacheMaxEntries) EvictStaleFileTouches(force: true);
    }

    // Event 25 (ProcessTamper) — Sysmon fires this when one process tampers with another's
    // memory/threads (the hollowing/injection sibling of Event 8, and the signal that would-be
    // malware is interfering with protected processes — incl. attempts on this agent). HIGH,
    // report-only: system components and AV engines legitimately touch other processes, so this
    // can't be autonomous. The Sysmon config excludes nothing here (onmatch="exclude" with no
    // rules = capture all).
    private static async Task HandleProcessTamperAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var image = Field(fields, "Image");
        if (IsOwnToolingContext(image, Field(fields, "ProcessGuid"), Field(fields, "User"))) return;
        if (NetworkQuietImages.Contains(BaseName(image))) return;

        var report = new
        {
            label = cfg.Label,
            rule = "process_tamper",
            severity = "high",
            time = DateTime.UtcNow.ToString("o"),
            image,
            target_image = Field(fields, "TargetImage"),
            target_process_guid = Field(fields, "TargetProcessGuid"),
            lineage_context = BuildLineageContext(Field(fields, "ProcessGuid")),
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"process tamper alert failed: {ex.Message}"); }
    }

    // Phase 4/5 — Sysmon Event 5 (ProcessTerminate): victim-side termination signals. Event 5's
    // schema has NO killer attribution (Sysmon emits the victim's ProcessGuid/PID/Image, never the
    // terminating process), so this handler is deliberately two-sided:
    //   * agent_process_killed (HIGH, report-only) — our OWN sensitive tooling (xray/sshd/
    //     SentinelRemoteAssist/...) was terminated. Mirrors shadow_copy_attack doctrine: the damage
    //     is done, the operator must see it immediately, and there is no reliable autonomous action
    //     from a victim-side event alone (no killer PID to act on). Suppressed by the normal per-rule
    //     EDR 30-min dedup window; accepted false positives (remote-update cutover kills, xray
    //     self-heal restart) are cheap compared to missing a real kill.
    //   * agent_process_killed_info (LOW) — a process that recently performed a credential-dump-
    //     shaped LSASS access (AgentKillerCandidates, populated by HandleProcessAccessAsync) has now
    //     terminated. The Event 5 victim's own ProcessGuid matches the candidate entry — the classic
    //     "dumper finished and exited" pattern — and pairs the lsass_access alert with its exit.
    //
    // CASCADE SUPPRESSION: killing one own process (e.g. xray.exe) cascades into Sentinel.exe
    // crashing/restarting dozens of times. Without suppression this floods the feed with 100+
    // Sentinel.exe alerts that bury the real root cause (xray.exe). A 30s per-image cooldown
    // ensures only the FIRST kill of each own-tooling image fires an alert; the cascade events
    // are silently dropped.
    private static readonly ConcurrentDictionary<string, DateTime> OwnKillCooldown = new();
    private static readonly TimeSpan OwnKillCooldownWindow = TimeSpan.FromSeconds(30);

    private static async Task HandleProcessTerminateAsync(WatchConfig cfg, Dictionary<string, string> fields)
    {
        var image = Field(fields, "Image");
        var processGuid = Field(fields, "ProcessGuid");
        var processId = Field(fields, "ProcessId");

        // Side A — our own sensitive tooling was terminated.
        if (IsOwnTooling(image) && KillSensitiveOwnToolingNames.Contains(BaseName(image)))
        {
            // Watchdog-check suppression: the SentinelRemoteAssist-Watchdog scheduled task spawns
            // `Sentinel.exe --watchdog-check` every 60s; it exits immediately after verifying the
            // main agent is alive. Sysmon Event 5 lacks CommandLine, so we match the ProcessGuid
            // against the set tagged by HandleProcessTerminateAsync (Event 1 carries CommandLine).
            if (!string.IsNullOrEmpty(processGuid) && WatchdogCheckGuids.TryRemove(processGuid, out _))
                return; // watchdog health check — not a real kill

            // Cascade suppression: skip if this exact image was alerted on within the cooldown window.
            var cooldownKey = BaseName(image);
            if (OwnKillCooldown.TryGetValue(cooldownKey, out var lastAlert) &&
                DateTime.UtcNow - lastAlert < OwnKillCooldownWindow)
            {
                return; // cascade — suppress
            }
            OwnKillCooldown[cooldownKey] = DateTime.UtcNow;
            if (OwnKillCooldown.Count > 100) OwnKillCooldown.Clear(); // simple bound

            var report = new
            {
                label = cfg.Label,
                rule = "agent_process_killed",
                severity = "high",
                time = DateTime.UtcNow.ToString("o"),
                image,
                process_guid = processGuid,
                process_id = processId,
                // NOTE: Event 5 has no killer field — do not invent one; the killer-candidate
                // buffer (agent_process_killed_info) + operator judgement is the attribution path.
                lineage_context = BuildLineageContext(processGuid),
                raw_xml = "",
            };
            try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
            catch (Exception ex) { LogLine($"agent process killed alert failed: {ex.Message}"); }
            return;
        }

        // Side B — a credential-dump candidate terminated. TryRemove so a candidate correlates at
        // most once (the process no longer exists; a lingering entry would be stale forever).
        if (!string.IsNullOrEmpty(processGuid) &&
            AgentKillerCandidates.TryRemove(processGuid, out _))
        {
            var report = new
            {
                label = cfg.Label,
                rule = "agent_process_killed_info",
                severity = "low",
                time = DateTime.UtcNow.ToString("o"),
                image,
                process_guid = processGuid,
                process_id = processId,
                lineage_context = BuildLineageContext(processGuid),
                raw_xml = "",
            };
            try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
            catch (Exception ex) { LogLine($"agent process killed info alert failed: {ex.Message}"); }
        }
    }

    private static async Task HandleCreateRemoteThreadAsync(WatchConfig cfg, EventRecord record,
        Dictionary<string, string> fields, string rawXml)
    {
        // Hollowing-adjacent, deliberately report-only/MEDIUM — Sysmon has no single "hollowing
        // detected" event; CreateRemoteThread alone is a noisy correlative approximation (browsers'
        // own multi-process IPC, RGB/OEM utilities, and debuggers all trigger it routinely). Never
        // wired to autonomous action — see the EDR feature plan's autonomous-action policy table.
        var sourceImageForFilter = Field(fields, "SourceImage");
        var sourceProcessGuid = Field(fields, "SourceProcessGuid");
        if (IsOwnToolingLineage(sourceImageForFilter, sourceProcessGuid)) return; // see IsOwnToolingLineage's comment
        // Core Windows system processes (csrss, dwm, winlogon, svchost, smss) legitimately use
        // CreateRemoteThread — suppressing the flood of MEDIUM noise these generate on every boot
        // and logon cycle (found live 2026-07-23: hundreds of csrss/dwm/winlogon CRT events).
        if (CreateRemoteThreadAllowedSources.Contains(BaseName(sourceImageForFilter))) return;

        var report = new
        {
            label = cfg.Label,
            rule = "create_remote_thread",
            severity = "medium",
            time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            source_image = Field(fields, "SourceImage"),
            source_process_guid = sourceProcessGuid,
            target_image = Field(fields, "TargetImage"),
            target_process_guid = Field(fields, "TargetProcessGuid"),
            // Phase 4 — the source process's own lineage (its parent chain + any known network
            // connections) is often the single most useful piece of context for judging whether a
            // CreateRemoteThread hit is routine (browser IPC, RGB/OEM utilities, debuggers) or worth
            // a closer look — see BuildLineageContext's doc comment.
            lineage_context = BuildLineageContext(sourceProcessGuid),
            raw_xml = rawXml,
        };
        await SendOrQueueAsync(cfg, report).ConfigureAwait(false);
    }

    private static async Task HandleProcessAccessAsync(WatchConfig cfg, EventRecord record,
        Dictionary<string, string> fields, string rawXml)
    {
        var targetImage = Field(fields, "TargetImage");
        if (BaseName(targetImage) != "lsass.exe") return; // only care about LSASS access

        var grantedAccess = Field(fields, "GrantedAccess");
        if (!LsassBadAccessMasks.Contains(grantedAccess)) return;

        var sourceImage = Field(fields, "SourceImage");
        if (LsassAllowedAccessors.Contains(BaseName(sourceImage))) return;
        var sourceProcessGuid = Field(fields, "SourceProcessGuid");
        if (IsOwnToolingLineage(sourceImage, sourceProcessGuid)) return; // see IsOwnToolingLineage's comment

        // Phase 4/5 — this process just performed a credential-dump-shaped LSASS access, so it's a
        // candidate killer: remember it so a subsequent Event 5 termination of our own tooling can
        // be attributed back to it (Event 5 has no killer field of its own). TTL/eviction handled
        // by EvictStaleAgentKillerCandidates.
        if (!string.IsNullOrEmpty(sourceProcessGuid))
            AgentKillerCandidates[sourceProcessGuid] = DateTime.UtcNow;

        var report = new
        {
            label = cfg.Label,
            rule = "lsass_access",
            severity = "high",
            time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            source_image = sourceImage,
            source_process_guid = sourceProcessGuid,
            granted_access = grantedAccess,
            // Phase 4 — e.g. "which process spawned the tool that just opened LSASS with a
            // credential-dump-shaped access mask" is exactly the forensic question an operator asks
            // first on this alert.
            lineage_context = BuildLineageContext(sourceProcessGuid),
            raw_xml = rawXml,
        };
        await SendOrQueueAsync(cfg, report).ConfigureAwait(false);
    }

    private static bool ContainsEncodedFlag(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return false;
        if (!commandLine.Contains("powershell", StringComparison.OrdinalIgnoreCase) &&
            !commandLine.Contains("pwsh", StringComparison.OrdinalIgnoreCase)) return false;
        return commandLine.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
               commandLine.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase);
    }

    private static string BaseName(string path) =>
        string.IsNullOrEmpty(path) ? "" : Path.GetFileName(path);

    // Known-benign SentinelRemoteAssist tooling — see the call sites' comments. Path.GetFileName
    // (via BaseName) handles Sysmon's occasional mixed \ and / separators fine on Windows.
    // "Sentinel.exe"/"Sentinel-Admin.exe" are the 3.0.0+ process names (AssemblyName rename, the
    // ProgramData folder itself is unchanged); "SentinelRemoteAssist.exe" kept for any box still
    // running a pre-3.0.0 install.
    private static readonly HashSet<string> OwnToolingNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "sshd-session.exe", "sshd.exe", "ssh-agent.exe",
        "SentinelRemoteAssist.exe", "Sentinel.exe", "Sentinel-Admin.exe", "xray.exe",
    };
    private static bool IsOwnTooling(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        if (!imagePath.Contains("SentinelRemoteAssist", StringComparison.OrdinalIgnoreCase)) return false;
        return OwnToolingNames.Contains(BaseName(imagePath));
    }

    // Phase 4/5 — a STRICTER subset of OwnToolingNames: the processes whose sudden termination is
    // an operator-facing "your own tooling was killed" event. `sshd-session.exe` is deliberately
    // NOT here — it exits on EVERY Hop-2 session close and would fire a catastrophic false-positive
    // flood on ordinary daily use; the rest of the agent can't be killed by legitimate session
    // lifecycle. Every name here is only ever matched together with a `SentinelRemoteAssist` path
    // prefix via IsOwnTooling, so an unrelated same-named binary can't trip this.
    private static readonly HashSet<string> KillSensitiveOwnToolingNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "sshd.exe", "ssh-agent.exe", "xray.exe",
        "SentinelRemoteAssist.exe", "Sentinel.exe", "Sentinel-Admin.exe",
    };

    // Phase 4/5 — "who plausibly killed our tooling" correlation buffer. Event 5 has NO killer
    // attribution (Sysmon emits the victim's PID/ProcessGuid/Image but never the terminating
    // process), so the killer side is reconstructed from the most recent suspicious LSASS-access
    // event that just fired: any process that opened LSASS with a credential-dump access mask is
    // a candidate, and when our own tooling is terminated shortly afterward the pairing is a
    // strong signal of credential-theft tooling destroying evidence. Keyed by the candidate's
    // sourceProcessGuid, TTL 15 min, capped like ProcessCache.
    private static readonly ConcurrentDictionary<string, DateTime> AgentKillerCandidates = new();
    private const int AgentKillerCandidatesMaxEntries = 2000;
    private static readonly TimeSpan AgentKillerCandidatesTtl = TimeSpan.FromMinutes(15);

    private static readonly HashSet<string> GenericShellWrapperNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe",
    };

    // Sensor health — Sysmon64/WinDefend service running state via `sc.exe query` (plaintext
    // output, the same external-exe idiom as LocalIsolation.cs's netsh calls — no new package
    // references, no PowerShell dependency).
    private static bool ServiceState(string serviceName)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"query {serviceName}")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return false;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task SendHealthReportAsync(WatchConfig cfg, string rule, string reason)
    {
        var report = new
        {
            label = cfg.Label,
            rule,
            severity = "high",
            reason,
            time = DateTime.UtcNow.ToString("o"),
            image = "",
            raw_xml = "",
        };
        try { await SendOrQueueAsync(cfg, report).ConfigureAwait(false); }
        catch (Exception ex) { LogLine($"{rule} report failed: {ex.Message}"); }
    }

    // Returns a human-readable reason string when the process image + command line match a
    // known shadow-copy-deletion / boot-recovery-disabling signature, else null. Case-insensitive
    // substring matching on the real (non-base64-encoded) command line — the encoded-PS path is
    // NOT evaluable here (base64 hides the text) and is intentionally left to the operator: the
    // shadow-copy rule is about the canonical vssadmin.exe/wbadmin.exe/diskshadow.exe/bcdedit.exe
    // binaries whose command lines are plaintext, which is how the real-world ransomware kill
    // chain behaves.
    private static string? ShadowCopyDeletionSignature(string imageBase, string commandLine)
    {
        var cl = commandLine ?? "";
        switch (imageBase)
        {
            case "vssadmin.exe":
                if (cl.Contains("delete", StringComparison.OrdinalIgnoreCase) &&
                    cl.Contains("shadows", StringComparison.OrdinalIgnoreCase))
                    return "vssadmin delete shadows — attacker removing restore points";
                break;
            case "wbadmin.exe":
                if (cl.Contains("delete", StringComparison.OrdinalIgnoreCase) &&
                    (cl.Contains("systemstatebackup", StringComparison.OrdinalIgnoreCase) ||
                     cl.Contains("backup", StringComparison.OrdinalIgnoreCase)))
                    return "wbadmin delete backup — attacker removing recovery backups";
                break;
            case "diskshadow.exe":
                if (cl.Contains("delete", StringComparison.OrdinalIgnoreCase) &&
                    cl.Contains("shadows", StringComparison.OrdinalIgnoreCase))
                    return "diskshadow delete shadows — attacker removing restore points";
                break;
            case "bcdedit.exe":
                if (cl.Contains("recoveryenabled", StringComparison.OrdinalIgnoreCase) &&
                    cl.Contains("no", StringComparison.OrdinalIgnoreCase))
                    return "bcdedit recoveryenabled no — attacker disabling boot recovery";
                break;
            case "wmic.exe":
                if (cl.Contains("shadowcopy", StringComparison.OrdinalIgnoreCase) &&
                    cl.Contains("delete", StringComparison.OrdinalIgnoreCase))
                    return "wmic shadowcopy delete — attacker removing restore points";
                break;
        }
        return null;
    }

    // Found live 2026-07-20: on a VM where OpenSSH's default exec shell is PowerShell, every
    // Hop-2 call (session_powershell/fleet_powershell, BitLocker/AppLocker/etc.'s one-shot
    // scripts) actually spawns as sshd-session.exe -> powershell.exe -c "powershell ...
    // -EncodedCommand ..." — one extra hop past what IsOwnTooling's direct-image check sees,
    // so it never recognized this shape and paged Signal on every single legitimate call (e.g.
    // BitLocker's 15-min status poller, unbounded, forever).
    //
    // 2026-08-02 (multi-level walk): STILL not enough — on a box whose OpenSSH default exec
    // shell is cmd.exe (the test VM), the shape is sshd-session.exe -> cmd.exe -> powershell
    // -EncodedCommand: the encoded PowerShell's DIRECT parent is cmd.exe, and cmd.exe was not in
    // the old one-level walk's GenericPowerShellHostNames, so every dashboard action paged
    // Signal again. The walk is now a bounded loop up the in-memory lineage buffer (ProcessCache,
    // TTL'd — every hop is created milliseconds before the event being guarded, so never stale
    // in practice) through any generic shell wrapper (cmd.exe/powershell.exe/pwsh.exe), stopping
    // at the first NON-shell ancestor: if that terminus is own tooling (sshd-session.exe),
    // suppress; if it's anything else (explorer.exe, a service host, a real attacker's process),
    // alert normally. Bounded to 6 hops so a pathological cache loop can't spin forever. A real
    // attacker's PowerShell spawned by a non-own-tooling parent still alerts normally.
    // The EPHEMERAL Remote Assist support account. Everything the bastion drives over Hop-2 runs as
    // this user and nothing else on the box ever does — it's created fresh per session with a random
    // password and removed on close (same account RansomwareGuard.cs already excludes by name).
    private static readonly HashSet<string> OwnServiceAccountNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "sentinel-support",
    };

    /// <summary>Sysmon's User field is DOMAIN\name (or "-" when unknown); match on the name half.</summary>
    private static bool IsOwnServiceAccount(string user)
    {
        if (string.IsNullOrEmpty(user) || user == "-") return false;
        var slash = user.LastIndexOf('\\');
        return OwnServiceAccountNames.Contains(slash >= 0 ? user[(slash + 1)..] : user);
    }

    /// <summary>Full "is this our own tooling?" test — the identity check FIRST, then the lineage walk.
    ///
    /// The lineage walk alone is not sufficient and cannot be made sufficient. Confirmed live
    /// 2026-08-03 on the test VM: the bastion's own 60s Sentry drain paged as an
    /// `encoded-powershell-command` finding because Sysmon emitted <c>ParentImage=-</c> and
    /// <c>ParentProcessGuid={00000000-...}</c> for the sshd-spawned shell — the parent was genuinely
    /// unresolvable, so IsOwnToolingLineage bailed at hop 0 and every subsequent hop inherited the
    /// dead end (our own ProcessCache missed it too: the report carried lineage_context=null).
    /// No amount of widening the traversal set fixes an absent parent.
    ///
    /// The user identity does not depend on parent resolution at all, and unlike a magic marker in
    /// the command line it is an OS-enforced security principal rather than a string an attacker can
    /// simply type. Reaching it requires already holding local admin — at which point the attacker's
    /// cheaper move is disabling Sysmon, which fires sysmon_sensor_down (a LEARN_CRITICAL rule that
    /// can never be muted).
    ///
    /// ⚠️ Use this ONLY where our own automation legitimately produces the behaviour being flagged —
    /// currently process-lineage (Event 1) and persistence-registry writes (Event 13). The
    /// lsass_access, create_remote_thread and unusual_outbound_connection handlers deliberately keep
    /// the bare lineage check and MUST NOT be "made consistent" with this one: our tooling never
    /// dumps LSASS, never injects threads, and does its own egress as SYSTEM under our signed exe
    /// (already covered by the walk). Adding an account-based exemption to those three would hand
    /// anyone who reaches the sentinel-support account a silent credential-theft / injection / exfil path —
    /// turning a false-positive fix into a real detection hole.</summary>
    private static bool IsOwnToolingContext(string directImage, string directProcessGuid, string user)
        => IsOwnServiceAccount(user) || IsOwnToolingLineage(directImage, directProcessGuid);

    private static bool IsOwnToolingLineage(string directImage, string directProcessGuid)
    {
        var image = directImage;
        var guid = directProcessGuid;
        for (var hop = 0; hop < 6; hop++)
        {
            if (IsOwnTooling(image)) return true;
            if (!GenericShellWrapperNames.Contains(BaseName(image))) return false;
            if (string.IsNullOrEmpty(guid)) return false;
            if (!ProcessCache.TryGetValue(guid, out var ctx)) return false;
            image = ctx.ParentImage;
            guid = ctx.ParentProcessGuid;
        }
        return false;
    }

    private static string Field(Dictionary<string, string> fields, string name) =>
        fields.TryGetValue(name, out var v) ? v : "";

    /// <summary>Phase 4 — surfaces the Phase-1 lineage/network correlation buffer as alert context.
    /// Returns null when the ProcessGuid was never seen (Sysmon unhealthy, or the process predates
    /// this watcher's own startup/TTL window) — callers attach it opportunistically, never require
    /// it. Deliberately a plain anonymous object (not a named type) since this only ever flows
    /// straight into a report's `lineage_context` field for JSON serialization.</summary>
    internal static object? BuildLineageContext(string processGuid)
    {
        if (string.IsNullOrEmpty(processGuid)) return null;
        if (!ProcessCache.TryGetValue(processGuid, out var ctx)) return null;
        List<string> conns;
        lock (ctx.NetworkConnections) { conns = ctx.NetworkConnections.ToList(); }
        return new
        {
            pid = ctx.Pid,
            image = ctx.Image,
            command_line = ctx.CommandLine,
            parent_image = ctx.ParentImage,
            parent_command_line = ctx.ParentCommandLine,
            network_connections = conns,
            seen_utc = ctx.SeenUtc.ToString("o"),
        };
    }

    /// <summary>Same as <see cref="BuildLineageContext"/> but for a PID-only caller (HollowingWatcher.cs
    /// — Process.GetProcesses() has no ProcessGuid) via the reverse index populated in
    /// HandleProcessCreateAsync.</summary>
    internal static object? BuildLineageContextByPid(int pid)
    {
        if (pid <= 0) return null;
        if (!PidToProcessGuid.TryGetValue(pid, out var entry)) return null;
        if (DateTime.UtcNow - entry.SeenUtc > ProcessCacheTtl) return null;
        return BuildLineageContext(entry.ProcessGuid);
    }

    private static void EvictStalePidMap(bool force = false)
    {
        var cutoff = DateTime.UtcNow - ProcessCacheTtl;
        foreach (var kv in PidToProcessGuid)
        {
            if (kv.Value.SeenUtc < cutoff) PidToProcessGuid.TryRemove(kv.Key, out _);
        }
        if (force && PidToProcessGuid.Count > PidMapMaxEntries)
        {
            foreach (var kv in PidToProcessGuid.OrderBy(k => k.Value.SeenUtc)
                         .Take(PidToProcessGuid.Count - PidMapMaxEntries))
            {
                PidToProcessGuid.TryRemove(kv.Key, out _);
            }
        }
    }

    private static void EvictStaleProcessContexts(bool force = false)
    {
        var cutoff = DateTime.UtcNow - ProcessCacheTtl;
        foreach (var kv in ProcessCache)
        {
            if (kv.Value.SeenUtc < cutoff) ProcessCache.TryRemove(kv.Key, out _);
        }
        if (force && ProcessCache.Count > ProcessCacheMaxEntries)
        {
            // Hard cap fallback — drop the oldest entries beyond the TTL sweep above.
            foreach (var kv in ProcessCache.OrderBy(k => k.Value.SeenUtc)
                         .Take(ProcessCache.Count - ProcessCacheMaxEntries))
            {
                ProcessCache.TryRemove(kv.Key, out _);
            }
        }
    }

    private static void EvictStaleAgentKillerCandidates(bool force = false)
    {
        var cutoff = DateTime.UtcNow - AgentKillerCandidatesTtl;
        foreach (var kv in AgentKillerCandidates)
        {
            if (kv.Value < cutoff) AgentKillerCandidates.TryRemove(kv.Key, out _);
        }
        if (force && AgentKillerCandidates.Count > AgentKillerCandidatesMaxEntries)
        {
            foreach (var kv in AgentKillerCandidates.OrderBy(k => k.Value)
                         .Take(AgentKillerCandidates.Count - AgentKillerCandidatesMaxEntries))
            {
                AgentKillerCandidates.TryRemove(kv.Key, out _);
            }
        }
    }

    private static void EvictStaleWatchdogCheckGuids()
    {
        var cutoff = DateTime.UtcNow - WatchdogCheckGuidsTtl;
        foreach (var kv in WatchdogCheckGuids)
        {
            if (kv.Value < cutoff) WatchdogCheckGuids.TryRemove(kv.Key, out _);
        }
        // Watchdog processes exit within seconds — if we somehow have >max without stale entries,
        // clear the oldest excess.
        if (WatchdogCheckGuids.Count > WatchdogCheckGuidsMaxEntries)
        {
            foreach (var kv in WatchdogCheckGuids.OrderBy(k => k.Value)
                         .Take(WatchdogCheckGuids.Count - WatchdogCheckGuidsMaxEntries))
            {
                WatchdogCheckGuids.TryRemove(kv.Key, out _);
            }
        }
    }

    private static Dictionary<string, string> ParseDataFields(string rawXml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(rawXml)) return result;
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(rawXml);
            var nodes = doc.GetElementsByTagName("Data");
            foreach (XmlNode node in nodes)
            {
                var name = node.Attributes?["Name"]?.Value;
                if (!string.IsNullOrEmpty(name))
                {
                    result[name] = node.InnerText ?? "";
                }
            }
        }
        catch
        {
            // Malformed/unexpected schema — caller falls back to raw_xml in the report payload.
        }
        return result;
    }

    /// <summary>Shared by RansomwareGuard.cs too — same report/outbox/retry pipeline for canary
    /// and mass-modification findings as every Sysmon-driven rule above (including the local
    /// outbox persistence that IS this process's connectivity-independent audit trail — see
    /// RansomwareGuard's doc comment on why a separate audit log wasn't needed).</summary>
    internal static async Task SendOrQueueAsync(WatchConfig cfg, object report)
    {
        var ok = await TryReportAsync(cfg, report).ConfigureAwait(false);
        if (!ok) QueueToOutbox(report);
    }

    private static async Task<bool> TryReportAsync(WatchConfig cfg, object report)
    {
        try
        {
            var json = JsonSerializer.Serialize(report);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var req = new HttpRequestMessage(HttpMethod.Post,
                $"http://127.0.0.1:{cfg.LocalPort}/api/edr/report")
            {
                Content = content,
            };
            req.Headers.Add("X-Edr-Token", cfg.Token);
            using var resp = await Http.SendAsync(req).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                LogLine("reported EDR event to bastion");
                return true;
            }
            LogLine($"report POST failed: HTTP {(int)resp.StatusCode}");
            return false;
        }
        catch (Exception ex)
        {
            LogLine($"report POST error (tunnel likely down): {ex.Message}");
            return false;
        }
    }

    // Found live 2026-07-22: a bastion-side report_token/on-device endpoint-config.json mismatch
    // (root cause on this box was almost certainly a QEMU/VM snapshot revert after a later
    // re-provision — see EdrWatcher.cs's report_token doc) sent every single report POST into a
    // permanent 403 loop for DAYS, and this outbox has no cap — it grew to several hundred files
    // over 2+ days before anyone noticed, all for events nobody could ever see (dashboard/Signal
    // alerting is server-side, entirely downstream of a successful POST). Cap both by count and by
    // age so a persistently-broken token can never turn this into unbounded local disk growth —
    // pruning happens before every enqueue, oldest-first (filenames are already
    // yyyyMMddHHmmssfff-prefixed, so a plain ordinal sort IS chronological order).
    private const int MaxOutboxFiles = 2000;
    private static readonly TimeSpan MaxOutboxAge = TimeSpan.FromDays(14);

    private static void QueueToOutbox(object report)
    {
        try
        {
            Directory.CreateDirectory(OutboxDir);
            PruneOutbox();
            var fname = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.json";
            File.WriteAllText(Path.Combine(OutboxDir, fname), JsonSerializer.Serialize(report));
        }
        catch (Exception ex)
        {
            LogLine($"could not queue to outbox: {ex.Message}");
        }
    }

    private static void PruneOutbox()
    {
        try
        {
            var files = Directory.GetFiles(OutboxDir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList();
            var cutoff = DateTime.UtcNow - MaxOutboxAge;
            var prunedByAge = 0;
            foreach (var f in files.ToList())
            {
                if (File.GetLastWriteTimeUtc(f) < cutoff)
                {
                    try { File.Delete(f); prunedByAge++; } catch { /* best-effort */ }
                    files.Remove(f);
                }
            }
            // Reserve room for the new file about to be written right after this call returns.
            var excess = files.Count - (MaxOutboxFiles - 1);
            var prunedByCount = 0;
            if (excess > 0)
            {
                foreach (var f in files.Take(excess))
                {
                    try { File.Delete(f); prunedByCount++; } catch { /* best-effort */ }
                }
            }
            if (prunedByAge > 0 || prunedByCount > 0)
            {
                LogLine($"outbox pruned: {prunedByAge} by age (>{MaxOutboxAge.TotalDays:F0}d), {prunedByCount} by count (cap {MaxOutboxFiles})");
            }
        }
        catch (Exception ex)
        {
            LogLine($"outbox prune failed: {ex.Message}");
        }
    }

    private static async Task FlushOutboxAsync(WatchConfig cfg)
    {
        if (!Directory.Exists(OutboxDir)) return;
        foreach (var file in Directory.GetFiles(OutboxDir, "*.json").OrderBy(f => f))
        {
            object? report;
            try
            {
                var json = File.ReadAllText(file);
                report = JsonSerializer.Deserialize<Dictionary<string, object?>>(json);
                if (report is null) { File.Delete(file); continue; }
            }
            catch
            {
                try { File.Delete(file); } catch { /* best-effort */ }
                continue;
            }

            var ok = await TryReportAsync(cfg, report).ConfigureAwait(false);
            if (ok)
            {
                try { File.Delete(file); } catch { /* best-effort */ }
            }
            else
            {
                break; // tunnel still down — stop trying the rest of the queue this pass
            }
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
