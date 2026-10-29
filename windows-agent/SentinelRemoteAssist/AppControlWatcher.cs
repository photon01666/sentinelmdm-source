using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace SentinelRemoteAssist;

/// <summary>
/// Endpoint Application Control (WDAC default-deny) watcher — entry point for the
/// <c>--appcontrol-watch</c> mode, registered as its own SYSTEM AtStartup scheduled task by the
/// bastion-pushed provisioning script (see bastion-web.py's _APPCONTROL_PROVISION_PS1), separate
/// from SentinelRemoteAssist's own SetupRunner-managed tasks (see Config.AppControlDir's doc
/// comment for why). Tails Microsoft-Windows-CodeIntegrity/Operational for Event ID 3076
/// (audit-mode "would have blocked") and 3077 (enforced block) via the real-time
/// <see cref="EventLogWatcher"/> API (push-based, no polling), and reports each one back to the
/// bastion over the tunnel's conditional -L forward (see TunnelRunner.cs).
///
/// Field-name mapping for the 3076/3077/3089 event schema was NOT independently verified against
/// a real live event before this was written (no block event had fired yet) — the raw event XML
/// is always included in the report payload as a fallback so field-mapping issues found on the
/// real M5 run are fixable bastion-side without needing to re-trigger anything on the endpoint.
/// </summary>
internal static class AppControlWatcher
{
    private const string LogName = "Microsoft-Windows-CodeIntegrity/Operational";
    private const int AuditEventId = 3076;
    private const int EnforcedEventId = 3077;
    private const int SignerInfoEventId = 3089;

    private static string Dir => Config.AppControlDir;
    private static string ConfigPath => Path.Combine(Dir, "endpoint-config.json");
    private static string WatcherStatePath => Path.Combine(Dir, "watcher-state.json");
    private static string OutboxDir => Path.Combine(Dir, "outbox");
    private static string LogPath => Path.Combine(Dir, "logs", "watcher.log");

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private sealed record WatchConfig(bool Enabled, int LocalPort, string Token, string Label);

    public static int Run()
    {
        var cfg = LoadConfig();
        if (cfg is null || !cfg.Enabled)
        {
            LogLine("app-control not enabled for this endpoint — exiting (task will no-op until re-enabled)");
            return 0;
        }

        LogLine($"--appcontrol-watch starting (pid {Environment.ProcessId}, label {cfg.Label}, port {cfg.LocalPort})");

        try
        {
            // Catch-up pass — covers events that fired while the tunnel/watcher was down.
            CatchUpAsync(cfg).GetAwaiter().GetResult();

            // Flush anything queued from a prior run before subscribing to new events.
            FlushOutboxAsync(cfg).GetAwaiter().GetResult();

            var query = new EventLogQuery(LogName, PathType.LogName,
                $"*[System[(EventID={AuditEventId} or EventID={EnforcedEventId})]]");
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

            // Periodic outbox flush in case the tunnel was down when a report was generated.
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(2)).ConfigureAwait(false);
                    try { await FlushOutboxAsync(cfg).ConfigureAwait(false); }
                    catch (Exception ex) { LogLine($"outbox flush error: {ex.Message}"); }
                }
                // ReSharper disable once FunctionNeverReturns
            });

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
            if (!File.Exists(ConfigPath)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(ConfigPath));
            var root = doc.RootElement;
            var enabled = root.TryGetProperty("enabled", out var e) && e.ValueKind == JsonValueKind.True;
            var localPort = root.TryGetProperty("localPort", out var p) ? p.GetInt32() : 0;
            var token = root.TryGetProperty("token", out var t) ? t.GetString() ?? "" : "";
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
            // First run for this endpoint — nothing was "missed" since watching just started.
            // Record the current tip of the log as the baseline rather than replaying the log's
            // entire history (which may include years of Microsoft's own built-in
            // VerifiedAndReputableDesktopEvaluation audit noise, unrelated to our policy — seen
            // live on the reference host via the reference host's citool --list-policies output, already Enabled:Audit Mode).
            SaveLastRecordId(CurrentMaxRecordId());
            LogLine("catch-up: first run — baselined to current log tip, no backlog replay");
            return;
        }

        var query = new EventLogQuery(LogName, PathType.LogName,
            $"*[System[(EventID={AuditEventId} or EventID={EnforcedEventId}) and EventRecordID > {lastId}]]");
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
        if (eventId != AuditEventId && eventId != EnforcedEventId) return;

        string rawXml;
        try { rawXml = record.ToXml(); }
        catch { rawXml = ""; }

        var fields = ParseDataFields(rawXml);
        var filePath = ResolveDevicePath(FirstNonEmpty(fields, "File Name", "FileName", "File Path", "FilePath"));
        var sha256 = FirstNonEmpty(fields, "SHA256 Hash", "SHA256 Flat Hash", "File Hash", "Hash");
        var policyName = FirstNonEmpty(fields, "Policy Name", "PolicyName");

        // Skip audit events from policies we didn't deploy — Windows 11 ships its own built-in
        // VerifiedAndReputableDesktopEvaluation policy already in Audit Mode by default (confirmed
        // live via citool --list-policies on the reference host, the reference host) which would otherwise flood our reports
        // with unrelated Microsoft reputation-evaluation noise. Our base policy is always named
        // "SentinelAppControl-Base-<label>" by _APPCONTROL_BASELINE_PS1. If the policy-name field
        // didn't parse (schema uncertainty — see class doc comment), forward the event anyway
        // rather than silently dropping a possibly-real block on an unverified assumption.
        if (!string.IsNullOrEmpty(policyName) &&
            !policyName.Contains("SentinelAppControl", StringComparison.OrdinalIgnoreCase))
        {
            LogLine($"skipping event {eventId} from unrelated policy '{policyName}'");
            return;
        }

        // Best-effort correlation with the paired 3089 (signer info) event — same ActivityId when
        // present, else nearest 3089 within 2s after this one. Not independently verified live.
        string? publisher = null;
        try
        {
            publisher = FindSignerInfo(record);
        }
        catch (Exception ex)
        {
            LogLine($"signer-info lookup failed: {ex.Message}");
        }

        var report = new
        {
            label = cfg.Label,
            event_id = eventId,
            time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            file_path = filePath,
            sha256,
            publisher,
            policy_name = policyName,
            raw_xml = rawXml,
        };

        var ok = await TryReportAsync(cfg, report).ConfigureAwait(false);
        if (!ok)
        {
            QueueToOutbox(report);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint QueryDosDevice(string? lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    /// <summary>
    /// CodeIntegrity's "File Name" field is an NT device path (<c>\Device\HarddiskVolume3\...</c>),
    /// not a drive-letter Win32 path — confirmed live on the reference host M5: <c>Test-Path</c> in
    /// <c>_APPCONTROL_APPROVE_PS1</c> can't resolve it, so Approve failed with
    /// "file no longer present" even though the file was right there. Reported to bastion already
    /// resolved so both the WebUI display and the Approve flow's file-identity check work.
    /// Falls back to the raw device path (rather than throwing) if no drive letter matches, so a
    /// report is never dropped just because this lookup failed.
    /// </summary>
    private static string ResolveDevicePath(string path)
    {
        if (string.IsNullOrEmpty(path) || !path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }
        try
        {
            for (var letter = 'A'; letter <= 'Z'; letter++)
            {
                var drive = $"{letter}:";
                var sb = new StringBuilder(260);
                if (QueryDosDevice(drive, sb, sb.Capacity) == 0) continue;
                var devicePath = sb.ToString();
                if (path.StartsWith(devicePath, StringComparison.OrdinalIgnoreCase))
                {
                    return drive + path.Substring(devicePath.Length);
                }
            }
        }
        catch (Exception ex)
        {
            LogLine($"device-path resolve failed for '{path}': {ex.Message}");
        }
        return path;
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

    private static string? FirstNonEmpty(Dictionary<string, string> fields, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (fields.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v)) return v;
        }
        return null;
    }

    private static string? FindSignerInfo(EventRecord source)
    {
        if (source.TimeCreated is null) return null;
        var start = source.TimeCreated.Value;
        var end = start.AddSeconds(2);
        var startStr = start.ToUniversalTime().ToString("o");
        var endStr = end.ToUniversalTime().ToString("o");
        var query = new EventLogQuery(LogName, PathType.LogName,
            $"*[System[(EventID={SignerInfoEventId}) and TimeCreated[@SystemTime>='{startStr}' and @SystemTime<='{endStr}']]]");
        using var reader = new EventLogReader(query);
        if (reader.ReadEvent() is not { } rec) return null;
        using (rec)
        {
            try
            {
                var xml = rec.ToXml();
                var fields = ParseDataFields(xml);
                return FirstNonEmpty(fields, "Signer", "PublisherName", "Publisher");
            }
            catch
            {
                return null;
            }
        }
    }

    private static async Task<bool> TryReportAsync(WatchConfig cfg, object report)
    {
        try
        {
            var json = JsonSerializer.Serialize(report);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var req = new HttpRequestMessage(HttpMethod.Post,
                $"http://127.0.0.1:{cfg.LocalPort}/api/appcontrol/report")
            {
                Content = content,
            };
            req.Headers.Add("X-AppControl-Token", cfg.Token);
            using var resp = await Http.SendAsync(req).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                LogLine("reported blocked-event to bastion");
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

    private static void QueueToOutbox(object report)
    {
        try
        {
            Directory.CreateDirectory(OutboxDir);
            var fname = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.json";
            File.WriteAllText(Path.Combine(OutboxDir, fname), JsonSerializer.Serialize(report));
        }
        catch (Exception ex)
        {
            LogLine($"could not queue to outbox: {ex.Message}");
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
                using var doc = JsonDocument.Parse(json);
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
                // Tunnel still down — stop trying the rest of the queue this pass.
                break;
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
