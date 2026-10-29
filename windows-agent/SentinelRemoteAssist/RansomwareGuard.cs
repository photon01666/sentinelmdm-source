using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// Anti-ransomware file tracking + canary files — Phase 3 of the EDR feature plan. Started from
/// EdrWatcher.Run() (same process/config/attribution buffer, not a separate --mode) because canary
/// and mass-modification attribution both depend structurally on EdrWatcher's Sysmon Event 11
/// (FileCreate) correlation buffer (<see cref="EdrWatcher.TryGetRecentFileTouch"/>) — without a
/// live Sysmon feed there is no reliable way to know WHICH process touched a given file at all.
///
/// Two independent detectors, per the plan's autonomous-action policy table:
    ///   - Canary files: a handful of realistically-named decoys seeded into common directories.
    ///     ANY touch (change/rename/delete) is autonomous and INSTANT — kill the attributed process
    ///     tree (if attribution succeeded) + isolate the host's network — no toggle, no threshold,
    ///     same "zero legitimate reason this is ever touched" doctrine as the honeypot's own bait
    ///     filesystem (docs/ARCHITECTURE.md §10). A 60s periodic backstop re-checks existence+content hash in
    ///     case FileSystemWatcher dropped the live event during exactly the burst that matters most
    ///     (a documented FSW limitation under extreme event volume — see the InternalBufferSize note
    ///     on Start()). Two placement tiers: user-profile folders (provisioned with the hidden
    ///     attribute — a visible "Passwords.docx" in the user's own Documents would invite a genuine
    ///     user open/delete, the one FP a zero-tolerance detector can't argue with) and machine-wide
    ///     roots (C:\Users\Public\* + a dedicated ProgramData subdir — deliberately NOT hidden there,
    ///     see MachineWideRoots).
///   - Mass file modification (the ransomware-loop fingerprint): a weighted sliding-window rate
///     heuristic across ALL watched roots (cross-directory, matching real ransomware's behavior of
///     hitting many folders near-simultaneously, not one folder in isolation). Deliberately
///     REPORT-ONLY per the user's own decision — thresholds here are unavoidably guessed constants
///     that need tuning against a real controlled-detonation test before being trusted to act
///     autonomously; promote to autonomous kill+isolate (mirroring the canary path) only after
///     that live tuning pass.
///
/// Attribution and the allowlist (OneDrive/Dropbox/Search Indexer/Defender/backup software
/// legitimately touching many files fast) apply to the mass-modification path; canary hits are
/// zero-tolerance and skip allowlist filtering entirely, same as the honeypot's bait-file doctrine.
/// If Sysmon isn't deployed/healthy, attribution silently fails (TryGetRecentFileTouch returns
/// false) — canary hits still isolate (no attribution needed for that), just can't target a kill;
/// mass-modification reports still fire, just without an attributed process in the payload.
/// </summary>
internal static class RansomwareGuard
{
    private static string LogPath => Path.Combine(Config.EdrDir, "logs", "watcher.log");
    private static string AuditLogPath => Path.Combine(Config.EdrDir, "logs", "autonomous-actions.log");

    private static readonly string[] WatchedSubdirs = { "Documents", "Desktop", "Pictures", "Downloads", "OneDrive" };
    private static readonly HashSet<string> ExcludedProfileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Public", "Default", "Default User", "All Users",
        // 2.0.5 — exclude the EPHEMERAL Remote Assist support account. `sentinel-support` is created fresh
        // per session and removed on app close, so its profile takes canaries with it. When the
        // watcher next starts, DiffAgainstPersistedState sees a batch of canaries that vanished
        // "while the watcher was down" and fires autonomous kill+isolate responses — the exact
        // false-positive storm class fixed for subst/alias drives in 2.0.2, just via a different
        // disappearing root. Found on the test VM 2026-08-03: 20 of 60 canaries were provisioned into
        // C:\Users\sentinel-support. Protecting the support account's own profile has no value either —
        // nothing of the customer's lives there.
        "sentinel-support",
    };

    // 2.0.0 — audit-gap fix (was: C:\Users only). DiscoverWatchedRoots now enumerates ALL fixed
    // drives (DriveInfo.DriveType.Fixed), not just C:. A ransomware variant targeting D:/E: data
    // drives, a second internal disk, or OneDrive-redirected folders (the Win11 default — local
    // Documents/Desktop are often empty shells that watch nothing real) used to be COMPLETELY
    // invisible. Per-drive handling:
    //   - every fixed drive: watch <drive>\Users\<profile>\{Documents,Desktop,Pictures,Downloads}
    //     (OneDrive included above — a redirected-folder setup lives under Users\<profile>\OneDrive)
    //   - the system drive (C:) additionally gets exactly the profile-dirs behavior it already had
    //     (never watch C:\ itself — Windows/system churn is the classic FSW false-positive storm)
    //   - NON-system fixed drives: watch the DRIVE ROOT too (a data drive may keep files at
    //     D:\Projects, D:\Finance, ... outside any Users tree — the actual ransomware target)
    //   - removable/network drives are still skipped on purpose: USB sticks churn in/out (FSW
    //     churn + the mass-modification detector would fire on every mount), and network shares
    //     aren't local filesystem events Sysmon/FSW can attribute anyway.
    private const string SystemDriveRoot = @"C:\";

    // The File Backup restore feature's location picker (server.js/the support service) can now target
    // ANY folder including Desktop/Documents/Pictures/Downloads — the exact roots this class
    // watches — and pushes a whole backup's worth of files via one scp -r burst straight into it.
    // That legitimate, admin-initiated write is indistinguishable from a real encryptor's fast
    // multi-file burst by rate alone, and it always lands inside a folder named "Restored-<epoch
    // seconds>" (the support service's restore_file_backup(): `f"{base_dest}\\Restored-{ts}"`) — a name
    // no real ransomware or legitimate third-party software would ever produce. Skip rate-weighting
    // entirely for anything under such a folder (not just skip the report) so a large restore never
    // pollutes the sliding window at all — a genuinely separate concurrent attack elsewhere still
    // evaluates normally. Deliberately does NOT touch canary detection (an untouched decoy file
    // living inside a restored tree — extremely unlikely given decoy names — is still a genuine hit).
    private static readonly System.Text.RegularExpressions.Regex RestoreDropFolderRe =
        new(@"(^|[\\/])Restored-\d+([\\/]|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static bool IsSentinelRestorePath(string path) =>
        !string.IsNullOrEmpty(path) && RestoreDropFolderRe.IsMatch(path);

    // Dual-purpose bait names (attractive to credential-stealers too, not just ransomware) — same
    // "realistic decoy" doctrine as the honeypot's own skins. Content plainly says what it is (see
    // ProvisionCanaries) so an innocent curious open by the actual device owner isn't alarming.
    private static readonly string[] CanaryNames =
    {
        "Passwords.docx",
        "Tax Documents 2025.pdf",
        "Family Budget.xlsx",
        "Backup - Do Not Delete.docx",
        "Photos Backup Archive.zip",
    };

    // 2.0.1 — machine-wide canary tier. The profile-dir canaries above live where the USER
    // browses, so they're provisioned with the hidden attribute (a visible "Passwords.docx" in
    // the user's own Documents invites the one FP a zero-tolerance detector can't argue with:
    // the user themselves). The machine-wide tier is the opposite problem: C:\Users\Public\*
    // and a dedicated ProgramData subdir are never browsed by anyone on a personal PC, so there
    // the canaries are deliberately NOT hidden — visible, believable business-flavored decoys.
    // Two reasons this tier exists: (1) encrypt-everything ransomware (the dominant shape)
    // encrypts ProgramData/Public just like profile docs — coverage the user-dirs-only scope
    // structurally missed; (2) the FP risk is near zero since no human interaction ever happens
    // there. Public\Documents is NOT already covered: ExcludedProfileNames skips the Public
    // profile in DiscoverWatchedRoots, so these roots are watched exactly once.
    private static readonly string[] MachineWideRoots =
    {
        @"C:\Users\Public\Documents",
        @"C:\Users\Public\Downloads",
    };

    // Single dedicated ProgramData subdir for the third machine-wide root — created by us if
    // missing; if a real, non-empty directory already exists under this name the root is skipped
    // entirely (same "a decoy must never collide with something real" doctrine as the per-root
    // name-collision check). BackupVault is deliberately business-flavored bait that matches the
    // existing "Backup - Do Not Delete" canary name — ransomware hunts backup files specifically.
    private const string MachineWideProgramDataRoot = @"C:\ProgramData\BackupVault";

    // OneDrive/Dropbox/Google Drive sync clients, Windows Search indexing, Defender scans, and
    // Windows Backup/VSS all legitimately touch many files fast — exactly the pattern that would
    // otherwise false-positive the mass-modification heuristic. NOT applied to canary hits (see
    // class doc comment — canaries are zero-tolerance, matching the honeypot's bait-file doctrine).
    private static readonly HashSet<string> AllowlistedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "onedrive.exe", "dropbox.exe", "googledrivefs.exe", "searchindexer.exe",
        "searchprotocolhost.exe", "searchfilterhost.exe", "msmpeng.exe", "nissrv.exe",
        "wbengine.exe", "vssvc.exe",
    };

    private static readonly HashSet<string> CanaryPaths = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, string> CanaryHashes = new(StringComparer.OrdinalIgnoreCase);
    private static readonly List<FileSystemWatcher> Watchers = new();

    // Persisted path->hash snapshot, survives process restarts (crash, reboot, re-enable) — see
    // Start()'s doc comment on why this exists. Deliberately a flat JSON dict, not a database: this
    // is a best-effort forensic aid, not a source of truth anything else depends on.
    private static string StatePath => Path.Combine(Config.EdrDir, "canary-state.json");

    // ── Weighted sliding-window rate heuristic (mass-modification) ─────────────────────────────
    // ⚠️ TUNE LIVE — these are starting guesses, not measured values (see class doc comment on why
    // this path stays report-only until a real controlled-detonation test on the QEMU/test VM).
    private const double RateWindowSeconds = 10;
    private const double RateThreshold = 40;
    private static readonly TimeSpan RateAlertCooldown = TimeSpan.FromMinutes(5);
    private static readonly object RateLock = new();
    private static readonly Queue<(DateTime Time, double Weight, string Path)> RateWindow = new();
    private static DateTime _lastRateAlertUtc = DateTime.MinValue;

    // ── Shutdown / post-boot guard for the mass-modification heuristic ─────────────────────────
    // Found live 2026-08-08: a defensive reboot (stale WU RebootRequired flag -> forced reboot at
    // 10:05:08Z) fired a mass_file_modification alert at 10:05:45Z — the Windows servicing churn
    // around shutdown/boot (wevtutil Defender manifest reinstall, boot-time service start, etc.)
    // legitimately touches many profile files fast, indistinguishable from a ransomware loop by
    // the rate heuristic alone. Two windows are covered: (1) GetSystemMetrics(SM_SHUTTINGDOWN) is
    // TRUE during the actual shutdown servicing phase and is visible to ANY process including this
    // session-0 SYSTEM task (unlike SystemEvents.SessionEnding, which only fires for interactive
    // sessions); (2) a startup grace period — the worst-case churn in the observed incident landed
    // within seconds of boot, before any real attacker could have started encrypting. Deliberately
    // applied ONLY to the mass-modification heuristic (report-only anyway); canary hits remain
    // zero-tolerance and evaluate unconditionally — a shutdown/boot window must never mask a canary.
    private static readonly TimeSpan MassModStartupGrace = TimeSpan.FromSeconds(120);
    private static DateTime _massModStartUtc = DateTime.MinValue;

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private const int SM_SHUTTINGDOWN = 0x2000;

    private static bool SystemShuttingDown() => GetSystemMetrics(SM_SHUTTINGDOWN) != 0;

    private static bool MassModSuppressed()
    {
        if (SystemShuttingDown()) return true;
        if (DateTime.UtcNow - _massModStartUtc < MassModStartupGrace) return true;
        return false;
    }

    // Storm guard — caps autonomous actions (canary responses) regardless of trigger source, so a
    // misfiring/looping condition can't hammer taskkill/netsh in a tight loop forever. Isolation
    // itself is already idempotent (LocalIsolation.Block() no-ops if already isolated) so the real
    // risk this guards against is wasted CPU/noise, not repeated real damage — the actual harm from
    // capping too LOW is a genuinely separate malicious process going un-killed because an earlier,
    // unrelated canary hit already spent the budget. Raised 5 -> 500 (2026-07-19, explicit user
    // call: "make it high enough it won't miss killing anything") — worst-case realistic canary
    // count is (5 names x 4 folders x real user profiles); even a machine with 20 real profiles
    // only produces 400 canaries total, so 500 comfortably covers every canary on the box being hit
    // at once while still bounding a truly pathological infinite-loop bug.
    private const int MaxAutonomousActionsPerWindow = 500;
    private static readonly TimeSpan AutonomousActionWindow = TimeSpan.FromMinutes(2);
    private static readonly object BudgetLock = new();
    private static readonly Queue<DateTime> AutonomousActionTimestamps = new();

    // Per-path canary-hit cooldown (2.0.2) — see RespondToCanaryHit's comment.
    private static readonly TimeSpan CanaryHitCooldown = TimeSpan.FromHours(1);
    private static readonly Dictionary<string, DateTime> CanaryHitReportedUtc = new(StringComparer.OrdinalIgnoreCase);

    public static void Start(EdrWatcher.WatchConfig cfg)
    {
        _massModStartUtc = DateTime.UtcNow;
        // Diff against whatever was persisted from the LAST run, BEFORE re-provisioning touches
        // anything — ProvisionCanaries() below silently recreates any canary that's missing, so
        // checking after would always find it "present" again. Covers exactly the gap a crash/
        // restart leaves open: anything deleted or modified while this process wasn't running (no
        // FileSystemWatcher, no backstop) would otherwise go completely unnoticed forever — found
        // live 2026-07-23 on a real customer box after --edr-watch died silently for ~21 hours.
        var persisted = LoadPersistedState();
        if (persisted.Count > 0) DiffAgainstPersistedState(cfg, persisted);

        var roots = DiscoverWatchedRoots();
        if (roots.Count == 0)
        {
            LogLine("RansomwareGuard: no watched roots found — nothing to watch");
            return;
        }

        foreach (var root in roots)
        {
            ProvisionCanaries(root);
            WatchRoot(cfg, root);
        }

        // Machine-wide canary tier — see MachineWideRoots' doc comment. These roots never appear
        // in `roots` (the Public profile is excluded by ExcludedProfileNames), so each is watched
        // exactly once.
        foreach (var root in MachineWideRoots)
        {
            if (!Directory.Exists(root)) continue;
            ProvisionCanaries(root, hidden: false);
            WatchRoot(cfg, root);
        }

        var programDataRoot = EnsureMachineWideProgramDataRoot();
        if (programDataRoot is not null)
        {
            ProvisionCanaries(programDataRoot, hidden: false);
            WatchRoot(cfg, programDataRoot);
        }

        LogLine($"RansomwareGuard watching {roots.Count + MachineWideRoots.Length + (programDataRoot is not null ? 1 : 0)} root(s), {CanaryPaths.Count} canary file(s) provisioned");
        PersistState();
        StartCanaryBackstop(cfg);
    }

    private static void WatchRoot(EdrWatcher.WatchConfig cfg, string root)
    {
        try
        {
            var watcher = new FileSystemWatcher(root)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                IncludeSubdirectories = true,
                // 64KB is the practical max for FileSystemWatcher's internal buffer — reduces
                // but does NOT eliminate the documented overflow-under-extreme-burst risk
                // (exactly the load pattern a fast encryption loop produces). The 60s canary
                // backstop below exists specifically to catch a dropped-event worst case; the
                // mass-modification heuristic has no equivalent backstop (report-only, lower
                // stakes than a missed canary kill).
                InternalBufferSize = 65536,
            };
            watcher.Renamed += (_, e) => SafeHandle(() => OnRenamed(cfg, e));
            watcher.Changed += (_, e) => SafeHandle(() => OnChanged(cfg, e));
            watcher.Created += (_, e) => SafeHandle(() => OnCreated(cfg, e));
            watcher.Deleted += (_, e) => SafeHandle(() => OnDeleted(cfg, e));
            watcher.Error += (_, e) => LogLine($"FileSystemWatcher error on {root}: {e.GetException().Message}");
            watcher.EnableRaisingEvents = true;
            lock (Watchers) { Watchers.Add(watcher); }
        }
        catch (Exception ex)
        {
            LogLine($"could not watch {root}: {ex.Message}");
        }
    }

    private static string? EnsureMachineWideProgramDataRoot()
    {
        try
        {
            if (!Directory.Exists(MachineWideProgramDataRoot))
            {
                Directory.CreateDirectory(MachineWideProgramDataRoot);
                return MachineWideProgramDataRoot;
            }
            if (Directory.EnumerateFileSystemEntries(MachineWideProgramDataRoot).Any())
            {
                // Non-empty: a genuine collision only if it contains anything that is NOT one of
                // our own canaries (a prior run's canaries, or a re-provisioned box, must keep
                // being tracked — not abandoned to the untracked state). Collision doctrine
                // still fully applies to real files.
                var foreign = Directory.EnumerateFileSystemEntries(MachineWideProgramDataRoot)
                    .Any(e => !LooksLikeOurCanary(e));
                if (foreign)
                {
                    LogLine($"machine-wide canary root {MachineWideProgramDataRoot} already exists and is not empty — skipping (real-data collision doctrine)");
                    return null;
                }
            }
            return MachineWideProgramDataRoot;
        }
        catch (Exception ex)
        {
            LogLine($"machine-wide canary root setup failed for {MachineWideProgramDataRoot}: {ex.Message}");
            return null;
        }
    }

    private static List<string> DiscoverWatchedRoots()
    {
        var roots = new List<string>();
        try
        {
            // 2.0.2 — alias/subst drive skip. A subst'd letter (e.g. the S3 Drive feature's
            // Y:\ => C:\ProgramData\SentinelRemoteAssist\s3drive\Public) is NOT a real volume:
            // GetVolumeInformation reports the UNDERLYING volume's serial, so any Fixed drive
            // whose serial duplicates another drive's is an alias. Aliases must never be
            // watched or provisioned: the watcher runs as SYSTEM and per-session subst mappings
            // appear/disappear with the logon session, so canaries on them look "deleted" on
            // every restart and fire deleted-while-watcher-down + autonomous isolation (found
            // live 2026-08-02: five false isolates in one minute after a single agent update).
            // They also duplicate-watch the same bytes as the source volume.
            var fixedDrives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed).ToList();
            var serials = new HashSet<uint>();
            var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var drive in fixedDrives)
            {
                var root = drive.RootDirectory.FullName;
                var serial = Win32Native.VolumeSerial(root);
                if (serial is null) continue; // can't read it — treat as real (best-effort)
                if (!serials.Add(serial.Value)) aliases.Add(root); // serial already seen — alias
            }

            foreach (var drive in fixedDrives)
            {
                try
                {
                    var driveRoot = drive.RootDirectory.FullName;
                    if (aliases.Contains(driveRoot))
                    {
                        LogLine($"RansomwareGuard: skipping alias/subst drive {driveRoot} (volume serial duplicates another drive)");
                        continue;
                    }
                    var isSystemDrive = string.Equals(driveRoot, SystemDriveRoot, StringComparison.OrdinalIgnoreCase);

                    // Users-tree profile dirs on every fixed drive (a data drive can host profiles too).
                    var usersDir = Path.Combine(driveRoot, "Users");
                    if (Directory.Exists(usersDir))
                    {
                        foreach (var profileDir in Directory.GetDirectories(usersDir))
                        {
                            var name = Path.GetFileName(profileDir);
                            if (ExcludedProfileNames.Contains(name)) continue;
                            foreach (var sub in WatchedSubdirs)
                            {
                                var full = Path.Combine(profileDir, sub);
                                if (Directory.Exists(full)) roots.Add(full);
                            }
                        }
                    }

                    // Non-system fixed drives: the drive root itself is the anti-ransomware net —
                    // a data drive's files may sit anywhere (D:\Projects, D:\Finance, drive root),
                    // not just under a Users tree. C:\ itself is deliberately NOT watched (system
                    // churn false-positive storm; Windows/Program Files changes are AppLocker's
                    // and Sysmon's job, not a file-encryption signature).
                    if (!isSystemDrive && drive.IsReady)
                    {
                        roots.Add(driveRoot);
                    }
                }
                catch
                {
                    // drive not ready / access denied — best-effort per drive, never abort the scan
                }
            }
        }
        catch (Exception ex)
        {
            LogLine($"drive discovery failed: {ex.Message}");
        }
        return roots.Distinct().ToList();
    }

    // Fixed canary content — hoisted to a constant (was a local inside the "create new" branch)
    // because ProvisionCanaries below now also uses it to tell "this is OUR canary from a prior
    // run" apart from "this is a genuine real file that happens to collide with a canary name" —
    // the two cases must be handled very differently (track vs. never touch).
    private const string CanaryContent =
        "This is a Sentinel security decoy file used to detect ransomware and unauthorized " +
        "file access on this PC. Do not delete it. If you are seeing this message because " +
        "an automated security response just triggered, contact support.";

    // Bounded content check — never read a large real file wholesale just to answer "is this ours".
    // Canary files are always this exact short blob, so a length check alone rules out virtually
    // every real-file collision before any content is even read.
    private static bool LooksLikeOurCanary(string path)
    {
        try
        {
            if (new FileInfo(path).Length > 4096) return false;
            return File.ReadAllText(path).StartsWith(CanaryContent, StringComparison.Ordinal);
        }
        catch { return false; }
    }

    // Never overwrites a real file — hard collision check first, same "a decoy must never collide
    // with something real" doctrine as the honeypot's own decoy DNS records. A name that collides
    // in this root is just skipped (never re-picked), same as the ARP canary-IP precedent's "a
    // candidate that answers before confirmation was just a bad pick, silently dropped."
    //
    // ⚠️ MUST track (CanaryPaths/CanaryHashes) a canary that ALREADY EXISTS on disk, not just one
    // this call just wrote — CanaryPaths/CanaryHashes are in-memory only and reset to empty on
    // every process start, but the files themselves persist across restarts (that's the whole
    // point). Found live 2026-07-23: after any restart of an already-provisioned box, this method
    // used to `continue` (skip tracking entirely) for every pre-existing canary — the very next
    // restart on the test Windows host went from "60 canary file(s) provisioned" to "6" (only the handful of
    // roots that happened to be missing one). The other 54 real, on-disk canary files were
    // completely untracked by IsCanaryPath() from that point on — deleting, renaming, or editing
    // any of them raised zero alerts, silently, with no error anywhere. A decoy nobody is watching
    // is worse than no decoy: it looks like protection to anyone checking the dashboard.
    //
    // ⚠️ Must NOT start tracking a genuine real-file collision (a user who really has their own
    // "Passwords.docx") — that would make an ordinary edit/delete of the user's OWN file trigger
    // the zero-tolerance autonomous kill+isolate response. LooksLikeOurCanary() disambiguates by
    // content, not just the name-collision check the original code already did.
    private static void ProvisionCanaries(string root, bool hidden = true)
    {
        foreach (var name in CanaryNames)
        {
            var path = Path.Combine(root, name);
            try
            {
                if (File.Exists(path))
                {
                    if (LooksLikeOurCanary(path))
                    {
                        lock (CanaryPaths) { CanaryPaths.Add(path); }
                        CanaryHashes[path] = HashFile(path) ?? "";
                    }
                    // else: genuine real-file collision — leave it alone, don't track it, exactly
                    // as before. The name is simply retired for canary use in this root.
                    continue;
                }
                File.WriteAllText(path, CanaryContent);
                if (hidden)
                {
                    // Profile-dir canaries only — machine-wide roots pass hidden: false, see
                    // MachineWideRoots' doc comment (nobody browses those locations, so the
                    // visible-decoy realism has no user-FP downside there).
                    try { File.SetAttributes(path, FileAttributes.Hidden); } catch { /* best-effort */ }
                }
                lock (CanaryPaths) { CanaryPaths.Add(path); }
                CanaryHashes[path] = HashFile(path) ?? "";
            }
            catch (Exception ex)
            {
                LogLine($"canary provisioning failed for {path}: {ex.Message}");
            }
        }
    }

    private static bool IsCanaryPath(string path)
    {
        lock (CanaryPaths) { return CanaryPaths.Contains(path); }
    }

    // ── FileSystemWatcher handlers ──────────────────────────────────────────────────────────────

    private static void OnRenamed(EdrWatcher.WatchConfig cfg, RenamedEventArgs e)
    {
        if (IsCanaryPath(e.OldFullPath)) { RespondToCanaryHit(cfg, e.OldFullPath, "renamed-from"); return; }
        if (IsCanaryPath(e.FullPath)) { RespondToCanaryHit(cfg, e.FullPath, "renamed-to"); return; }
        if (IsSentinelRestorePath(e.FullPath) || IsSentinelRestorePath(e.OldFullPath)) return;
        RecordRateEvent(WeightRenamed(e.OldFullPath, e.FullPath), e.FullPath);
        MaybeEvaluateRateThreshold(cfg);
    }

    private static void OnChanged(EdrWatcher.WatchConfig cfg, FileSystemEventArgs e)
    {
        if (IsCanaryPath(e.FullPath)) { RespondToCanaryHit(cfg, e.FullPath, "changed"); return; }
        if (IsSentinelRestorePath(e.FullPath)) return;
        RecordRateEvent(1.0, e.FullPath);
        MaybeEvaluateRateThreshold(cfg);
    }

    private static void OnCreated(EdrWatcher.WatchConfig cfg, FileSystemEventArgs e)
    {
        if (IsCanaryPath(e.FullPath)) return; // we created it ourselves — not a hit
        if (IsSentinelRestorePath(e.FullPath)) return;
        RecordRateEvent(1.0, e.FullPath);
        MaybeEvaluateRateThreshold(cfg);
    }

    private static void OnDeleted(EdrWatcher.WatchConfig cfg, FileSystemEventArgs e)
    {
        // Deletion alone doesn't feed the rate heuristic (too many benign causes — editors'
        // save-as-temp-then-delete-original patterns, ordinary cleanup) but DOES matter for
        // canary detection: an encrypt-then-delete-original ransomware style shows up here.
        if (IsCanaryPath(e.FullPath))
        {
            lock (CanaryPaths) { CanaryPaths.Remove(e.FullPath); }
            CanaryHashes.Remove(e.FullPath);
            PersistState();
            RespondToCanaryHit(cfg, e.FullPath, "deleted");
        }
    }

    private static double WeightRenamed(string oldPath, string newPath)
    {
        var oldExt = Path.GetExtension(oldPath);
        var newExt = Path.GetExtension(newPath);
        // Extension-changing renames are the classic encryptor fingerprint (document.docx ->
        // document.docx.locked) — weighted well above an ordinary same-extension rename.
        return !string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase) ? 3.0 : 1.5;
    }

    // ── Canary response (autonomous, instant, zero-tolerance) ──────────────────────────────────

    private static void RespondToCanaryHit(EdrWatcher.WatchConfig cfg, string canaryPath, string trigger)
    {
        // 2.0.2 — per-path cooldown. Every watcher restart (agent update, crash) re-runs
        // DiffAgainstPersistedState; a canary already reported (and the host already isolated —
        // LocalIsolation.Block() is idempotent) must not page the operator again for the SAME
        // path within an hour. A genuinely new touch of a DIFFERENT path still responds
        // instantly; a real repeat touch of the same path after the window still responds too.
        lock (CanaryHitReportedUtc)
        {
            if (CanaryHitReportedUtc.TryGetValue(canaryPath, out var last) && DateTime.UtcNow - last < CanaryHitCooldown)
            {
                LogLine($"canary hit for {canaryPath} within cooldown window — suppressing repeat response");
                return;
            }
            CanaryHitReportedUtc[canaryPath] = DateTime.UtcNow;
            if (CanaryHitReportedUtc.Count > 2000)
            {
                var cutoff = DateTime.UtcNow - CanaryHitCooldown;
                foreach (var stale in CanaryHitReportedUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                {
                    CanaryHitReportedUtc.Remove(stale);
                }
            }
        }

        if (!TryConsumeAutonomousActionBudget())
        {
            LogLine($"canary hit but autonomous-action budget exhausted this window — skipping response for {canaryPath}");
            return;
        }

        var attributed = EdrWatcher.TryGetRecentFileTouch(canaryPath, out var image, out var pid, out var processGuid);
        var killedOk = false;
        if (attributed && pid > 0)
        {
            killedOk = ProcessIntervention.KillProcessTree(pid);
        }

        // Always isolates regardless of attribution success — per the plan's fallback: no
        // per-process attribution needed for isolation, only for the targeted kill.
        var isolateOk = LocalIsolation.Block($"canary file touched: {canaryPath}");

        WriteAuditLog($"CANARY HIT path={canaryPath} trigger={trigger} attributedImage={image} " +
                       $"attributedPid={pid} killed={killedOk} isolated={isolateOk}");

        SecurityNotification.Show("Sentinel Security Alert",
            "A protected decoy file was touched — this usually means ransomware or another attacker " +
            $"tool is active on this PC.\n\nFile: {canaryPath}\n" +
            (attributed ? $"Process: {image} (PID {pid}) — killed: {(killedOk ? "yes" : "no")}\n" : "Process: could not be identified\n") +
            $"Network isolated: {(isolateOk ? "yes" : "no")}\n\nContact support immediately.");

        var report = new
        {
            label = cfg.Label,
            rule = "canary_file_touch",
            severity = "high",
            reason = $"canary_file_{trigger}: {canaryPath} — killed={killedOk} isolated={isolateOk}",
            time = DateTime.UtcNow.ToString("o"),
            image = attributed ? image : "",
            command_line = "",
            // Phase 4 — the attributing process's own lineage (parent chain/network activity), when
            // Sysmon's Event 11 carried a ProcessGuid for it.
            lineage_context = EdrWatcher.BuildLineageContext(processGuid),
            raw_xml = JsonSerializer.Serialize(new
            {
                canary_path = canaryPath, trigger, attributed_pid = pid, killed = killedOk, isolated = isolateOk,
            }),
        };
        try { EdrWatcher.SendOrQueueAsync(cfg, report).GetAwaiter().GetResult(); }
        catch (Exception ex) { LogLine($"canary report failed: {ex.Message}"); }
    }

    // ── Mass-modification response (report-only) ────────────────────────────────────────────────

    private static void RecordRateEvent(double weight, string path)
    {
        if (MassModSuppressed()) return; // shutdown/boot servicing churn — never pollute the window
        lock (RateLock)
        {
            var now = DateTime.UtcNow;
            RateWindow.Enqueue((now, weight, path));
            while (RateWindow.Count > 0 && (now - RateWindow.Peek().Time).TotalSeconds > RateWindowSeconds)
            {
                RateWindow.Dequeue();
            }
        }
    }

    private static void MaybeEvaluateRateThreshold(EdrWatcher.WatchConfig cfg)
    {
        if (MassModSuppressed()) return; // report-only heuristic — skip while shutdown/boot churn
        double sum;
        List<string> recentPaths;
        lock (RateLock)
        {
            sum = RateWindow.Sum(x => x.Weight);
            recentPaths = RateWindow.Select(x => x.Path).Where(p => !string.IsNullOrEmpty(p)).Distinct().TakeLast(10).ToList();
        }
        if (sum < RateThreshold) return;
        if (DateTime.UtcNow - _lastRateAlertUtc < RateAlertCooldown) return; // already reported this burst
        _lastRateAlertUtc = DateTime.UtcNow;
        ReportMassModification(cfg, sum, recentPaths);
    }

    private static void ReportMassModification(EdrWatcher.WatchConfig cfg, double totalWeight, List<string> recentPaths)
    {
        var attributed = new List<(string Image, string ProcessGuid)>();
        foreach (var path in recentPaths)
        {
            if (EdrWatcher.TryGetRecentFileTouch(path, out var image, out _, out var guid) && !string.IsNullOrEmpty(image))
            {
                attributed.Add((image, guid));
            }
        }
        var attributedImages = attributed.Select(a => a.Image).ToList();

        if (attributedImages.Count > 0)
        {
            var dominant = attributedImages.GroupBy(img => Path.GetFileName(img), StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count()).First();
            if ((double)dominant.Count() / attributedImages.Count >= 0.6 && AllowlistedProcessNames.Contains(dominant.Key))
            {
                LogLine($"mass-modification pattern (weight={totalWeight:F1}) attributed to allowlisted '{dominant.Key}' — suppressing");
                return;
            }
        }

        var mainImage = attributedImages.FirstOrDefault() ?? "";
        var mainProcessGuid = attributed.FirstOrDefault(a => a.Image == mainImage).ProcessGuid ?? "";
        LogLine($"MASS MODIFICATION pattern detected: weight={totalWeight:F1} attributedImage={mainImage}");
        WriteAuditLog($"MASS MODIFICATION weight={totalWeight:F1} attributedImage={mainImage} " +
                       $"sampledPaths={string.Join(";", recentPaths.Take(5))}");

        var report = new
        {
            label = cfg.Label,
            rule = "mass_file_modification",
            severity = "high",
            reason = $"rapid_file_modification_pattern: weight={totalWeight:F1} over {RateWindowSeconds:F0}s" +
                     (string.IsNullOrEmpty(mainImage) ? "" : $" (likely {Path.GetFileName(mainImage)})"),
            time = DateTime.UtcNow.ToString("o"),
            image = mainImage,
            command_line = "",
            lineage_context = EdrWatcher.BuildLineageContext(mainProcessGuid),
            raw_xml = JsonSerializer.Serialize(new { weight = totalWeight, sampled_paths = recentPaths.Take(10) }),
        };
        try { EdrWatcher.SendOrQueueAsync(cfg, report).GetAwaiter().GetResult(); }
        catch (Exception ex) { LogLine($"mass-modification report failed: {ex.Message}"); }

        // Deliberately REPORT-ONLY (see class doc comment) — no autonomous kill/isolate here until
        // thresholds are tuned live and explicitly promoted. Notification still fires so the
        // operator learns about it immediately even though nothing was auto-blocked.
        SecurityNotification.Show("Sentinel Security Alert",
            "Rapid file modification pattern detected (possible ransomware) — reported, NOT automatically blocked.\n\n" +
            (string.IsNullOrEmpty(mainImage) ? "" : $"Likely process: {mainImage}\n") +
            "Review the dashboard and isolate manually if this looks like an active attack.");
    }

    // ── 60s canary backstop (existence + content hash) ──────────────────────────────────────────

    private static void StartCanaryBackstop(EdrWatcher.WatchConfig cfg)
    {
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(60)).ConfigureAwait(false);
                List<string> paths;
                lock (CanaryPaths) { paths = CanaryPaths.ToList(); }
                var changed = false;
                foreach (var path in paths)
                {
                    try
                    {
                        if (!File.Exists(path))
                        {
                            lock (CanaryPaths) { CanaryPaths.Remove(path); }
                            CanaryHashes.Remove(path);
                            changed = true;
                            RespondToCanaryHit(cfg, path, "backstop-missing");
                            continue;
                        }
                        var hash = HashFile(path);
                        if (hash is not null && CanaryHashes.TryGetValue(path, out var prior) && hash != prior)
                        {
                            CanaryHashes[path] = hash;
                            changed = true;
                            RespondToCanaryHit(cfg, path, "backstop-modified");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogLine($"canary backstop check failed for {path}: {ex.Message}");
                    }
                }
                if (changed) PersistState();
            }
            // ReSharper disable once FunctionNeverReturns
        });
    }

    private static string? HashFile(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch
        {
            return null;
        }
    }

    // ── Cross-restart canary state (survives a crash, reboot, or re-enable) ────────────────────

    private static Dictionary<string, string> LoadPersistedState()
    {
        try
        {
            if (!File.Exists(StatePath)) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var raw = File.ReadAllText(StatePath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(raw);
            return loaded is not null
                ? new Dictionary<string, string>(loaded, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            LogLine($"could not load canary state: {ex.Message}");
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static void PersistState()
    {
        try
        {
            Dictionary<string, string> snapshot;
            lock (CanaryPaths) { snapshot = new Dictionary<string, string>(CanaryHashes, StringComparer.OrdinalIgnoreCase); }
            Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
            var tmp = StatePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(snapshot));
            File.Move(tmp, StatePath, overwrite: true); // atomic-ish swap — never leaves a half-written state file
        }
        catch (Exception ex)
        {
            LogLine($"could not persist canary state: {ex.Message}");
        }
    }

    // Runs once, at the very start of Start(), against whatever was persisted from the prior
    // process instance — before ProvisionCanaries() has a chance to silently recreate anything
    // missing. This is what actually answers "did something happen to a canary while nobody was
    // watching" (the gap a crash/restart otherwise leaves completely blind). No process-kill
    // attempted here (whatever touched it, if anything, is long gone and there is no live Sysmon
    // attribution buffer from before this process existed) — isolation still fires, same
    // zero-tolerance posture as a live hit, since a compromise could still be in progress even if
    // this specific canary's damage is already done.
    private static void DiffAgainstPersistedState(EdrWatcher.WatchConfig cfg, Dictionary<string, string> persisted)
    {
        foreach (var (path, priorHash) in persisted)
        {
            try
            {
                if (!IsCanaryDrivePresent(path))
                {
                    // The VOLUME is gone, not the file — an unmounted drive, or a per-session
                    // subst mapping invisible to this SYSTEM watcher (the S3 Drive feature's
                    // Y:/Z:). A missing drive is not a deletion: skipping prevents an
                    // intermittent drive from firing deleted-while-watcher-down + autonomous
                    // isolation on every watcher restart (found live 2026-08-02: five false
                    // isolates in one minute after a single agent update). When the drive
                    // returns, provisioning re-tracks the files and the 60s backstop re-checks.
                    LogLine($"canary retroactive-state check skipped for {path}: drive not currently present");
                    continue;
                }
                if (!File.Exists(path))
                {
                    RespondToCanaryHit(cfg, path, "deleted-while-watcher-down");
                    continue;
                }
                var currentHash = HashFile(path);
                if (currentHash is not null && !string.IsNullOrEmpty(priorHash) && currentHash != priorHash)
                {
                    RespondToCanaryHit(cfg, path, "modified-while-watcher-down");
                }
            }
            catch (Exception ex)
            {
                LogLine($"canary retroactive-state check failed for {path}: {ex.Message}");
            }
        }
    }

    private static bool IsCanaryDrivePresent(string path)
    {
        try
        {
            var root = Path.GetPathRoot(path);
            return string.IsNullOrEmpty(root) || Directory.Exists(root);
        }
        catch
        {
            return true; // can't determine — never suppress a real signal on doubt
        }
    }

    // ── Storm guard ──────────────────────────────────────────────────────────────────────────────

    private static bool TryConsumeAutonomousActionBudget()
    {
        lock (BudgetLock)
        {
            var now = DateTime.UtcNow;
            while (AutonomousActionTimestamps.Count > 0 && (now - AutonomousActionTimestamps.Peek()) > AutonomousActionWindow)
            {
                AutonomousActionTimestamps.Dequeue();
            }
            if (AutonomousActionTimestamps.Count >= MaxAutonomousActionsPerWindow) return false;
            AutonomousActionTimestamps.Enqueue(now);
            return true;
        }
    }

    // ── Logging ──────────────────────────────────────────────────────────────────────────────────

    private static void SafeHandle(Action action)
    {
        try { action(); }
        catch (Exception ex) { LogLine($"file event handling error: {ex.Message}"); }
    }

    // Permanent, never deleted (unlike EdrWatcher's outbox, which is a retry queue purged on
    // successful send) — this IS the connectivity-independent audit trail for autonomous actions:
    // a record survives locally even if bastion is never reached at all.
    private static void WriteAuditLog(string s)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(AuditLogPath)!);
            File.AppendAllText(AuditLogPath, $"{DateTime.Now:O}  {s}{Environment.NewLine}");
        }
        catch { /* best-effort */ }
    }

    private static void LogLine(string s)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"{DateTime.Now:O}  [RansomwareGuard] {s}{Environment.NewLine}");
        }
        catch { /* best-effort */ }
    }
}
