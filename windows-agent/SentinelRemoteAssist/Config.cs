using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Build-time constants. The optional standing support public key is the public half of a
/// keypair held by the operator; it is reused across sessions and never changes per-session.
/// The per-session Hop-1 tunnel key is baked into <c>SessionEmbedded.cs</c> at build time
/// (single .exe, no companion file).
///
/// The matching private half is held by the operator. A leak would grant Administrator access
/// to every machine that CURRENTLY has a live session (or has "start automatically" enabled —
/// that path deliberately keeps the account/key/sshd installed). Attended/ephemeral mode removes
/// the account on app close so the window is bounded to the open window; autostart reintroduces
/// standing access by explicit customer opt-in.
/// </summary>
internal static class Config
{
    private static string BuildAcctName() => string.Concat("ssh", "-roo", "t");
    public static string LocalAccountName => BuildAcctName();

    /// <summary>
    /// SentinelMDM dashboard origin — same value as the Android agent's Prefs.WEB_URL. Only used
    /// by the account-linked login flow (AccountAuthClient/AccountLoginForm/RemoteAssistSocket);
    /// the legacy ad hoc build (SessionEmbedded-baked, no login) never calls it.
    /// </summary>
    public static readonly string WebUrl =
        System.Environment.GetEnvironmentVariable("SENTINEL_SERVER_URL") ?? "https://app.example.com";

    /// <summary>Bastion host used for the Hop-1 HostKeyAlias. Override with SENTINEL_BASTION_HOST.</summary>
    public static readonly string BastionHost =
        System.Environment.GetEnvironmentVariable("SENTINEL_BASTION_HOST") ?? "bastion.example.com";

    /// <summary>
    /// Build-time switch mirroring the Android agent's BuildConfig.ADMIN_AGENT: false = public
    /// build (email+password, posts to /login), true = admin/sub-user build (username+password,
    /// posts to /api/device-admin/login). Set via the AdminAgent MSBuild property — see the csproj.
    /// </summary>
    public const bool AdminAgent =
#if ADMIN_AGENT
        true;
#else
        false;
#endif

    /// <summary>True for any build produced by bastion-builder's build_account_linked_exe() (both
    /// AdminAgent variants alike) — the "is this a real account-linked build, not a template/dev
    /// build" signal that RemoteAssistHop1Key.IsConfigured used to serve before per-device Hop-1
    /// identity (see Hop1Identity.cs) replaced the old account-baked key. Set via the
    /// AccountLinkedBuild MSBuild property — see the csproj.</summary>
    public const bool AccountLinkedBuild =
#if ACCOUNT_LINKED_BUILD
        true;
#else
        false;
#endif

    /// <summary>True for the auto-provisioning installer variant (bastion-builder's
    /// /build-installer) — a per-account exe with the account's enrollment ticket + server URL +
    /// ToS version baked in (AutoProvisionEmbedded). A double-click on the target PC shows the
    /// ToS/MSA, elevates, installs with persistence, and enrolls with zero login (see
    /// AutoProvisionFlow.cs). Set via the AutoProvisionBuild MSBuild property — see the csproj.</summary>
    public const bool AutoProvisionBuild =
#if AUTOPROVISION_BUILD
        true;
#else
        false;
#endif


    /// <summary>
    /// Standing admin key REMOVED — the per-session Hop-2 keypair (minted by the bastion at
    /// session provisioning, pushed to the device via remote_assist_ssh_key on first Connect)
    /// replaces it. Every device now gets session-scoped keys with full lifecycle management.
    /// The bastion falls back to the old bastion-support-key for backward compat during migration.
    /// See the support service's hop2_ssh_base_args() and _ensure_session_hop2_key().
    /// </summary>
    public const string AdminHopTwoPublicKey = "";

    /// <summary>
    /// Hop-1 (reverse-tunnel-to-bastion) identity for the ACCOUNT-LINKED login flow — a per-DEVICE
    /// keypair generated at runtime by <see cref="Hop1Identity"/>, unlike the ad hoc flow's
    /// per-CUSTOMER Hop-1 key (SessionEmbedded, baked per new-support-session.sh build). Nothing
    /// account- or device-specific is baked into the .exe at build time any more — the same build
    /// works for any device under the account, and each device mints its own identity the first
    /// time it runs. The ForwardPort/BastionHost/BastionPort for a given session are learned at
    /// runtime via RemoteAssistSocket's "set_remote_assist_transport" push (see
    /// AccountLinkedSession.BastionForwardPort etc.); the Hop-1 public key is sent the other
    /// direction, up to the server, on every "register".
    ///
    /// PREVIOUSLY one shared keypair baked into every build for an account (RemoteAssistHop1Key.cs,
    /// now removed) — that worked for authentication ("prove this is legitimate SentinelRemoteAssist
    /// software") but not for sshd's `permitlisten=` port restriction, which is also tied to
    /// whichever key authenticates a connection: two devices sharing one key means sshd can only
    /// ever honor the FIRST matching authorized_keys line for that key, silently rejecting every
    /// OTHER device's own `-R` port-forward request. Found live 2026-07-18 testing two devices
    /// under one account for the first time — see Hop1Identity.cs's doc comment and memory
    /// ssh-bastion-account-linked-port-collision.
    /// </summary>

    /// <summary>The bastion's SSH host public key line (ssh-keyscan format) — same value
    /// TunnelRunner's UserKnownHostsFile pins for the ad hoc flow's per-customer known_hosts,
    /// just baked as a build-time constant here since the account-linked flow has no per-session
    /// known_hosts file generated for it. Live output of
    /// `ssh-keyscan -p 22022 remote.example.com`, captured 2026-07-13.</summary>
    public static readonly string RemoteAssistBastionKnownHostsLine =
        System.Environment.GetEnvironmentVariable("SENTINEL_BASTION_KNOWN_HOSTS") ?? "";

    /// <summary>Fleet REALITY node public IPs — same default fleet list + convention as the
    /// Android agent's Prefs.realityNodesCsv (public, non-secret; safe to bake in like the APK
    /// does). XrayTransportManager dials these nodes using the PER-NODE camouflage SNI in
    /// <see cref="RealitySnis"/> (index-aligned), exactly like Android's realitySniForNode and the
    /// desktop xray client. The node's :443 sni-dispatch only routes a client to the REALITY inbound
    /// whose serverNames contain that node's SNI — a single shared SNI (e.g. www.microsoft.com) is
    /// REJECTED on every node whose decoy dest differs, so the reverse tunnel never forms
    /// (connected:false). Keep this list in lockstep with the server's per-node dest/serverNames and
    /// with Android's Prefs.realitySniCsv default.</summary>
    public static readonly string[] RealityNodes =
        (System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_NODES") ?? "")
            .Split(',', System.StringSplitOptions.RemoveEmptyEntries);
    /// <summary>Per-node REALITY camouflage SNI, index-aligned with <see cref="RealityNodes"/>
    /// (node A/B/C) — matches Android Prefs.realitySniCsv default "www.microsoft.com,www.microsoft.com,
    /// www.microsoft.com" and the desktop /opt/sentinel-xray/config.json outbounds.</summary>
    public static readonly string[] RealitySnis =
        (System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_SNIS") ?? "www.microsoft.com")
            .Split(',', System.StringSplitOptions.RemoveEmptyEntries);
    /// <summary>Fallback SNI when a node has no aligned entry in <see cref="RealitySnis"/>.</summary>
    public static readonly string RealitySni =
        System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_SNI") ?? "www.microsoft.com";

    /// <summary>Per-node IPv6 literals, index-aligned with <see cref="RealityNodes"/> (node A/B/C) —
    /// the same public/non-secret fleet values the Android agent ships as its `reality_nodes_v6`
    /// pref default (the reference implementation). The nodes' REALITY :443 listeners are
    /// dual-stack (re-verified live 2026-09-26 alongside the sentineld port), so dialing a v6
    /// literal needs no server-side change. An empty entry means "this node has no v6 literal" —
    /// <see cref="NodeAddresses"/> then returns the v4 literal alone, exactly like Android's
    /// nodeAddresses().</summary>
    public static readonly string[] RealityNodesV6 =
        (System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_NODES_V6") ?? "")
            .Split(',', System.StringSplitOptions.RemoveEmptyEntries);

    /// <summary>Ordered dial candidates for a node index: the IPv6 literal FIRST when this machine
    /// actually has a v6 route to it, then the IPv4 literal (always last, so a v6 failure degrades
    /// to the legacy path) — the Windows counterpart of the Android agent's nodeAddresses() +
    /// realityAddrIdx ladder (memory agent-reality-ipv6-first).</summary>
    public static List<string> NodeAddresses(int nodeIdx)
    {
        var list = new List<string>();
        if (nodeIdx < 0 || nodeIdx >= RealityNodes.Length) return list;
        if (nodeIdx < RealityNodesV6.Length)
        {
            var v6 = RealityNodesV6[nodeIdx].Trim();
            if (v6.Length > 0 && HasIPv6Route(v6)) list.Add(v6);
        }
        list.Add(RealityNodes[nodeIdx]);
        return list;
    }

    /// <summary>Cheap route probe for a v6 literal: a UDP "connect" performs a route lookup without
    /// sending a packet, so it fails exactly when a real dial would fail with WSAENETUNREACH (a v6
    /// address with no working default route — the condition behind the Android agent's original
    /// "v6 address but no route" bug). Best-effort: any unexpected socket error reads as "no v6
    /// route", and the caller falls back to the v4 literal.</summary>
    public static bool HasIPv6Route(string v6)
    {
        try
        {
            if (!System.Net.IPAddress.TryParse(v6, out var addr) ||
                addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                return false;
            using var probe = new System.Net.Sockets.Socket(
                System.Net.Sockets.AddressFamily.InterNetworkV6,
                System.Net.Sockets.SocketType.Dgram,
                System.Net.Sockets.ProtocolType.Udp);
            probe.Connect(new System.Net.IPEndPoint(addr, 443));
            return true;
        }
        catch
        {
            return false;
        }
    }
    /// <summary>Same public/non-secret REALITY parameters baked into the Android APK
    /// (TransportManager.kt PUBLIC_KEY/SHORT_ID/FINGERPRINT) — the matching private key never
    /// leaves the server (sentinel_xray_private_key secret).</summary>
    public static readonly string RealityPublicKey =
        System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_PUBLIC_KEY") ?? "";
    public static readonly string RealityShortId =
        System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_SHORT_ID") ?? "";
    public const string RealityFingerprint = "chrome";
    public static readonly string RealityControlUuid =
        System.Environment.GetEnvironmentVariable("SENTINEL_REALITY_CONTROL_UUID") ?? "";

    public const string SetupCompleteMarkerPath = @"C:\ProgramData\SentinelRemoteAssist\setup-complete.txt";
    /// <summary>Written by RemoteAssistSocket's ssh_key handler before spawning the SYSTEM
    /// scheduled task, so the child --setup process (which always starts with null statics)
    /// can still read the dashboard-pushed Hop-2 key. BuildScript() reads this file as a
    /// fallback when AccountLinkedSession.PendingSshPublicKeys is empty. Newline-separated: one key per line.</summary>
    public const string ExtraPubKeyPath = @"C:\ProgramData\SentinelRemoteAssist\extra-pubkey-pending.txt";
    public const string SessionKeyDir = @"C:\ProgramData\SentinelRemoteAssist";

    /// <summary>
    /// ABSOLUTE path to Windows PowerShell 5.1. Always use this for ProcessStartInfo.FileName —
    /// never the bare string "powershell.exe".
    ///
    /// powershell.exe does NOT live in System32; it lives in System32\WindowsPowerShell\v1.0,
    /// which is reachable only via %PATH%. With UseShellExecute=false, CreateProcess resolves a
    /// bare filename against the app directory, the CURRENT directory, System32, Windows, then
    /// PATH — so on a machine whose PATH is truncated or damaged (common: the 2047-char legacy
    /// limit, or a bad installer overwriting it) every launch fails with
    /// Win32Exception (2) "The system cannot find the file specified", naming whatever the current
    /// directory happened to be. Found live 2026-08-04 on the test Windows host: SetupRunner.RunSetup() died
    /// that way with working directory C:\Users\&lt;user&gt;\Desktop, which made it look like a
    /// problem with the folder the installer was run from rather than with PATH.
    ///
    /// Environment.SystemDirectory is bitness-correct for the running process (win-x64 → System32),
    /// so this resolves to the 64-bit PowerShell that the setup scripts expect. Falls back to the
    /// bare name only if the resolved file is somehow absent, which keeps behaviour no worse than
    /// before on an unusual install layout.
    /// </summary>
    public static readonly string PowerShellExe = ResolvePowerShellExe();

    private static string ResolvePowerShellExe()
    {
        try
        {
            // Prefer Windows PowerShell 5.1 (ships with every Windows install).
            var p = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (File.Exists(p)) return p;
            // Fall back to PowerShell 7+ (pwsh.exe) — some stripped/Win11 boxes lack 5.1.
            // Check common locations: System32, ProgramFiles\PowerShell\7, WindowsApps (Store).
            var candidates = new[]
            {
                Path.Combine(Environment.SystemDirectory, "pwsh.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps", "pwsh.exe"),
            };
            foreach (var c in candidates)
                if (File.Exists(c)) return c;
            // Last resort: try to find it via `where pwsh` (works even when not on the
            // default PATH, since pwsh's WindowsApps shim IS on PATH).
            try
            {
                var psi = new ProcessStartInfo("where.exe", "pwsh")
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                };
                using var proc = Process.Start(psi)!;
                var output = proc.StandardOutput.ReadToEnd().Trim();
                proc.WaitForExit();
                if (proc.ExitCode == 0 && !string.IsNullOrEmpty(output))
                {
                    var firstLine = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();
                    if (File.Exists(firstLine)) return firstLine;
                }
            }
            catch { /* best-effort */ }
        }
        catch { /* fall through to PATH lookup */ }
        return "powershell.exe";
    }
    public const string AppPidFilePath = @"C:\ProgramData\SentinelRemoteAssist\app.pid";
    /// <summary>Written by --unattended-tunnel so Start-auto can verify the tunnel is live
    /// without needing a prior CONNECT click.</summary>
    public const string UnattendedTunnelPidPath = @"C:\ProgramData\SentinelRemoteAssist\unattended-tunnel.pid";

    /// <summary>In-session audit log (ephemeral Connect only). Copied to the customer's Desktop
    /// on disconnect/uninstall so it survives the ProgramData wipe.</summary>
    public const string SessionAuditLogPath = @"C:\ProgramData\SentinelRemoteAssist\session-audit.log";
    /// <summary>Uninstall verification report written next to the Desktop audit copy.</summary>
    public const string CleanupReportFileName = "Sentinel-Support-Cleanup-Report.txt";

    /// <summary>Display name for the support organization shown in the session indicator,
    /// consent dialog, and customer-facing audit log (ephemeral Connect only).</summary>
    public const string TechnicianDisplayName = "Sentinel Support";

    /// <summary>Bumped when the consent/EULA text changes so re-acceptance is required.</summary>
    public const string ConsentAgreementVersion = "2026-07-10-v1";

    /// <summary>
    /// The running exe's own FileVersion (from SentinelRemoteAssist.csproj's &lt;Version&gt;) —
    /// read via <see cref="FileVersionInfo"/> off the actual exe on disk, NOT
    /// Assembly.GetExecutingAssembly().Location (which is empty for a PublishSingleFile bundle —
    /// Environment.ProcessPath is the single-file-safe way to find "this exe", same idiom already
    /// used throughout SetupRunner/UninstallRunner/AutoStartManager). This is the exact same
    /// resource field the bastion WebUI reads back remotely over Hop-2
    /// (`(Get-Item 'C:\ProgramData\SentinelRemoteAssist\Sentinel.exe').VersionInfo.FileVersion`)
    /// — using the same field in both places means the in-app display and the WebUI's remote
    /// display can never disagree.
    /// </summary>
    public static readonly string AgentVersion = ReadOwnFileVersion();

    private static string ReadOwnFileVersion()
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;
            return FileVersionInfo.GetVersionInfo(exePath).FileVersion ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }

    /// <summary>Scheduled-task name for the unattended cleanup watchdog — see WatchdogRunner.</summary>
    public const string WatchdogTaskName = "SentinelRemoteAssist-Watchdog";

    /// <summary>Scheduled-task name for the SYSTEM-run, silent (no UAC), logon-triggered setup —
    /// see AutoStartManager. Only registered while "start automatically" is enabled.</summary>
    public const string AutoSetupTaskName = "SentinelRemoteAssist-AutoSetup";

    /// <summary>Unattended reverse-tunnel task (AtStartup). Uninstall must remove this too.</summary>
    public static string UnattendedTunnelTaskName => AutoSetupTaskName + "_Tunnel";

    /// <summary>
    /// Endpoint Application Control (WDAC default-deny) state — a SEPARATE top-level ProgramData
    /// tree, deliberately NOT under <see cref="SessionKeyDir"/>. UninstallRunner.cs recursively
    /// deletes SessionKeyDir on every ephemeral app close/uninstall (by design — see the
    /// "Remote Assist" ephemeral-lifecycle invariant in docs/ARCHITECTURE.md); app-control's policy files,
    /// report token, and watcher state are a standing security control that must survive across
    /// support sessions and reboots, so they live here instead. UninstallRunner.cs's delete call
    /// must never be broadened to touch this path.
    /// </summary>
    public const string AppControlDir = @"C:\ProgramData\SentinelAppControl";

    /// <summary>
    /// EDR watcher (--edr-watch) state — a SEPARATE top-level ProgramData tree, same reasoning as
    /// <see cref="AppControlDir"/>: watcher state, the local telemetry correlation buffer, canary
    /// registry, and isolation-block marker are a standing security control that must survive
    /// UninstallRunner.cs's ephemeral wipe of <see cref="SessionKeyDir"/> across support sessions
    /// and reboots. UninstallRunner.cs's delete call must never be broadened to touch this path.
    /// The watcher's ENABLE/localPort/token config still lives in the SHARED endpoint-config.json
    /// under <see cref="AppControlDir"/> (see EdrConfig.cs) — only this directory, the runtime
    /// state it accumulates, is EDR-specific.
    /// </summary>
    public const string EdrDir = @"C:\ProgramData\SentinelEdr";

    /// <summary>
    /// Breaks ACL inheritance on <see cref="SessionKeyDir"/> — whose parent, C:\ProgramData, grants
    /// BUILTIN\Users read access by default — and grants only the current user, SYSTEM, and
    /// Administrators, propagating to files created afterward. MUST run before anything sensitive
    /// (the Hop-1 tunnel private key, written later by TunnelRunner) lands in the directory:
    /// hardening the directory itself means every file created afterward inherits the restricted
    /// ACL from the moment it's created, instead of briefly holding the old, broader
    /// ProgramData-inherited permissions between creation and a later per-file lockdown (the race
    /// the old write-then-icacls-the-file approach had). Only called from the elevated setup path,
    /// which always runs before TunnelRunner ever touches this directory.
    /// </summary>
    public static void HardenSessionDir() => HardenDirectory(SessionKeyDir);

    /// <summary>Generalized form of the ACL-hardening logic above — also used by
    /// DeviceIdentity.cs for its own persistent identity store (a separate top-level directory,
    /// deliberately outside SessionKeyDir since that tree is wiped on every ephemeral
    /// disconnect/uninstall, same reasoning as AppControlDir above).</summary>
    public static void HardenDirectory(string path)
    {
        Directory.CreateDirectory(path);
        var psi = new ProcessStartInfo("icacls.exe",
            $"\"{path}\" /inheritance:r " +
            $"/grant:r \"{Environment.UserName}:(OI)(CI)F\" \"SYSTEM:(OI)(CI)F\" \"Administrators:(OI)(CI)F\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        p?.WaitForExit();
    }
}

    /// <summary>Public control-channel UUID for the REALITY relay — same value as the
