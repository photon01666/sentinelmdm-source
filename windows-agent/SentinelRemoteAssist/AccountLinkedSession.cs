namespace SentinelRemoteAssist;

/// <summary>
/// Shared, process-lifetime state for the account-linked (login) flow — the seam between
/// AccountLoginForm/AccountAuthClient (authenticate + enroll), RemoteAssistSocket (persistent
/// control channel; receives server pushes), SetupRunner (installs the pushed SSH key into
/// administrators_authorized_keys), XrayTransportManager (builds the local REALITY-tunneled SOCKS
/// port), and MainForm (drives the existing consent + TunnelRunner flow). Kept as a single static
/// holder rather than threading a config object through every one of those, since — like
/// SessionEmbedded before it — there is only ever one session per process.
///
/// Entirely unused (all null/false/default) by the legacy ad hoc build (no login, SessionEmbedded-
/// baked identity) — every reader here falls back to that build's existing behavior.
/// </summary>
internal static class AccountLinkedSession
{
    /// <summary>True once AccountLoginForm has completed a successful login + enrollment ticket
    /// consumption is underway (RemoteAssistSocket connecting). Gates SessionConfig's account-
    /// linked branch — see SessionConfig.Current.</summary>
    public static bool IsLinked { get; set; }

    /// <summary>Set once, near the top of Program.RunUnattendedAccountLinkedSocket — true only
    /// for the SYSTEM-scheduled --unattended-tunnel process (Session 0, no interactive desktop),
    /// false (default) for MainForm's interactive process. SetupRunner.RunElevatedSetup() reads
    /// this to decide whether a fresh UAC prompt is even possible: a real person can click
    /// through one in the interactive case, but Session 0 has nobody to click it, so that path
    /// must instead trigger the already-registered SentinelRemoteAssist-AutoSetup scheduled task
    /// (SYSTEM, RunLevel Highest — registered once during the original elevated --setup run,
    /// see sentinel-setup.ps1) rather than raw runas.</summary>
    public static bool IsUnattendedProcess { get; set; }
    internal static bool _reconnectingSession;

    /// <summary>This install's persistent device id (DeviceIdentity.DeviceId) — the value signed
    /// into every socket handshake, mirroring the Android agent's Prefs.getOrCreateDeviceId().</summary>
    public static string? DeviceId { get; set; }

    /// <summary>Every SSH public key pushed by the server that has not yet been installed
    /// (RemoteAssistSocket's "remote_assist_ssh_key" handler). Read by SetupRunner.BuildScript()
    /// on every setup re-run and rendered into sentinel-setup.ps1's __EXTRA_PUBKEY__ as one key
    /// per line.
    ///
    /// ⚠️ 2.0.6 — this MUST stay a COLLECTION, never a single string. `/api/devices/:id/
    /// remote-assist/ssh-key` emits TWO pushes ~15ms apart (the browser session key, then the
    /// bastion admin-support key added by the 2.0.4 fix). With a single-valued static, push #2
    /// overwrote push #1 long before RunSetup() got as far as BuildScript() — so BOTH setup runs
    /// substituted the ADMIN key, which was already present in administrators_authorized_keys, so
    /// `$lines -notcontains $extraPubkey` was false, nothing was written, and the file's mtime
    /// never moved. The browser key was silently dropped on every single Regen Private Key, the
    /// setup log still said "Setup complete.", and every WebUI feature kept working (they
    /// authenticate with the admin key) — so the only visible symptom was the customer's own
    /// connect.sh failing at Hop-2 with "Permission denied (publickey)". Found live on the test VM
    /// 2026-08-03 after four failed Regen cycles.</summary>
    public static System.Collections.Concurrent.ConcurrentDictionary<string, byte> PendingSshPublicKeys { get; }
        = new(StringComparer.Ordinal);

    /// <summary>Newline-joined snapshot of <see cref="PendingSshPublicKeys"/> for script
    /// substitution; empty string when there is nothing pending.</summary>
    public static string PendingSshPublicKeysJoined =>
        string.Join("\n", PendingSshPublicKeys.Keys);

    /// <summary>Records a server-pushed key. Deduped, so the repeated pushes that happen on every
    /// reconnect/Regen cycle can't stack duplicates.</summary>
    public static void AddPendingSshPublicKey(string? pubKey)
    {
        if (string.IsNullOrWhiteSpace(pubKey)) return;
        PendingSshPublicKeys.TryAdd(pubKey.Trim(), 0);
    }

    /// <summary>True when this device is ZK-owned (public-user-claimed) — the server-pushed flag
    /// that accompanies PendingSshPublicKeys. When true, SetupRunner installs ONLY the pushed key
    /// and actively REMOVES the standing shared operator key from administrators_authorized_keys,
    /// rather than merely leaving it unused — the mechanism that makes admin access physically
    /// impossible for this device, not just permission-denied. See sentinel-setup.ps1 step 4.</summary>
    public static bool ExcludeSharedOperatorKey { get; set; }

    /// <summary>xray REALITY transport parameters pushed via the "set_remote_assist_transport"
    /// command (mirrors the Android VPN egress-UUID push) — the secret egress UUID is never baked
    /// into the binary, only ever received over the already-authenticated control socket.</summary>
    public static string? XrayEgressUuid { get; set; }
    public static int XrayPort { get; set; } = 443;

    /// <summary>The bastion-allocated Hop-1 reverse-forward port for THIS session (bastionClient.js
    /// provisionSession()'s returned port) — pushed alongside the transport params since the
    /// forward port is allocated at session-start time. The Hop-1 KEY itself is neither baked at
    /// build time nor pushed here — each device generates its own on first run and sends the
    /// public half up separately, on every "register" — see Hop1Identity.cs.</summary>
    public static int BastionForwardPort { get; set; }

    /// <summary>The LOCAL port XrayTransportManager exposes once its client process is up — this
    /// is what TunnelRunner's ssh.exe actually dials (BastionHost="127.0.0.1",
    /// BastionPort=XrayLocalPort) for the account-linked flow. Set by MainForm right before
    /// building SessionConfig.Current, once XrayTransportManager.Start() succeeds.</summary>
    public static int XrayLocalPort { get; set; }

    /// <summary>Raised by RemoteAssistSocket when the dashboard has requested an interactive
    /// session (POST /api/devices/:id/remote-assist/start reaching this device). MainForm
    /// subscribes to this to show the EXISTING consent dialog (unchanged — see
    /// MainForm.EnsureEphemeralConsent) before starting the tunnel; the login screen only adds
    /// account-gated access control on top of that, it does not bypass local consent.</summary>
    public static event Action? SessionRequested;
    public static void RaiseSessionRequested() => SessionRequested?.Invoke();

    /// <summary>Raised by RemoteAssistSocket on a dedicated "restart_ra_tunnel" server command —
    /// a lightweight, direct restart of the EXISTING Hop-1 SSH tunnel (same Hop1Identity key, same
    /// xray/control channel — neither is touched). Distinct from SessionRequested/remote_assist_ssh_key
    /// on purpose: those either regenerate session key material or tear down and rebuild the whole
    /// xray+control-channel stack, which is unnecessary (and disruptive) just to recover a tunnel
    /// that died for a reason the agent's own process could not detect (e.g. an externally killed
    /// ssh.exe whose exit TunnelRunner's retry loop never observed — see the EDR/AppControl/WinUpdate
    /// "kick" call sites in bastion-web.py, which used to kill ssh.exe externally and hope the agent's
    /// retry loop noticed; unreliable, confirmed live 2026-07-22 on the test Windows host: the tunnel stayed down
    /// ~2m19s with no retry-log line until a full Regen Private Key cycle recovered it). The handler
    /// in Program.cs just calls Stop()+Start() on the same TunnelRunner instance already in use.</summary>
    public static event Action? TunnelRestartRequested;
    public static void RaiseTunnelRestartRequested() => TunnelRestartRequested?.Invoke();

    /// <summary>Admin per-device opt-in for the AI Live Chat tray feature — server-pushed via the
    /// "set_ai_chat" command (mirrors set_vpn/set_s3_drive), re-sent on every register/reconnect so
    /// it survives an app restart without waiting for an admin to re-toggle it. Off (false) by
    /// default, matching "admin opt-in per device" rollout. Disk-persisted so the interactive tray
    /// process (which has no socket in autostart mode — the SYSTEM service owns the control channel)
    /// can still read the flag that the SYSTEM process wrote; mirroring ZkPubKey's pattern exactly.</summary>
    public static bool AiChatEnabled
    {
        get
        {
            try { return File.Exists(AiChatEnabledPath); }
            catch { return false; }
        }
        set
        {
            try
            {
                Directory.CreateDirectory(Config.SessionKeyDir);
                if (value) File.WriteAllText(AiChatEnabledPath, "1");
                else { if (File.Exists(AiChatEnabledPath)) File.Delete(AiChatEnabledPath); }
            }
            catch { /* best-effort — worst case the tray item is briefly wrong until the next toggle */ }
        }
    }

    private static readonly string AiChatEnabledPath = Path.Combine(Config.SessionKeyDir, "ai-chat-enabled.flag");

    private static readonly string EnrolledMarkerPath = Path.Combine(Config.SessionKeyDir, "account-linked-enrolled.marker");

    /// <summary>True if THIS install has ever completed account-linked enrollment before (a
    /// process-lifetime-independent, disk-persisted fact — unlike IsLinked/DeviceId above, which
    /// reset on every restart). Lets --unattended-tunnel reconnect the control socket via
    /// DeviceIdentity's signed auth alone, with no login prompt, exactly like a reconnecting
    /// Android agent — set once by RemoteAssistSocket right after a first-time-enrollment
    /// connection actually succeeds (never on a bare login; the SERVER accepting the connection is
    /// what "enrolled" means here, not merely submitting credentials).</summary>
    public static bool IsPreviouslyEnrolled => File.Exists(EnrolledMarkerPath);

    public static void ClearEnrolled()
    {
        try { if (File.Exists(EnrolledMarkerPath)) File.Delete(EnrolledMarkerPath); } catch { }
    }

    public static void MarkEnrolled()
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(EnrolledMarkerPath, DateTimeOffset.UtcNow.ToString("O"));
        }
        catch { /* best-effort — worst case, the next unattended run shows the login form again */ }
    }

    private static readonly string ZkPubKeyPath = Path.Combine(Config.SessionKeyDir, "zk-pub-key.txt");
    private static string? _zkPubKeyCache;
    private static bool _zkPubKeyLoaded;

    /// <summary>The owning public user's EC P-256 public key (base64 SPKI) — mirrors Android's
    /// Prefs.zkPubKey. Present only for a public-user-owned (ZK) device; null for an admin-fleet
    /// device, which never gets a zkPubKey push at all. Disk-persisted so RemoteAssistSocket can
    /// resume ZK-encrypting device_status immediately on reconnect, without waiting for the
    /// server to re-push it. Set from RemoteAssistSocket's "registered" (initial) and
    /// "zk_pub_key" (live reassignment) handlers — never written anywhere else.</summary>
    public static string? ZkPubKey
    {
        get
        {
            if (!_zkPubKeyLoaded)
            {
                _zkPubKeyLoaded = true;
                try { _zkPubKeyCache = File.Exists(ZkPubKeyPath) ? File.ReadAllText(ZkPubKeyPath).Trim() : null; }
                catch { _zkPubKeyCache = null; }
                if (string.IsNullOrEmpty(_zkPubKeyCache)) _zkPubKeyCache = null;
            }
            return _zkPubKeyCache;
        }
        set
        {
            _zkPubKeyCache = string.IsNullOrEmpty(value) ? null : value;
            _zkPubKeyLoaded = true;
            try
            {
                Directory.CreateDirectory(Config.SessionKeyDir);
                if (_zkPubKeyCache is null) { if (File.Exists(ZkPubKeyPath)) File.Delete(ZkPubKeyPath); }
                else File.WriteAllText(ZkPubKeyPath, _zkPubKeyCache);
            }
            catch { /* best-effort — worst case the next reconnect just waits for a fresh push */ }
        }
    }
}
