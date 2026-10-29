using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Persistent per-install ED25519 keypair for Hop-1 (reverse-tunnel-to-bastion) authentication —
/// the account-linked flow's per-DEVICE analog of DeviceIdentity's per-device tracker-auth key.
/// Generated via the OS's own ssh-keygen.exe (the same binary TunnelRunner already depends on for
/// ssh.exe), so the files are natively OpenSSH-formatted with zero conversion — usable directly by
/// `ssh -i` and directly matching what the bastion's authorized_keys expects.
///
/// Replaces the old account-level RemoteAssistHop1Key (one shared keypair baked into every build
/// for an account, embedded at build time by bastion-builder). That design assumed Hop-1 only
/// needed to prove "this is legitimate SentinelRemoteAssist software," with real per-device
/// authorization happening earlier at the SentinelMDM login/enrollment layer — true for
/// AUTHENTICATION, but sshd's own `permitlisten=` port restriction is ALSO tied to whichever key
/// authenticates a connection, and that genuinely needs per-device granularity: two devices
/// sharing one key means sshd can only ever honor the FIRST matching authorized_keys line for that
/// key, silently rejecting every other device's `-R` port-forward request ("remote port forwarding
/// failed" client-side, "the request was denied" server-side) — found live 2026-07-18 testing two
/// devices under one account for the first time. See memory
/// ssh-bastion-account-linked-port-collision.
///
/// The public half is sent to the server on every `register` (RemoteAssistSocket.cs) as
/// `hop1PublicKey`; the server stores it on the device row and hands it to the bastion at provision
/// time instead of looking up a shared account-level key — see the support service's
/// `_create_remote_assist_session()`.
/// </summary>
internal static class Hop1Identity
{
    private static readonly string StoreDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SentinelRemoteAssistIdentity");
    private static readonly string PrivateKeyPath = Path.Combine(StoreDir, "hop1_ed25519");
    private static readonly string PublicKeyPath = Path.Combine(StoreDir, "hop1_ed25519.pub");

    private static string? _publicKeyOpenSsh;
    private static string? _privateKeyPem;
    private static bool _loaded;
    private static bool _configured;

    /// <summary>"ssh-ed25519 AAAA... &lt;comment&gt;" line, trimmed — sent to the server as-is; the
    /// bastion writes it verbatim into authorized_keys.</summary>
    public static string? PublicKeyOpenSsh { get { EnsureLoaded(); return _publicKeyOpenSsh; } }

    /// <summary>OpenSSH PEM-format private key file content — slots directly into
    /// SessionConfig.PrivateKeyPem with no changes needed to TunnelRunner.WriteKeyMaterial, which
    /// just writes whatever string it's given to its own ephemeral per-connection file.</summary>
    public static string? PrivateKeyPem { get { EnsureLoaded(); return _privateKeyPem; } }

    public static bool IsConfigured { get { EnsureLoaded(); return _configured; } }

    private static void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;

        if (File.Exists(PrivateKeyPath) && File.Exists(PublicKeyPath))
        {
            try
            {
                _privateKeyPem = File.ReadAllText(PrivateKeyPath);
                _publicKeyOpenSsh = File.ReadAllText(PublicKeyPath).Trim();
                if (!string.IsNullOrEmpty(_privateKeyPem) && !string.IsNullOrEmpty(_publicKeyOpenSsh))
                {
                    _configured = true;
                    return;
                }
            }
            catch
            {
                // Corrupt/unreadable (e.g. moved to a different machine) — fall through and mint a
                // fresh pair rather than crash the agent, mirroring DeviceIdentity's own fallback.
            }
        }

        _configured = GenerateFresh();
    }

    private static bool GenerateFresh()
    {
        try
        {
            Directory.CreateDirectory(StoreDir);
            // Harden BEFORE ssh-keygen writes anything — a file created under an already-hardened
            // directory inherits the restricted ACL from the moment it exists, instead of briefly
            // holding the broader ProgramData-inherited default. Same lesson TunnelRunner's
            // WriteKeyMaterial doc comment already spells out for a different file.
            Config.HardenDirectory(StoreDir);

            try { File.Delete(PrivateKeyPath); } catch { /* fine if absent */ }
            try { File.Delete(PublicKeyPath); } catch { /* fine if absent */ }

            var sshKeygenExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "OpenSSH", "ssh-keygen.exe");
            var psi = new ProcessStartInfo(sshKeygenExe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            // ArgumentList — never a hand-quoted Arguments string — so the empty passphrase ("")
            // and the comment can't be mangled by Win32 command-line requoting.
            psi.ArgumentList.Add("-t");
            psi.ArgumentList.Add("ed25519");
            psi.ArgumentList.Add("-N");
            psi.ArgumentList.Add("");
            psi.ArgumentList.Add("-f");
            psi.ArgumentList.Add(PrivateKeyPath);
            psi.ArgumentList.Add("-C");
            psi.ArgumentList.Add("remoteassist-device-" + DeviceIdentity.DeviceId);

            using var proc = Process.Start(psi);
            if (proc is null) return false;
            if (!proc.WaitForExit(15000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                return false;
            }
            if (proc.ExitCode != 0) return false;
            if (!File.Exists(PrivateKeyPath) || !File.Exists(PublicKeyPath)) return false;

            _privateKeyPem = File.ReadAllText(PrivateKeyPath);
            _publicKeyOpenSsh = File.ReadAllText(PublicKeyPath).Trim();
            return !string.IsNullOrEmpty(_privateKeyPem) && !string.IsNullOrEmpty(_publicKeyOpenSsh);
        }
        catch
        {
            return false;
        }
    }
}
