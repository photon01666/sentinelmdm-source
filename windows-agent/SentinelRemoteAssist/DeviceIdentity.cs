using System.Security.Cryptography;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// Persistent per-install EC P-256 device identity for the account-linked login flow — mirrors the
/// Android agent's hardware-backed Keystore key (Prefs.getOrCreateDeviceId() + the signed
/// {deviceId, timestamp, signature} handshake, see docs/ARCHITECTURE.md "Device Identity & Handshakes"). The
/// server's verifyWithPublicKey() (server.js) expects: public key = base64(DER SPKI), signature =
/// base64(DER ECDSA-SHA256 over UTF8 "{deviceId}:{timestamp}") — exactly what ECDsa produces with
/// DSASignatureFormat.Rfc3279DerSequence, so no format translation is needed on either side.
///
/// Stored OUTSIDE Config.SessionKeyDir (which UninstallRunner wipes on every ephemeral
/// disconnect/uninstall) so identity survives across sessions on the SAME physical machine, the
/// same way Prefs.getOrCreateDeviceId() survives app restarts on Android. DPAPI-protected at
/// LocalMachine scope since setup/tunnel code runs both interactively and as SYSTEM (WatchdogRunner,
/// the unattended-tunnel task) and all of them must be able to read the same identity.
/// </summary>
internal static class DeviceIdentity
{
    private static readonly string StoreDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SentinelRemoteAssistIdentity");
    private static readonly string IdPath  = Path.Combine(StoreDir, "device-id.txt");
    private static readonly string KeyPath = Path.Combine(StoreDir, "device-key.dat");

    private static string? _deviceId;
    private static ECDsa? _ecdsa;

    public static string DeviceId
    {
        get
        {
            EnsureLoaded();
            return _deviceId!;
        }
    }

    /// <summary>base64(DER SPKI) — sent once at first-bind enrollment (POST /api/enrollment/ticket's
    /// socket handshake carries {publicKey, deviceId, ...}), mirroring the Android agent's TOFU
    /// public-key bind.</summary>
    public static string PublicKeyBase64
    {
        get
        {
            EnsureLoaded();
            return Convert.ToBase64String(_ecdsa!.ExportSubjectPublicKeyInfo());
        }
    }

    /// <summary>Signs "{deviceId}:{timestampMs}" — the exact string verifyWithPublicKey() checks.</summary>
    public static string Sign(long timestampMs)
    {
        EnsureLoaded();
        var data = Encoding.UTF8.GetBytes($"{DeviceId}:{timestampMs}");
        var sig = _ecdsa!.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Convert.ToBase64String(sig);
    }

    /// <summary>
    /// Stable per-OS-install hardware identifier, sent as auth.hwId in the socket handshake — the
    /// Windows counterpart of the Android agent's stableHardwareId() (SocketManager.kt) and the
    /// Linux daemon's /etc/machine-id reader (daemon.go stableHardwareID()). Reads the MachineGuid
    /// Windows mints once at OS install (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid) and caches
    /// it. Unlike DeviceId this is NOT the agent's identity: it survives agent reinstall but changes
    /// on a full Windows reinstall — which is exactly the "same physical machine" signal the server's
    /// trial-abuse serial_hmac leg keys on. Empty string if the value can't be read (the server
    /// treats a missing hwId as "unknown" and that leg stays alert-only — never a hard gate).
    /// </summary>
    public static string HardwareId
    {
        get
        {
            if (_hardwareId is null)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                    var guid = key?.GetValue("MachineGuid") as string;
                    _hardwareId = string.IsNullOrWhiteSpace(guid) ? "" : guid.Trim();
                }
                catch
                {
                    _hardwareId = "";
                }
            }
            return _hardwareId;
        }
    }
    private static string? _hardwareId;

    private static void EnsureLoaded()
    {
        if (_ecdsa is not null) return;
        Directory.CreateDirectory(StoreDir);

        if (File.Exists(IdPath) && File.Exists(KeyPath))
        {
            try
            {
                _deviceId = File.ReadAllText(IdPath).Trim();
                var protectedBytes = File.ReadAllBytes(KeyPath);
                var derBytes = ProtectedDataUnprotect(protectedBytes);
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(derBytes, out _);
                _ecdsa = ecdsa;
                if (!string.IsNullOrEmpty(_deviceId)) return;
            }
            catch
            {
                // Corrupt/unreadable identity (e.g. moved to a different machine, DPAPI scope
                // mismatch) — fall through and mint a fresh one rather than crash the agent.
            }
        }

        // First run on this machine (or a corrupt store) — mint a fresh identity.
        _deviceId = "ra-" + Guid.NewGuid().ToString("N");
        var fresh = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _ecdsa = fresh;
        try
        {
            File.WriteAllText(IdPath, _deviceId);
            var protectedBytes = ProtectedDataProtect(fresh.ExportECPrivateKey());
            File.WriteAllBytes(KeyPath, protectedBytes);
            Config.HardenDirectory(StoreDir);
        }
        catch
        {
            // Best-effort persistence — a failure here just means a fresh identity gets minted
            // again next launch, not a crash.
        }
    }

    private static byte[] ProtectedDataProtect(byte[] data) =>
        System.Security.Cryptography.ProtectedData.Protect(data, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);

    private static byte[] ProtectedDataUnprotect(byte[] data) =>
        System.Security.Cryptography.ProtectedData.Unprotect(data, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
}
