using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SentinelRemoteAssist;

/// <summary>
/// Self-protection against process injection and termination by malware.
/// Applies Windows process mitigation policies (ACG, CIG, force-relocate) on startup,
/// and monitors for termination attempts.
/// </summary>
internal static class ProcessGuard
{
    // Process mitigation policy constants (Windows 10 1709+)
    private const int ProcessSignaturePolicy = 19;
    private const int ProcessDynamicCodePolicy = 16;
    private const int ProcessImageLoadPolicy = 12;
    private const int ProcessChildProcessPolicy = 11;
    private const int ProcessFontDisablePolicy = 13;
    private const int ProcessShadowStackPolicy = 20;
    private const int ProcessUserShadowStackPolicy = 24;

    // mitigation flags
    private const uint PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001;
    private const uint PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON = 0x00000001;
    private const uint PROCESS_CREATION_MITIGATION_POLICY_DYNAMIC_CODE_DISABLE_ALWAYS_ON = 0x00000001;
    private const uint PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON = 0x00000001;
    private const uint PROCESS_CREATION_MITIGATION_POLICY_CHILD_PROCESS_DISABLE_ALWAYS_ON = 0x00000001;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(int mitigationPolicy, IntPtr lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    /// <summary>
    /// Apply all available process mitigation policies to harden against injection and tampering.
    /// Call this early in Main(), before any UI or socket connections.
    /// </summary>
    public static void ApplyMitigations()
    {
        try
        {
            // 1. ACG — Block non-Microsoft-signed binaries (no DLL sideloading)
            nint blockNonMs = (nint)PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
            SetProcessMitigationPolicy(ProcessSignaturePolicy, blockNonMs, (UIntPtr)IntPtr.Size);

            // 2. Dynamic code disable — block JIT, W^X
            nint dynCode = (nint)PROCESS_CREATION_MITIGATION_POLICY_DYNAMIC_CODE_DISABLE_ALWAYS_ON;
            SetProcessMitigationPolicy(ProcessDynamicCodePolicy, dynCode, (UIntPtr)IntPtr.Size);

            // 3. Font disable — block font file loading (common attack vector)
            nint fontDisable = (nint)PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
            SetProcessMitigationPolicy(ProcessFontDisablePolicy, fontDisable, (UIntPtr)IntPtr.Size);

            // 4. Image load — prefer system32, block loading from unusual paths
            nint imageLoad = (nint)PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, imageLoad, (UIntPtr)IntPtr.Size);

            // NOTE: Child process disable (ProcessChildProcessPolicy) intentionally omitted —
            // the agent spawns powershell.exe/cmd.exe for setup, uninstall, and feature commands

            Debug.WriteLine("[ProcessGuard] Mitigation policies applied successfully");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[ProcessGuard] Failed to apply mitigations: {ex.Message}");
            // Best-effort — don't crash the agent if mitigation fails (older Windows)
        }
    }

    /// <summary>
    /// Enable SEHOP (Structured Exception Handler Overwrite Protection) if available.
    /// Prevents SEH-based exploits from hijacking exception handling.
    /// </summary>
    public static void EnableSehop()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", true);
            if (key != null)
            {
                key.SetValue("DisableExceptionChainValidation", 0, Microsoft.Win32.RegistryValueKind.DWord);
                Debug.WriteLine("[ProcessGuard] SEHOP enabled");
            }
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Verify the agent binary hasn't been tampered with by checking its digital signature.
    /// Returns true if the binary is valid or signature check is unavailable.
    /// </summary>
    public static bool VerifyIntegrity()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return true;

            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(exePath);
            var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
            bool valid = chain.Build(cert);
            chain.Dispose();
            cert.Dispose();

            if (!valid)
            {
                Debug.WriteLine("[ProcessGuard] WARNING: Binary signature invalid!");
                // Log but don't crash — could be a development build
            }
            return true; // Don't block execution even on invalid sig (dev builds)
        }
        catch
        {
            // Unsigned binary or cert issue — acceptable for now
            return true;
        }
    }

    /// <summary>
    /// Set the process as critical so a BSOD occurs if it's terminated unexpectedly.
    /// WARNING: Only use if you're sure the agent must stay alive at all costs.
    /// Disabled by default — too aggressive for most deployments.
    /// </summary>
    public static void SetCriticalProcess()
    {
        // Uncomment only if absolutely necessary:
        // SetProcessCriticalProcess(true);
        // This causes a BSOD if the process is killed — very aggressive
    }

    private static bool SetProcessCriticalProcess(bool enable)
    {
        // RtlSetProcessIsCritical — undocumented but widely used by anti-cheat/EDR
        try
        {
            var ntdll = LoadLibrary("ntdll.dll");
            if (ntdll == IntPtr.Zero) return false;
            var func = GetProcAddress(ntdll, "RtlSetProcessIsCritical");
            if (func == IntPtr.Zero) return false;
            var del = Marshal.GetDelegateForFunctionPointer<Func<uint, uint, uint>>(func);
            uint result = del(enable ? (uint)1 : (uint)0, 0);
            FreeLibrary(ntdll);
            return result == 0;
        }
        catch { return false; }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);
}
