using System.Runtime.InteropServices;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// Shared Win32 P/Invoke declarations — this codebase's convention is to keep P/Invoke file-local
/// (see AppControlWatcher.cs/DeviceStatusHelper.cs/SessionIndicatorForm.cs/SingleInstance.cs) until
/// a genuine need for 3+ overlapping calls exists. Thread suspend/resume has no managed .NET
/// wrapper at all (ProcessThread exposes no .Suspend()/.Resume()), which is exactly that case —
/// introduced for ProcessIntervention.cs's local autonomous-response path (see the EDR feature
/// plan's Phase 2/3 design).
/// </summary>
internal static class Win32Native
{
    internal const uint THREAD_SUSPEND_RESUME = 0x0002;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern int ResumeThread(IntPtr hThread);

    // Session-0-to-interactive-session notification (SecurityNotification.cs) — EdrWatcher.cs's
    // --edr-watch process runs as a SYSTEM scheduled task, which on a real Windows box means
    // Session 0 with NO interactive desktop of its own (the same isolation docs/ARCHITECTURE.md's screenshot
    // workflow already documents working around). A plain MessageBox.Show() from that process
    // would be invisible to the actual logged-in user. WTSSendMessage is the standard, purpose-
    // built Windows API for exactly this — a SYSTEM/Session-0 process popping a real message box
    // into a target interactive session.
    [DllImport("kernel32.dll")]
    internal static extern int WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool WTSSendMessage(IntPtr hServer, int sessionId, string title, int titleLength,
        string message, int messageLength, uint style, uint timeoutSeconds, out int response, bool bWait);

    // Process-hollowing heuristic (HollowingWatcher.cs, Phase 4) — checking whether the memory
    // region backing a process's own main-module base address is still MEM_IMAGE (a normal
    // loader-mapped EXE) is a standard, if narrow, indicator of the classic "unmap + rewrite"
    // hollowing technique (NtUnmapViewOfSection then VirtualAllocEx/WriteProcessMemory over the
    // same base) — the replacement memory shows up as MEM_PRIVATE instead. No managed API surfaces
    // this (Process/ProcessModule expose neither the underlying mapping type nor page protection).
    internal const uint PROCESS_QUERY_INFORMATION = 0x0400;
    internal const uint PROCESS_VM_READ = 0x0010;
    internal const uint MEM_COMMIT = 0x1000;
    internal const uint MEM_IMAGE = 0x1000000;
    internal const uint PAGE_EXECUTE_READWRITE = 0x40;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    // Drive-alias (subst) detection for RansomwareGuard.cs's drive-root watch scope. A subst'd
    // drive letter is NOT a real volume: GetVolumeInformation on Y:\ (subst of a folder on C:)
    // reports the UNDERLYING volume's serial, so any Fixed drive whose serial collides with
    // another drive is an alias. Aliases must be skipped entirely — the --edr-watch watcher
    // runs as SYSTEM, and per-session subst mappings (e.g. the S3 Drive feature's Y:/Z:) can
    // be invisible to that session, which made every canary on them look "deleted" on each
    // watcher restart and fired deleted-while-watcher-down + autonomous isolation (found live
    // 2026-08-02: five false isolates in one minute after a single agent update).
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool GetVolumeInformation(
        string lpRootPathName,
        StringBuilder lpVolumeNameBuffer, int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder lpFileSystemNameBuffer, int nFileSystemNameSize);

    internal static uint? VolumeSerial(string rootPath)
    {
        try
        {
            var vol = new StringBuilder(MAX_PATH);
            var fs = new StringBuilder(MAX_PATH);
            if (!GetVolumeInformation(rootPath, vol, vol.Capacity, out var serial, out _, out _, fs, fs.Capacity)) return null;
            return serial;
        }
        catch
        {
            return null;
        }
    }

    private const int MAX_PATH = 260;
}
