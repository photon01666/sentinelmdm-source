using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Local process/thread intervention primitives — the in-process, zero-round-trip path used by
/// autonomous local response (EdrWatcher.cs's canary-file/mass-encryption triggers, see the EDR
/// feature plan's autonomous-action policy table: only the near-zero-false-positive tier acts
/// without a human, and it must not wait on a dashboard/bastion round trip to do it). The
/// dashboard-triggered "Kill" button goes through a SEPARATE bastion-side one-shot PS1
/// (taskkill /PID $Pid /T /F — Windows' own tree-kill, no P/Invoke needed there) with its own
/// Hop-2 safety rails; this class is not used for that path.
/// </summary>
internal static class ProcessIntervention
{
    /// <summary>Kills a process and its full descendant tree by PID. Best-effort, matching every
    /// other process-kill call in this codebase (e.g. TunnelRunner.Stop()) — a PID that already
    /// exited, or one this process lacks rights to touch, is swallowed rather than thrown.</summary>
    public static bool KillProcessTree(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (!proc.HasExited) proc.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Suspends every thread of the given process. No managed .NET wrapper exists for
    /// thread suspend/resume (ProcessThread has no .Suspend()) — P/Invoke via Win32Native is the
    /// only option. Best-effort per thread: one thread failing to suspend does not roll back
    /// threads already suspended (a partially-suspended process is still safer than a fully-live
    /// one for this primitive's callers).</summary>
    public static bool SuspendProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var ok = true;
            foreach (ProcessThread thread in proc.Threads)
            {
                var handle = Win32Native.OpenThread(Win32Native.THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (handle == IntPtr.Zero) { ok = false; continue; }
                try
                {
                    if (Win32Native.SuspendThread(handle) == 0xFFFFFFFF) ok = false;
                }
                finally
                {
                    Win32Native.CloseHandle(handle);
                }
            }
            return ok;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Resumes every thread of the given process — undoes <see cref="SuspendProcess"/>.</summary>
    public static bool ResumeProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var ok = true;
            foreach (ProcessThread thread in proc.Threads)
            {
                var handle = Win32Native.OpenThread(Win32Native.THREAD_SUSPEND_RESUME, false, (uint)thread.Id);
                if (handle == IntPtr.Zero) { ok = false; continue; }
                try
                {
                    if (Win32Native.ResumeThread(handle) == -1) ok = false;
                }
                finally
                {
                    Win32Native.CloseHandle(handle);
                }
            }
            return ok;
        }
        catch
        {
            return false;
        }
    }
}
