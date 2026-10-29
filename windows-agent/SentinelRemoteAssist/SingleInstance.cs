using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SentinelRemoteAssist;

/// <summary>
/// Ensures the customer UI cannot be opened twice (double-click / second launch).
/// Uses a named mutex scoped by the session's reverse-forward port so two different
/// customer EXEs (different sessions) can coexist on the same PC, but the same
/// support session cannot run two UIs at once (which would fight over the tunnel).
///
/// Elevated helpers (--setup / --uninstall / --set-autostart / --watchdog-check) and
/// the SYSTEM --unattended-tunnel process do NOT take the UI mutex — they must be
/// allowed to run while the UI is open (or in Session 0 before login).
/// </summary>
internal static class SingleInstance
{
    // Local\ = this Windows logon session only (user double-clicks). SYSTEM unattended
    // tunnel lives in Session 0 and has its own Local\ namespace, so it does not block the UI.
    private static string UiMutexName =>
        $@"Local\SentinelRemoteAssist-UI-p{SessionEmbedded.ForwardPort}";

    private static string TunnelMutexName =>
        $@"Global\SentinelRemoteAssist-Tunnel-p{SessionEmbedded.ForwardPort}";

    // Account-linked build only. Unlike UiMutexName/TunnelMutexName (port-scoped — the ad hoc
    // flow can have multiple different customer sessions' exes on the SAME operator machine), an
    // account-linked install has exactly ONE device identity, so a single fixed name is correct:
    // there is only ever one SentinelMDM device behind this mutex on this machine.
    //
    // Guards against a real first-run race (found live 2026-07-14): a user installs, logs in
    // (MainForm.BeginAccountLinkFlow opens a RemoteAssistSocket), then checks "Start
    // automatically" — SetupRunner registers the SYSTEM task and fires it immediately, so
    // RunUnattendedAccountLinkedSocket opens a SECOND, independent RemoteAssistSocket with the
    // SAME device identity. Neither TryAcquireUi nor TryAcquireTunnel catches this because they
    // are separate mutex families (Session-0 SYSTEM task vs interactive logon session) and
    // TryAcquireTunnel is never even called from the interactive path. The server's
    // connectedSockets map (server.js emitToDevice) is a last-write-wins Map keyed by deviceId —
    // whichever of the two registers LAST silently wins the command channel, so dashboard pushes
    // (set_remote_assist_transport, remote_assist_ssh_key, ...) can go to the "wrong" one with
    // zero error anywhere. This mutex ensures only one of the two ever holds a live
    // RemoteAssistSocket connection at a time.
    private static string ControlMutexName => @"Global\SentinelRemoteAssist-AccountLinked-Control";

    // --edr-watch (SYSTEM scheduled task, re-registered+started on every EDR enable/provision
    // AND on every agent cutover that re-provisions EDR). A second task fire while the first
    // watcher is still alive used to start a SECOND --edr-watch process that tailed the same
    // Sysmon log and fought the first over watcher-state.json — found live 2026-08-14 on the test VM
    // (two watchers, PIDs 3228+4336, recurring "could not save watcher state: file in use"
    // log spam, and events dropped/raced between the two). Global + fixed name: one device
    // identity per box, and the watcher must be unique across logon sessions (SYSTEM vs user).
    private static string EdrWatchMutexName => @"Global\SentinelRemoteAssist-EdrWatch";

    private static Mutex? _uiMutex;
    private static Mutex? _tunnelMutex;
    private static Mutex? _controlMutex;
    private static Mutex? _edrWatchMutex;

    /// <summary>
    /// Try to become the sole UI instance. Returns false if another UI is already running
    /// (caller should exit). Holds the mutex until process exit.
    /// </summary>
    public static bool TryAcquireUi()
    {
        try
        {
            _uiMutex = new Mutex(initiallyOwned: true, name: UiMutexName, createdNew: out var created);
            if (created) return true;
            // Another UI already holds it — release our failed wait ownership attempt.
            try { _uiMutex.Dispose(); } catch { /* ignore */ }
            _uiMutex = null;
            return false;
        }
        catch (AbandonedMutexException)
        {
            // Previous owner crashed without releasing — we own it now.
            return true;
        }
        catch
        {
            // Fail open only if mutex machinery is broken — still better to run support
            // than hard-block. (Extremely rare.)
            return true;
        }
    }

    /// <summary>
    /// Try to own the sole tunnel for this session port (used by --unattended-tunnel).
    /// Prevents two unattended processes from fighting over the same bastion reverse port.
    /// </summary>
    public static bool TryAcquireTunnel()
    {
        try
        {
            _tunnelMutex = new Mutex(initiallyOwned: true, name: TunnelMutexName, createdNew: out var created);
            if (created) return true;
            try { _tunnelMutex.Dispose(); } catch { /* ignore */ }
            _tunnelMutex = null;
            return false;
        }
        catch (AbandonedMutexException)
        {
            return true;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Account-linked build only. Try to become the sole holder of the live
    /// RemoteAssistSocket control channel — see ControlMutexName's doc comment for the exact
    /// race this closes. Non-blocking: returns immediately either way.
    /// </summary>
    public static bool TryAcquireControlChannel()
    {
        try
        {
            _controlMutex = new Mutex(initiallyOwned: true, name: ControlMutexName, createdNew: out var created);
            if (created) return true;
            try { _controlMutex.Dispose(); } catch { /* ignore */ }
            _controlMutex = null;
            return false;
        }
        catch (AbandonedMutexException)
        {
            return true;
        }
        catch
        {
            return true;
        }
    }

    public static void ReleaseControlChannel()
    {
        try { _controlMutex?.ReleaseMutex(); } catch { /* ignore */ }
        try { _controlMutex?.Dispose(); } catch { /* ignore */ }
        _controlMutex = null;
    }

    /// <summary>
    /// Try to become the sole --edr-watch watcher on this machine. Returns false if another
    /// watcher is already running (caller should exit immediately). Holds the mutex until
    /// process exit. Same fail-open-on-mutex-broken policy as the UI/tunnel guards.
    /// </summary>
    public static bool TryAcquireEdrWatch()
    {
        try
        {
            _edrWatchMutex = new Mutex(initiallyOwned: true, name: EdrWatchMutexName, createdNew: out var created);
            if (created) return true;
            try { _edrWatchMutex.Dispose(); } catch { /* ignore */ }
            _edrWatchMutex = null;
            return false;
        }
        catch (AbandonedMutexException)
        {
            // Previous owner crashed without releasing — we own it now.
            return true;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Interactive path only (MainForm.BeginAccountLinkFlow): a real person is at the keyboard
    /// and about to open the control channel, but an unattended --unattended-tunnel instance
    /// already holds it. Mirrors the existing precedent for the ad hoc flow's analogous race
    /// ("Unattended Access & UI race-condition fixes" — disabling the UI during connection
    /// states and killing lingering foreground tunnels during handover): the interactive
    /// session, with an actual user present who can see the consent dialog, always wins — kill
    /// the headless instance rather than silently opening a second, competing socket that would
    /// leave the server's connectedSockets map pointed at whichever registers last.
    /// </summary>
    public static void TakeOverFromUnattendedInstance()
    {
        foreach (var p in Process.GetProcessesByName("SentinelRemoteAssist"))
        {
            try
            {
                if (p.Id == Environment.ProcessId) continue;
                p.Kill(entireProcessTree: true);
                p.WaitForExit(5000);
            }
            catch { /* access denied / already exited — best effort */ }
            finally
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
    }

    /// <summary>Show a brief message when a second UI launch is blocked, and try to focus the first.</summary>
    public static void NotifyAlreadyRunning()
    {
        try
        {
            // Best-effort: bring an existing window to the foreground if we can find one
            // with our title. Silent if it fails (tray-only / unattended-covert mode).
            TryActivateExistingWindow();
        }
        catch { /* ignore */ }

        try
        {
            MessageBox.Show(
                "Sentinel Remote Assist is already running.\n\n" +
                "Check the system tray (or C:\\ProgramData\\SentinelRemoteAssist if Start-automatically is on).",
                "Already running",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch { /* headless / no desktop */ }
    }

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_RESTORE = 9;

    private static void TryActivateExistingWindow()
    {
        // Match MainForm title prefix used for the window.
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id == Environment.ProcessId) continue;
                var title = p.MainWindowTitle;
                if (string.IsNullOrEmpty(title)) continue;
                if (!title.Contains("Sentinel Remote Assist", StringComparison.OrdinalIgnoreCase))
                    continue;
                var h = p.MainWindowHandle;
                if (h == IntPtr.Zero) continue;
                ShowWindow(h, SW_RESTORE);
                SetForegroundWindow(h);
                return;
            }
            catch { /* access denied / exited */ }
            finally
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
    }
}
