namespace SentinelRemoteAssist;

internal sealed class MainForm : Form
{
    private readonly Label _explainer;
    private readonly TextBox _log;
    private readonly ProgressBar _progress;
    private readonly Button _connectButton;
    /// <summary>"Install the EDR" toggle button — same underlying action as the old "Start
    /// automatically after reboot" checkbox (AutoStartManager.SetEnabled), just presented as a
    /// button next to CONNECT instead of a checkbox below it, with typed-YES confirmation instead
    /// of a technician PIN. See OnAutoStartButtonClick/UpdateAutoStartButtonText.</summary>
    private readonly Button _autoStartButton;
    private readonly NotifyIcon _trayIcon;
    /// <summary>AI Live Chat tray menu item — visibility gated on the admin's per-device opt-in
    /// flag (AccountLinkedSession.AiChatEnabled), NOT on attended/unattended mode (that governs the
    /// tray icon's own top-level Visible, unchanged, so Disconnect/Exit stay reachable regardless of
    /// this feature's opt-in state). See RemoteAssistSocket.AiChatEnabledChanged subscription below.</summary>
    private ToolStripMenuItem? _liveChatItem;
    /// <summary>Singleton — reused across menu clicks so the customer doesn't accumulate multiple
    /// chat windows/conversations. Recreated only if disposed (window closed) or the socket
    /// reference changes (a fresh RemoteAssistSocket after reconnect/handover).</summary>
    private AiChatForm? _aiChatForm;

    private TunnelRunner? _tunnel;
    /// <summary>Account-linked build only — null for the legacy ad hoc build. Owns the local xray
    /// REALITY client process TunnelRunner's ssh.exe tunnels through; see SessionConfig.Current's
    /// account-linked branch and BeginConnect's xray-start step.</summary>
    private XrayTransportManager? _xrayTransport;
    /// <summary>Account-linked build only — manages the xray SOCKS5 VPN tunnel and Windows system
    /// proxy for SentinelRemoteAssist devices. Created alongside RemoteAssistSocket; receives the
    /// XrayTransportManager reference when one is created.</summary>
    private VpnManager? _vpnManager;
    /// <summary>Account-linked build only — manages the S3 Bucket Network Drive (Private + Public
    /// shares). Created once and persists across control-channel handovers (unlike VpnManager/
    /// XrayTransportManager, its rclone bisync loop has nothing to do with which process holds the
    /// socket) — Start()/Stop() are called once per process lifetime, not per StartControlChannelInteractive().</summary>
    private S3DriveManager? _s3DriveManager;
    private bool _s3DriveManagerStarted;
    /// <summary>Account-linked build only — the persistent control-channel socket, connected once
    /// after a successful AccountLoginForm login (or immediately on startup if a device identity
    /// already exists from a prior run, mirroring the Android agent's SocketManager.connect()
    /// restoring state across restarts).</summary>
    private RemoteAssistSocket? _remoteAssistSocket;
    /// <summary>True while Connect→Start-auto (or Start-auto alone) is handing the tunnel from
    /// the local process over to the SYSTEM unattended tunnel. BeginConnect must not start a
    /// second local ssh during this window (port fight on the bastion).</summary>
    private volatile bool _autoStartHandoff;
    private bool _connected;
    private System.Windows.Forms.Timer? _elapsedTimer;
    private DateTime _workStartedAt;

    private readonly bool _startHidden;

    /// <summary>Ephemeral CONNECT only: consent accepted this process lifetime (not for Start-auto).</summary>
    private bool _ephemeralConsentGranted;
    /// <summary>Ephemeral CONNECT only: always-on-top "session active" banner.</summary>
    private SessionIndicatorForm? _sessionIndicator;

    /// <param name="startHiddenAndAutoConnect">True when launched as "--autostart" from the HKCU
    /// Run key (AutoStartManager) — the window starts hidden (tray icon only, no flash of a
    /// visible window at every login) and immediately attempts Connect on its own, same as if the
    /// user had clicked the button.</param>
    public MainForm(bool startHiddenAndAutoConnect = false)
    {
        _startHidden = startHiddenAndAutoConnect;
        // Real-device testing (2026-07-08) showed hardcoded pixel coordinates clip badly under
        // Windows display scaling (125%/150%+ is common) — a fixed-pixel layout doesn't grow with
        // it. AutoScaleMode.Dpi + a TableLayoutPanel (rows size themselves to content / fill / fit)
        // replaces all manual Left/Top/Width/Height math so the window is correct at any DPI.
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96F, 96F);

        Text = $"Sentinel Remote Assist — v{Config.AgentVersion}";
        // Height bumped from 640 to 720 (2026-07-20, agent 1.8.6) — the explainer text grew to
        // describe both CONNECT and the new "Install the EDR" button; the old fixed height left
        // the button row squeezed off the bottom of the window (found live, screenshot showed no
        // buttons at all, just an overflowed/scrollable explainer label).
        ClientSize = new Size(820, 720);
        MinimumSize = new Size(700, 640);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        BackColor = Color.FromArgb(32, 32, 32);
        ForeColor = Color.White;

        if (_startHidden)
        {
            // Belt-and-suspenders on top of the Hide()-in-Load below: park the window off-screen
            // and out of the taskbar BEFORE it's ever shown, so even if the framework's internal
            // show sequence briefly makes it Visible before Load's Hide() call takes effect, there
            // is nothing on-screen for the user to see or click into. Found necessary live
            // (2026-07-09): Hide()-in-Load alone still let the window visibly pop up on screen at
            // boot — the timing between the framework showing it and our own code hiding it again
            // isn't reliable enough on its own to promise zero visible flash.
            StartPosition = FormStartPosition.Manual;
            Location = new Point(-32000, -32000);
            ShowInTaskbar = false;
        }
        else
        {
            StartPosition = FormStartPosition.CenterScreen;
        }

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(16),
            ColumnCount = 1,
            RowCount = 4,
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _explainer = new Label
        {
            Text =
                "This lets Sentinel support connect to your PC to help you.\n\n" +
                "CONNECT starts a one-time support session (short agreement first; an on-screen\n" +
                "banner shows while active). End with DISCONNECT, or close this window to fully\n" +
                "remove access (a session log is left on your Desktop).\n\n" +
                "INSTALL THE EDR keeps protection running in the background across reboots, with\n" +
                "no window or CONNECT needed. A type-YES prompt confirms turning it on; click\n" +
                "again anytime to turn it off.",
            AutoSize = true,
            MaximumSize = new Size(780, 0),
            Margin = new Padding(0, 0, 0, 16),
            Font = new Font("Segoe UI", 11F),
            ForeColor = Color.FromArgb(200, 205, 210),
        };

        _log = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Text = "Ready.",
            Margin = new Padding(0, 0, 0, 12),
            BackColor = Color.FromArgb(20, 20, 20),
            ForeColor = Color.LightGreen,
            Font = new Font("Consolas", 10F),
            BorderStyle = BorderStyle.FixedSingle,
        };

        // Marquee (not percentage) — Add-WindowsCapability doesn't expose reliable progress over
        // a redirected, non-interactive stream without reintroducing the pipe-deadlock risk that
        // was just fixed in SetupRunner (see its comments), so this is honest "working", not a
        // fake percentage. Paired with the elapsed-time ticker below so it's never silent long.
        _progress = new ProgressBar
        {
            Dock = DockStyle.Fill,
            Style = ProgressBarStyle.Marquee,
            MarqueeAnimationSpeed = 30,
            Height = 20,
            Visible = false,
            Margin = new Padding(0, 0, 0, 12),
        };

        _connectButton = new Button
        {
            Text = "CONNECT",
            Dock = DockStyle.Fill,
            Height = 56,
            Margin = new Padding(0, 0, 6, 0),
            Font = new Font(Font.FontFamily, 14, FontStyle.Bold),
            BackColor = Color.SeaGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
        };
        _connectButton.FlatAppearance.BorderSize = 0;
        _connectButton.Click += OnConnectButtonClick;

        // "Install the EDR" — same underlying action as the old "Start automatically after
        // reboot" checkbox (AutoStartManager.SetEnabled), now a button next to CONNECT instead
        // of a checkbox below it. Text/color reflect current state via UpdateAutoStartButtonText.
        _autoStartButton = new Button
        {
            Dock = DockStyle.Fill,
            Height = 56,
            Margin = new Padding(6, 0, 0, 0),
            Font = new Font(Font.FontFamily, 14, FontStyle.Bold),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
        };
        _autoStartButton.FlatAppearance.BorderSize = 0;
        _autoStartButton.Click += OnAutoStartButtonClick;
        UpdateAutoStartButtonText();

        var actionRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0),
        };
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        actionRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        actionRow.Controls.Add(_connectButton, 0, 0);
        actionRow.Controls.Add(_autoStartButton, 1, 0);

        layout.Controls.Add(_explainer, 0, 0);
        layout.Controls.Add(_log, 0, 1);
        layout.Controls.Add(_progress, 0, 2);
        layout.Controls.Add(actionRow, 0, 3);

        Controls.Add(layout);

        // Form.Icon is never auto-populated from app.ico for a hand-written (non-designer) form —
        // ApplicationIcon in the csproj only sets the compiled exe's own Win32 resource icon.
        // ExtractAssociatedIcon reads that resource back out at runtime, so the window and tray
        // icon both show the real Sentinel icon instead of the generic WinForms default.
        var appIcon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;
        Icon = appIcon;

        // In ATTENDED (ephemeral) mode the tray icon is always present — "clearly show it's
        // running" — visible whether the window is shown, minimized, or started hidden. In
        // UNATTENDED mode (autostart enabled) the tool is meant to run silently, so the tray icon
        // is hidden from the start (and kept hidden as Install the EDR is toggled — see the
        // handler below). To manage/disable it the operator relaunches the exe from
        // C:\ProgramData\SentinelRemoteAssist manually, which opens the window with the button
        // already showing "Disable the EDR".
        _trayIcon = new NotifyIcon
        {
            Icon = appIcon,
            Text = "Sentinel Remote Assist — Ready",
            // No tray icon at all unless AI Live Chat is enabled for this device — in ANY mode
            // (attended or autostart/"Install the EDR"). The tray's only job now is Live Chat; a
            // device without it enabled gets no tray presence.
            Visible = AccountLinkedSession.AiChatEnabled,
        };
        var trayMenu = new ContextMenuStrip();
        var showItem = new ToolStripMenuItem("Show window");
        showItem.Click += (_, _) => RestoreFromTray();
        showItem.Visible = !AutoStartManager.IsEnabled;   // agent UI hidden in autostart
        _liveChatItem = new ToolStripMenuItem("Live Chat") { Visible = AccountLinkedSession.AiChatEnabled };
        _liveChatItem.Click += (_, _) => OpenLiveChat();
        var disconnectItem = new ToolStripMenuItem("Disconnect");
        disconnectItem.Click += (_, _) =>
        {
            if (_connected && ConfirmTermination()) Disconnect();
        };
        disconnectItem.Visible = !AutoStartManager.IsEnabled;   // agent UI hidden in autostart
        // "Exit (removes remote-support access)" removed from the tray menu on purpose — the tray's
        // primary job is now opening Live Chat; removing local remote-support access is no longer a
        // one-click tray action (still reachable from the visible MainForm window's X/Alt+F4 when
        // that window is shown at all).
        trayMenu.Items.Add(showItem);
        trayMenu.Items.Add(_liveChatItem);
        trayMenu.Items.Add(disconnectItem);
        _trayIcon.ContextMenuStrip = trayMenu;
        // Clicking the icon itself opens Live Chat when it's enabled for this device (the tray's
        // primary purpose) — falls back to the old "show the Connect/EDR window" behavior when AI
        // Chat isn't enabled, so the icon still does something useful on a device without it.
        void OnTrayIconActivate()
        {
            if (AccountLinkedSession.AiChatEnabled) OpenLiveChat();
            else RestoreFromTray();
        }
        _trayIcon.Click += (_, e) => { if (e is MouseEventArgs { Button: MouseButtons.Left }) OnTrayIconActivate(); };
        _trayIcon.DoubleClick += (_, _) => OnTrayIconActivate();

        // Poll the disk-persisted AiChatEnabled flag so the tray icon (and its Live Chat item)
        // stay correct as the admin toggles it remotely — in autostart mode THIS interactive
        // process has no socket of its own (the SYSTEM service's socket receives the server-pushed
        // "set_ai_chat" command, and this process reads it from disk instead); in attended mode
        // this process DOES have a live socket and AiChatEnabledChanged already updates things
        // immediately, but the poll is harmless/redundant there, not gated to one mode only — the
        // tray's visibility rule (AiChatEnabled, full stop) applies identically in both.
        var aiChatPollTimer = new System.Windows.Forms.Timer { Interval = 5000 };
        aiChatPollTimer.Tick += (_, _) =>
        {
            var ai = AccountLinkedSession.AiChatEnabled;
            if (_liveChatItem is not null) _liveChatItem.Visible = ai;
            _trayIcon.Visible = ai;
        };
        aiChatPollTimer.Start();

        Resize += (_, _) =>
        {
            if (WindowState == FormWindowState.Minimized) Hide();
        };

        Load += (_, _) =>
        {
            if (_startHidden)
            {
                // The reliable way to start invisible: let the form go through its NORMAL show
                // sequence (so Load actually fires) and hide it from WITHIN Load itself, before
                // the framework ever paints/shows the native window on screen. An earlier attempt
                // instead overrode SetVisibleCore to force Visible=false permanently and never let
                // the form become visible at all — that looked reasonable but silently broke
                // autostart: WinForms only raises Load as part of a form BECOMING visible, and
                // Control.CreateControl() (the documented way to force that without becoming
                // visible) turned out to itself check Visible and no-op when it's already false —
                // so Load never fired, and the app just sat there doing nothing until the window
                // was shown manually. Found live, 2026-07-09, confirmed twice (once on the
                // original bug, once again after the CreateControl() fix attempt didn't help).
                Hide();
            }

            if (AutoStartManager.IsEnabled && AccountLinkedSession.IsPreviouslyEnrolled)
            {
                // Autostart ON + already enrolled: the SYSTEM background service (the AtStartup
                // --unattended-tunnel task) owns the control channel and handles ALL sessions +
                // Hop-2 key installs as SYSTEM, with no UAC. The interactive UI must NOT open a
                // competing RemoteAssistSocket / take the control-channel mutex — that deadlocks the
                // SYSTEM process (it waits forever on the mutex), which is exactly what left
                // dashboard sessions stuck "Orphan" and re-prompted UAC on every session start
                // (found live 2026-07-15). So this window is status-only; the real work is the
                // SYSTEM service's. Clicking "Disable the EDR" returns to on-demand mode.
                _connected = true;
                _connectButton.Text = "DISCONNECT";
                _connectButton.BackColor = Color.Firebrick;
                _trayIcon.Text = "Sentinel Protection - Enabled";
                if (!_startHidden)
                    AppendLog("Running in background (unattended) mode — the background service is "
                        + "handling the connection with no prompts. Support can start a session at "
                        + "any time. Click “Disable the EDR” to switch to on-demand mode.");
            }
            else if (!SessionEmbedded.IsConfigured &&
                     Config.AutoProvisionBuild &&
                     AutoProvisionFlow.IsConfigured &&
                     !AccountLinkedSession.IsPreviouslyEnrolled)
            {
                // Auto-provisioning installer variant (2.0.3), FIRST run on this PC: ToS/MSA
                // dialog -> elevated cutover+install (UAC) -> enroll with the baked account ticket.
                // No login is ever shown on the target PC. Declining the ToS exits without
                // installing. Already-enrolled upgrades/reboots never reach this branch.
                if (!_startHidden) Hide();
                BeginAutoProvisionFlow();
            }
            else if (!SessionEmbedded.IsConfigured &&
                     Config.AutoProvisionBuild &&
                     AutoProvisionFlow.IsConfigured &&
                     AccountLinkedSession.IsPreviouslyEnrolled)
            {
                // Already-enrolled auto-provisioning install (upgrade or reboot with autostart
                // OFF) — reconnect the control socket via the existing signed-auth identity, no
                // ToS, no ticket, no login.
                AccountLinkedSession.IsLinked = true;
                if (!_startHidden) AppendLog("Reconnecting this device to the SentinelMDM dashboard...");
                StartControlChannelInteractive(null);
            }
            else if (!SessionEmbedded.IsConfigured &&
                     Config.AccountLinkedBuild &&
                     !Config.AutoProvisionBuild &&
                     !AccountLinkedSession.IsLinked)
            {
                // Account-linked build, first Load of this run — show the SentinelMDM login
                // screen. This is purely account-gated access control on top of the UNCHANGED
                // consent dialog/session indicator/ephemeral-account flow below — logging in does
                // not itself start a tunnel or bypass local consent; it only lets the dashboard
                // reach this device's control socket and, later, trigger the SAME consent-gated
                // Connect flow OnConnectButtonClick uses (see OnRemoteAssistSessionRequested).
                //
                // Hide FIRST, unconditionally (not just when _startHidden) -- Load fires as part of
                // this window BECOMING visible (see the _startHidden comment above), so without
                // this the main "connect page" was already on screen underneath the login dialog
                // the whole time. Dismissing/cancelling that dialog then just revealed the
                // still-open, fully-usable window regardless of whether sign-in actually succeeded
                // — found live 2026-07-21. BeginAccountLinkFlow() re-Shows it on a successful
                // sign-in, or exits the process on cancel; either way this window must never be
                // visible without a completed sign-in for an account-linked build.
                if (!_startHidden) Hide();
                BeginAccountLinkFlow();
            }
        };

        FormClosed += (_, _) =>
        {
            HideSessionIndicator();
            _sessionIndicator?.Dispose();
            _sessionIndicator = null;
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            AccountLinkedSession.SessionRequested -= OnRemoteAssistSessionRequested;
            try { _remoteAssistSocket?.Disconnect(); } catch { /* best-effort */ }
            try { _vpnManager?.Stop(); } catch { /* best-effort */ }
            try { _xrayTransport?.Stop(); } catch { /* best-effort */ }
        };

        FormClosing += (sender, e) =>
        {
            // UNATTENDED mode (autostart enabled): closing this window must NOT tear anything down.
            // The tunnel + account are owned by the SYSTEM tasks and are SUPPOSED to persist across
            // reboots and across the UI process coming and going — that is the entire point of the
            // "Install the EDR" button. So skip the confirm dialog AND the uninstall here; the
            // SYSTEM AtStartup tunnel keeps running, and the operator only ever tears it down by
            // clicking "Disable the EDR" (which routes through OnAutoStartButtonClick).
            if (AutoStartManager.IsEnabled)
            {
                _tunnel?.Stop(); // no-op in this mode (no local tunnel), but harmless.
                HideSessionIndicator(); // never shown in unattended, but safe.
                return;
            }

            if (e.CloseReason == CloseReason.UserClosing)
            {
                if (!ConfirmTermination())
                {
                    e.Cancel = true;
                    return;
                }
            }
            _tunnel?.Stop();
            HideSessionIndicator();

            // ATTENDED (ephemeral) mode: closing the app itself (X / Alt+F4 / task-manager "End
            // task" — anything that reaches FormClosing) removes the local admin account this run
            // installed. Deliberately NOT done from OnConnectButtonClick's Disconnect path — only
            // actually closing the window revokes standing access, so the customer can
            // disconnect/reconnect within one open session without re-elevating each time. Skipped
            // for WindowsShutDown specifically: popping a UAC prompt during OS shutdown is unreliable
            // and can hang the shutdown sequence — the watchdog task catches that case on next boot
            // instead (see WatchdogRunner). A true forced kill (task-manager "End process", crash,
            // power loss) never reaches this handler at all — same watchdog fallback, ~1 minute.
            if (e.CloseReason != CloseReason.WindowsShutDown && SetupRunner.IsSetupComplete)
            {
                AppendLog("Removing remote-support access from this PC (a Windows permission prompt will appear)...");
                SessionAuditLog.LogAction("UNINSTALL requested (app closing — ephemeral session cleanup)");
                _log.Refresh();
                // RunElevatedUninstall publishes the session log to Desktop first, then elevates.
                var ok = UninstallRunner.RunElevatedUninstall();
                AppendLog(ok
                    ? "Cleanup finished. A cleanup verification report was also saved to your Desktop."
                    : "Cleanup failed or the permission prompt was declined — residual access is removed within about a minute.");
                // Whether or not that succeeded (e.g. the UAC prompt was declined) the window still
                // closes — the watchdog task remains armed until a successful uninstall unregisters
                // it, so a declined prompt here is still caught within about a minute.
                var logPath = SessionAuditLog.DesktopCopyPath;
                if (!string.IsNullOrEmpty(logPath))
                    AppendLog($"Session log saved to: {logPath}");
            }
            else if (SessionAuditLog.IsActive)
            {
                var logPath = SessionAuditLog.EndAndPublish("app-closed-no-setup");
                if (!string.IsNullOrEmpty(logPath))
                    AppendLog($"Session log saved to: {logPath}");
            }
        };

        if (SessionEmbedded.IsConfigured)
        {
            // Legacy ad hoc build — unchanged behavior.
        }
        else if (!Config.AccountLinkedBuild)
        {
            // Neither a baked ad hoc session NOR a real account-linked build — template/dev build
            // (this .exe wasn't produced by bastion-builder's build_account_linked_exe(), which is
            // what passes -p:AccountLinkedBuild=true).
            AppendLog("This build has no session configured — it's a template/dev build.");
            AppendLog("Ask support to send you a build made for your session.");
            _connectButton.Enabled = false;
        }
        else
        {
            // Account-linked build, ready to go — the CONNECT button stays enabled but
            // BeginConnect (via OnConnectButtonClick) requires AccountLinkedSession.IsLinked,
            // which the login flow (triggered from Load below) sets on success. No separate gate
            // needed here: SessionConfig.IsConfigured already covers this via
            // AccountLinkedSession's XrayLocalPort/BastionForwardPort checks.
        }
    }

    /// <summary>
    /// Account-linked build only. Shows AccountLoginForm; on success starts the persistent
    /// RemoteAssistSocket control channel (register/heartbeat + server pushes) and subscribes to
    /// AccountLinkedSession.SessionRequested — the signal that a dashboard user has clicked
    /// "start remote-assist session" for THIS device. That handler (below) reuses the EXISTING
    /// consent-gated Connect flow unchanged; login only adds account-based access control on top.
    /// </summary>
    private void BeginAccountLinkFlow()
    {
        var ticket = AccountLoginForm.ShowAndGetTicket(this);
        if (!AccountLinkedSession.IsLinked)
        {
            // An account-linked build must not proceed to a usable window at all without a
            // completed sign-in (the caller already Hid() this window before showing the login
            // dialog specifically so this never has anything visible to leave behind) — exit
            // outright rather than falling through to the old "ad hoc" fallback, which used to
            // leave the fully-usable main window sitting open with no actual account link behind
            // it. Environment.Exit (not Close()/Application.Exit) is deliberate: nothing has been
            // set up yet at this point in the flow (no tunnel, no ephemeral account), so this
            // skips FormClosing's cleanup/confirm-termination logic entirely rather than risking
            // it doing something meant for an ACTIVE session's teardown.
            Environment.Exit(0);
            return;
        }

        Show();
        AppendLog("Signed in — connecting to the SentinelMDM dashboard...");
        StartControlChannelInteractive(ticket);
    }

    /// <summary>
    /// Auto-provisioning installer variant flow (2.0.3). The full sequence (ToS/MSA -> elevated
    /// cutover+install -> ticket) already ran in Program.Main BEFORE the UI started (see
    /// Program.cs — it must, because the cutover kills the old instance that held this window's
    /// mutex). MainForm only consumes the result: connect with the cached ticket (first run),
    /// reconnect via signed auth (upgrade over an already-enrolled install), or exit (declined).
    /// </summary>
    private void BeginAutoProvisionFlow()
    {
        var ticket = AutoProvisionFlow.LastTicket;
        if (ticket is null)
        {
            // Already enrolled — the cutover already ran in Main; reconnect with the existing
            // identity (no login, no ToS).
            AccountLinkedSession.IsLinked = true;
            if (!_startHidden) Show();
            StartControlChannelInteractive(null);
            return;
        }
        if (ticket.Length == 0)
        {
            AppendLog("Install cancelled — this computer was not modified.");
            Environment.Exit(0);
            return;
        }
        AccountLinkedSession.IsLinked = true;
        // Never Show() for auto-provision builds (always start hidden — tray only, see
        // Program.Main's comment). The connection still starts regardless.
        if (!_startHidden) Show();
        AppendLog("Installed — connecting to the SentinelMDM dashboard...");
        StartControlChannelInteractive(ticket);
    }

    /// <summary>
    /// Opens (or re-opens) THIS interactive process's control channel: takes the control-channel
    /// mutex (taking over any waiting SYSTEM --unattended-tunnel instance — see
    /// SingleInstance.ControlMutexName's doc comment), subscribes to dashboard session requests,
    /// and connects the RemoteAssistSocket over a fresh xray control channel. Used by the sign-in
    /// flow and when returning to on-demand mode after autostart is turned OFF.
    ///
    /// NOT used while autostart is ON — there the SYSTEM background service owns the control channel
    /// and handles every session + Hop-2 key install as SYSTEM (no UAC). If the interactive UI also
    /// opened a socket it would hold this mutex forever, deadlocking that SYSTEM process (which then
    /// never connects Hop-1 → dashboard sessions stay "Orphan", and every session start re-prompts
    /// UAC). See the autostart handling in Load / OnAutoStartButtonClick, and
    /// ReleaseControlChannelInteractive below.
    /// </summary>
    private void StartControlChannelInteractive(string? ticket)
    {
        if (!SingleInstance.TryAcquireControlChannel())
        {
            AppendLog("A background remote-assist instance is already running — taking over...");
            SingleInstance.TakeOverFromUnattendedInstance();
            for (var i = 0; i < 20 && !SingleInstance.TryAcquireControlChannel(); i++)
                System.Threading.Thread.Sleep(250);
        }

        AccountLinkedSession.SessionRequested -= OnRemoteAssistSessionRequested;
        AccountLinkedSession.SessionRequested += OnRemoteAssistSessionRequested;

        try { _xrayTransport?.Stop(); } catch { /* best-effort */ }
        _xrayTransport = new XrayTransportManager();
        _vpnManager = new VpnManager(_xrayTransport);
        _vpnManager.Start();
        _xrayTransport.StartControlChannel();
        // S3DriveManager's rclone bisync loop is independent of which process holds the control
        // channel (unlike VPN/xray, which must restart with the fresh transport) — create+Start it
        // once per process lifetime, not on every handover.
        _s3DriveManager ??= new S3DriveManager();
        if (!_s3DriveManagerStarted) { _s3DriveManager.Start(); _s3DriveManagerStarted = true; }
        var socket = new RemoteAssistSocket(_vpnManager, _xrayTransport, _s3DriveManager);
        socket.StatusChanged += status => UiInvoke(() => AppendLog(status));
        socket.AiChatEnabledChanged += enabled => UiInvoke(() =>
        {
            if (_liveChatItem is not null) _liveChatItem.Visible = enabled;
        });
        _remoteAssistSocket = socket;
        socket.Connect(ticket);
    }

    /// <summary>
    /// Releases THIS interactive process's control channel so the SYSTEM background service can
    /// take it over: disconnects the socket, drops the session-request subscription, stops the
    /// interactive xray/VPN, and releases the control-channel mutex. Called when autostart is
    /// turned ON — from then on the SYSTEM --unattended-tunnel process (already running and blocked
    /// on the mutex) owns channel + sessions + key installs, all with no UAC. It acquires within
    /// its ~15s mutex-wait loop (see Program.RunUnattendedAccountLinkedSocket).
    /// </summary>
    private void ReleaseControlChannelInteractive()
    {
        try { _remoteAssistSocket?.Disconnect(); } catch { /* best-effort */ }
        _remoteAssistSocket = null;
        AccountLinkedSession.SessionRequested -= OnRemoteAssistSessionRequested;
        try { _xrayTransport?.Stop(); } catch { /* best-effort */ }
        _xrayTransport = null;
        try { _vpnManager?.Stop(); } catch { /* best-effort */ }
        _vpnManager = null;
        SingleInstance.ReleaseControlChannel();
    }

    /// <summary>
    /// Fires when the dashboard has requested an interactive session (POST
    /// /api/devices/:id/remote-assist/start reaching this device via the control socket). Reuses
    /// the SAME consent dialog + Connect flow as a local CONNECT click — the login/dashboard path
    /// requests a session, it does not itself grant access; whoever is physically at this PC must
    /// still accept the consent dialog before any tunnel comes up.
    /// </summary>
    private void OnRemoteAssistSessionRequested()
    {
        // Suppress re-entrancy when the unattended path is reconnecting the control socket
        // after an xray restart (the new xray has a different control port).
        if (AccountLinkedSession._reconnectingSession) return;

        UiInvoke(() =>
        {
            if (_connected || (_tunnel is not null && _tunnel.IsSshAlive))
            {
                AppendLog("Remote-assist session requested — already connected.");
                return;
            }
            if (!EnsureEphemeralConsent())
            {
                AppendLog("Remote-assist session requested but declined locally (consent not given).");
                return;
            }
            BeginConnect(isAutoStart: false);
        });
    }

    private void OnConnectButtonClick(object? sender, EventArgs e)
    {
        if (_connected)
        {
            if (ConfirmTermination())
            {
                Disconnect();
            }
            return;
        }

        // Ephemeral CONNECT only: mandatory support agreement before any setup/tunnel work.
        // Install the EDR does not use this path (it has its own typed-YES + UAC opt-in).
        if (!EnsureEphemeralConsent())
            return;

        BeginConnect(isAutoStart: false);
    }

    /// <summary>
    /// Shows the remote-support agreement once per process for ephemeral CONNECT.
    /// Returns false if the customer declines (no connect, no setup).
    /// </summary>
    private bool EnsureEphemeralConsent()
    {
        if (_ephemeralConsentGranted) return true;
        if (AutoStartManager.IsEnabled) return true; // unattended path — not this agreement

        if (!SessionAuditLog.IsActive)
            SessionAuditLog.BeginEphemeralSession();

        var accepted = ConsentDialog.Show(this);
        if (accepted)
        {
            _ephemeralConsentGranted = true;
            SessionAuditLog.LogConsentAccepted();
            AppendLog("Support agreement accepted — you can end the session anytime with DISCONNECT or by closing this window.");
            return true;
        }

        SessionAuditLog.LogConsentDeclined();
        AppendLog("Support agreement declined — no connection was made.");
        SessionAuditLog.EndAndPublish("consent-declined");
        return false;
    }

    /// <summary>Sets _autoStartButton's text/color from the current AutoStartManager.IsEnabled
    /// state — the button always describes the action a click will perform: "Install the EDR"
    /// when off, "Disable the EDR" when on.</summary>
    private void UpdateAutoStartButtonText()
    {
        var on = AutoStartManager.IsEnabled;
        _autoStartButton.Text = on ? "Disable the EDR" : "Install the EDR";
        _autoStartButton.BackColor = on ? Color.FromArgb(60, 60, 60) : Color.SteelBlue;
    }

    /// <summary>
    /// Clicking "Install the EDR" is real work — SetEnabled elevates (UAC) and, when enabling,
    /// runs a full SYSTEM setup pass that registers + starts the AtStartup unattended-tunnel
    /// task. That must NOT run on the UI thread (it would freeze the window for the duration of
    /// the UAC + setup), so it's dispatched to a background task. The UI is then reconciled to
    /// the ACTUAL resulting state (AutoStartManager.IsEnabled) so a declined UAC prompt snaps the
    /// button's label back instead of lying about being on.
    /// </summary>
    private void OnAutoStartButtonClick(object? sender, EventArgs e)
    {
        var enable = !AutoStartManager.IsEnabled;

        // Enabling unattended/standing access requires typed confirmation so a customer cannot
        // accidentally leave reboot-surviving access on. Turning OFF never needs confirmation.
        if (enable)
        {
            if (!ConfirmAutoStartYes())
            {
                AppendLog("Install the EDR was not enabled (confirmation cancelled).");
                return;
            }
            AppendLog("Confirmed — enabling Install the EDR (unattended access)...");
        }

        _autoStartButton.Enabled = false;
        _connectButton.Enabled = false;
        if (enable)
        {
            // Leaving ephemeral CONNECT mode: hide the customer session banner and stop treating
            // this as an attended session (unattended has no on-screen indicator by design).
            HideSessionIndicator();
            if (SessionAuditLog.IsActive)
            {
                SessionAuditLog.LogAction("MODE CHANGE: enabling Start-auto (unattended) — ephemeral audit ends");
                SessionAuditLog.EndAndPublish("switched-to-autostart");
            }

            AppendLog("Install the EDR: installing everything needed to connect (OpenSSH, local "
                + "account, keys) and starting the tunnel now. You do NOT need to click CONNECT first.");
            AppendLog("A Windows permission prompt will appear — approve it to continue...");
            StartBusyIndicator();
        }
        else
        {
            AppendLog("Turning off Install the EDR (a Windows permission prompt will appear)...");
        }

        Task.Run(() =>
        {
            // Remember whether we had a live Connect (local) tunnel before this toggle — if the
            // user already clicked CONNECT and then enables Install the EDR, we hand off; if
            // enable fails we restore that local session so they are not left dark.
            var hadLocalTunnel = false;

            if (enable)
            {
                _autoStartHandoff = true;
                hadLocalTunnel = StopLocalTunnelForHandoff(
                    "Handing off from Connect to background mode: stopping the local tunnel so the "
                    + "background tunnel can take the same bastion port (no conflict)...");
            }
            else
            {
                // Turning OFF: kill unattended first (inside SetEnabled); do not start local here.
                _autoStartHandoff = true;
            }

            // SetEnabled returns true only when the elevated child exit code is 0 (UAC accepted AND
            // full setup + tunnel kick succeeded). Do NOT trust IsEnabled alone.
            var ok = AutoStartManager.SetEnabled(enable);
            var actual = AutoStartManager.IsEnabled;
            var tunnelUp = actual && AutoStartManager.IsUnattendedTunnelProcessAlive();
            _autoStartHandoff = false;

            UiInvoke(() =>
            {
                StopBusyIndicator();
                _autoStartButton.Enabled = true;
                _connectButton.Enabled = true;
                UpdateAutoStartButtonText();

                if (!ok || actual != enable)
                {
                    // The elevated change didn't take (UAC declined / setup failed) — button text
                    // was already reconciled to the real state by UpdateAutoStartButtonText above.
                    _trayIcon.Visible = true;
                    AppendLog(enable
                        ? "Install the EDR was not enabled (permission declined, or setup failed — see C:\\ProgramData\\SentinelRemoteAssist\\setup-log.txt)."
                        : "Install the EDR was not turned off (the permission prompt may have been declined).");

                    // Connect-then-Start-auto failed: put the local tunnel back so support is not cut off.
                    if (enable && hadLocalTunnel && !AutoStartManager.IsEnabled)
                    {
                        AppendLog("Restoring your previous Connect session...");
                        BeginConnect(isAutoStart: false);
                    }
                    return;
                }

                // Tray icon stays visible regardless of autostart — AI Live Chat needs a home
                _trayIcon.Visible = true;

                if (actual)
                {
                    // Local tunnel must stay dead — unattended owns the bastion reverse port now.
                    _tunnel?.Stop();
                    _tunnel = null;
                    _connected = true;
                    _connectButton.Text = "DISCONNECT";
                    _connectButton.BackColor = Color.Firebrick;
                    // Hand the control channel to the SYSTEM background service. It is already
                    // running (SetupRunner started the AtStartup --unattended-tunnel task) and
                    // BLOCKED waiting on the control-channel mutex this interactive UI holds. If we
                    // keep our own socket open we hold that mutex forever, so the SYSTEM process
                    // never connects Hop-1 → dashboard sessions stay "Orphan" and every session
                    // start re-prompts UAC (found live 2026-07-15). Release it so the SYSTEM service
                    // owns channel + Hop-1 + Hop-2 key installs, all no-UAC; it acquires within its
                    // ~15s mutex-wait loop.
                    ReleaseControlChannelInteractive();
                    _trayIcon.Text = tunnelUp
                        ? "Sentinel Protection - Enabled"
                        : "Sentinel Remote Assist — Install the EDR ON (tunnel starting)";
                    AppendLog(hadLocalTunnel
                        ? (tunnelUp
                            ? "Hand-off complete: local Connect tunnel released, background tunnel is running. "
                              + "Support can connect now. Survives reboot/login."
                            : "Hand-off complete: local Connect tunnel released. Background tunnel is still starting — "
                              + "see unattended-tunnel.log if the bastion stays Waiting.")
                        : (tunnelUp
                            ? "Install the EDR is ON and the background tunnel is running. Support can connect now. "
                              + "The tunnel also comes up at boot before login. Relaunch from "
                              + @"C:\ProgramData\SentinelRemoteAssist to change this."
                            : "Install the EDR is ON (setup installed). The background tunnel is still starting — "
                              + "check C:\\ProgramData\\SentinelRemoteAssist\\unattended-tunnel.log if the bastion stays Waiting. "
                              + "Connect is not required; wait a few seconds or reboot."));
                }
                else
                {
                    _connected = false;
                    _connectButton.Text = "CONNECT";
                    _connectButton.BackColor = Color.SeaGreen;
                    _trayIcon.Text = "Sentinel Remote Assist — Disconnected";
                    // This process is no longer a bridge client — either it will own the control
                    // channel directly (below) or it's simply idle. The Session-0 SYSTEM process
                    // was just torn down anyway, so there's no host left to talk to.
                    // Returning to on-demand mode: the SYSTEM service was just torn down, so this
                    // process no longer has a control channel (it was handed off on enable). If we
                    // signed in this run, re-open it so the device stays reachable for an on-demand
                    // Connect; the mutex is free now (SYSTEM tunnel ended), so this is fast.
                    if (AccountLinkedSession.IsLinked && !(_remoteAssistSocket?.IsConnected ?? false))
                    {
                        StartControlChannelInteractive(null);
                    }
                    AppendLog("Install the EDR is OFF. Click CONNECT if you still need a session.");
                }
            });
        });
    }

    /// <summary>
    /// Stop any in-process TunnelRunner (from CONNECT) and wait until ssh.exe is gone + a short
    /// grace so the bastion frees the reverse-forward port before Start-auto's unattended tunnel
    /// binds the same port. Returns true if a local tunnel was actually running.
    /// </summary>
    private bool StopLocalTunnelForHandoff(string logMessage)
    {
        TunnelRunner? local = null;
        var had = false;
        // Capture+clear on UI thread if possible; safe from background too (_tunnel is only
        // published/cleared by UI or this handoff path).
        try
        {
            local = _tunnel;
            _tunnel = null;
            had = local is not null || _connected;
        }
        catch { /* best-effort */ }

        if (local is not null)
        {
            try { UiInvoke(() => AppendLog(logMessage)); } catch { /* may already be on UI */ }
            local.Stop();
            // Extra grace beyond WaitForExit inside Stop(): bastion sshd can take a beat to drop
            // the reverse listener after the client TCP session closes.
            Thread.Sleep(2500);
        }
        else if (had)
        {
            try { UiInvoke(() => AppendLog(logMessage)); } catch { }
            Thread.Sleep(500);
        }
        return had;
    }

    /// <summary>Shared by the CONNECT button and the autostart Load handler.</summary>
    private void BeginConnect(bool isAutoStart)
    {
        // Never start a local tunnel while Start-auto handoff is in progress or unattended mode
        // already owns the bastion port — that is the Connect-then-Start-auto conflict.
        if (_autoStartHandoff)
        {
            AppendLog("Start-auto handoff in progress — not starting a second local tunnel.");
            return;
        }
        if (AutoStartManager.IsEnabled && !isAutoStart)
        {
            AppendLog("Install the EDR is already ON — using the background tunnel (no second Connect).");
            HideSessionIndicator(); // unattended: no customer banner
            _connected = true;
            _connectButton.Text = "DISCONNECT";
            _connectButton.BackColor = Color.Firebrick;
            _connectButton.Enabled = true;
            _autoStartButton.Enabled = true;
            _trayIcon.Text = "Sentinel Protection - Enabled";
            return;
        }
        if (_tunnel is not null && _tunnel.IsSshAlive)
        {
            AppendLog("Already connected (local tunnel). Click Install the EDR to hand off to background mode.");
            _connectButton.Enabled = true;
            _autoStartButton.Enabled = true;
            return;
        }

        _connectButton.Enabled = false;
        _autoStartButton.Enabled = false;
        AppendLog("Checking local setup...");
        if (!isAutoStart)
            SessionAuditLog.LogAction("CONNECT requested (ephemeral)");

        Task.Run(() =>
        {
            try
            {
                // Re-check after async gap (user may have toggled Start-auto during setup UAC).
                if (_autoStartHandoff || AutoStartManager.IsEnabled)
                {
                    UiInvoke(() =>
                    {
                        HideSessionIndicator();
                        _connected = AutoStartManager.IsEnabled;
                        _connectButton.Text = _connected ? "DISCONNECT" : "CONNECT";
                        _connectButton.BackColor = _connected ? Color.Firebrick : Color.SeaGreen;
                        _connectButton.Enabled = true;
                        _autoStartButton.Enabled = true;
                        if (AutoStartManager.IsEnabled)
                        {
                            _trayIcon.Text = "Sentinel Protection - Enabled";
                            AppendLog("Start-auto took over — using background tunnel (local Connect skipped).");
                        }
                        else
                        {
                            AppendLog("Connect cancelled (Start-auto handoff).");
                        }
                    });
                    return;
                }

                if (!SetupRunner.IsSetupComplete)
                {
                    if (isAutoStart)
                    {
                        // Started automatically — a SYSTEM-run scheduled task (registered the last
                        // time Setup ran with "Install the EDR" enabled) is doing this same setup
                        // right now with no UAC prompt, since it already runs as SYSTEM. Wait for
                        // it instead of popping an interactive elevation at an unattended login.
                        UiInvoke(() => AppendLog("Waiting for automatic setup to finish (no permission prompt needed)..."));
                        UiInvoke(StartBusyIndicator);
                        var completed = WaitForSetupComplete(TimeSpan.FromSeconds(45));
                        UiInvoke(StopBusyIndicator);
                        if (!completed)
                        {
                            UiInvoke(() =>
                            {
                                AppendLog("Automatic setup didn't finish in time — click CONNECT to try again manually.");
                                _connectButton.Enabled = true;
                                _autoStartButton.Enabled = true;
                            });
                            return;
                        }
                        UiInvoke(() => AppendLog("Automatic setup complete."));
                    }
                    else
                    {
                        UiInvoke(() => AppendLog("First-time setup needed — a Windows permission prompt will appear."));
                        UiInvoke(() => AppendLog("After you approve it, this should only take a few seconds (installing " +
                                                  "the SSH component) — the bar below means it's still working."));
                        SessionAuditLog.LogAction("SETUP starting (elevated UAC — OpenSSH / account / keys)");
                        UiInvoke(StartBusyIndicator);
                        var ok = SetupRunner.RunElevatedSetup();
                        UiInvoke(StopBusyIndicator);
                        if (!ok)
                        {
                            SessionAuditLog.LogAction("SETUP failed or UAC declined");
                            UiInvoke(() =>
                            {
                                AppendLog(@"C:\ProgramData\SentinelRemoteAssist\setup-log.txt for details.");
                                _connectButton.Enabled = true;
                                _autoStartButton.Enabled = true;
                            });
                            return;
                        }
                        SessionAuditLog.LogAction("SETUP complete");
                        UiInvoke(() => AppendLog("Local setup complete."));
                    }
                }

                // Again after setup (Start-auto may have completed during our UAC).
                if (_autoStartHandoff || AutoStartManager.IsEnabled)
                {
                    UiInvoke(() =>
                    {
                        _tunnel?.Stop();
                        _tunnel = null;
                        HideSessionIndicator();
                        _connected = AutoStartManager.IsEnabled;
                        _connectButton.Text = _connected ? "DISCONNECT" : "CONNECT";
                        _connectButton.BackColor = _connected ? Color.Firebrick : Color.SeaGreen;
                        _connectButton.Enabled = true;
                        _autoStartButton.Enabled = true;
                        if (_connected)
                        {
                            _trayIcon.Text = "Sentinel Protection - Enabled";
                            AppendLog("Connected in the background (Unattended mode) — local tunnel not started.");
                        }
                    });
                    return;
                }

                // Account-linked build: the local port TunnelRunner needs doesn't exist until the
                // xray REALITY client is actually up — start it here (after setup, before reading
                // SessionConfig.Current, which reads AccountLinkedSession.XrayLocalPort).
                // _xrayTransport is created in BeginAccountLinkFlow (or lazily if not yet created)
                // and reused here — no second instance, so VpnManager's reference stays valid.
                if (AccountLinkedSession.IsLinked)
                {
                    _xrayTransport?.Stop();
                    _xrayTransport ??= new XrayTransportManager();
                    _xrayTransport.StatusChanged += status => UiInvoke(() => AppendLog(status));
                    if (!_xrayTransport.Start(AccountLinkedSession.XrayEgressUuid ?? ""))
                    {
                        UiInvoke(() =>
                        {
                            _connectButton.Enabled = true;
                            _autoStartButton.Enabled = true;
                        });
                        return;
                    }
                    AccountLinkedSession.XrayLocalPort = _xrayTransport.LocalPort;
                }

                var cfg = SessionConfig.Current;
                // Drop any dead leftover runner before starting a new one.
                _tunnel?.Stop();
                var runner = new TunnelRunner(cfg);
                _tunnel = runner;
                runner.StatusChanged += status => UiInvoke(() =>
                {
                    // Ignore late events if we handed off to Start-auto (runner was replaced/stopped).
                    if (!ReferenceEquals(_tunnel, runner) || AutoStartManager.IsEnabled || _autoStartHandoff)
                        return;
                    AppendLog(status);
                    SessionAuditLog.LogAction($"TUNNEL: {status}");
                    if (status.StartsWith("Connected —"))
                    {
                        // Ephemeral CONNECT only: show the mandatory on-screen session indicator.
                        ShowSessionIndicator();
                    }
                    if (status.StartsWith("Tunnel dropped") || status.StartsWith("ssh.exe failed")
                        || status.StartsWith("Disconnected") || status.StartsWith("Tunnel error"))
                    {
                        HideSessionIndicator();
                        _connectButton.Enabled = true;
                        _autoStartButton.Enabled = true;
                    }
                    if (status.StartsWith("Connected —") || status.StartsWith("Tunnel dropped") || status.StartsWith("ssh.exe failed")
                        || status.StartsWith("Disconnected") || status.StartsWith("Tunnel error"))
                    {
                        _connectButton.Enabled = true;
                        _autoStartButton.Enabled = true;
                    }
                    _trayIcon.Text = Truncate($"Sentinel Remote Assist — {status}", 127);
                });

                UiInvoke(() =>
                {
                    if (AutoStartManager.IsEnabled || _autoStartHandoff)
                    {
                        runner.Stop();
                        if (ReferenceEquals(_tunnel, runner)) _tunnel = null;
                        HideSessionIndicator();
                        _connected = AutoStartManager.IsEnabled;
                        _connectButton.Text = _connected ? "DISCONNECT" : "CONNECT";
                        _connectButton.BackColor = _connected ? Color.Firebrick : Color.SeaGreen;
                        _connectButton.Enabled = true;
                        _autoStartButton.Enabled = true;
                        AppendLog("Start-auto handoff won the race — local tunnel aborted.");
                        return;
                    }
                    _connected = true;
                    _connectButton.Text = "DISCONNECT";
                    _connectButton.BackColor = Color.Firebrick;
                    _trayIcon.Text = "Sentinel Remote Assist — Connected";
                    // Banner also appears on the "Connected —" status line; show optimistically here
                    // so the customer sees it as soon as the local session is considered active.
                    ShowSessionIndicator();
                    SessionAuditLog.LogAction("TUNNEL starting (ephemeral reverse tunnel)");
                });
                // Final race check before ssh.exe starts.
                if (AutoStartManager.IsEnabled || _autoStartHandoff || !ReferenceEquals(_tunnel, runner))
                {
                    runner.Stop();
                    return;
                }
                runner.Start();
            }
            catch (Exception ex)
            {
                UiInvoke(() =>
                {
                    StopBusyIndicator();
                    HideSessionIndicator();
                    SessionAuditLog.LogAction($"ERROR: {ex.Message}");
                    AppendLog($"Error: {ex.Message}");
                    _connectButton.Enabled = true;
                    _autoStartButton.Enabled = true;
                });
            }
        });
    }

    private void Disconnect()
    {
        if (AutoStartManager.IsEnabled)
        {
            // Unattended mode: "Disconnect" means turn OFF "Install the EDR" entirely — tear down
            // the SYSTEM tunnel + tasks. Route it through the same click handler the button uses
            // (it stops/unregisters the SYSTEM tunnel, restores the tray, and resets the UI) so
            // there is a SINGLE teardown code path instead of a duplicate inline one. No
            // confirmation required to disable.
            OnAutoStartButtonClick(this, EventArgs.Empty);
            return;
        }

        // Stop() waits for ssh.exe death + bastion reverse-port release (~2s+). Run it off the UI
        // thread so the window does not freeze. A fast Disconnect→Connect without that wait races
        // the bastion and produces mid-session drops (PTY / reset / DNS flap on retry).
        var runner = _tunnel;
        _tunnel = null;
        _connected = false;
        HideSessionIndicator();
        _connectButton.Enabled = false;
        _autoStartButton.Enabled = false;
        _connectButton.Text = "CONNECT";
        _connectButton.BackColor = Color.SeaGreen;
        _trayIcon.Text = "Sentinel Remote Assist — Disconnecting…";
        AppendLog("Disconnecting (waiting for tunnel to fully release)...");
        SessionAuditLog.LogAction("DISCONNECT (tunnel stopped — support access remains until app is closed)");

        var xray = _xrayTransport;
        _xrayTransport = null;
        Task.Run(() =>
        {
            try { runner?.Stop(); } catch { /* best-effort */ }
            try { xray?.Stop(); } catch { /* best-effort */ }
            UiInvoke(() =>
            {
                _connectButton.Enabled = true;
                _autoStartButton.Enabled = true;
                _trayIcon.Text = "Sentinel Remote Assist — Disconnected";
                AppendLog("Disconnected. You can click CONNECT again when ready.");
            });
        });
    }

    private void ShowSessionIndicator()
    {
        // Never show for unattended / Start-auto.
        if (AutoStartManager.IsEnabled || _autoStartHandoff) return;
        try
        {
            if (_sessionIndicator is null)
            {
                _sessionIndicator = new SessionIndicatorForm();
                // Banner "End session" → same disconnect path as the main DISCONNECT button
                // (after its own 3s countdown confirm inside the indicator form).
                _sessionIndicator.EndSessionRequested += () =>
                {
                    try
                    {
                        UiInvoke(() =>
                        {
                            if (!_connected) return;
                            Disconnect();
                            SessionAuditLog.LogAction("DISCONNECT from session banner (customer confirmed after countdown)");
                            AppendLog("Session ended from the on-screen banner.");
                        });
                    }
                    catch { /* best-effort */ }
                };
            }
            _sessionIndicator.ShowConnected();
            SessionAuditLog.LogAction("SESSION INDICATOR shown (on-screen banner active)");
        }
        catch (Exception ex)
        {
            AppendLog($"Session indicator failed to show: {ex.Message}");
        }
    }

    private void HideSessionIndicator()
    {
        try { _sessionIndicator?.HideIndicator(); } catch { /* best-effort */ }
    }

    /// <summary>
    /// Typed-confirmation gate for enabling "Install the EDR" (unattended standing access) —
    /// replaces the old technician-PIN gate (<c>Config.AutoStartEnablePin</c>, removed). Requires
    /// the operator to type the word YES exactly. Wrong text or Cancel → false. Turning OFF never
    /// needs this.
    /// </summary>
    private bool ConfirmAutoStartYes()
    {
        using var dialog = new Form
        {
            Text = "Install the EDR — confirm",
            ClientSize = new Size(380, 170),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            BackColor = Color.FromArgb(32, 32, 32),
            ForeColor = Color.White,
        };

        var label = new Label
        {
            Text = "Type YES to confirm Install the EDR\n"
                 + "(unattended remote access that survives reboot).",
            AutoSize = false,
            Location = new Point(16, 16),
            Size = new Size(348, 48),
            Font = new Font("Segoe UI", 9.5F),
        };

        var confirmBox = new TextBox
        {
            Location = new Point(16, 72),
            Size = new Size(200, 28),
            MaxLength = 8,
            Font = new Font("Segoe UI", 12F),
        };

        var btnOk = new Button
        {
            Text = "Confirm",
            DialogResult = DialogResult.OK,
            Size = new Size(100, 36),
            Location = new Point(160, 118),
            BackColor = Color.SeaGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
        };
        btnOk.FlatAppearance.BorderSize = 0;

        var btnCancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Size = new Size(100, 36),
            Location = new Point(268, 118),
            BackColor = Color.FromArgb(60, 60, 60),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
        };
        btnCancel.FlatAppearance.BorderSize = 0;

        dialog.Controls.Add(label);
        dialog.Controls.Add(confirmBox);
        dialog.Controls.Add(btnOk);
        dialog.Controls.Add(btnCancel);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        // Focus the confirmation field when shown.
        dialog.Shown += (_, _) => confirmBox.Focus();

        if (dialog.ShowDialog(this) != DialogResult.OK)
            return false;

        var entered = (confirmBox.Text ?? "").Trim();
        if (string.Equals(entered, "YES", StringComparison.Ordinal))
            return true;

        MessageBox.Show(this,
            "Confirmation text didn't match (type YES exactly). Install the EDR was not enabled.",
            "Confirmation required",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
        return false;
    }

    private void OpenLiveChat()
    {
        if (_remoteAssistSocket is null)
        {
            // Autostart mode: the SYSTEM background service owns the control channel, so this
            // interactive process has no socket. Spin up a temporary one for the chat session.
            // The temporary socket temporarily displaces the SYSTEM's in connectedSockets; when
            // the chat closes, the SYSTEM watchdog reconnects within ~45s.
            if (AutoStartManager.IsEnabled)
            {
                AppendLog("Opening Live Chat — starting a temporary control channel...");
                _xrayTransport = new XrayTransportManager();
                _xrayTransport.StartControlChannel();
                _vpnManager = new VpnManager(_xrayTransport);
                _vpnManager.Start();
                _s3DriveManager ??= new S3DriveManager();
                var chatSocket = new RemoteAssistSocket(_vpnManager, _xrayTransport, _s3DriveManager);
                chatSocket.StatusChanged += status => UiInvoke(() => AppendLog(status));
                chatSocket.AiChatEnabledChanged += enabled => UiInvoke(() =>
                {
                    if (_liveChatItem is not null) _liveChatItem.Visible = enabled;
                });
                _remoteAssistSocket = chatSocket;
                chatSocket.Connect(null);
                // Give the socket a moment to register before opening the form — the first chat
                // message would silently drop if the register hasn't landed server-side yet.
                Task.Delay(3000).ContinueWith(_ => UiInvoke(() =>
                {
                    if (_aiChatForm is null || _aiChatForm.IsDisposed)
                    {
                        _aiChatForm = new AiChatForm(chatSocket);
                        // Tear down the temporary channel when the chat form closes — the SYSTEM
                        // watchdog reconnects its own control channel within ~45s.
                        _aiChatForm.FormClosed += (_, _) =>
                        {
                            try { chatSocket.Disconnect(); } catch { }
                            try { _vpnManager?.Stop(); } catch { }
                            try { _xrayTransport?.Stop(); } catch { }
                            _vpnManager = null;
                            _xrayTransport = null;
                            _remoteAssistSocket = null;
                        };
                    }
                    _aiChatForm.Show();
                    if (_aiChatForm.WindowState == FormWindowState.Minimized) _aiChatForm.WindowState = FormWindowState.Normal;
                    _aiChatForm.Activate();
                }));
                return;
            }
            MessageBox.Show(this, "Not connected yet — please wait a moment and try again.",
                "Sentinel Remote Assist", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (_aiChatForm is null || _aiChatForm.IsDisposed)
        {
            _aiChatForm = new AiChatForm(_remoteAssistSocket);
        }
        _aiChatForm.Show();
        if (_aiChatForm.WindowState == FormWindowState.Minimized) _aiChatForm.WindowState = FormWindowState.Normal;
        _aiChatForm.Activate();
    }

    private void RestoreFromTray()
    {
        ShowInTaskbar = true;
        // Undo the off-screen parking from the constructor (see its comment) — without this, a
        // hidden-autostart window that gets shown via the tray would appear far off any monitor's
        // bounds, effectively invisible/unreachable to the user despite Show() having "worked".
        if (Left < -1000 || Top < -1000)
        {
            var area = Screen.FromPoint(Cursor.Position).WorkingArea;
            Left = area.Left + (area.Width - Width) / 2;
            Top = area.Top + (area.Height - Height) / 2;
        }
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    /// <summary>Polls (off the UI thread — called from within a Task.Run) for the SYSTEM-run
    /// auto-setup-at-login task to finish, instead of triggering our own interactive UAC prompt.</summary>
    private static bool WaitForSetupComplete(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (SetupRunner.IsSetupComplete) return true;
            Task.Delay(TimeSpan.FromSeconds(1)).Wait();
        }
        return SetupRunner.IsSetupComplete;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private void AppendLog(string message) => _log.AppendText($"{DateTime.Now:HH:mm:ss}  {message}\r\n");

    // Must be called on the UI thread (via UiInvoke). Marquee bar + a periodic log line so a
    // multi-minute install never looks frozen — Add-WindowsCapability gives no real percentage
    // we can surface safely (see the ProgressBar's own comment above), so this is honest, not fake.
    private void StartBusyIndicator()
    {
        _progress.Visible = true;
        _workStartedAt = DateTime.Now;
        _elapsedTimer?.Stop();
        _elapsedTimer?.Dispose();
        _elapsedTimer = new System.Windows.Forms.Timer { Interval = 15000 };
        _elapsedTimer.Tick += (_, _) =>
        {
            var elapsed = (int)(DateTime.Now - _workStartedAt).TotalSeconds;
            AppendLog($"Still working... ({elapsed}s elapsed)");
        };
        _elapsedTimer.Start();
    }

    private void StopBusyIndicator()
    {
        _progress.Visible = false;
        _elapsedTimer?.Stop();
        _elapsedTimer?.Dispose();
        _elapsedTimer = null;
    }

    private void UiInvoke(Action action)
    {
        if (InvokeRequired) Invoke(action);
        else action();
    }

    private bool ConfirmTermination()
    {
        using var dialog = new Form
        {
            Text = "Confirm",
            ClientSize = new Size(350, 150),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = Color.FromArgb(32, 32, 32),
            ForeColor = Color.White
        };

        var label = new Label
        {
            Text = "Are you Sure you want to terminate the assistant?",
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleCenter,
            Dock = DockStyle.Top,
            Height = 60,
            Font = new Font("Segoe UI", 10F)
        };

        var btnYes = new Button
        {
            Text = "YES (5)",
            Enabled = false,
            DialogResult = DialogResult.Yes,
            Size = new Size(100, 40),
            Location = new Point(40, 80),
            BackColor = Color.Gray,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        btnYes.FlatAppearance.BorderSize = 0;

        var btnNo = new Button
        {
            Text = "NO",
            DialogResult = DialogResult.No,
            Size = new Size(100, 40),
            Location = new Point(200, 80),
            BackColor = Color.SeaGreen,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat
        };
        btnNo.FlatAppearance.BorderSize = 0;

        dialog.Controls.Add(label);
        dialog.Controls.Add(btnYes);
        dialog.Controls.Add(btnNo);

        var timeLeft = 5;
        var timer = new System.Windows.Forms.Timer { Interval = 1000 };
        timer.Tick += (_, _) =>
        {
            timeLeft--;
            if (timeLeft > 0)
            {
                btnYes.Text = $"YES ({timeLeft})";
            }
            else
            {
                btnYes.Text = "YES";
                btnYes.Enabled = true;
                btnYes.BackColor = Color.Firebrick;
                timer.Stop();
            }
        };
        timer.Start();

        var result = dialog.ShowDialog(this);
        timer.Stop();
        timer.Dispose();

        return result == DialogResult.Yes;
    }
}
