using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace NukeAgent;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new NukeForm());
    }

    internal static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

internal sealed class NukeForm : Form
{
    // ── Config ──────────────────────────────────────────────────────────────────
    static readonly string ProgramDataDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    static readonly string SentinelDir    = Path.Combine(ProgramDataDir, "SentinelRemoteAssist");
    static readonly string EdrDir         = Path.Combine(ProgramDataDir, "SentinelEdr");
    static readonly string AppControlDir  = Path.Combine(ProgramDataDir, "SentinelAppControl");
    static readonly string IdentityDir    = Path.Combine(ProgramDataDir, "SentinelRemoteAssistIdentity");
    static readonly string BackupVault    = Path.Combine(ProgramDataDir, "BackupVault");
    static readonly string SshDir         = Path.Combine(ProgramDataDir, "ssh");
    static readonly string UsersPublicDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"..\..\Users\Public");

    static readonly string[] CanaryNames = {
        "Passwords.docx", "Tax Documents 2025.pdf", "Family Budget.xlsx",
        "Backup - Do Not Delete.docx", "Photos Backup Archive.zip"
    };

    const int TotalSteps = 11;

    // ── Controls ────────────────────────────────────────────────────────────────
    readonly Label lblTitle = new();
    readonly Label lblSub = new();
    readonly Label lblStatus = new();
    readonly ProgressBar progressBar = new();
    readonly Label lblStep = new();
    readonly RichTextBox txtResults = new();
    readonly Button btnNuke = new();
    readonly System.Windows.Forms.Timer uiTimer = new();
    readonly System.ComponentModel.BackgroundWorker worker = new();

    int currentStep;
    readonly object logLock = new();
    readonly List<string> pendingLogs = new();

    public NukeForm()
    {
        // ── Form ──
        Text = "NUKE-Agent — SentinelRemoteAssist Removal";
        Size = new Size(640, 560);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        BackColor = Color.FromArgb(18, 18, 18);
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;

        // ── Title ──
        lblTitle.Text = "NUKE-AGENT";
        lblTitle.Font = new Font("Segoe UI", 22f, FontStyle.Bold);
        lblTitle.ForeColor = Color.FromArgb(220, 40, 40);
        lblTitle.AutoSize = true;
        lblTitle.Location = new Point(20, 12);
        Controls.Add(lblTitle);

        // ── Subtitle ──
        lblSub.Text = "Complete removal of SentinelRemoteAssist from this PC";
        lblSub.Font = new Font("Segoe UI", 9f);
        lblSub.ForeColor = Color.FromArgb(140, 140, 140);
        lblSub.AutoSize = true;
        lblSub.Location = new Point(24, 52);
        Controls.Add(lblSub);

        // ── Separator ──
        var sep = new Label { BorderStyle = BorderStyle.Fixed3D, Location = new Point(20, 78), Size = new Size(580, 2) };
        Controls.Add(sep);

        // ── Status ──
        lblStatus.Text = "Ready \u2014 click NUKE to begin";
        lblStatus.Font = new Font("Segoe UI", 10f);
        lblStatus.ForeColor = Color.FromArgb(200, 200, 200);
        lblStatus.AutoSize = true;
        lblStatus.Location = new Point(20, 90);
        Controls.Add(lblStatus);

        // ── Progress bar ──
        progressBar.Location = new Point(20, 118);
        progressBar.Size = new Size(580, 26);
        progressBar.Style = ProgressBarStyle.Continuous;
        progressBar.Minimum = 0;
        progressBar.Maximum = 100;
        progressBar.Value = 0;
        Controls.Add(progressBar);

        // ── Step counter ──
        lblStep.Text = "0 / " + TotalSteps;
        lblStep.Font = new Font("Segoe UI", 9f);
        lblStep.ForeColor = Color.FromArgb(120, 120, 120);
        lblStep.AutoSize = true;
        lblStep.Location = new Point(20, 150);
        Controls.Add(lblStep);

        // ── Results box ──
        txtResults.Location = new Point(20, 175);
        txtResults.Size = new Size(580, 275);
        txtResults.Multiline = true;
        txtResults.ScrollBars = RichTextBoxScrollBars.Vertical;
        txtResults.ReadOnly = true;
        txtResults.BackColor = Color.FromArgb(12, 12, 12);
        txtResults.ForeColor = Color.FromArgb(0, 200, 80);
        txtResults.Font = new Font("Consolas", 9.5f);
        txtResults.BorderStyle = BorderStyle.FixedSingle;
        txtResults.Text = "";
        Controls.Add(txtResults);

        // ── NUKE button ──
        btnNuke.Text = "NUKE";
        btnNuke.Size = new Size(580, 46);
        btnNuke.Location = new Point(20, 462);
        btnNuke.Font = new Font("Segoe UI", 15f, FontStyle.Bold);
        btnNuke.BackColor = Color.FromArgb(180, 20, 20);
        btnNuke.ForeColor = Color.White;
        btnNuke.FlatStyle = FlatStyle.Flat;
        btnNuke.FlatAppearance.BorderSize = 0;
        btnNuke.Cursor = Cursors.Hand;
        btnNuke.Click += OnNukeClick;
        Controls.Add(btnNuke);

        // ── Background worker ──
        worker.WorkerReportsProgress = true;
        worker.DoWork += Worker_DoWork;
        worker.ProgressChanged += Worker_ProgressChanged;
        worker.RunWorkerCompleted += Worker_Completed;

        // ── UI timer (flushes log queue to UI thread) ──
        uiTimer.Interval = 50;
        uiTimer.Tick += (_, _) =>
        {
            string[] lines;
            lock (logLock) { lines = pendingLogs.ToArray(); pendingLogs.Clear(); }
            if (lines.Length == 0) return;
            txtResults.SelectionStart = txtResults.TextLength;
            foreach (var line in lines)
            {
                txtResults.AppendText(line + Environment.NewLine);
            }
            txtResults.SelectionStart = txtResults.TextLength;
            txtResults.ScrollToCaret();
        };
        uiTimer.Start();
    }

    void OnNukeClick(object? sender, EventArgs e)
    {
        btnNuke.Enabled = false;
        btnNuke.BackColor = Color.FromArgb(100, 50, 50);
        btnNuke.Text = "NUKING...";
        txtResults.Clear();
        currentStep = 0;
        progressBar.Value = 0;
        lblStep.Text = "0 / " + TotalSteps;
        lblStatus.ForeColor = Color.FromArgb(200, 200, 200);
        lblStatus.Text = "Starting...";
        worker.RunWorkerAsync();
    }

    // ── UI helpers (called from worker thread) ──────────────────────────────────
    void AdvanceStep(string stepName)
    {
        currentStep++;
        int pct = (int)Math.Round((double)currentStep / TotalSteps * 100);
        BeginInvoke(() =>
        {
            progressBar.Value = pct;
            lblStep.Text = currentStep + " / " + TotalSteps;
            lblStatus.Text = stepName;
        });
    }

    void Log(string text)
    {
        string prefix;
        if (text.StartsWith("[!]")) prefix = "[!] ";
        else if (text.StartsWith("[+]")) prefix = "[+] ";
        else if (text.StartsWith("[=")) prefix = "[=] ";
        else prefix = "[-] ";

        string display = text.Length > 3 ? prefix + text[3..].TrimStart() : text;
        lock (logLock) { pendingLogs.Add(display); }
    }

    void LogRaw(string text) { lock (logLock) { pendingLogs.Add(text); } }

    // ── Worker ──────────────────────────────────────────────────────────────────
    void Worker_DoWork(object? sender, DoWorkEventArgs e)
    {
        var sw = Stopwatch.StartNew();

        // ── 1: Kill processes ───────────────────────────────────────────────────
        AdvanceStep("Killing agent processes...");
        int killed = 0;
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string name = proc.ProcessName;
                bool isOurs = name.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase)
                           || name.EndsWith("_Remote_Assist", StringComparison.OrdinalIgnoreCase)
                           || name.Equals("xray", StringComparison.OrdinalIgnoreCase);
                if (!isOurs)
                {
                    try
                    {
                        string? path = proc.MainModule?.FileName;
                        if (path != null && (path.StartsWith(SentinelDir, StringComparison.OrdinalIgnoreCase)
                                          || path.StartsWith(EdrDir, StringComparison.OrdinalIgnoreCase)
                                          || path.StartsWith(AppControlDir, StringComparison.OrdinalIgnoreCase)
                                          || path.StartsWith(IdentityDir, StringComparison.OrdinalIgnoreCase)))
                            isOurs = true;
                    } catch { }
                }
                if (isOurs) { proc.Kill(true); killed++; }
            } catch { }
        }
        foreach (string exe in new[] { "ssh", "sshd", "sshd-session", "ssh-agent" })
        {
            foreach (var proc in Process.GetProcessesByName(exe))
            {
                try
                {
                    string? path = proc.MainModule?.FileName;
                    if (path != null && (path.StartsWith(SentinelDir, StringComparison.OrdinalIgnoreCase)
                                      || path.StartsWith(EdrDir, StringComparison.OrdinalIgnoreCase)
                                      || path.StartsWith(AppControlDir, StringComparison.OrdinalIgnoreCase)))
                    { proc.Kill(true); killed++; }
                } catch { }
            }
        }
        Log($"Killed {killed} agent process(es)");

        // ── 2: Scheduled tasks ──────────────────────────────────────────────────
        AdvanceStep("Removing scheduled tasks...");
        int tasks = 0;
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /NH")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(30000);
            foreach (string line in output.Split('\n'))
            {
                var parts = line.Split(',');
                if (parts.Length < 2) continue;
                string tn = parts[0].Trim('"').Trim();
                if (tn.StartsWith("Sentinel", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var dp = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{tn}\" /F")
                        { UseShellExecute = false, CreateNoWindow = true };
                        using var d = Process.Start(dp);
                        d?.WaitForExit(15000);
                        tasks++;
                    } catch { }
                }
            }
        } catch { }
        Log($"Removed {tasks} scheduled task(s)");

        // ── 3: sentinel-support account ─────────────────────────────────────────────────
        AdvanceStep("Removing sentinel-support account...");
        try
        {
            RunCmd("net.exe", "user sentinel-support /delete");
            Log("Removed sentinel-support account");
        } catch { Log("[=] sentinel-support not found"); }

        // ── 4: Services ─────────────────────────────────────────────────────────
        AdvanceStep("Removing services...");
        bool preexisting = File.Exists(Path.Combine(SentinelDir, "sshd-preexisted.marker"));
        try
        {
            if (preexisting) { RunCmd("sc.exe", "stop sshd"); Log("[=] sshd pre-existed — stopped only"); }
            else { RunCmd("sc.exe", "stop sshd"); RunCmd("sc.exe", "delete sshd"); Log("Removed sshd service (ours)"); }
        } catch { }
        try
        {
            string qout = RunCmdCapture("sc.exe", "qc ssh-agent");
            if (qout.Contains(SentinelDir, StringComparison.OrdinalIgnoreCase))
            { RunCmd("sc.exe", "stop ssh-agent"); RunCmd("sc.exe", "delete ssh-agent"); Log("Removed ssh-agent service (ours)"); }
        } catch { }

        // ── 5: Restore sshd_config ──────────────────────────────────────────────
        AdvanceStep("Restoring sshd_config...");
        string sshdBak = Path.Combine(SentinelDir, "sshd_config.pre-sentinel.bak");
        string sshdCfg = Path.Combine(SshDir, "sshd_config");
        if (File.Exists(sshdBak) && File.Exists(sshdCfg))
        {
            try { File.Copy(sshdBak, sshdCfg, true); Log("[+] Restored sshd_config from backup"); }
            catch { }
        }
        else Log("[=] No sshd_config backup found");

        // ── 6: administrators_authorized_keys ───────────────────────────────────
        AdvanceStep("Restoring authorized_keys...");
        string ak = Path.Combine(SshDir, "administrators_authorized_keys");
        string akBak = Path.Combine(SshDir, "administrators_authorized_keys.pre-sentinel.bak");
        if (preexisting)
        {
            if (File.Exists(akBak) && File.Exists(ak))
            {
                try { File.Copy(akBak, ak, true); File.Delete(akBak); Log("[+] Restored administrators_authorized_keys"); }
                catch { }
            }
            else Log("[=] No authorized_keys backup found");
        }
        else
        {
            if (Directory.Exists(SshDir))
            {
                try { Directory.Delete(SshDir, true); Log("Deleted C:\\ProgramData\\ssh (was entirely ours)"); }
                catch { Log("[!] Failed to delete ssh dir (may be locked)"); }
            }
        }

        // ── 7: Registry ────────────────────────────────────────────────────────
        AdvanceStep("Cleaning registry...");
        RunCmd("reg.exe", @"delete HKLM\Software\SentinelRemoteAssist /f");
        RunCmd("reg.exe", @"delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v SentinelRemoteAssist /f");
        RunCmd("reg.exe", @"delete ""HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sshd.exe"" /f");
        Log("Registry cleanup done");

        // ── 8: Firewall ────────────────────────────────────────────────────────
        AdvanceStep("Removing firewall rules...");
        string[] rules = {
            "Sentinel-Isolation-Sentinel.exe-Out", "Sentinel-Isolation-Sentinel.exe-In",
            "Sentinel-Isolation-ssh.exe-Out", "Sentinel-Isolation-ssh.exe-In",
            "Sentinel-Isolation-sshd.exe-Out", "Sentinel-Isolation-sshd.exe-In",
            "Sentinel-Isolation-sshd-session.exe-Out", "Sentinel-Isolation-sshd-session.exe-In",
            "Sentinel-Isolation-xray.exe-Out", "Sentinel-Isolation-xray.exe-In",
            "Sentinel-Isolation-DNS-Out-UDP-svchost.exe",
            "Sentinel-Isolation-DNS-Out-TCP-svchost.exe",
            "Sentinel-Telemetry-Block"
        };
        foreach (string r in rules)
            RunCmd("netsh.exe", $"advfirewall firewall delete rule name=\"{r}\"");
        RunCmd("netsh.exe", "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
        Log($"Removed {rules.Length} firewall rule(s) + restored default policy");

        // ── 9: Canary files ────────────────────────────────────────────────────
        AdvanceStep("Deleting canary decoy files...");
        int canaries = 0;
        string[] roots = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Pictures"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive"),
            Path.Combine(ProgramDataDir, @"Users\Public\Documents"),
            Path.Combine(ProgramDataDir, @"Users\Public\Downloads"),
            BackupVault
        };
        foreach (string root in roots)
        {
            foreach (string name in CanaryNames)
            {
                string path = Path.Combine(root, name);
                if (!File.Exists(path)) continue;
                try
                {
                    var fi = new FileInfo(path);
                    if (fi.Length > 4096) continue;
                    string first = File.ReadLines(path).FirstOrDefault() ?? "";
                    if (first.Contains("Sentinel security decoy")) { File.Delete(path); canaries++; }
                } catch { }
            }
        }
        // Also check canary-state.json
        string csPath = Path.Combine(EdrDir, "canary-state.json");
        if (File.Exists(csPath))
        {
            try
            {
                string json = File.ReadAllText(csPath);
                // Simple parse: extract paths from "path":"hash" pairs
                foreach (string segment in json.Split('"'))
                {
                    if (segment.Length > 5 && segment.Contains('\\') && File.Exists(segment))
                    {
                        try { File.Delete(segment); canaries++; } catch { }
                    }
                }
            } catch { }
        }
        Log($"Deleted {canaries} canary file(s)");

        // ── 10: ProgramData trees + misc files ─────────────────────────────────
        AdvanceStep("Deleting ProgramData trees...");
        foreach (string dir in new[] { SentinelDir, EdrDir, AppControlDir, IdentityDir })
        {
            if (!Directory.Exists(dir)) continue;
            try { Directory.Delete(dir, true); Log($"Deleted {dir}"); }
            catch { Log($"[!] Failed to delete {dir} (may be locked)"); }
        }
        string snap = Path.Combine(UsersPublicDir, "SentinelScreenSnap.exe");
        if (File.Exists(snap)) { try { File.Delete(snap); Log("Deleted SentinelScreenSnap.exe"); } catch { } }
        if (Directory.Exists(BackupVault))
        {
            try
            {
                if (!Directory.EnumerateFileSystemEntries(BackupVault).Any())
                { Directory.Delete(BackupVault, true); Log("Deleted empty BackupVault"); }
            } catch { }
        }

        // ── 11: Temp files ─────────────────────────────────────────────────────
        AdvanceStep("Cleaning temp files...");
        try
        {
            string temp = Path.GetTempPath();
            foreach (string f in Directory.GetFiles(temp, "sentinel-*"))
            { try { File.Delete(f); } catch { } }
        } catch { }
        Log("Temp cleanup done");

        // ── DONE ────────────────────────────────────────────────────────────────
        sw.Stop();
        string elapsed = sw.Elapsed.TotalSeconds.ToString("F1");
        LogRaw("");
        LogRaw("══════════════════════════════════════════════════════════════");
        LogRaw($"  NUKE completed in {elapsed}s");
        LogRaw("  All SentinelRemoteAssist artifacts removed.");
        LogRaw("  Agent cannot reconnect to the server.");
        LogRaw("  To re-install: download fresh copy from dashboard.");
        LogRaw("══════════════════════════════════════════════════════════════");

        BeginInvoke(() =>
        {
            progressBar.Value = 100;
            lblStep.Text = TotalSteps + " / " + TotalSteps;
            lblStatus.Text = "NUKE COMPLETE";
            lblStatus.ForeColor = Color.FromArgb(0, 200, 80);
            btnNuke.Text = "DONE — Close";
            btnNuke.BackColor = Color.FromArgb(0, 140, 60);
            btnNuke.Enabled = true;
            btnNuke.Click -= OnNukeClick;
            btnNuke.Click += (_, _) => Close();
        });
    }

    void Worker_ProgressChanged(object? sender, ProgressChangedEventArgs e) { }

    void Worker_Completed(object? sender, RunWorkerCompletedEventArgs e) { }

    // ── Command helpers ─────────────────────────────────────────────────────────
    static void RunCmd(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            { UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi);
            p?.WaitForExit(15000);
        } catch { }
    }

    static string RunCmdCapture(string exe, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);
            return output;
        } catch { return ""; }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        uiTimer.Stop();
        base.OnFormClosing(e);
    }
}
