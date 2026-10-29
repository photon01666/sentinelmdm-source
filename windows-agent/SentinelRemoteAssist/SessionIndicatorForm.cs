namespace SentinelRemoteAssist;

/// <summary>
/// Persistent always-on-top banner shown for the entire duration of an ephemeral CONNECT
/// session. Mirrors the TeamViewer/AnyDesk/ConnectWise expectation that the customer can always
/// see that remote support is active — liability cover if they later ask "was someone watching
/// on date X?" (paired with the Desktop audit log).
/// Not shown for "Start automatically" / unattended mode.
/// </summary>
internal sealed class SessionIndicatorForm : Form
{
    private readonly Label _title;
    private readonly Label _detail;
    private readonly Button _endButton;
    private readonly System.Windows.Forms.Timer _ticker;
    private DateTime _connectedAt;
    private bool _shown;

    /// <summary>Raised when the customer confirms End Session on the banner (after countdown).</summary>
    public event Action? EndSessionRequested;

    public SessionIndicatorForm()
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = Color.FromArgb(175, 28, 28);
        ForeColor = Color.White;
        // Wider + taller so title, detail, and End button have breathing room.
        Size = new Size(760, 88);
        MinimumSize = Size;
        MaximumSize = Size;
        ControlBox = false;
        Padding = new Padding(0);

        // Root: [ text column | End button ]
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Color.Transparent,
            Padding = new Padding(16, 10, 12, 10),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 168));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var textCol = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = Color.Transparent,
            Margin = new Padding(0, 0, 12, 0),
        };
        textCol.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        textCol.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
        textCol.RowStyles.Add(new RowStyle(SizeType.Percent, 45));

        _title = new Label
        {
            Text = "●  SENTINEL SUPPORT SESSION ACTIVE",
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI Semibold", 14F, FontStyle.Bold),
            ForeColor = Color.White,
            BackColor = Color.Transparent,
            Margin = new Padding(0),
        };

        _detail = new Label
        {
            Text = "",
            AutoSize = false,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10F),
            ForeColor = Color.FromArgb(255, 220, 220),
            BackColor = Color.Transparent,
            Margin = new Padding(0),
        };

        textCol.Controls.Add(_title, 0, 0);
        textCol.Controls.Add(_detail, 0, 1);

        _endButton = new Button
        {
            Text = "End session",
            Dock = DockStyle.Fill,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(40, 40, 40),
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 11F),
            Cursor = Cursors.Hand,
            Margin = new Padding(4, 6, 4, 6),
            TabStop = false,
        };
        _endButton.FlatAppearance.BorderSize = 1;
        _endButton.FlatAppearance.BorderColor = Color.FromArgb(255, 200, 200);
        _endButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(60, 60, 60);
        _endButton.Click += OnEndButtonClick;

        root.Controls.Add(textCol, 0, 0);
        root.Controls.Add(_endButton, 1, 0);
        Controls.Add(root);

        _ticker = new System.Windows.Forms.Timer { Interval = 1000 };
        _ticker.Tick += (_, _) => RefreshDetail();

        // Drag from the red bar / labels (not from the button).
        MouseDown += StartDrag;
        _title.MouseDown += StartDrag;
        _detail.MouseDown += StartDrag;
        textCol.MouseDown += StartDrag;
        root.MouseDown += StartDrag;

        // Re-assert TopMost periodically (some full-screen apps steal z-order).
        var topMostTimer = new System.Windows.Forms.Timer { Interval = 5000 };
        topMostTimer.Tick += (_, _) =>
        {
            if (Visible && !IsDisposed)
            {
                try { TopMost = true; } catch { /* ignore */ }
            }
        };
        topMostTimer.Start();
        FormClosed += (_, _) =>
        {
            topMostTimer.Stop();
            topMostTimer.Dispose();
        };
    }

    public void ShowConnected()
    {
        if (IsDisposed) return;
        _connectedAt = DateTime.Now;
        RefreshDetail();
        PositionTopCenter();
        if (!_shown)
        {
            Show();
            _shown = true;
        }
        else
        {
            Visible = true;
            TopMost = true;
        }
        _ticker.Start();
    }

    public void HideIndicator()
    {
        if (IsDisposed) return;
        _ticker.Stop();
        Hide();
    }

    private void OnEndButtonClick(object? sender, EventArgs e)
    {
        // 3-second "Are you sure?" countdown before actually ending — same idea as the
        // main form ConfirmTermination dialog, so a mis-click on the banner doesn't drop support.
        if (!ConfirmEndSession()) return;
        EndSessionRequested?.Invoke();
    }

    /// <summary>
    /// Modal confirm with a 3s countdown before YES is enabled (accidental-click guard).
    /// </summary>
    private bool ConfirmEndSession()
    {
        using var dialog = new Form
        {
            Text = "End support session?",
            ClientSize = new Size(420, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterScreen,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            TopMost = true,
            BackColor = Color.FromArgb(28, 28, 28),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10F),
        };

        var label = new Label
        {
            Text = "Are you sure you want to disconnect?\n\n"
                 + "This ends the live support tunnel.\n"
                 + "(Closing the main app removes temporary access entirely.)",
            AutoSize = false,
            TextAlign = ContentAlignment.MiddleLeft,
            Dock = DockStyle.Top,
            Height = 100,
            Padding = new Padding(20, 16, 20, 8),
            Font = new Font("Segoe UI", 10.5F),
        };

        var btnYes = new Button
        {
            Text = "YES (3)",
            Enabled = false,
            DialogResult = DialogResult.Yes,
            Size = new Size(120, 42),
            Location = new Point(60, 118),
            BackColor = Color.Gray,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10F),
        };
        btnYes.FlatAppearance.BorderSize = 0;

        var btnNo = new Button
        {
            Text = "NO — keep connected",
            DialogResult = DialogResult.No,
            Size = new Size(180, 42),
            Location = new Point(200, 118),
            BackColor = Color.FromArgb(46, 160, 110),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10F),
        };
        btnNo.FlatAppearance.BorderSize = 0;

        dialog.Controls.Add(label);
        dialog.Controls.Add(btnYes);
        dialog.Controls.Add(btnNo);
        dialog.CancelButton = btnNo;
        dialog.AcceptButton = btnNo; // default = keep session

        var timeLeft = 3;
        using var timer = new System.Windows.Forms.Timer { Interval = 1000 };
        timer.Tick += (_, _) =>
        {
            timeLeft--;
            if (timeLeft > 0)
            {
                btnYes.Text = $"YES ({timeLeft})";
            }
            else
            {
                btnYes.Text = "YES — disconnect";
                btnYes.Enabled = true;
                btnYes.BackColor = Color.FromArgb(180, 40, 40);
                timer.Stop();
            }
        };
        timer.Start();

        var result = dialog.ShowDialog(this);
        timer.Stop();
        return result == DialogResult.Yes;
    }

    private void RefreshDetail()
    {
        if (IsDisposed) return;
        var elapsed = DateTime.Now - _connectedAt;
        var label = string.IsNullOrEmpty(SessionEmbedded.SessionLabel)
            ? "support"
            : SessionEmbedded.SessionLabel;
        var elapsedText = elapsed.TotalHours >= 1
            ? $"{(int)elapsed.TotalHours}h {elapsed.Minutes:D2}m {elapsed.Seconds:D2}s"
            : $"{elapsed.Minutes:D2}m {elapsed.Seconds:D2}s";
        _detail.Text = $"{Config.TechnicianDisplayName}  ·  {label}  ·  connected {elapsedText}";
    }

    private void PositionTopCenter()
    {
        var area = Screen.PrimaryScreen?.WorkingArea
            ?? new Rectangle(0, 0, 1280, 720);
        // Prefer nearly full-width when the screen is wide enough.
        var targetW = Math.Min(960, Math.Max(720, area.Width - 80));
        if (Width != targetW)
        {
            Size = new Size(targetW, 88);
            MinimumSize = Size;
            MaximumSize = Size;
        }
        Left = area.Left + (area.Width - Width) / 2;
        Top = area.Top + 10;
    }

    private void StartDrag(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;
        try
        {
            NativeMethods.ReleaseCapture();
            NativeMethods.SendMessage(Handle, NativeMethods.WM_NCLBUTTONDOWN, NativeMethods.HTCAPTION, 0);
        }
        catch { /* ignore */ }
    }

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            // WS_EX_TOOLWINDOW — no taskbar button, no alt-tab clutter for a status banner.
            cp.ExStyle |= 0x00000080;
            return cp;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _ticker.Stop();
            _ticker.Dispose();
        }
        base.Dispose(disposing);
    }

    private static class NativeMethods
    {
        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HTCAPTION = 0x2;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool ReleaseCapture();

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, int wParam, int lParam);
    }
}
