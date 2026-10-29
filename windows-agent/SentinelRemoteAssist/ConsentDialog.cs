using System.Diagnostics;

namespace SentinelRemoteAssist;

/// <summary>
/// Mandatory support-agreement / remote-access consent shown once per app run before the first
/// ephemeral CONNECT. Not shown for "Start automatically" (unattended) — that path is a separate
/// standing-access opt-in with its own UAC. For your own machines, verbal consent is fine; for
/// customers, this puts remote-access authorization in writing with a timestamped audit entry.
/// </summary>
internal static class ConsentDialog
{
    // Palette — matches the main app dark chrome, with a clear accent for consent actions.
    private static readonly Color Bg = Color.FromArgb(22, 24, 28);
    private static readonly Color Card = Color.FromArgb(32, 36, 42);
    private static readonly Color CardBorder = Color.FromArgb(55, 62, 72);
    private static readonly Color TextPrimary = Color.FromArgb(245, 247, 250);
    private static readonly Color TextMuted = Color.FromArgb(160, 170, 185);
    private static readonly Color Accent = Color.FromArgb(46, 160, 110);       // sea-green
    private static readonly Color AccentDim = Color.FromArgb(70, 80, 90);
    private static readonly Color DangerMuted = Color.FromArgb(70, 74, 82);

    /// <summary>
    /// Shows the agreement modal. Returns true if the customer accepted.
    /// Does not write the audit log itself — caller logs accept/decline.
    /// The optional overrides let the auto-provisioning installer (2.0.3, AutoProvisionFlow) reuse
    /// the exact same dialog chrome for the versioned ToS/MSA fetch — body/title/accept/checkbox
    /// text + an optional "View full terms" link. Defaults preserve the original support-session
    /// copy byte-for-byte.
    /// </summary>
    public static bool Show(IWin32Window? owner, string? bodyOverride = null, string? titleOverride = null,
        string? acceptOverride = null, string? checkOverride = null, string? linkUrl = null)
    {
        var sessionLabel = string.IsNullOrEmpty(SessionEmbedded.SessionLabel)
            ? "this support session"
            : $"“{SessionEmbedded.SessionLabel}”";

        using var dialog = new Form
        {
            Text = "Remote Support Agreement — Sentinel",
            ClientSize = new Size(720, 680),
            MinimumSize = new Size(640, 560),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = owner is null ? FormStartPosition.CenterScreen : FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            ShowInTaskbar = false,
            BackColor = Bg,
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 10F),
            Padding = new Padding(0),
            AutoScaleMode = AutoScaleMode.Dpi,
            AutoScaleDimensions = new SizeF(96F, 96F),
        };

        // ── Root: header | scroll body | consent strip | buttons ──────────────
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Bg,
            Padding = new Padding(28, 24, 28, 20),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        // Header row grows to fit the optional "View full terms" link (the auto-provisioning ToS
        // flow) — a fixed 88px header clipped the link at its old hardcoded Y=118, showing a
        // squeezed/truncated URL (found live 2026-08-03).
        var headerHeight = 88 + (string.IsNullOrEmpty(linkUrl) ? 0 : 36);
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, headerHeight)); // header
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // agreement card
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));   // checkbox strip
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));   // buttons

        // ── Header ────────────────────────────────────────────────────────────
        var header = new Panel { Dock = DockStyle.Fill, BackColor = Bg, Margin = new Padding(0, 0, 0, 12) };

        var badge = new Label
        {
            Text = "  SENTINEL SUPPORT  ",
            AutoSize = true,
            Location = new Point(0, 0),
            Font = new Font("Segoe UI Semibold", 8.5F),
            ForeColor = Accent,
            BackColor = Color.FromArgb(28, 48, 40),
            Padding = new Padding(8, 4, 8, 4),
        };

        var title = new Label
        {
            Text = titleOverride ?? "Remote Support Agreement",
            AutoSize = true,
            Location = new Point(0, 28),
            Font = new Font("Segoe UI Semibold", 18F),
            ForeColor = TextPrimary,
            BackColor = Color.Transparent,
        };

        var subtitle = new Label
        {
            Text = "Please read carefully, then check the box below to authorize this session.",
            AutoSize = true,
            Location = new Point(0, 60),
            Font = new Font("Segoe UI", 10F),
            ForeColor = TextMuted,
            BackColor = Color.Transparent,
        };

        header.Controls.Add(badge);
        header.Controls.Add(title);
        header.Controls.Add(subtitle);

        // Optional "View full terms" link (auto-provisioning ToS/MSA flow) — opens the terms page
        // in the default browser; the dialog itself stays up. Positioned inside the (now taller)
        // header row so the full URL is visible and clickable.
        if (!string.IsNullOrEmpty(linkUrl))
        {
            var link = new LinkLabel
            {
                Text = $"View full terms && conditions — {linkUrl}",
                AutoSize = true,
                Location = new Point(0, 90),
                LinkColor = Color.FromArgb(120, 190, 245),
                ActiveLinkColor = Color.White,
                BackColor = Color.Transparent,
                Font = new Font("Segoe UI", 9.5F),
                TabStop = false,
            };
            link.LinkClicked += (_, _) =>
            {
                try { Process.Start(new ProcessStartInfo(linkUrl) { UseShellExecute = true }); } catch { /* best-effort */ }
            };
            header.Controls.Add(link);
        }

        // ── Agreement card (scrollable text with breathing room) ──────────────
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Card,
            Padding = new Padding(1), // border thickness via outer color
            Margin = new Padding(0, 4, 0, 12),
        };
        // Fake border: outer panel CardBorder, inner fill Card
        card.BackColor = CardBorder;
        var cardInner = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Card,
            Padding = new Padding(22, 18, 18, 18),
        };

        var body = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            BackColor = Card,
            ForeColor = Color.FromArgb(210, 218, 228),
            Font = new Font("Segoe UI", 10.5F),
            Text = bodyOverride ?? BuildAgreementText(sessionLabel),
            TabStop = false,
            Cursor = Cursors.Default,
        };
        // Extra line height via slightly larger font + padded content in BuildAgreementText.
        // Select all disabled so it reads as a document, not an editor.
        body.GotFocus += (_, _) => dialog.ActiveControl = null;

        cardInner.Controls.Add(body);
        card.Controls.Add(cardInner);

        // ── Consent checkbox strip (clearly BELOW the card — no overlap) ──────
        var consentStrip = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(28, 40, 36),
            Margin = new Padding(0, 0, 0, 12),
            Padding = new Padding(16, 12, 16, 12),
        };

        var check = new CheckBox
        {
            Text = checkOverride ?? "I have read this agreement and authorize Sentinel Support to remotely access this computer for this session only.",
            AutoSize = false,
            Dock = DockStyle.Fill,
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 10.5F),
            BackColor = Color.Transparent,
            CheckAlign = ContentAlignment.TopLeft,
            TextAlign = ContentAlignment.TopLeft,
            Padding = new Padding(4, 2, 4, 2),
            Cursor = Cursors.Hand,
        };

        consentStrip.Controls.Add(check);
        // Draw a soft accent bar on the left of the strip.
        consentStrip.Paint += (_, e) =>
        {
            using var brush = new SolidBrush(Accent);
            e.Graphics.FillRectangle(brush, 0, 0, 4, consentStrip.Height);
        };

        // ── Buttons ───────────────────────────────────────────────────────────
        var btnRow = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Bg,
            Margin = new Padding(0),
        };

        var btnDecline = new Button
        {
            Text = "Decline",
            DialogResult = DialogResult.Cancel,
            Size = new Size(130, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = DangerMuted,
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI Semibold", 10.5F),
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Left | AnchorStyles.Top,
        };
        btnDecline.FlatAppearance.BorderSize = 0;
        btnDecline.FlatAppearance.MouseOverBackColor = Color.FromArgb(90, 94, 102);

        var btnAccept = new Button
        {
            Text = acceptOverride ?? "Accept  &  Connect",
            DialogResult = DialogResult.None, // gated — we set DialogResult only when enabled path runs
            Size = new Size(200, 44),
            FlatStyle = FlatStyle.Flat,
            BackColor = AccentDim,
            ForeColor = Color.FromArgb(180, 185, 190),
            Font = new Font("Segoe UI Semibold", 10.5F),
            Enabled = false,
            Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Right | AnchorStyles.Top,
        };
        btnAccept.FlatAppearance.BorderSize = 0;

        void LayoutButtons()
        {
            btnDecline.Location = new Point(0, 8);
            btnAccept.Location = new Point(Math.Max(0, btnRow.ClientSize.Width - btnAccept.Width), 8);
        }
        btnRow.Resize += (_, _) => LayoutButtons();
        btnRow.Controls.Add(btnDecline);
        btnRow.Controls.Add(btnAccept);
        LayoutButtons();

        check.CheckedChanged += (_, _) =>
        {
            btnAccept.Enabled = check.Checked;
            if (check.Checked)
            {
                btnAccept.BackColor = Accent;
                btnAccept.ForeColor = Color.White;
                btnAccept.FlatAppearance.MouseOverBackColor = Color.FromArgb(56, 180, 125);
            }
            else
            {
                btnAccept.BackColor = AccentDim;
                btnAccept.ForeColor = Color.FromArgb(180, 185, 190);
            }
        };

        // Accept only if still checked (defensive).
        btnAccept.Click += (_, _) =>
        {
            if (!check.Checked) return;
            dialog.DialogResult = DialogResult.OK;
            dialog.Close();
        };

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(card, 0, 1);
        root.Controls.Add(consentStrip, 0, 2);
        root.Controls.Add(btnRow, 0, 3);

        dialog.Controls.Add(root);
        dialog.CancelButton = btnDecline;
        dialog.AcceptButton = btnAccept;

        // Start scrolled to the top of the agreement.
        body.Select(0, 0);
        body.ScrollToCaret();

        var result = owner is null ? dialog.ShowDialog() : dialog.ShowDialog(owner);
        return result == DialogResult.OK && check.Checked;
    }

    private static string BuildAgreementText(string sessionLabel)
    {
        // Generous blank lines between sections so the document has real breathing room.
        var tech = Config.TechnicianDisplayName;
        var ver = Config.ConsentAgreementVersion;
        var machine = Environment.MachineName;
        var user = Environment.UserName;

        return
            "SENTINEL REMOTE SUPPORT AGREEMENT\r\n" +
            $"Version  {ver}\r\n" +
            "\r\n" +
            "──────────────────────────────────────────────────────────────\r\n" +
            "\r\n" +
            "By checking the box below and clicking Accept, you authorize the\r\n" +
            "following for THIS support session only.\r\n" +
            "\r\n" +
            "\r\n" +
            "1.  REMOTE ACCESS\r\n" +
            "\r\n" +
            $"    A technician from {tech} may connect to this\r\n" +
            $"    computer remotely to provide technical support for {sessionLabel}.\r\n" +
            "\r\n" +
            "    Access uses a secure reverse tunnel. The technician does not\r\n" +
            "    need your Windows password.\r\n" +
            "\r\n" +
            "\r\n" +
            "2.  WHAT THE TECHNICIAN MAY DO\r\n" +
            "\r\n" +
            "    •  Run diagnostic and repair commands (PowerShell / shell)\r\n" +
            "    •  Inspect system configuration and installed software\r\n" +
            "    •  Install or remove software you requested for this issue\r\n" +
            "    •  Take other steps reasonably needed to resolve support\r\n" +
            "\r\n" +
            "    This tool provides command-line remote access (not a full\r\n" +
            "    desktop screen-share by itself). If screen capture or other\r\n" +
            "    tools are used in the same engagement, you will be aware as\r\n" +
            "    part of the live support call.\r\n" +
            "\r\n" +
            "\r\n" +
            "3.  VISIBLE SESSION INDICATOR\r\n" +
            "\r\n" +
            "    While CONNECT is active, a persistent on-screen banner shows\r\n" +
            "    that a support session is live (similar to TeamViewer or\r\n" +
            "    AnyDesk). You can end the session at any time with DISCONNECT\r\n" +
            "    or by closing this app.\r\n" +
            "\r\n" +
            "\r\n" +
            "4.  ACTIVITY LOG\r\n" +
            "\r\n" +
            "    Session start and end, technician identity, your consent, and\r\n" +
            "    local app actions are written to a log file. When the session\r\n" +
            "    ends, a copy is left on your Desktop so you (or your security\r\n" +
            "    team) can see that support ran and when.\r\n" +
            "\r\n" +
            "\r\n" +
            "5.  CLEAN REMOVAL\r\n" +
            "\r\n" +
            "    Closing this app (X / Exit) removes the temporary support\r\n" +
            "    account, scheduled cleanup task, and related components\r\n" +
            "    installed for this session.\r\n" +
            "\r\n" +
            "    DISCONNECT alone only drops the tunnel so you can reconnect\r\n" +
            "    without re-setup during the same open window.\r\n" +
            "\r\n" +
            "\r\n" +
            "6.  NOT UNATTENDED ACCESS\r\n" +
            "\r\n" +
            "    This agreement covers the CONNECT button only (attended /\r\n" +
            "    ephemeral session).\r\n" +
            "\r\n" +
            "    “Start automatically after reboot” is a separate opt-in for\r\n" +
            "    standing access and is not covered by this dialog.\r\n" +
            "\r\n" +
            "\r\n" +
            "7.  YOUR RIGHTS\r\n" +
            "\r\n" +
            "    •  You may decline this agreement — no connection is made.\r\n" +
            "    •  You may end a live session at any time.\r\n" +
            "    •  Keep the Desktop session log for your records.\r\n" +
            "\r\n" +
            "\r\n" +
            "──────────────────────────────────────────────────────────────\r\n" +
            "\r\n" +
            $"Technician identity:   {tech}\r\n" +
            $"This machine:          {machine}\r\n" +
            $"Windows user:          {user}\r\n" +
            "\r\n";
    }
}
