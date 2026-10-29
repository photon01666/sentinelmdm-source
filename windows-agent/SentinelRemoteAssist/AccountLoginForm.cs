namespace SentinelRemoteAssist;

/// <summary>
/// SentinelMDM account login — mirrors AccountLinkActivity.kt's "Parent Login"/admin-agent screen.
/// Public build: Email + Password (posts to /login). Admin/sub-user build (Config.AdminAgent):
/// Username + Password (posts to /api/device-admin/login). Shown once per app run, before the
/// existing ConsentDialog — this ADDS account-gated access control on top of the unchanged
/// consent/session-indicator/ephemeral-account flow, it does not replace or bypass any of it.
/// </summary>
internal sealed class AccountLoginForm : Form
{
    private static readonly Color Bg = Color.FromArgb(22, 24, 28);
    private static readonly Color Card = Color.FromArgb(32, 36, 42);
    private static readonly Color CardBorder = Color.FromArgb(55, 62, 72);
    private static readonly Color TextPrimary = Color.FromArgb(245, 247, 250);
    private static readonly Color TextMuted = Color.FromArgb(160, 170, 185);
    private static readonly Color Accent = Color.FromArgb(46, 160, 110);
    private static readonly Color ErrorColor = Color.FromArgb(220, 90, 90);

    private readonly TextBox _identifierBox;
    private readonly TextBox _passwordBox;
    private readonly TextBox _totpBox;
    private readonly Label _errorLabel;
    private readonly Button _submitButton;
    private readonly Panel _totpPanel;
    private readonly AccountAuthClient _auth = new();
    private string? _deviceIdForTicket;

    // Row layout — indices into _root.RowStyles, and the two rows that toggle between 0 (hidden)
    // and their real height (shown). Kept as explicit, code-driven RowStyle.Height mutation rather
    // than TableLayoutPanel's AutoSize-row-collapses-when-hidden behavior — that behavior is
    // real but its exact interaction with a Dock=Fill child panel isn't something worth gambling
    // on without a live Windows runtime to verify against. A dead-simple "set Height, recompute
    // ClientSize" is fully deterministic instead.
    private const int TotpRowIndex = 6;
    private const int ErrorRowIndex = 7;
    // Reported live 2026-07-17: "the OTP text is cut off" even after the 18->22px totpLabel fix
    // below (which itself fixed the same clipping class for this same label once already) — so
    // 22px evidently still isn't enough margin at 10pt Segoe UI on the reporting machine (most
    // likely DPI-scaling-dependent: AutoScaleMode.Dpi scales fonts and fixed pixel RowStyle
    // heights slightly differently, so a value that's exactly-enough at 100% scaling can clip
    // again at 125%/150%). Grown further with real margin this time rather than the smallest
    // value that happened to look right once. Could not visually re-verify this against a live
    // Windows runtime this round (this dialog only shows pre-enrollment; getting a screenshot of
    // it over this session's SSH path needs the interactive-session-injection technique, not
    // worth it for this fix) — if it's STILL clipped, grow these further rather than assuming the
    // sizing is fine and looking elsewhere.
    private const int TotpLabelHeight = 26; // was 22
    private const int TotpRowHeight = 64;   // label(26) + textbox's same 38px share as before
    private const int ErrorRowHeight = 28;  // was 24 — same margin reasoning as the totp label
    private readonly TableLayoutPanel _root;

    public string? EnrollmentTicket { get; private set; }

    private AccountLoginForm()
    {
        var identifierLabel = Config.AdminAgent ? "Username or email" : "Email";
        Text = "Sign in — Sentinel Remote Assist";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        BackColor = Bg;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F);
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96F, 96F);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(28, 24, 28, 20) };
        // Title/subtitle rows bumped up from their original 40/24px — at 16pt bold / 10pt Segoe UI
        // those were too tight and clipped descenders ("Sign in" rendered as "Sian in"). Combined
        // with MiddleLeft alignment below so the glyph box has room on both sides, not just more
        // room below a still-top-anchored baseline.
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));   // title
        // Subtitle text (esp. the admin variant: "Sign in with an admin or sub-user account to
        // manage this device.") wraps to 2 lines at this dialog's width — 30px only fit ~1.3
        // lines, silently clipping the wrapped second line off the bottom of the row. Sized for
        // 2 full lines of 10pt Segoe UI now, both variants.
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));   // subtitle
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));   // identifier
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 10));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));   // password
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));    // totp — 0 until 2FA is actually needed
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));    // error — 0 until there's an error to show
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // spacer before button (was Percent 100 —
                                                                    // that soaked up the dead space between
                                                                    // the password field and the Sign In button)
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));   // button
        _root = root;

        var title = new Label
        {
            Text = "Sign in", AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 16F, FontStyle.Bold), ForeColor = TextPrimary,
        };
        var subtitle = new Label
        {
            Text = Config.AdminAgent
                ? "Sign in with an admin or sub-user account to manage this device."
                : "Sign in with your SentinelMDM account",
            AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = TextMuted,
        };

        _identifierBox = MakeTextBox(identifierLabel);
        _passwordBox = MakeTextBox("Password");
        _passwordBox.UseSystemPasswordChar = true;

        _totpBox = MakeTextBox("6-digit code");
        _totpPanel = new Panel { Dock = DockStyle.Fill, Visible = false };
        // Height=18 was too short for 10pt Segoe UI (same clipping bug as the title/subtitle
        // labels — "Two-factor code" rendered with its tops/bottoms cut off). Then grew to 22,
        // which per the 2026-07-17 report still wasn't enough — see TotpLabelHeight's doc comment.
        var totpLabel = new Label { Text = "Two-factor code", AutoSize = false, Dock = DockStyle.Top, Height = TotpLabelHeight, TextAlign = ContentAlignment.MiddleLeft, ForeColor = TextMuted };
        _totpPanel.Controls.Add(_totpBox);
        _totpPanel.Controls.Add(totpLabel);

        _errorLabel = new Label { AutoSize = false, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = ErrorColor, Visible = false };

        _submitButton = new Button
        {
            Text = "Sign In", Dock = DockStyle.Right, Width = 140, Height = 36,
            FlatStyle = FlatStyle.Flat, BackColor = Accent, ForeColor = Color.White, Cursor = Cursors.Hand,
        };
        _submitButton.FlatAppearance.BorderSize = 0;
        _submitButton.Click += async (_, _) => await OnSubmitAsync();
        AcceptButton = _submitButton;

        root.Controls.Add(title, 0, 0);
        root.Controls.Add(subtitle, 0, 1);
        root.Controls.Add(_identifierBox, 0, 3);
        root.Controls.Add(_passwordBox, 0, 5);
        root.Controls.Add(_totpPanel, 0, TotpRowIndex);
        root.Controls.Add(_errorLabel, 0, ErrorRowIndex);
        root.Controls.Add(_submitButton, 0, 9);
        Controls.Add(root);

        ClientSize = new Size(440, ComputeContentHeight());
    }

    /// <summary>Padding (44) + every row's CURRENT height — recomputed whenever the totp/error
    /// rows toggle between 0 and their real height, so the dialog only ever reserves space for
    /// what's actually on screen.</summary>
    private int ComputeContentHeight()
    {
        var rows = 0;
        foreach (RowStyle rs in _root.RowStyles) rows += (int)rs.Height;
        return 44 + rows; // 44 = root Padding top(24) + bottom(20)
    }

    private TextBox MakeTextBox(string placeholder) => new()
    {
        Dock = DockStyle.Fill, BackColor = Card, ForeColor = TextPrimary,
        BorderStyle = BorderStyle.FixedSingle, PlaceholderText = placeholder,
    };

    private async Task OnSubmitAsync()
    {
        SetBusy(true);
        HideError();
        try
        {
            if (_totpPanel.Visible)
            {
                var code = _totpBox.Text.Trim();
                if (code.Length < 6) { ShowError("Enter the 6-digit code"); return; }
                var totpResult = await _auth.VerifyTotpAsync(code);
                if (!totpResult.Ok) { ShowError(totpResult.Error ?? "Invalid code"); return; }
                await CompleteEnrollmentAsync();
                return;
            }

            var identifier = _identifierBox.Text.Trim();
            var password = _passwordBox.Text;
            if (identifier.Length == 0 || password.Length == 0)
            {
                ShowError("Please enter your credentials");
                return;
            }

            var result = await _auth.LoginAsync(identifier, password);
            if (!result.Ok)
            {
                ShowError(result.Error ?? "Invalid credentials");
                return;
            }
            if (result.TotpRequired)
            {
                _totpPanel.Visible = true;
                _root.RowStyles[TotpRowIndex].Height = TotpRowHeight;
                ClientSize = new Size(ClientSize.Width, ComputeContentHeight());
                _totpBox.Focus();
                return;
            }
            await CompleteEnrollmentAsync();
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task CompleteEnrollmentAsync()
    {
        _submitButton.Text = "Registering…";
        _deviceIdForTicket ??= DeviceIdentity.DeviceId;
        var ticketResult = await _auth.RequestEnrollmentTicketAsync(_deviceIdForTicket);
        if (!ticketResult.Ok)
        {
            ShowError(ticketResult.Error ?? "Registration failed");
            _submitButton.Text = "Sign In";
            return;
        }
        EnrollmentTicket = ticketResult.Ticket;
        AccountLinkedSession.IsLinked = true;
        AccountLinkedSession.DeviceId = _deviceIdForTicket;
        DialogResult = DialogResult.OK;
        Close();
    }

    private void SetBusy(bool busy)
    {
        _submitButton.Enabled = !busy;
        _identifierBox.Enabled = !busy;
        _passwordBox.Enabled = !busy;
        if (busy) _submitButton.Text = "Signing in…";
        else if (_submitButton.Text != "Registering…") _submitButton.Text = "Sign In";
    }

    private void ShowError(string message)
    {
        _errorLabel.Text = message;
        _errorLabel.Visible = true;
        _root.RowStyles[ErrorRowIndex].Height = ErrorRowHeight;
        ClientSize = new Size(ClientSize.Width, ComputeContentHeight());
    }

    private void HideError()
    {
        if (!_errorLabel.Visible) return;
        _errorLabel.Visible = false;
        _root.RowStyles[ErrorRowIndex].Height = 0;
        ClientSize = new Size(ClientSize.Width, ComputeContentHeight());
    }

    /// <summary>Shows the modal login dialog. Returns the enrollment ticket on success, or null if
    /// the user closed/cancelled without completing login.</summary>
    public static string? ShowAndGetTicket(IWin32Window? owner)
    {
        using var form = new AccountLoginForm();
        var result = form.ShowDialog(owner);
        return result == DialogResult.OK ? form.EnrollmentTicket : null;
    }
}
