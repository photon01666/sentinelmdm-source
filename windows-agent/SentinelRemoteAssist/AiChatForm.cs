using System.Text.Json;

namespace SentinelRemoteAssist;

/// <summary>
/// The "Live Chat" tray window — a non-modal chat with the DeepSeek V4 Flash AI assistant (via the
/// server's runChatTurn(), never talking to the AI directly). Chrome follows ConsentDialog's dark
/// palette; shown via Show(owner), not ShowDialog, since it stays open while chatting. One ongoing
/// conversation per device (server-side v1 design) — this window is a singleton per MainForm.
///
/// Fully autonomous (locked design decision) — every action (PowerShell script or an AppLocker
/// Install Mode toggle) the AI decides to take already executed by the time it's shown here; each
/// gets its own card with the script/action shown VERBATIM plus a live "Running…"/"Done." status,
/// informational only, no confirmation step. See RemoteAssistSocket's
/// ChatToolProposalReceived/ChatToolResultReceived events.
/// </summary>
internal sealed class AiChatForm : Form
{
    private static readonly Color Bg = Color.FromArgb(22, 24, 28);
    private static readonly Color Card = Color.FromArgb(32, 36, 42);
    private static readonly Color CardBorder = Color.FromArgb(55, 62, 72);
    private static readonly Color TextPrimary = Color.FromArgb(245, 247, 250);
    private static readonly Color TextMuted = Color.FromArgb(160, 170, 185);
    private static readonly Color Accent = Color.FromArgb(46, 160, 110);       // sea-green
    private static readonly Color UserBubble = Color.FromArgb(40, 66, 96);     // muted blue
    private static readonly Color ProposalBorder = Color.FromArgb(198, 148, 40); // amber — draws the eye before a Run click

    private readonly RemoteAssistSocket _socket;
    private readonly FlowLayoutPanel _transcript;
    private readonly Panel _transcriptScroll;
    private readonly TextBox _input;
    private readonly Button _sendButton;
    private readonly Label _thinkingLabel;

    // Tool-action cards, keyed by msgId, so a later ai_chat_tool_result can find and update the
    // SAME card (show the executed output) instead of appending a new one.
    private readonly Dictionary<string, (Panel Card, Label ResultLabel)> _proposalCards = new();

    public AiChatForm(RemoteAssistSocket socket)
    {
        _socket = socket;

        Text = "Live Chat — Sentinel Remote Assist";
        ClientSize = new Size(520, 640);
        MinimumSize = new Size(420, 420);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Bg;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 10F);
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96F, 96F);
        var appIcon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        if (appIcon is not null) Icon = appIcon;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Bg,
            Padding = new Padding(12),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));   // header
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // transcript
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));   // "Thinking…" status, above the input box
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));   // input row

        var header = new Label
        {
            Text = "Chat with the Sentinel AI assistant about this PC",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI Semibold", 11F),
            ForeColor = TextPrimary,
        };

        _transcript = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Width = 480,
            BackColor = Bg,
        };
        _transcriptScroll = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            BackColor = Bg,
            Padding = new Padding(0, 0, 4, 0),
        };
        _transcriptScroll.Controls.Add(_transcript);
        // Keep the flow panel's width pinned to the scroll viewport so bubble labels wrap instead
        // of growing the panel horizontally (AutoSize + a fixed Width would otherwise fight).
        _transcriptScroll.Resize += (_, _) => _transcript.Width = Math.Max(200, _transcriptScroll.ClientSize.Width - 4);

        var inputRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
        };
        inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        inputRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _input = new TextBox
        {
            Multiline = true,
            Dock = DockStyle.Fill,
            BackColor = Card,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.FixedSingle,
        };
        _input.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter && !e.Shift)
            {
                e.SuppressKeyPress = true;
                _ = OnSendAsync();
            }
        };

        _sendButton = new Button
        {
            Text = "Send",
            Dock = DockStyle.Fill,
            BackColor = Accent,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
        };
        _sendButton.FlatAppearance.BorderSize = 0;
        _sendButton.Click += (_, _) => _ = OnSendAsync();

        _thinkingLabel = new Label
        {
            Text = "",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = TextMuted,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Italic),
        };

        inputRow.Controls.Add(_input, 0, 0);
        inputRow.Controls.Add(_sendButton, 1, 0);

        root.Controls.Add(header, 0, 0);
        root.Controls.Add(_transcriptScroll, 0, 1);
        root.Controls.Add(_thinkingLabel, 0, 2);
        root.Controls.Add(inputRow, 0, 3);
        Controls.Add(root);

        _socket.ChatMessageReceived += OnChatMessageReceived;
        _socket.ChatToolProposalReceived += OnChatToolProposalReceived;
        _socket.ChatToolResultReceived += OnChatToolResultReceived;

        FormClosed += (_, _) =>
        {
            _socket.ChatMessageReceived -= OnChatMessageReceived;
            _socket.ChatToolProposalReceived -= OnChatToolProposalReceived;
            _socket.ChatToolResultReceived -= OnChatToolResultReceived;
        };

        AppendSystemBubble("Ask about anything going on with this PC. I can check things and make fixes directly — you'll see exactly what I run and what happens as I go.");
    }

    private async Task OnSendAsync()
    {
        var text = _input.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;
        _input.Text = "";
        AppendBubble("user", text);
        _sendButton.Enabled = false;
        _thinkingLabel.Text = "Thinking…";
        await _socket.SendChatMessage(text, Guid.NewGuid().ToString("N"));
        // Re-enabled by the eventual ai_chat_message/ai_chat_tool_proposal reply, not here — a
        // reply may take a few seconds (a real DeepSeek round-trip), and re-enabling immediately
        // would let the customer fire off a burst of messages before the first one is answered.
    }

    private void UiInvoke(Action action)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { BeginInvoke(action); } catch (ObjectDisposedException) { } return; }
        action();
    }

    private void OnChatMessageReceived(string role, string text, string? clientMsgId)
    {
        UiInvoke(() =>
        {
            AppendBubble(role, text);
            _sendButton.Enabled = true;
            _thinkingLabel.Text = "";
        });
    }

    private void OnChatToolProposalReceived(string msgId, string kind, string payloadJson, string reason)
    {
        UiInvoke(() =>
        {
            AppendProposalCard(msgId, kind, payloadJson, reason);
            // Send stays disabled / "Working…" stays up — the autonomous loop may take several more
            // steps before it settles on a plain-text reply (see OnChatMessageReceived, the only
            // place that re-enables Send), and letting the customer fire off another message mid-loop
            // would race a second runChatTurn against this one.
            _thinkingLabel.Text = "Working…";
        });
    }

    private void OnChatToolResultReceived(string msgId, bool ok, string resultJson)
    {
        UiInvoke(() =>
        {
            if (!_proposalCards.TryGetValue(msgId, out var card)) return;
            card.ResultLabel.Text = ok ? "Done." : "That didn't work — see the reply above for details.";
            card.ResultLabel.ForeColor = ok ? Accent : Color.FromArgb(214, 100, 90);
        });
    }

    private void AppendSystemBubble(string text) => AppendBubble("system", text);

    private void AppendBubble(string role, string text)
    {
        var isUser = role == "user";
        var isSystem = role == "system";
        var bubble = new Panel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = isUser ? UserBubble : Card,
            Margin = new Padding(isUser ? 60 : 0, 4, isUser ? 0 : 60, 4),
            Padding = new Padding(10, 8, 10, 8),
        };
        var label = new Label
        {
            Text = text,
            AutoSize = true,
            MaximumSize = new Size(340, 0),
            ForeColor = isSystem ? TextMuted : TextPrimary,
            Font = isSystem ? new Font("Segoe UI", 9F, FontStyle.Italic) : Font,
        };
        bubble.Controls.Add(label);
        _transcript.Controls.Add(bubble);
        ScrollToBottom();
    }

    private void AppendProposalCard(string msgId, string kind, string payloadJson, string reason)
    {
        string scriptOrAction;
        string title;
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;
            if (kind == "toggle_applocker_install_mode")
            {
                var action = root.TryGetProperty("action", out var a) ? a.GetString() : "enable";
                title = action == "disable" ? "Switch AppLocker back to Enforce" : "Turn on Install Mode (auto-reverts in 1 hour)";
                scriptOrAction = action == "disable"
                    ? "Switches this PC's app allow-list back to normal enforcement."
                    : "Temporarily allows installing/running new apps on this PC. Automatically switches back to normal enforcement in 1 hour — you never have to remember to turn it off.";
            }
            else
            {
                title = "Run a command on this PC";
                scriptOrAction = root.TryGetProperty("script", out var s) ? (s.GetString() ?? "") : "";
            }
        }
        catch
        {
            title = "Proposed action";
            scriptOrAction = payloadJson;
        }

        var card = new Panel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Card,
            Margin = new Padding(0, 6, 60, 6),
            Padding = new Padding(10),
            BorderStyle = BorderStyle.None,
        };
        // Poor-man's colored border (Panel has no Border color property) via a 2px inset panel.
        var borderHost = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = ProposalBorder, Padding = new Padding(2) };
        borderHost.Controls.Add(card);

        var layout = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1 };
        var titleLabel = new Label { Text = title, AutoSize = true, Font = new Font("Segoe UI Semibold", 9.5F), ForeColor = TextPrimary, MaximumSize = new Size(340, 0) };
        var reasonLabel = new Label { Text = reason, AutoSize = true, ForeColor = TextMuted, MaximumSize = new Size(340, 0), Margin = new Padding(0, 2, 0, 6) };
        Control detail = kind == "run_powershell"
            ? new TextBox { Text = scriptOrAction, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical, Width = 320, Height = 60, BackColor = Bg, ForeColor = TextPrimary, Font = new Font("Consolas", 9F) }
            : new Label { Text = scriptOrAction, AutoSize = true, MaximumSize = new Size(340, 0), ForeColor = TextMuted };

        // Fully autonomous (locked design decision) — no Run/Deny here. The action already
        // executed by the time this card is shown; this is a live progress readout only.
        var resultLabel = new Label { Text = "Running…", AutoSize = true, ForeColor = TextMuted, Margin = new Padding(0, 6, 0, 0) };

        layout.Controls.Add(titleLabel);
        layout.Controls.Add(reasonLabel);
        layout.Controls.Add(detail);
        layout.Controls.Add(resultLabel);
        card.Controls.Add(layout);

        _proposalCards[msgId] = (card, resultLabel);
        _transcript.Controls.Add(borderHost);
        ScrollToBottom();
    }

    private void ScrollToBottom()
    {
        _transcriptScroll.VerticalScroll.Value = _transcriptScroll.VerticalScroll.Maximum;
        _transcriptScroll.PerformLayout();
    }
}
