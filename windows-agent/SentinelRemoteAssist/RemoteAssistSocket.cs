using System.Text.Json;
using System.Threading;
using SIO = SocketIOClient.SocketIO;
using SIOCore = SocketIO.Core;

namespace SentinelRemoteAssist;

internal sealed class RemoteAssistSocket
{
    private SIO? _client;
    private string? _pendingEnrollmentTicket;
    private VpnManager? _vpn;
    private XrayTransportManager? _xray;
    private S3DriveManager? _s3drive;
    private System.Threading.Timer? _statusTimer;
    private System.Threading.Timer? _xrayHealthTimer;
    private int _consecutiveXrayHealthFailures;
    private const int MaxXrayHealthFailuresBeforeRestart = 2;
    private static readonly TimeSpan XrayHealthInterval = TimeSpan.FromSeconds(30);
    // Control-channel watchdog: CheckXrayHealth() ran on this same 30s timer but only ever
    // inspected xray/REALITY transport health, never whether the Socket.IO control channel
    // ITSELF was actually connected. Found live 2026-07-17: a reconnect rejected server-side
    // ("Socket error: Invalid signature" — e.g. transient clock skew on a heavily-loaded host)
    // left the control channel permanently disconnected with xray still reporting healthy, so
    // this watchdog never noticed and the agent never retried again on its own — only a full
    // process kill/restart recovered it. _lastConnectAttemptUtc + this threshold let the SAME
    // timer also catch "still not connected N seconds after we last tried" and force a fresh
    // Connect(), independent of xray's own state.
    private DateTime _lastConnectAttemptUtc = DateTime.MinValue;
    private static readonly TimeSpan ControlChannelStuckThreshold = TimeSpan.FromSeconds(45);

    public event Action<string>? StatusChanged;
    public bool IsConnected => _client?.Connected ?? false;

    public RemoteAssistSocket(VpnManager? vpn, XrayTransportManager? xray, S3DriveManager? s3drive = null)
    {
        _vpn = vpn;
        _xray = xray;
        _s3drive = s3drive;
        if (_vpn is not null)
        {
            _vpn.StatusChanged += (_, _) => EmitVpnStatus();
        }
        if (_xray is not null)
        {
            _xray.RunningChanged += running =>
            {
                _vpn?.SetXrayRunning(running);
                EmitVpnStatus();
            };
        }
        if (_s3drive is not null)
        {
            _s3drive.StatusUpdated += () => { try { _ = EmitS3DriveStatus(); } catch { } };
        }
    }

    public void Connect(string? enrollmentTicket)
    {
        _lastConnectAttemptUtc = DateTime.UtcNow;
        _pendingEnrollmentTicket = enrollmentTicket;
        var controlUrl = (_xray?.IsRunning ?? false) && (_xray?.ControlPort ?? 0) > 0
            ? $"http://127.0.0.1:{_xray.ControlPort}"
            : Config.WebUrl;
        var opts = new SocketIOClient.SocketIOOptions
        {
            Path = "/socket.io",
            Reconnection = true,
            ReconnectionDelay = 3000,
            EIO = SIOCore.EngineIO.V4,
            ////Transport = SocketIOClient.Transport.TransportProtocol.Polling,
            Auth = BuildAuthPayload(),
        };
        if (_xray?.IsRunning ?? false)
        {
            opts.ExtraHeaders = new Dictionary<string, string>
            {
                { "X-Via-Reality", _xray?.SelectedNode ?? "1" },
            };
        }
        var client = new SIO(controlUrl, opts);
        _client = client;

        client.OnConnected += async (_, _) =>
        {
            StatusChanged?.Invoke("Control channel connected");
            StartXrayHealthCheck();
            // A session is up on the current REALITY address — re-arm the IPv6-first preference
            // (see XrayTransportManager's ladder comment) so the NEXT deliberate xray start dials
            // the preferred candidate rather than staying parked on a v4 fallback.
            _xray?.ResetAddressLadder();
            await client.EmitAsync("register", new
            {
                platform = "windows",
                agentKind = "remote_assist",
                deviceId = DeviceIdentity.DeviceId,
                name = Environment.MachineName,
                model = "Windows PC",
                appVersion = Config.AgentVersion,
                // This device's own Hop-1 (reverse-tunnel-to-bastion) public key — replaces the old
                // shared per-account key baked in at build time. The server stores it on the device
                // row and hands it to the bastion at provision time instead. Only meaningful for
                // account-linked builds; null for the legacy ad hoc flow (Hop1Identity still
                // generates a keypair regardless, but nothing reads it there — harmless).
                hop1PublicKey = Hop1Identity.PublicKeyOpenSsh,
            });
            // The server just accepted this connection — for a first-time-enrollment attempt
            // (_pendingEnrollmentTicket was set), that acceptance IS what "enrolled" means (not
            // merely submitting a login). Persist that fact so a future --unattended-tunnel run
            // can reconnect via signed auth alone, no login prompt.
            if (_pendingEnrollmentTicket is not null) AccountLinkedSession.MarkEnrolled();
            _pendingEnrollmentTicket = null;
            StartStatusTimer(client);
        };

        client.OnDisconnected += (_, reason) =>
        {
            StatusChanged?.Invoke($"Control channel disconnected ({reason})");
            StopStatusTimer();
        };

        client.On("registered", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                if (payload.TryGetProperty("zkPubKey", out var zk) && zk.ValueKind == JsonValueKind.String)
                {
                    AccountLinkedSession.ZkPubKey = zk.GetString();
                    StatusChanged?.Invoke("ZK pubkey received from server");
                }
            }
            catch { /* no zkPubKey field = admin-fleet (non-ZK) device, nothing to do */ }
        });

        client.On("zk_pub_key", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                // Live reassignment (server.js's updateDeviceOwner()) — {zkPubKey} or
                // {zkPubKey:null} if the owner was removed. Both are valid: set or clear.
                AccountLinkedSession.ZkPubKey = payload.TryGetProperty("zkPubKey", out var zk) && zk.ValueKind == JsonValueKind.String
                    ? zk.GetString()
                    : null;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process zk_pub_key push: {ex.Message}");
            }
        });

        client.On("remote_assist_ssh_key", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var pubKey = payload.TryGetProperty("publicKeyOpenSsh", out var pk) ? pk.GetString() : null;
                var exclude = payload.TryGetProperty("excludeSharedOperatorKey", out var ex) && ex.GetBoolean();
                if (string.IsNullOrEmpty(pubKey)) return;
                // Accumulate — never assign. The server pushes the browser key and the
                // standing support key back to back (~15ms apart); a single-valued field let the
                // second clobber the first before setup ever read it. See
                // AccountLinkedSession.PendingSshPublicKeys for the full forensics.
                AccountLinkedSession.AddPendingSshPublicKey(pubKey);
                AccountLinkedSession.ExcludeSharedOperatorKey = exclude;
                StatusChanged?.Invoke(
                    $"Received a new remote-assist session key from the dashboard ({AccountLinkedSession.PendingSshPublicKeys.Count} pending)");
                SetupRunner.RunElevatedSetup();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process remote-assist SSH key push: {ex.Message}");
            }
        });

        client.On("ai_chat_message", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var role = payload.TryGetProperty("role", out var r) ? r.GetString() ?? "assistant" : "assistant";
                var text = payload.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";
                var clientMsgId = payload.TryGetProperty("clientMsgId", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
                ChatMessageReceived?.Invoke(role, text, clientMsgId);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process ai_chat_message: {ex.Message}");
            }
        });

        client.On("ai_chat_tool_proposal", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var msgId = payload.TryGetProperty("msgId", out var m) ? m.GetString() ?? "" : "";
                var kind = payload.TryGetProperty("kind", out var k) ? k.GetString() ?? "" : "";
                var payloadJson = payload.TryGetProperty("payload", out var p) ? p.GetRawText() : "{}";
                var reason = payload.TryGetProperty("reason", out var re) ? re.GetString() ?? "" : "";
                ChatToolProposalReceived?.Invoke(msgId, kind, payloadJson, reason);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process ai_chat_tool_proposal: {ex.Message}");
            }
        });

        client.On("ai_chat_tool_result", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var msgId = payload.TryGetProperty("msgId", out var m) ? m.GetString() ?? "" : "";
                var ok = payload.TryGetProperty("ok", out var o) && o.GetBoolean();
                var resultJson = payload.GetRawText();
                ChatToolResultReceived?.Invoke(msgId, ok, resultJson);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process ai_chat_tool_result: {ex.Message}");
            }
        });

        client.On("command", response =>
        {
            try
            {
                var payload = response.GetValue<JsonElement>();
                var command = payload.TryGetProperty("command", out var c) ? c.GetString() : null;
                switch (command)
                {
                    case "set_remote_assist_transport":
                        HandleSetTransport(payload);
                        break;
                    case "set_vpn":
                        HandleSetVpn(payload);
                        break;
                    case "set_s3_drive":
                        HandleSetS3Drive(payload);
                        break;
                    case "set_ai_chat":
                        HandleSetAiChat(payload);
                        break;
                    case "restart_ra_tunnel":
                        HandleRestartTunnel();
                        break;
                }
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Failed to process command: {ex.Message}");
            }
        });

        client.On("rescue_pending", _ =>
        {
            StatusChanged?.Invoke("Server rejected connection — public key not recognized, falling back to re-enrollment");
            AccountLinkedSession.ClearEnrolled();
        });

        client.OnError += (_, error) => StatusChanged?.Invoke($"Socket error: {error}");

        // Started here (not only inside OnConnected) so the watchdog runs even if THIS attempt
        // never succeeds at all — see the field doc comment above for why that gap mattered live.
        StartXrayHealthCheck();
        _ = client.ConnectAsync();
    }

    public void Disconnect()
    {
        StopStatusTimer();
        StopXrayHealthCheck();
        try { _client?.DisconnectAsync(); } catch { }
        _client = null;
    }

    private void HandleSetTransport(JsonElement payload)
    {
        var egressUuid = payload.TryGetProperty("egressUuid", out var eu) ? eu.GetString() : null;
        var port = payload.TryGetProperty("port", out var p) && p.TryGetInt32(out var pv) ? pv : 443;
        var forwardPort = payload.TryGetProperty("forwardPort", out var fp) && fp.TryGetInt32(out var fpv) ? fpv : 0;
        AccountLinkedSession.XrayEgressUuid = egressUuid;
        AccountLinkedSession.XrayPort = port;
        AccountLinkedSession.BastionForwardPort = forwardPort;
        StatusChanged?.Invoke("Remote-assist transport configured — requesting session");
        AccountLinkedSession.RaiseSessionRequested();
    }

    private void HandleSetVpn(JsonElement payload)
    {
        if (_vpn is null) return;
        var enabled = payload.TryGetProperty("enabled", out var e) && e.GetBoolean();
        var force = payload.TryGetProperty("force", out var f) && f.GetBoolean();
        var egressUuid = payload.TryGetProperty("egressUuid", out var u) ? u.GetString() : null;
        _vpn.ReceiveConfig(enabled, force, egressUuid);
    }

    private void HandleSetS3Drive(JsonElement payload)
    {
        if (_s3drive is null) return;
        string? Str(string name) => payload.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        var enabled = payload.TryGetProperty("enabled", out var e) && e.GetBoolean();
        var resync = payload.TryGetProperty("resync", out var r) && r.GetBoolean();
        var bandwidthMbps = payload.TryGetProperty("bandwidthMbps", out var bw) && bw.TryGetInt32(out var bwv) ? bwv : 10;
        _s3drive.ReceiveConfig(enabled, Str("endpoint"), Str("bucket"), Str("accessKey"), Str("secretKey"),
            Str("region"), bandwidthMbps, Str("publicEncryptionPassword"), Str("privateEncryptionPassword"),
            Str("privatePrefix"), Str("publicPrefix"), resync);
        StatusChanged?.Invoke(enabled ? "S3 Drive config received — syncing" : "S3 Drive disabled");
    }

    /// <summary>Raised whenever the admin's per-device AI Live Chat opt-in flag changes (initial
    /// register-time push or a live toggle) so MainForm can show/hide the tray menu item without
    /// requiring a reconnect.</summary>
    public event Action<bool>? AiChatEnabledChanged;

    private void HandleSetAiChat(JsonElement payload)
    {
        var enabled = payload.TryGetProperty("enabled", out var e) && e.GetBoolean();
        AccountLinkedSession.AiChatEnabled = enabled;
        AiChatEnabledChanged?.Invoke(enabled);
    }

    // Dedicated, lightweight tunnel-restart command — server-side, this is emitted right after any
    // action that needs the Hop-1 SSH tunnel bounced (EDR/AppControl/WinUpdate/ARP-sweep enable),
    // REPLACING the old bastion-side "kill ssh.exe externally and hope TunnelRunner's retry loop
    // notices" kick, which was found live (2026-07-22, the test Windows host) to leave the tunnel down for
    // minutes with no self-heal. Deliberately does NOT regenerate any key material and does NOT
    // touch xray/the control channel — see AccountLinkedSession.TunnelRestartRequested's doc comment.
    private void HandleRestartTunnel()
    {
        StatusChanged?.Invoke("Server requested a direct tunnel restart (no new key, no control-channel drop)");
        AccountLinkedSession.RaiseTunnelRestartRequested();
    }


    // ── AI Live Chat transcript events (role, text, clientMsgId) / (msgId, kind, payloadJson, reason) /
    // (msgId, ok, resultJson) — AiChatForm subscribes to these while open, unsubscribes on close.
    public event Action<string, string, string?>? ChatMessageReceived;
    public event Action<string, string, string, string>? ChatToolProposalReceived;
    public event Action<string, bool, string>? ChatToolResultReceived;

    public async Task SendChatMessage(string text, string clientMsgId)
    {
        if (_client is null) return;
        try { await _client.EmitAsync("ai_chat_send", new { text, clientMsgId }); }
        catch (Exception ex) { StatusChanged?.Invoke($"Failed to send chat message: {ex.Message}"); }
    }

    private void StartStatusTimer(SIO client)
    {
        StopStatusTimer();
        _statusTimer = new System.Threading.Timer(async _ =>
        {
            try { await EmitVpnStatus(client); } catch { }
            try { await EmitDeviceStatus(client); } catch { }
            try { await EmitS3DriveStatus(client); } catch { }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    private void StopStatusTimer()
    {
        _statusTimer?.Dispose();
        _statusTimer = null;
    }

    private void StartXrayHealthCheck()
    {
        StopXrayHealthCheck();
        Interlocked.Exchange(ref _consecutiveXrayHealthFailures, 0);
        _xrayHealthTimer = new System.Threading.Timer(_ =>
        {
            CheckXrayHealth();
        }, null, XrayHealthInterval, XrayHealthInterval);
    }

    private void StopXrayHealthCheck()
    {
        _xrayHealthTimer?.Dispose();
        _xrayHealthTimer = null;
    }

    private void CheckXrayHealth()
    {
        // xray-unhealthy takes priority: if the underlying transport itself is bad, fixing THAT
        // (which ends with its own Connect() once xray is back) is the right move, not racing it
        // against the control-channel check below. Only when xray is healthy (or there's no xray
        // in play at all) does a still-stuck control channel fall through to that check instead.
        if (_xray is not null && !_xray.IsHealthy(3000))
        {
            if (Interlocked.Increment(ref _consecutiveXrayHealthFailures) < MaxXrayHealthFailuresBeforeRestart)
                return;
            Interlocked.Exchange(ref _consecutiveXrayHealthFailures, 0);
            StatusChanged?.Invoke("xray REALITY tunnel unresponsive — restarting xray and reconnecting");
            _xray.Stop();
            Thread.Sleep(1000);
            // advanceLadder: step the IPv6-first address ladder (same node's v4 first, then the
            // next node) instead of re-dialing the same address that just proved unresponsive.
            if (!_xray.StartControlChannel(advanceLadder: true))
            {
                StatusChanged?.Invoke("Failed to restart xray after health-check failure");
                return;
            }
            StatusChanged?.Invoke("xray restarted with fresh REALITY config");
            try { _client?.DisconnectAsync(); } catch { }
            Connect(null);
            return;
        }
        Interlocked.Exchange(ref _consecutiveXrayHealthFailures, 0);

        // xray (if any) is healthy, but the control channel itself may STILL be stuck
        // disconnected — the observed bug: a reconnect rejected server-side ("Socket error:
        // Invalid signature", e.g. transient clock skew on a heavily-loaded host) that the
        // underlying SocketIOClient library never recovers from on its own, with nothing
        // xray-side to ever notice. The threshold gives a normal in-progress handshake room to
        // finish first; anything still down past it forces a fresh Connect(), which also resets
        // _lastConnectAttemptUtc for the next tick.
        if (!IsConnected && DateTime.UtcNow - _lastConnectAttemptUtc > ControlChannelStuckThreshold)
        {
            StatusChanged?.Invoke("Control channel still disconnected after health-check interval — forcing reconnect");
            try { _client?.DisconnectAsync(); } catch { }
            Connect(null);
        }
    }

    private async Task EmitVpnStatus(SIO? client = null)
    {
        client ??= _client;
        if (client is null) return;
        try
        {
            await client.EmitAsync("vpn_status", new
            {
                vpn = _vpn?.IsActive ?? false,
                reality = _xray?.IsRunning ?? false,
                realityNode = _xray?.SelectedNode,
            });
        }
        catch
        {
        }
    }

    // Separate event from device_status (dropped for ZK-owned devices server-side) — drive
    // letter/sync-time/error state is control-plane metadata, not user content, same reasoning as
    // vpn_status above. See server.js's socket.on('s3_drive_status', ...) handler.
    private async Task EmitS3DriveStatus(SIO? client = null)
    {
        client ??= _client;
        if (client is null || _s3drive is null) return;
        try
        {
            await client.EmitAsync("s3_drive_status", new
            {
                privateDriveLetter = _s3drive.PrivateDriveLetter,
                publicDriveLetter = _s3drive.PublicDriveLetter,
                privateLastSyncAt = _s3drive.PrivateLastSyncAt.HasValue ? new DateTimeOffset(_s3drive.PrivateLastSyncAt.Value).ToUnixTimeMilliseconds() : (long?)null,
                publicLastSyncAt = _s3drive.PublicLastSyncAt.HasValue ? new DateTimeOffset(_s3drive.PublicLastSyncAt.Value).ToUnixTimeMilliseconds() : (long?)null,
                privateLastError = _s3drive.PrivateLastError,
                publicLastError = _s3drive.PublicLastError,
            });
        }
        catch
        {
        }
    }

    /// <summary>Populates the dashboard's Device Overview card (Session/Uptime/Network). For an
    /// admin-fleet (non-ZK) device this is plain "device_status", same as the Android agent's own
    /// non-ZK devices. For a ZK-owned device (AccountLinkedSession.ZkPubKey present) it MUST be
    /// envelope-encrypted first — per the ZK Security invariant, a wrap failure means the event is
    /// DROPPED, never sent as a plaintext fallback.</summary>
    private async Task EmitDeviceStatus(SIO? client = null)
    {
        client ??= _client;
        if (client is null) return;
        try
        {
            var status = DeviceStatusHelper.Build();
            var zkPubKey = AccountLinkedSession.ZkPubKey;
            if (string.IsNullOrEmpty(zkPubKey))
            {
                await client.EmitAsync("device_status", status);
                StatusChanged?.Invoke("device_status emitted (plaintext)");
                return;
            }
            var json = JsonSerializer.Serialize(status);
            var wrapped = new ZkPayloadHelper(zkPubKey).Wrap("device_status", json);
            if (wrapped is null)
            {
                StatusChanged?.Invoke("ZK wrap of device_status failed — dropped (never sent in plaintext)");
                return;
            }
            await client.EmitAsync("zk_data", wrapped);
            StatusChanged?.Invoke("zk_data(device_status) emitted (ZK-encrypted)");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"EmitDeviceStatus error: {ex.Message}");
        }
    }

    private object BuildAuthPayload()
    {
        // Server's io.use auth middleware branches on shape, in this order: (1) deviceId+timestamp+
        // signature = "key-based auth", requires a public key ALREADY on file for this deviceId, or
        // it rejects with rescue_pending; (2) publicKey+deviceId(+enrollmentTicket) = "new device
        // enrollment", the ticket-consuming auto-enroll path. A brand-new device has no key on file
        // yet, so it MUST take branch (2) — sending timestamp+signature alongside a first-time
        // ticket makes the server match branch (1) first and reject before ever looking at the
        // ticket. Mirrors the Android agent's own enrolled/not-yet-enrolled auth-shape switch.
        if (_pendingEnrollmentTicket is not null)
        {
            return new
            {
                deviceId = DeviceIdentity.DeviceId,
                publicKey = DeviceIdentity.PublicKeyBase64,
                enrollmentTicket = _pendingEnrollmentTicket,
                platform = "windows",
                agentKind = "remote_assist",
                hwId = DeviceIdentity.HardwareId,
            };
        }
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var signature = DeviceIdentity.Sign(timestamp);
return new
            {
                deviceId = DeviceIdentity.DeviceId,
                timestamp,
                signature,
                publicKey = DeviceIdentity.PublicKeyBase64,
                platform = "windows",
                agentKind = "remote_assist",
                hwId = DeviceIdentity.HardwareId,
            };
    }
}
