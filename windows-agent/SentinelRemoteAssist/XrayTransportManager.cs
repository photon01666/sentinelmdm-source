using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;

namespace SentinelRemoteAssist;

internal sealed class XrayTransportManager
{
    private readonly string _xrayDir = Path.Combine(Config.SessionKeyDir, "xray");
    private Process? _proc;
    private int _localPort;
    private int _controlPort;
    private string? _selectedNode;
    private string? _vpnEgressUuid;
    private static readonly object _lock = new();
    internal const int VpnSocksPort = 10809;

    // IPv6-first address-ladder state (see Start's ladder comment): -1 = no node picked yet, so a
    // fresh process starts with a random node dialed v6-first; addrIdx indexes the current node's
    // candidate list (Config.NodeAddresses), advancing only on an explicit health-restart step.
    private int _nodeIdx = -1;
    private int _addrIdx = 0;

    public event Action<string>? StatusChanged;
    public event Action<bool>? RunningChanged;

    public int LocalPort => _localPort;
    public int ControlPort => _controlPort;
    public string? SelectedNode => _selectedNode;
    public bool IsRunning
    {
        get { lock (_lock) { try { return _proc is not null && !_proc.HasExited; } catch { return false; } } }
    }

    public bool StartControlChannel(bool advanceLadder = false) { return Start(Config.RealityControlUuid, null, advanceLadder); }

    public bool Start(string egressUuid, string? vpnEgressUuid = null, bool advanceLadder = false)
    {
        _vpnEgressUuid = vpnEgressUuid;
        if (string.IsNullOrEmpty(egressUuid))
        {
            StatusChanged?.Invoke("No remote-assist transport UUID received yet");
            return false;
        }

        if (!TryExtractXray(out var xrayExePath))
        {
            StatusChanged?.Invoke(
                "This build is missing its bundled xray.exe");
            return false;
        }

        _localPort = GetFreeLocalPort();
        _controlPort = GetFreeLocalPort();
        var configPath = Path.Combine(_xrayDir, "config.json");

        // IPv6-first REALITY addressing — the Windows port of the Android agent's realityAddrIdx
        // ladder (memory agent-reality-ipv6-first): candidates for a node are [v6, v4] when this
        // machine has a v6 route to it, else [v4] alone (Config.NodeAddresses). A fresh manager
        // picks a random node and dials its PREFERRED (v6) address; an xray-health restart passes
        // advanceLadder:true to step to the next candidate — same node's IPv4 first, then the next
        // node — so a v6 route that cannot actually carry traffic degrades to the legacy path
        // instead of looping. ResetAddressLadder() re-arms the v6 preference after a session is up.
        if (_nodeIdx < 0) _nodeIdx = Random.Shared.Next(Config.RealityNodes.Length);
        if (advanceLadder) AdvanceLadder();
        var candidates = Config.NodeAddresses(_nodeIdx);
        if (candidates.Count == 0)
        {
            StatusChanged?.Invoke("No REALITY nodes configured");
            return false;
        }
        if (_addrIdx < 0 || _addrIdx >= candidates.Count) _addrIdx = 0;
        var node = candidates[_addrIdx];
        _selectedNode = node;
        // Per-node camouflage SNI (index-aligned) — a single shared SNI is REJECTED by every node
        // whose decoy dest differs, so REALITY never completes. See Config.RealitySnis.
        var sni = _nodeIdx < Config.RealitySnis.Length ? Config.RealitySnis[_nodeIdx] : Config.RealitySni;
        var config = BuildConfigJson(node, egressUuid, sni);
        Directory.CreateDirectory(_xrayDir);
        File.WriteAllText(configPath, config);

        var psi = new ProcessStartInfo(xrayExePath, $"run -config \"{configPath}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = _xrayDir,
        };
        try
        {
            lock (_lock) { _proc = Process.Start(psi); }
            if (_proc is null)
            {
                StatusChanged?.Invoke("Failed to start xray process.");
                return false;
            }
            // xray's own stdout/stderr was being redirected (RedirectStandardOutput/Error above)
            // but never actually read anywhere — meaning any REALITY/VLESS-level failure (TLS
            // rejection, DNS failure, outbound blocked, auth failure) was silently discarded
            // instead of reaching unattended-tunnel.log. Surface it through the same
            // StatusChanged pipe everything else uses. loglevel is "warning" in BuildConfigJson,
            // so this stays quiet on the happy path.
            _proc.OutputDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) StatusChanged?.Invoke($"xray: {e.Data}"); };
            _proc.ErrorDataReceived += (_, e) => { if (!string.IsNullOrEmpty(e.Data)) StatusChanged?.Invoke($"xray: {e.Data}"); };
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
            StatusChanged?.Invoke(_vpnEgressUuid is not null
                ? $"Remote-assist transport + VPN connecting via node {node}..."
                : $"Remote-assist transport connecting via node {node}...");
            RunningChanged?.Invoke(true);
            return true;
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Failed to start xray: {ex.Message}");
            return false;
        }
    }

    public void Reconfigure(string? vpnEgressUuid)
    {
        _vpnEgressUuid = vpnEgressUuid;
        Stop();
        var egressUuid = AccountLinkedSession.XrayEgressUuid;
        if (!string.IsNullOrEmpty(egressUuid))
        {
            Start(egressUuid, vpnEgressUuid);
            AccountLinkedSession.XrayLocalPort = _localPort;
        }
    }

    public void Stop()
    {
        Process? proc;
        lock (_lock) { proc = _proc; _proc = null; }
        try
        {
            if (proc is { HasExited: false }) proc.Kill(entireProcessTree: true);
        }
        catch { }
        finally
        {
            try { proc?.Dispose(); } catch { }
            RunningChanged?.Invoke(false);
        }
    }

    /// <summary>Steps the address ladder one notch: the same node's next candidate (v6 → v4), then
    /// the next node's preferred candidate, wrapping — see Start's IPv6-first comment.</summary>
    private void AdvanceLadder()
    {
        var candidates = Config.NodeAddresses(_nodeIdx);
        _addrIdx++;
        if (candidates.Count == 0 || _addrIdx >= candidates.Count)
        {
            _nodeIdx = (_nodeIdx + 1) % Math.Max(1, Config.RealityNodes.Length);
            _addrIdx = 0;
        }
    }

    /// <summary>Called by the control-channel layer once a session is actually established: re-arms
    /// the v6 preference for the NEXT deliberate xray start. The current session keeps the address
    /// that proved to work (the ladder exists to get a session UP, not to churn a live one).</summary>
    public void ResetAddressLadder() { _addrIdx = 0; }

    /// <summary>Verifies xray's local control proxy is actually accepting connections.
    /// IsRunning only checks process liveness; a zombie or REALITY-dead xray process
    /// can stay alive indefinitely with a listening-but-broken proxy.</summary>
    public bool IsHealthy(int timeoutMs = 3000)
    {
        if (!IsRunning) return false;
        if (_controlPort <= 0) return false;
        try
        {
            using var tcp = new TcpClient();
            var result = tcp.BeginConnect(IPAddress.Loopback, _controlPort, null, null);
            if (result.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                tcp.EndConnect(result);
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    private bool TryExtractXray(out string exePath)
    {
        exePath = Path.Combine(_xrayDir, "xray.exe");
        if (File.Exists(exePath)) return true;
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("SentinelRemoteAssist.xray.exe.gz");
            if (stream is null) return false;
            Directory.CreateDirectory(_xrayDir);
            // Embedded as gzip (2.1.2 — see the csproj's CompressNativeBinaries target; the raw
            // 35 MB binary compressed to ~13 MB). Decompress here so xray.exe on disk is byte-identical
            // to a non-compressed build.
            using (var gz = new GZipStream(stream, CompressionMode.Decompress))
            using (var fs = new FileStream(exePath, FileMode.Create))
                gz.CopyTo(fs);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreeLocalPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private string BuildConfigJson(string node, string egressUuid, string sni)
    {
        var inbounds = new List<object>();
        var outbounds = new List<object>();
        var routingRules = new List<object>();

        inbounds.Add(new
        {
            tag = "to-bastion-local",
            listen = "127.0.0.1",
            port = _localPort,
            protocol = "dokodemo-door",
            settings = new { address = "127.0.0.1", port = 22, network = "tcp" },
        });

        outbounds.Add(new
        {
            tag = "vless-out-ra",
            protocol = "vless",
            settings = new
            {
                vnext = new object[]
                {
                    new
                    {
                        address = node,
                        port = 443,
                        users = new object[] { new { id = egressUuid, encryption = "none" } },
                    },
                },
            },
            streamSettings = new
            {
                network = "tcp",
                security = "reality",
                realitySettings = new
                {
                    serverName = sni,
                    fingerprint = Config.RealityFingerprint,
                    publicKey = Config.RealityPublicKey,
                    shortId = Config.RealityShortId,
                },
            },
        });

        routingRules.Add(new { type = "field", inboundTag = new[] { "to-bastion-local" }, outboundTag = "vless-out-ra" });

        inbounds.Add(new
        {
            tag = "to-control-local",
            listen = "127.0.0.1",
            port = _controlPort,
            protocol = "dokodemo-door",
            settings = new { address = new System.Uri(Config.WebUrl).Host, port = 443, network = "tcp" },
        });

        outbounds.Add(new
        {
            tag = "vless-out-control",
            protocol = "vless",
            settings = new
            {
                vnext = new object[]
                {
                    new
                    {
                        address = node,
                        port = 443,
                        users = new object[] { new { id = Config.RealityControlUuid, encryption = "none" } },
                    },
                },
            },
            streamSettings = new
            {
                network = "tcp",
                security = "reality",
                realitySettings = new
                {
                    serverName = sni,
                    fingerprint = Config.RealityFingerprint,
                    publicKey = Config.RealityPublicKey,
                    shortId = Config.RealityShortId,
                },
            },
        });

        routingRules.Add(new { type = "field", inboundTag = new[] { "to-control-local" }, outboundTag = "vless-out-control" });

        if (!string.IsNullOrEmpty(_vpnEgressUuid))
        {
            inbounds.Add(new
            {
                tag = "vpn-socks",
                listen = "127.0.0.1",
                port = VpnSocksPort,
                protocol = "socks",
                settings = new { udp = true },
            });

            outbounds.Add(new
            {
                tag = "vless-out-vpn",
                protocol = "vless",
                settings = new
                {
                    vnext = new object[]
                    {
                        new
                        {
                            address = node,
                            port = 443,
                            users = new object[] { new { id = _vpnEgressUuid, encryption = "none" } },
                        },
                    },
                },
                streamSettings = new
                {
                    network = "tcp",
                    security = "reality",
                    realitySettings = new
                    {
                        serverName = sni,
                        fingerprint = Config.RealityFingerprint,
                        publicKey = Config.RealityPublicKey,
                        shortId = Config.RealityShortId,
                    },
                },
            });

            routingRules.Add(new { type = "field", inboundTag = new[] { "vpn-socks" }, outboundTag = "vless-out-vpn" });
        }

        var config = new
        {
            // TEMPORARY diagnostic bump from "warning" — live debugging 2026-07-14 found xray
            // logs NOTHING at warning level for this failure (kex_exchange_identification:
            // Connection reset ~6.5s after every "Connected", zero packets ever reaching any of
            // the 3 REALITY nodes' xray containers per server-side log checks), meaning whatever
            // is happening either succeeds silently at the xray layer or doesn't rise to
            // warning. "info" surfaces every accepted/dialed connection so we can see whether
            // xray's own outbound dial is even being attempted. Revert to "warning" once this is
            // root-caused — see the StatusChanged wiring above.
            log = new { loglevel = "info" },
            inbounds = inbounds.ToArray(),
            outbounds = outbounds.ToArray(),
            routing = new { rules = routingRules.ToArray() },
        };
        return JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
    }
}
