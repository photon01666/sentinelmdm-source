using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// Spawns and supervises the OS's built-in ssh.exe holding the reverse tunnel open
/// (`-R 127.0.0.1:&lt;ForwardPort&gt;:localhost:22`), with a bounded retry loop while running.
/// Session key material is written to disk only while connected and removed on Stop() — nothing
/// is left resident on the customer's machine after the call ends.
/// </summary>
internal sealed class TunnelRunner
{
    private readonly SessionConfig _cfg;
    private readonly object _procLock = new();
    private Process? _proc;
    private CancellationTokenSource? _cts;
    private string? _keyPath;
    private string? _knownHostsPath;
    private static string SshPidPath => Path.Combine(Config.SessionKeyDir, "ssh-tunnel.pid");

    public event Action<string>? StatusChanged;

    /// <summary>Raised when the session config is unusable (missing/zero ports or key) — the
    /// caller should re-request the transport config from the server instead of retrying ssh.</summary>
    public event Action? ConfigInvalid;

    public TunnelRunner(SessionConfig cfg) => _cfg = cfg;

    public void Start()
    {
        // Cancel any prior loop on this same instance (defensive — MainForm usually builds a new one).
        try { _cts?.Cancel(); } catch { /* ignore */ }
        _cts = new CancellationTokenSource();
        WriteKeyMaterial();
        // Orphans from a previous CONNECT that Stop() missed will hold the bastion reverse port.
        KillTrackedSsh();
        _ = Task.Run(() => RunLoopAsync(_cts.Token));
    }

    /// <summary>
    /// Stop the tunnel and wait until ssh.exe is gone + a short bastion grace period.
    /// Safe to call from a background thread (preferred) so the UI does not freeze.
    /// </summary>
    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        Process? proc;
        lock (_procLock)
        {
            proc = _proc;
            _proc = null;
        }
        if (proc is not null)
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch { /* already exited */ }
            // Wait for ssh.exe to actually die so the bastion releases the reverse-forward
            // listen port before a reconnect (or Start-auto handoff) claims it.
            try { proc.WaitForExit(5000); } catch { /* best-effort */ }
            try { proc.Dispose(); } catch { /* best-effort */ }
        }
        KillTrackedSsh();
        // Bastion sshd can take a beat to drop the reverse listener after the client TCP session
        // closes. Without this, a fast Disconnect→Connect races the bastion and produces a
        // half-broken session that later dies with confusing PTY / reset / DNS errors.
        try { Thread.Sleep(2000); } catch { /* ignore */ }
        CleanupKeyMaterial();
    }

    /// <summary>True while this runner still owns a live ssh.exe child.</summary>
    public bool IsSshAlive
    {
        get
        {
            lock (_procLock)
            {
                try { return _proc is not null && !_proc.HasExited; }
                catch { return false; }
            }
        }
    }

    private void WriteKeyMaterial()
    {
        // Re-harden defensively, every time — NOT just trusting that SetupRunner already did it.
        // Found live (2026-07-09): the "already set up, just reconnect" path skips RunSetup —
        // and therefore Config.HardenSessionDir — entirely. Re-running icacls needs no elevation
        // here: this same user already owns the directory from whenever it WAS hardened.
        Config.HardenSessionDir();

        _keyPath = Path.Combine(Config.SessionKeyDir, "session_id_ed25519");
        _knownHostsPath = Path.Combine(Config.SessionKeyDir, "bastion_known_hosts");
        // Delete any pre-existing file first — File.WriteAllText on an existing file reuses that
        // file's ACL rather than inheriting the hardened directory ACL.
        try { File.Delete(_keyPath); } catch { /* fine if it didn't already exist */ }
        try { File.Delete(_knownHostsPath); } catch { /* fine if it didn't already exist */ }
        var keyContent = _cfg.PrivateKeyPem.Replace("\r\n", "\n").TrimEnd() + "\n";
        File.WriteAllText(_keyPath, keyContent);
        File.WriteAllText(_knownHostsPath, _cfg.KnownHostsLine.TrimEnd() + "\n");

        // SYSTEM (unattended) requires a locked-down key ACL or ssh.exe refuses to load it.
        try
        {
            var icaclsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "icacls.exe");
            using (var proc1 = Process.Start(new ProcessStartInfo(icaclsPath, $"\"{_keyPath}\" /reset")
                   { UseShellExecute = false, CreateNoWindow = true }))
            {
                proc1?.WaitForExit();
            }

            string grantArgs;
            if (Environment.UserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                Environment.UserName.EndsWith("$"))
            {
                grantArgs = "/grant:r \"SYSTEM:F\" \"Administrators:F\"";
            }
            else
            {
                grantArgs = $"/grant:r \"{Environment.UserName}:F\" \"SYSTEM:F\" \"Administrators:F\"";
            }

            using (var proc2 = Process.Start(new ProcessStartInfo(icaclsPath, $"\"{_keyPath}\" /inheritance:r {grantArgs}")
                   { UseShellExecute = false, CreateNoWindow = true }))
            {
                proc2?.WaitForExit();
            }
        }
        catch { /* best-effort */ }
    }

    private void CleanupKeyMaterial()
    {
        try { if (_keyPath is not null) File.Delete(_keyPath); } catch { /* best-effort */ }
        try { if (_knownHostsPath is not null) File.Delete(_knownHostsPath); } catch { /* best-effort */ }
        try { File.Delete(SshPidPath); } catch { /* best-effort */ }
    }

    private static void WriteSshPid(int pid)
    {
        try
        {
            Directory.CreateDirectory(Config.SessionKeyDir);
            File.WriteAllText(SshPidPath, pid.ToString());
        }
        catch { /* best-effort */ }
    }

    /// <summary>Kill ssh.exe tracked by ssh-tunnel.pid (orphans after a raced Stop / crash).</summary>
    private static void KillTrackedSsh()
    {
        try
        {
            if (!File.Exists(SshPidPath)) return;
            var text = File.ReadAllText(SshPidPath).Trim();
            if (!int.TryParse(text, out var pid) || pid <= 0) return;
            try
            {
                using var p = Process.GetProcessById(pid);
                // Only kill if it still looks like ssh (name can be "ssh" on Windows).
                if (p.ProcessName.Equals("ssh", StringComparison.OrdinalIgnoreCase))
                {
                    try { p.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                    try { p.WaitForExit(3000); } catch { /* best-effort */ }
                }
            }
            catch (ArgumentException)
            {
                // PID already gone
            }
            try { File.Delete(SshPidPath); } catch { /* best-effort */ }
        }
        catch { /* best-effort */ }
    }

    private async Task RunLoopAsync(CancellationToken token)
    {
        var sshExe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "OpenSSH", "ssh.exe");

        // Critical flags (found via reconnect failures 2026-07-10):
        //   -T / RequestTTY=no  — bastion authorized_keys uses `restrict` which DISABLES PTYs.
        //                         Without -T, Windows OpenSSH can request a PTY and then die with
        //                         "PTY allocation request failed on channel 0" + connection reset;
        //                         the retry loop then often flaps on DNS.
        //   -N                  — NOT used: the force-command (alert.sh) must run so the WebUI
        //                         presence file + hang-alive keep the reverse-forward up.
        //   -4                  — prefer IPv4 (broken AAAA paths on some ISPs).
        //   BatchMode=yes       — never block on password/host prompts.
        //   ExitOnForwardFailure=yes — fail fast if bastion port still held after reconnect.
        //   ConnectTimeout=15   — don't hang the retry loop for minutes on a dead network.
        //
        // Args are rebuilt fresh EVERY retry attempt (not once outside the loop) specifically so
        // the Endpoint Application Control -L forward below can be toggled on/off by the bastion
        // (via endpoint-config.json) and take effect on the very next reconnect, without needing
        // the exe itself restarted.
        var retryDelaySec = 5;
        const int maxRetryDelaySec = 30;

        while (!token.IsCancellationRequested)
        {
            // Guard against a half-provisioned session config (found live 2026-08-16 on
            // the test device: the server's set_remote_assist_transport push with forwardPort had
            // never landed, so ForwardPort stayed 0 and ssh.exe was launched with
            // `-R 127.0.0.1:0:...` → "Connection to UNKNOWN port -1: Connection refused"
            // every retry, forever, until a dashboard "Regen Private Key" re-pushed a valid
            // transport config). NEVER run ssh against an uninitialized port — that just
            // hammers the retry loop with the same meaningless error, and it masks the real
            // problem (missing transport push) from both the log and the WebUI. Instead:
            // surface the real cause, notify the caller so it can re-request the transport
            // config from the server, and back off instead of spinning hot.
            if (_cfg.BastionPort <= 0 || _cfg.ForwardPort <= 0 ||
                string.IsNullOrWhiteSpace(_cfg.BastionHost) ||
                string.IsNullOrWhiteSpace(_cfg.PrivateKeyPem))
            {
                var reason = _cfg.BastionPort <= 0 ? "bastion port" : _cfg.ForwardPort <= 0 ? "forward port" : "key material";
                StatusChanged?.Invoke(
                    $"Remote-assist transport not configured yet ({reason} missing) — waiting for server push");
                ConfigInvalid?.Invoke();
                try { await Task.Delay(TimeSpan.FromSeconds(15), token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                continue;
            }

            var args = new StringBuilder();
            args.Append("-T -4 ");
            args.Append("-o BatchMode=yes ");
            args.Append("-o RequestTTY=no ");
            args.Append("-o StrictHostKeyChecking=accept-new ");
            args.Append($"-o HostKeyAlias={Config.BastionHost} ");
            args.Append($"-o UserKnownHostsFile=\"{_knownHostsPath}\" ");
            args.Append("-o ServerAliveInterval=30 -o ServerAliveCountMax=3 ");
            args.Append("-o ExitOnForwardFailure=yes ");
            args.Append("-o ConnectTimeout=15 ");
            args.Append($"-R 127.0.0.1:{_cfg.ForwardPort}:127.0.0.1:22 ");
            // Endpoint services (WDAC App Control's --appcontrol-watch, Windows Update Control's
            // periodic scan task, the EDR watcher's --edr-watch) — conditional local forward so
            // any of them can reach the bastion's own WebUI API port over this SAME authenticated
            // session, no new key/port. Requires sshd_config's PermitOpen 127.0.0.1:9098
            // (bastion-side fix, verified live 2026-07-11) — anything other than that exact target
            // stays rejected by the daemon regardless of this flag. All three features share ONE
            // provisioned config/port (see Config.AppControlDir's doc comment) — add the forward
            // if ANY wants it; each feature's own token still gates its own report ingestion
            // bastion-side.
            var acWant = AppControlConfig.TryLoad(out var acEnabled, out var acLocalPort) && acEnabled;
            var wuWant = WinUpdateConfig.TryLoad(out var wuEnabled, out var wuLocalPort) && wuEnabled;
            var edrWant = EdrConfig.TryLoad(out var edrEnabled, out var edrLocalPort) && edrEnabled;
            if (acWant || wuWant || edrWant)
            {
                var localPort = acWant ? acLocalPort : (wuWant ? wuLocalPort : edrLocalPort);
                args.Append($"-L 127.0.0.1:{localPort}:127.0.0.1:9098 ");
            }
            args.Append($"-p {_cfg.BastionPort} ");
            args.Append($"-i \"{_keyPath}\" ");
            args.Append($"tunnel@{_cfg.BastionHost}");

            // Preflight DNS so the customer sees a clear message instead of a raw ssh error,
            // and so a transient resolver glitch after reconnect can recover on the next loop.
            if (!await TryResolveBastionAsync(token).ConfigureAwait(false))
            {
                if (token.IsCancellationRequested) break;
                StatusChanged?.Invoke(
                    $"Cannot resolve {_cfg.BastionHost} (DNS). Check internet — retrying in {retryDelaySec}s...");
                try { await Task.Delay(TimeSpan.FromSeconds(retryDelaySec), token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                retryDelaySec = Math.Min(maxRetryDelaySec, retryDelaySec + 5);
                continue;
            }

            StatusChanged?.Invoke("Connecting...");
            // Rewrite key material each attempt — Disconnect deletes it; a mid-loop retry after
            // a partial Stop must not run ssh against a missing key file.
            if (_keyPath is null || !File.Exists(_keyPath) || _knownHostsPath is null || !File.Exists(_knownHostsPath))
            {
                try { WriteKeyMaterial(); }
                catch (Exception ex)
                {
                    StatusChanged?.Invoke($"Tunnel error: could not write session keys ({ex.Message})");
                    break;
                }
            }

            var psi = new ProcessStartInfo(sshExe, args.ToString())
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                // Redirect stdin so OpenSSH never thinks it has a console TTY (reinforces -T).
                RedirectStandardInput = true,
                CreateNoWindow = true,
            };

            try
            {
                // DO NOT use `using var` here — the auto-dispose releases the native process
                // handle before Stop() can call Kill(), leaving ssh.exe orphaned.
                var proc = Process.Start(psi)!;
                // Close stdin immediately — no interactive input; keeps the session non-TTY.
                try { proc.StandardInput.Close(); } catch { /* ignore */ }

                lock (_procLock) { _proc = proc; }
                WriteSshPid(proc.Id);

                var stderrTask = proc.StandardError.ReadToEndAsync();

                // Wait up to 1.5s to see if it crashes immediately (port still held, auth fail, …)
                var startedTask = Task.Delay(1500, token);
                var exitTask = proc.WaitForExitAsync(token);
                var first = await Task.WhenAny(startedTask, exitTask).ConfigureAwait(false);

                if (first == startedTask && !proc.HasExited)
                {
                    retryDelaySec = 5; // healthy connect — reset backoff
                    StatusChanged?.Invoke("Connected — support can now assist you.");
                    await exitTask.ConfigureAwait(false);
                }

                var err = "";
                try { err = await stderrTask.ConfigureAwait(false); } catch { /* ignore */ }

                if (token.IsCancellationRequested) break;

                if (proc.ExitCode != 0)
                {
                    var msg = string.IsNullOrWhiteSpace(err) ? $"exited with code {proc.ExitCode}" : err.Trim();
                    // Collapse multi-line ssh noise to one status line for the UI log.
                    msg = msg.Replace("\r\n", " | ").Replace("\n", " | ");
                    if (msg.Length > 300) msg = msg[..300] + "…";
                    StatusChanged?.Invoke($"Tunnel error: {msg}");
                }
            }
            catch (OperationCanceledException)
            {
                // Stop() requested — process is killed there under the lock.
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"ssh.exe failed to start: {ex.Message}");
            }
            finally
            {
                lock (_procLock)
                {
                    try { if (_proc != null && !_proc.HasExited) _proc.Kill(entireProcessTree: true); } catch { /* best-effort */ }
                    try { _proc?.Dispose(); } catch { /* best-effort */ }
                    _proc = null;
                }
                try { File.Delete(SshPidPath); } catch { /* best-effort */ }
            }

            if (token.IsCancellationRequested) break;

            StatusChanged?.Invoke($"Tunnel dropped — retrying in {retryDelaySec}s...");
            try { await Task.Delay(TimeSpan.FromSeconds(retryDelaySec), token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            retryDelaySec = Math.Min(maxRetryDelaySec, retryDelaySec + 5);

            // Before retrying, ensure no orphan still holds the bastion reverse port.
            KillTrackedSsh();
            try { await Task.Delay(500, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }

        StatusChanged?.Invoke("Disconnected.");
    }

    private async Task<bool> TryResolveBastionAsync(CancellationToken token)
    {
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(_cfg.BastionHost, token).ConfigureAwait(false);
            return addrs.Any(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return false;
        }
    }
}
