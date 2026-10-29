// Package hop1 implements the Hop-1 reverse SSH tunnel to the bastion — the Linux port of
// TunnelRunner.cs. Unlike the Windows client (which bundles a full OpenSSH-Win64 distribution and
// spawns `ssh.exe -R ...` as a subprocess, because .NET has no embeddable SSH client),
// golang.org/x/crypto/ssh gives an in-process client here: no dependency on the target box having
// openssh-client installed, and direct control over reconnect/backoff/logging instead of parsing
// a subprocess's stdout.
package hop1

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ParsePinnedHostKey extracts the public key from a single known_hosts-format line (e.g.
// xraytransport.RemoteAssistBastionKnownHostsLine: "[host]:port keytype base64key") — used for
// REAL host-key pinning rather than TOFU/accept-new, since the actual pinned value is available
// (captured via `ssh-keyscan`, same value the Windows client bakes into Config.cs).
func ParsePinnedHostKey(knownHostsLine string) (ssh.PublicKey, error) {
	fields := strings.Fields(knownHostsLine)
	if len(fields) < 3 {
		return nil, fmt.Errorf("malformed known_hosts line (want 3 fields, got %d): %q", len(fields), knownHostsLine)
	}
	keyLine := fields[1] + " " + fields[2]
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return nil, fmt.Errorf("parse pinned host key: %w", err)
	}
	return pub, nil
}

// PinnedHostKeyCallback returns an ssh.HostKeyCallback that accepts ONLY the exact expected key,
// regardless of the hostname/address actually dialed — this is what lets the client connect to
// 127.0.0.1:<local xray port> (the real dial target, since the SSH connection itself is carried
// through the local xray/REALITY camouflage) while still verifying it's really talking to the
// bastion, by pinning the host key rather than trusting the dial address. Mirrors the Windows
// client's `-o HostKeyAlias=remote.example.com` trick, but stricter: real pinning instead of a
// TOFU accept-new fallback, since the real pinned value is available here.
func PinnedHostKeyCallback(expected ssh.PublicKey) ssh.HostKeyCallback {
	expectedBytes := expected.Marshal()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if !bytes.Equal(key.Marshal(), expectedBytes) {
			return fmt.Errorf("host key mismatch for %s (%s): presented key does not match the pinned bastion host key", hostname, remote)
		}
		return nil
	}
}

// LoadSigner parses an OpenSSH-format private key file (as written by
// internal/enroll.LoadOrCreateIdentity via `ssh-keygen`) into an ssh.Signer for client auth.
func LoadSigner(privateKeyPath string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// Tunnel is an established Hop-1 connection: authenticated to the bastion and holding the
// remote-forward listener the bastion uses to reach this box's Hop-2 (or, in tests, whatever
// localTarget is configured).
type Tunnel struct {
	client   *ssh.Client
	listener net.Listener
	fcmdSess *ssh.Session

	mu     sync.Mutex
	closed bool
}

// Open dials dialAddr (the local xray dokodemo-door port in production; a real bastion address in
// tests), authenticates as user using signer, verifies the presented host key via hostKeyCB, and
// requests a remote-forward bind at remoteBindAddr (the bastion-assigned session port — mirrors
// `ssh -R remoteBindAddr:127.0.0.1:22`). The bastion can now dial remoteBindAddr and have
// connections delivered to this Tunnel's Accept loop (see Serve).
func Open(dialAddr, user string, signer ssh.Signer, hostKeyCB ssh.HostKeyCallback, remoteBindAddr string) (*Tunnel, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
	}
	client, err := ssh.Dial("tcp", dialAddr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial bastion at %s: %w", dialAddr, err)
	}

	listener, err := client.Listen("tcp", remoteBindAddr)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("request remote forward on %s: %w", remoteBindAddr, err)
	}

	// Open a session channel purely so the bastion's authorized_keys `command=` restriction
	// (alert.sh) actually fires — mirrors the Windows client's ssh.exe invocation, which
	// deliberately omits -N for exactly this reason (see TunnelRunner.cs's comment: "-N NOT
	// used: the force-command (alert.sh) must run so the WebUI presence file + hang-alive keep
	// the reverse-forward up"). client.Listen() above only sends a tcpip-forward global
	// request — it never opens a "session" channel, and a server's forced command only ever
	// replaces a client's requested exec/shell/subsystem on a session channel. Without this,
	// alert.sh never runs for a Linux device's Hop-1 connection: no last_connected_at, no
	// Signal "customer connected" alert, no admin-WebUI presence file, and the cached
	// agent_version/latest_agent_version never re-checks after the first successful query —
	// found live 2026-08-06 (every Linux RA device, permanently, not intermittently).
	//
	// No PTY: production's authorized_keys line uses `restrict`, which disables PTY allocation
	// (same reason TunnelRunner.cs passes -T). Shell() sends a plain "shell" channel request;
	// the bastion's forced command overrides whatever we asked for, so what we request doesn't
	// matter beyond "a session channel exists". stdout is drained so alert.sh's few lines of
	// output (and the test-only case of a real unrestricted shell where no command= exists)
	// can never fill the channel's flow-control window and block the remote side.
	fcmdSess, err := client.NewSession()
	if err != nil {
		listener.Close()
		client.Close()
		return nil, fmt.Errorf("open force-command session: %w", err)
	}
	if stdout, err := fcmdSess.StdoutPipe(); err == nil {
		go io.Copy(io.Discard, stdout)
	}
	if err := fcmdSess.Shell(); err != nil {
		fcmdSess.Close()
		listener.Close()
		client.Close()
		return nil, fmt.Errorf("start force-command session: %w", err)
	}

	return &Tunnel{client: client, listener: listener, fcmdSess: fcmdSess}, nil
}

// Serve accepts connections the bastion opens against the remote-forward bind and proxies each
// one to localTarget (127.0.0.1:22 in production — the box's real sshd, i.e. Hop-2). Blocks until
// the listener is closed (via Close()) or a non-recoverable Accept error occurs; returns nil on a
// clean shutdown.
func (t *Tunnel) Serve(localTarget string) error {
	for {
		remoteConn, err := t.listener.Accept()
		if err != nil {
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("accept on remote forward: %w", err)
		}
		go t.proxyOne(remoteConn, localTarget)
	}
}

func (t *Tunnel) proxyOne(remoteConn net.Conn, localTarget string) {
	defer remoteConn.Close()

	localConn, err := net.Dial("tcp", localTarget)
	if err != nil {
		// The bastion (or, in tests, whatever's driving the forward) opened a channel expecting
		// to reach localTarget — if it's down, the correct behavior is to drop this one
		// connection, not tear down the whole tunnel.
		return
	}
	defer localConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(localConn, remoteConn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(remoteConn, localConn) }()
	wg.Wait()
}

// Close tears down the remote-forward listener and the underlying SSH connection. Safe to call
// multiple times.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()

	var firstErr error
	if t.fcmdSess != nil {
		if err := t.fcmdSess.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := t.listener.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := t.client.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
