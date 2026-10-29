package hop1

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestOpen_RealSSHD spins up a REAL sshd (not a mock) as a stand-in bastion, connects with a
// freshly-generated ed25519 keypair (same OpenSSH format internal/enroll.LoadOrCreateIdentity
// produces), requests a remote forward exactly like the bastion assigns a Hop-1 session port, and
// proves data actually flows end-to-end: a connection made against the forwarded port (simulating
// what the bastion does when it wants to reach this box) is correctly proxied through Tunnel.Serve
// to a local target listener, in both directions. This validates the Go SSH client mechanics for
// real; it does not and cannot validate the xray/REALITY camouflage layer, which needs a live
// fleet node.
func TestOpen_RealSSHD(t *testing.T) {
	if _, err := exec.LookPath("sshd"); err != nil {
		if _, err2 := os.Stat("/usr/sbin/sshd"); err2 != nil {
			t.Skip("sshd not available on this box")
		}
	}

	dir := t.TempDir()

	clientKeyPath := filepath.Join(dir, "client_ed25519")
	runOrFatal(t, "ssh-keygen", "-t", "ed25519", "-N", "", "-f", clientKeyPath, "-q")
	signer, err := LoadSigner(clientKeyPath)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}

	hostKeyPath := filepath.Join(dir, "host_ed25519")
	runOrFatal(t, "ssh-keygen", "-t", "ed25519", "-N", "", "-f", hostKeyPath, "-q")
	hostPubBytes, err := os.ReadFile(hostKeyPath + ".pub")
	if err != nil {
		t.Fatalf("read host pubkey: %v", err)
	}

	authorizedKeysPath := filepath.Join(dir, "authorized_keys")
	clientPub, err := os.ReadFile(clientKeyPath + ".pub")
	if err != nil {
		t.Fatalf("read client pubkey: %v", err)
	}
	if err := os.WriteFile(authorizedKeysPath, clientPub, 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}

	sshdPort := mustFreePort(t)
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	sshdConfigPath := filepath.Join(dir, "sshd_config")
	sshdConfig := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers %s
AllowTcpForwarding yes
GatewayPorts no
PermitRootLogin no
UsePAM no
PidFile none
StrictModes no
`, sshdPort, hostKeyPath, authorizedKeysPath, u.Username)
	// StrictModes no: TEST-ONLY relaxation. sshd's default StrictModes checks ownership/perms of
	// every ancestor directory of AuthorizedKeysFile, and t.TempDir() lives under /tmp (world-
	// writable) — sshd refuses to trust anything under it regardless of the temp dir's own 0700
	// perms ("Authentication refused: bad ownership or modes for directory /tmp"). Irrelevant to
	// the real product: production's sshd_hop2_config (etc/sshd_hop2_config) keeps default
	// StrictModes, since /etc/sentinel-ra is root-owned with correct permissions there.
	if err := os.WriteFile(sshdConfigPath, []byte(sshdConfig), 0o600); err != nil {
		t.Fatalf("write sshd_config: %v", err)
	}

	sshdPath := "/usr/sbin/sshd"
	if _, err := exec.LookPath("sshd"); err == nil {
		sshdPath, _ = exec.LookPath("sshd")
	}
	cmd := exec.Command(sshdPath, "-D", "-e", "-f", sshdConfigPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test sshd: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if !waitForPort(sshdPort, 3*time.Second) {
		t.Fatal("test sshd never started listening")
	}

	// Pin against the REAL host key this test sshd instance presents — proves
	// PinnedHostKeyCallback correctly accepts a genuinely-matching key.
	knownHostsLine := fmt.Sprintf("[127.0.0.1]:%d %s", sshdPort, string(hostPubBytes))
	pinnedKey, err := ParsePinnedHostKey(knownHostsLine)
	if err != nil {
		t.Fatalf("ParsePinnedHostKey: %v", err)
	}

	// The local "target" a forwarded connection should ultimately reach — stands in for Hop-2's
	// 127.0.0.1:22 in production.
	targetPort := mustFreePort(t)
	targetListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetListener.Close()
	go serveEcho(targetListener)

	forwardPort := mustFreePort(t)
	dialAddr := fmt.Sprintf("127.0.0.1:%d", sshdPort)
	remoteBindAddr := fmt.Sprintf("127.0.0.1:%d", forwardPort)

	tunnel, err := Open(dialAddr, u.Username, signer, PinnedHostKeyCallback(pinnedKey), remoteBindAddr)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer tunnel.Close()

	go func() {
		_ = tunnel.Serve(fmt.Sprintf("127.0.0.1:%d", targetPort))
	}()

	if !waitForPort(forwardPort, 3*time.Second) {
		t.Fatal("remote-forwarded port never came up")
	}

	// Simulate the bastion: dial the forwarded port and confirm a round-trip through
	// Tunnel.Serve -> the local echo target actually works.
	conn, err := net.DialTimeout("tcp", remoteBindAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded port: %v", err)
	}
	defer conn.Close()

	const msg = "hop1-tunnel-roundtrip-check\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestPinnedHostKeyCallback_RejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "a")
	keyB := filepath.Join(dir, "b")
	runOrFatal(t, "ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyA, "-q")
	runOrFatal(t, "ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyB, "-q")

	pubA, _ := os.ReadFile(keyA + ".pub")
	pubB, _ := os.ReadFile(keyB + ".pub")

	expected, err := ParsePinnedHostKey("[host]:22 " + string(pubA))
	if err != nil {
		t.Fatalf("ParsePinnedHostKey: %v", err)
	}
	presented, _, _, _, err := ssh.ParseAuthorizedKey(pubB)
	if err != nil {
		t.Fatalf("parse presented key: %v", err)
	}

	cb := PinnedHostKeyCallback(expected)
	if err := cb("irrelevant", nil, presented); err == nil {
		t.Error("expected PinnedHostKeyCallback to reject a mismatched key, got nil error")
	}
}

func runOrFatal(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func mustFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func serveEcho(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
	}
}
