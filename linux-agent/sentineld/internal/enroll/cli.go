package enroll

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sentineld/internal/config"
)

// EnrollmentState is persisted to config.StateDir after a successful CLI login so sentineld's
// next Hop-1 handshake can consume the single-use ticket. Mirrors what RemoteAssistSocket.cs's
// handshake carries: {ticket, deviceId, publicKey}.
type EnrollmentState struct {
	DeviceID      string    `json:"device_id"`
	Ticket        string    `json:"ticket"`
	PublicKeySSH  string    `json:"public_key_ssh"`
	EnrolledAtUTC time.Time `json:"enrolled_at_utc"`
	ServerBaseURL string    `json:"server_base_url"`
}

const enrollmentStateFile = "enrollment.json"

// RunInteractiveEnroll is the entry point for `sentineld enroll` — a fully CLI-driven login:
// prompts for the SentinelMDM account email and password on the terminal (password not echoed),
// runs the exact prehash-v1 login flow the Windows/Android clients use, requests a single-use
// enrollment ticket, and persists it for the daemon to consume on its next Hop-1 connect. No
// dashboard-generated token or browser step is required — this is the ONLY enrollment path.
func RunInteractiveEnroll() error {
	fmt.Println("SentinelMDM Remote Assist — Linux agent enrollment")
	fmt.Println("This links this server to your SentinelMDM account. Credentials are sent")
	fmt.Println("directly to " + config.WebUrl + " and never stored on disk.")
	fmt.Println()

	// Read from the controlling terminal directly, not os.Stdin — os.Stdin may be a pipe
	// (e.g. curl -fsSL ... | bash) whose content was already consumed by the shell, leaving
	// it at EOF. /dev/tty is always the real terminal when one exists.
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return fmt.Errorf("cannot open terminal for interactive input (is a TTY available?): %w", err)
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)

	email, err := promptLine(reader, "SentinelMDM email: ")
	if err != nil {
		return err
	}
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("email cannot be empty")
	}

	password, err := promptHidden(reader, "Password: ")
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	client, err := NewAccountAuthClient()
	if err != nil {
		return err
	}

	fmt.Println("Logging in...")
	result := client.Login(strings.TrimSpace(email), password)
	password = "" // don't hold the plaintext password in memory longer than needed
	if result.Err != nil {
		return fmt.Errorf("login failed: %w", result.Err)
	}
	if !result.OK {
		return fmt.Errorf("login failed")
	}

	if result.TotpRequired {
		code, err := promptLine(reader, "2FA code: ")
		if err != nil {
			return err
		}
		totpResult := client.VerifyTotp(strings.TrimSpace(code))
		if totpResult.Err != nil {
			return fmt.Errorf("2FA verification failed: %w", totpResult.Err)
		}
		if !totpResult.OK {
			return fmt.Errorf("2FA verification failed")
		}
	}

	fmt.Println("Generating device identity...")
	identity, err := LoadOrCreateIdentity()
	if err != nil {
		return fmt.Errorf("generate device identity: %w", err)
	}

	fmt.Println("Requesting enrollment ticket...")
	ticket, err := client.RequestEnrollmentTicket(identity.DeviceID)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	state := EnrollmentState{
		DeviceID:      identity.DeviceID,
		Ticket:        ticket,
		PublicKeySSH:  identity.PublicKeyOpenSSH,
		EnrolledAtUTC: time.Now().UTC(),
		ServerBaseURL: config.WebUrl,
	}
	if err := persistEnrollmentState(state); err != nil {
		return fmt.Errorf("persist enrollment state: %w", err)
	}

	fmt.Println()
	fmt.Println("Enrollment successful. Device ID:", identity.DeviceID)
	fmt.Println("Start (or restart) the sentineld service to complete the connection:")
	fmt.Println("  sudo systemctl enable --now sentineld")
	return nil
}

// RunTicketEnroll is the NO-LOGIN enrollment path for the account-bound installer flow (the Linux
// counterpart of the Windows auto-provisioning exe): the account's multi-use installer ticket was
// baked into the install command the dashboard copied (GET .../install.sh?ticket=<t>), so nothing
// needs to be typed on the target box. The ticket alone is the account binding — the server's
// consumeEnrollmentTicket() binds this device to the minting account on the first Hop-1 handshake,
// exactly like it does for the Windows exe. No email/password/TOTP round-trip at all.
func RunTicketEnroll(ticket string) error {
	if !validTicketFormat(ticket) {
		return fmt.Errorf("invalid enrollment ticket format — expected 64 hex characters")
	}

	identity, err := LoadOrCreateIdentity()
	if err != nil {
		return fmt.Errorf("generate device identity: %w", err)
	}

	state := EnrollmentState{
		DeviceID:      identity.DeviceID,
		Ticket:        ticket,
		PublicKeySSH:  identity.PublicKeyOpenSSH,
		EnrolledAtUTC: time.Now().UTC(),
		ServerBaseURL: config.WebUrl,
	}
	if err := persistEnrollmentState(state); err != nil {
		return fmt.Errorf("persist enrollment state: %w", err)
	}

	fmt.Println("SentinelMDM Remote Assist — Linux agent enrollment (installer ticket)")
	fmt.Println("Enrollment ticket accepted. Device ID:", identity.DeviceID)
	fmt.Println("No sign-in needed — this server is linked to the account that minted the ticket.")
	fmt.Println("Start (or restart) the sentineld service to complete the connection:")
	fmt.Println("  sudo systemctl enable --now sentineld")
	return nil
}

// validTicketFormat mirrors the server's mint: crypto.randomBytes(32).toString('hex') — a 64-char
// lowercase hex string. A strict format check up front rejects obviously bogus input (and any
// shell-injection attempt via the CLI) before anything is persisted.
func validTicketFormat(ticket string) bool {
	if len(ticket) != 64 {
		return false
	}
	for _, c := range ticket {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ClearTicket rewrites the persisted enrollment state with an empty ticket — called by the daemon
// after its FIRST successful registration, mirroring Windows' AccountLinkedSession.MarkEnrolled()
// (which nulls the ticket after the handshake that consumed it). All subsequent (re)connects then
// use signed auth instead of re-presenting a now-spent bootstrap credential.
func ClearTicket() error {
	return ClearTicketIn(config.StateDir)
}

// ClearTicketIn is ClearTicket against an explicit state directory instead of the real
// config.StateDir — parameterized so the daemon can clear the same dir it loaded the state from
// (its runControlLoop stateDir param; tests pass a temp dir without touching /var/lib/sentinel-ra).
func ClearTicketIn(stateDir string) error {
	state, err := LoadEnrollmentStateIn(stateDir)
	if err != nil {
		return err
	}
	if state.Ticket == "" {
		return nil // already clear — idempotent
	}
	state.Ticket = ""
	return persistEnrollmentStateIn(stateDir, *state)
}

func persistEnrollmentState(state EnrollmentState) error {
	return persistEnrollmentStateIn(config.StateDir, state)
}

func persistEnrollmentStateIn(stateDir string, state EnrollmentState) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, enrollmentStateFile)
	// Write to a temp file then rename — an interrupted write must never leave a partially
	// written, unparseable enrollment file for the daemon to trip over on its next start.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadEnrollmentState reads back what RunInteractiveEnroll persisted — used by sentineld's
// daemon-mode startup (Hop-1 connect) to find its ticket/device ID.
func LoadEnrollmentState() (*EnrollmentState, error) {
	return LoadEnrollmentStateIn(config.StateDir)
}

// LoadEnrollmentStateIn is LoadEnrollmentState against an explicit state directory.
func LoadEnrollmentStateIn(stateDir string) (*EnrollmentState, error) {
	path := filepath.Join(stateDir, enrollmentStateFile)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state EnrollmentState
	if err := json.Unmarshal(buf, &state); err != nil {
		return nil, fmt.Errorf("corrupt enrollment state at %s: %w", path, err)
	}
	return &state, nil
}

func promptLine(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptHidden reads a line with local echo disabled via `stty` (always on /dev/tty —
// the caller must pass a reader opened on /dev/tty, not os.Stdin, so this works even
// when stdin is a consumed pipe from `curl | bash`).
func promptHidden(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)

	if err := exec.Command("stty", "-F", "/dev/tty", "-echo").Run(); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() {
		_ = exec.Command("stty", "-F", "/dev/tty", "echo").Run()
		fmt.Println()
	}()

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

