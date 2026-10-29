package itaudit

import (
	"bytes"
	"os/exec"
	"strings"
	"time"
)

// runCmd runs an external tool with a bounded timeout and NEVER through a shell — every argument
// is passed individually via exec.Command's argv, so there is no command-injection surface here
// even though several collectors below build argument lists from filesystem-discovered names
// (unit names, package names, module names). This is the Linux generalization of the codebase's
// standing "never a raw/interpolated command string" rule (see design plan §4.1/§6).
func runCmd(timeout time.Duration, name string, args ...string) (stdout string, err error) {
	return runCmdStream(timeout, true, name, args...)
}

// runCmdStderr is runCmd for tools that report their interesting output on STDERR instead of
// stdout — `pacman -Qkk` prints every warning/per-file mismatch on stderr while its stdout is
// just the per-package "<pkg>: N total files, M altered files" summaries, so plain runCmd would
// capture nothing useful for the Arch package-integrity check. Same no-shell/bounded-timeout
// discipline as runCmd; only which stream is captured differs (the other is discarded, exactly as
// runCmd discards stderr today).
func runCmdStderr(timeout time.Duration, name string, args ...string) (stderr string, err error) {
	return runCmdStream(timeout, false, name, args...)
}

func runCmdStream(timeout time.Duration, captureStdout bool, name string, args ...string) (string, error) {
	if _, lookErr := exec.LookPath(name); lookErr != nil {
		return "", lookErr
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	if captureStdout {
		cmd.Stdout = &out
	} else {
		cmd.Stderr = &out
	}

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return out.String(), errTimeout(name)
	}
}

type timeoutErr string

func (e timeoutErr) Error() string { return string(e) + ": timed out" }
func errTimeout(name string) error { return timeoutErr(name) }

// commandAvailable reports whether a binary is on PATH — used to skip a collector gracefully
// (with an informative note, not a hard error) when an optional tool (debsums, arp-scan, aa-status,
// ...) isn't installed, rather than failing the whole category.
func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
