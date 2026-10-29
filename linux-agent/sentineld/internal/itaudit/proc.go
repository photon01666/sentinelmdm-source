package itaudit

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// collectProcesses walks /proc directly rather than shelling out to `ps`, so output format
// doesn't depend on which ps variant (procps-ng vs busybox) is installed. Resolves each process's
// exe symlink explicitly — a target ending in " (deleted)" is a Linux-specific fileless/replaced-
// binary indicator with no Windows FORENSICS_KINDS parallel (design plan §5.1).
func collectProcesses() ([]Row, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var rows []Row
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		base := filepath.Join("/proc", e.Name())

		comm := readTrimmed(filepath.Join(base, "comm"))
		cmdline := readCmdline(filepath.Join(base, "cmdline"))
		uid, uname := readProcOwner(filepath.Join(base, "status"))

		exeTarget, exeErr := os.Readlink(filepath.Join(base, "exe"))
		deleted := false
		if exeErr == nil && strings.HasSuffix(exeTarget, " (deleted)") {
			deleted = true
			exeTarget = strings.TrimSuffix(exeTarget, " (deleted)")
		}

		row := Row{
			"pid":         pid,
			"comm":        comm,
			"cmdline":     cmdline,
			"uid":         uid,
			"user":        uname,
			"exe":         exeTarget,
			"exe_deleted": deleted,
		}
		if exeErr != nil {
			row["exe_error"] = exeErr.Error() // usually EACCES for another user's process — expected, not a finding
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	// cmdline is NUL-separated argv — join with spaces for readability.
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	return strings.Join(parts, " ")
}

func readProcOwner(statusPath string) (uid int, username string) {
	f, err := os.Open(statusPath)
	if err != nil {
		return -1, ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ = strconv.Atoi(fields[1])
			}
			break
		}
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		username = u.Username
	}
	return uid, username
}

// collectNet shells out to `ss` (iproute2 — present on essentially every modern Linux server;
// far more portable and structurally simpler than hand-parsing /proc/net/{tcp,udp}* hex fields
// and cross-referencing socket inodes through every process's fd table). -tulpn: TCP+UDP,
// listening+non-listening, process info, numeric ports.
func collectNet() ([]Row, error) {
	out, err := runCmd(15*time.Second, "ss", "-tulpn")
	if err != nil {
		return nil, fmt.Errorf("run ss: %w", err)
	}
	lines := splitLines(out)
	if len(lines) == 0 {
		return nil, nil
	}
	// First line is the header; skip it if it looks like one.
	start := 0
	if len(lines) > 0 && strings.HasPrefix(strings.Fields(lines[0])[0], "Netid") {
		start = 1
	}

	var rows []Row
	for _, line := range lines[start:] {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		row := Row{
			"proto":         fields[0],
			"state":         fields[1],
			"local_address": fields[4],
		}
		if len(fields) > 5 {
			row["peer_address"] = fields[5]
		}
		// Everything after the peer address is process info, e.g. users:(("sshd",pid=123,fd=3))
		if len(fields) > 6 {
			row["process_info"] = strings.Join(fields[6:], " ")
		}
		rows = append(rows, row)
	}
	return rows, nil
}
