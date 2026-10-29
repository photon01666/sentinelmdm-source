// extras.go implements the Linux-native audit categories with no Windows FORENSICS_KINDS
// parallel — design plan §5.1 "net-new value, not required parity."
package itaudit

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// collectSuidSgid flags SUID/SGID binaries — the classic Linux privilege-escalation backdoor
// technique. Scoped to standard distro-managed dirs (not a full filesystem walk) to keep runtime
// bounded on a real server; -xdev keeps each `find` from crossing into a different mounted
// filesystem (e.g. an NFS share) per root.
func collectSuidSgid() ([]Row, error) {
	return findPermissionRows("suid_sgid", []string{"/usr", "/bin", "/sbin", "/opt"},
		"(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f")
}

// collectWorldWritable flags world-writable files in system paths — a dropped file here is
// trivially replaceable/persistable by any local user.
func collectWorldWritable() ([]Row, error) {
	return findPermissionRows("world_writable", []string{"/etc", "/usr/bin", "/usr/sbin"},
		"-perm", "-0002", "-type", "f")
}

func findPermissionRows(source string, roots []string, permArgs ...string) ([]Row, error) {
	if !commandAvailable("find") {
		return nil, fmt.Errorf("find not available")
	}
	args := append(append([]string{}, roots...), "-xdev")
	args = append(args, permArgs...)
	// `find` legitimately exits non-zero whenever it hits even ONE permission-denied
	// subdirectory while traversing as a non-root user (routine — e.g. /etc/ssl/private,
	// /etc/polkit-1) even though it still successfully lists everything else on stdout. Treating
	// that as a hard category failure discarded otherwise-valid partial results the first time
	// this ran live — the exit code is deliberately ignored here; whatever made it to stdout is
	// used regardless.
	out, _ := runCmd(90*time.Second, "find", args...)
	var rows []Row
	for _, line := range splitLines(out) {
		if line == "" {
			continue
		}
		rows = append(rows, Row{"source": source, "path": line})
	}
	return rows, nil
}

// collectHiddenProcessCheck compares the live process-table view (a raw /proc/[0-9]* directory
// listing) against `ps`'s own count — a mismatch is the classic userland-rootkit indicator
// (LD_PRELOAD or kernel-level process hiding making a process invisible to `ps` while it still
// has a /proc entry, or vice versa).
func collectHiddenProcessCheck() ([]Row, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	procCount := 0
	var procPids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			procCount++
			procPids = append(procPids, pid)
		}
	}

	psOut, err := runCmd(10*time.Second, "ps", "-e", "--no-headers", "-o", "pid")
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	psPids := make(map[int]bool)
	for _, line := range splitLines(psOut) {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			psPids[pid] = true
		}
	}

	var onlyInProc []int
	for _, pid := range procPids {
		if !psPids[pid] {
			onlyInProc = append(onlyInProc, pid)
		}
	}

	row := Row{
		"proc_dir_count": procCount,
		"ps_count":       len(psPids),
		"discrepancy":    procCount != len(psPids),
	}
	if len(onlyInProc) > 0 {
		// A PID present in /proc but missing from `ps` output is usually just a process that
		// exited in the brief window between the two reads (both are point-in-time snapshots) —
		// note it, don't treat a small discrepancy as automatically sinister.
		row["pids_in_proc_not_in_ps"] = onlyInProc
	}
	return []Row{row}, nil
}

// collectImmutableAttrs scans for the ext-family immutable ('i') and append-only ('a') file
// attributes outside their default (unset) state — a rootkit self-protection technique (an
// immutable malicious file can't be deleted or overwritten even by root without first clearing
// the attribute).
func collectImmutableAttrs() ([]Row, error) {
	if !commandAvailable("lsattr") {
		return nil, fmt.Errorf("lsattr not installed — install e2fsprogs to enable this check")
	}
	var rows []Row
	for _, dir := range []string{"/etc", "/usr/local/bin", "/usr/local/sbin", "/opt"} {
		// Same rationale as findPermissionRows: lsattr -R can exit non-zero on a single
		// unreadable subpath while still emitting valid results for everything else it could
		// reach — use whatever it printed regardless of exit status.
		out, _ := runCmd(30*time.Second, "lsattr", "-R", dir)
		for _, line := range splitLines(out) {
			fields := strings.SplitN(line, " ", 2)
			if len(fields) != 2 {
				continue
			}
			attrs, path := fields[0], strings.TrimSpace(fields[1])
			if strings.ContainsRune(attrs, 'i') || strings.ContainsRune(attrs, 'a') {
				rows = append(rows, Row{"source": "immutable_attr", "attrs": attrs, "path": path})
			}
		}
	}
	return rows, nil
}

// collectRecentlyModifiedEtc flags /etc files modified in the last 24h — a lightweight tamper
// signal alongside the package_integrity checksum check (config changes package verification
// wouldn't catch, since /etc is full of legitimately-editable-post-install files).
func collectRecentlyModifiedEtc() ([]Row, error) {
	if !commandAvailable("find") {
		return nil, fmt.Errorf("find not available")
	}
	// See findPermissionRows for why the exit status is ignored here too.
	out, _ := runCmd(30*time.Second, "find", "/etc", "-xdev", "-type", "f", "-mtime", "-1")
	var rows []Row
	for _, line := range splitLines(out) {
		if line == "" {
			continue
		}
		info, statErr := os.Stat(line)
		row := Row{"source": "recently_modified", "path": line}
		if statErr == nil {
			row["mtime"] = info.ModTime()
		}
		rows = append(rows, row)
	}
	return rows, nil
}
