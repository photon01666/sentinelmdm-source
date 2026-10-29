package itaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// isDebianFamily/isRpmFamily/isArchFamily let every package-aware collector share one detection
// instead of each re-implementing it.
func isDebianFamily() bool { return commandAvailable("dpkg") }
func isRpmFamily() bool    { return commandAvailable("rpm") }
func isArchFamily() bool   { return commandAvailable("pacman") }

func collectSoftware() ([]Row, error) {
	var rows []Row

	switch {
	case isDebianFamily():
		out, err := runCmd(30*time.Second, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n")
		if err != nil {
			return nil, fmt.Errorf("dpkg-query: %w", err)
		}
		for _, line := range splitLines(out) {
			fields := strings.SplitN(line, "\t", 3)
			if len(fields) < 3 {
				continue
			}
			rows = append(rows, Row{"pkg_manager": "dpkg", "name": fields[0], "version": fields[1], "status": fields[2]})
		}
	case isRpmFamily():
		out, err := runCmd(30*time.Second, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n")
		if err != nil {
			return nil, fmt.Errorf("rpm -qa: %w", err)
		}
		for _, line := range splitLines(out) {
			fields := strings.SplitN(line, "\t", 3)
			if len(fields) < 3 {
				continue
			}
			rows = append(rows, Row{"pkg_manager": "rpm", "name": fields[0], "version": fields[1], "vendor": fields[2]})
		}
	case isArchFamily():
		// `pacman -Q` = "name version" per installed package (both explicitly-installed and
		// dependencies). No status field like dpkg's — pacman has no half-installed states to
		// report here.
		out, err := runCmd(30*time.Second, "pacman", "-Q")
		if err != nil {
			return nil, fmt.Errorf("pacman -Q: %w", err)
		}
		for _, line := range splitLines(out) {
			fields := strings.SplitN(line, " ", 2)
			if len(fields) < 2 || fields[0] == "" {
				continue
			}
			rows = append(rows, Row{"pkg_manager": "pacman", "name": fields[0], "version": fields[1]})
		}
	default:
		return nil, fmt.Errorf("neither dpkg nor rpm nor pacman found — unsupported package manager")
	}

	rows = append(rows, orphanBinaries()...)
	return rows, nil
}

// orphanBinaries flags system-path executables with no owning package — a common signature of a
// dropped/replaced tool that didn't arrive via the package manager. Scoped to the standard binary
// dirs (not a full filesystem walk) to keep runtime bounded. Queries the package manager in
// BATCHES (one subprocess per ~150 candidate paths), not one subprocess per file — a first
// version shelled out to `dpkg -S <path>` per binary and hung for minutes on a real box with
// thousands of installed packages (dpkg -S does a linear scan of its metadata on every
// invocation; one-per-file is O(files × packages), batching is O(1) scans regardless of file
// count).
func orphanBinaries() []Row {
	var candidates []string
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} // /usr/local/{bin,sbin} intentionally excluded — legitimately unpackaged by design
	// On a usr-merge system /bin and /sbin are themselves symlinks to /usr/bin and /usr/sbin —
	// walking both roots would otherwise list every binary twice (once under each spelling).
	// Dedupe by each root's resolved canonical path so a non-merged system (where /bin, /sbin
	// are real independent directories) still gets scanned normally.
	seenDir := make(map[string]bool)
	for _, dir := range dirs {
		canonical, err := filepath.EvalSymlinks(dir)
		if err != nil {
			canonical = dir
		}
		if seenDir[canonical] {
			continue
		}
		seenDir[canonical] = true

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				candidates = append(candidates, filepath.Join(dir, e.Name()))
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Two independent path-normalization steps are needed before checking ownership, both found
	// live against this repo's own dev box on the first real run:
	//
	// 1. Symlink resolution: `/usr/bin/awk`, `/usr/bin/cc`, `/usr/bin/editor`, etc. are
	//    update-alternatives-managed symlinks that dpkg -S/rpm -qf/pacman -Qo genuinely do NOT
	//    track at their symlink path (only the resolved target, e.g. /usr/bin/mawk, is
	//    package-owned).
	// 2. usr-merge aliasing: on a merged-/usr system (/bin, /sbin are themselves symlinks to
	//    /usr/bin, /usr/sbin), a package's manifest can still record a file under the legacy
	//    /bin or /sbin path (e.g. iproute2 ships /bin/ip, /sbin/ip) even though walking
	//    /usr/bin, /usr/sbin turns up the identical file under the /usr-prefixed spelling — dpkg
	//    -S on the /usr-prefixed form alone reports "no path found". Stripping a leading "/usr"
	//    produces the alias to also check.
	//
	// A path is only reported as an orphan if NONE of its literal form, resolved symlink target,
	// or usr-merge alias is package-owned. Skipping either normalization step flagged the
	// majority of a stock Ubuntu install (or core packages like iproute2/brltty) as "orphan" the
	// first time this ran live — see git history for the before/after counts.
	aliasOf := make(map[string]string, len(candidates))
	resolved := make(map[string]string, len(candidates))
	lookupSet := make([]string, 0, len(candidates)*2)
	seen := make(map[string]bool)
	addLookup := func(p string) {
		if !seen[p] {
			seen[p] = true
			lookupSet = append(lookupSet, p)
		}
	}
	for _, path := range candidates {
		addLookup(path)

		if strings.HasPrefix(path, "/usr/bin/") || strings.HasPrefix(path, "/usr/sbin/") {
			alias := strings.TrimPrefix(path, "/usr")
			aliasOf[path] = alias
			addLookup(alias)
		}

		target, err := filepath.EvalSymlinks(path)
		if err == nil && target != path {
			resolved[path] = target
			addLookup(target)
		}
	}

	owned := packageOwnedSet(lookupSet)
	var rows []Row
	for _, path := range candidates {
		if owned[path] {
			continue
		}
		if alias, ok := aliasOf[path]; ok && owned[alias] {
			continue
		}
		if target, ok := resolved[path]; ok && owned[target] {
			continue
		}
		rows = append(rows, Row{"source": "orphan_binary", "path": path})
	}
	return rows
}

const orphanBatchSize = 150

// packageOwnedSet returns the subset of `paths` that the system's package manager reports as
// owned by an installed package.
func packageOwnedSet(paths []string) map[string]bool {
	owned := make(map[string]bool, len(paths))
	if !isDebianFamily() && !isRpmFamily() && !isArchFamily() {
		// Unknown package manager — treat everything as owned so we never false-positive every
		// binary on the box as an orphan.
		for _, p := range paths {
			owned[p] = true
		}
		return owned
	}

	for start := 0; start < len(paths); start += orphanBatchSize {
		end := start + orphanBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[start:end]

		switch {
		case isDebianFamily():
			out, _ := runCmd(30*time.Second, "dpkg", append([]string{"-S"}, batch...)...)
			// dpkg -S output is one "package[, package2, ...]: /path" line per OWNED match —
			// unowned paths in the batch simply produce no line at all (the "no path found
			// matching pattern" text goes to stderr, which runCmd discards). Parsed by exact
			// path, not substring — a naive Contains() check here previously mismatched e.g.
			// "/usr/bin/ls" against an owned "/usr/bin/lsblk" line.
			for _, line := range splitLines(out) {
				if idx := strings.LastIndex(line, ": /"); idx >= 0 {
					owned[line[idx+2:]] = true
				}
			}
		case isRpmFamily():
			out, _ := runCmd(30*time.Second, "rpm", append([]string{"-qf"}, batch...)...)
			// rpm -qf prints exactly one line per input argument, in argument order: either the
			// owning package NVR, or "file <path> is not owned by any package". Zip positionally
			// rather than substring-matching, since an owned line never echoes the queried path.
			lines := splitLines(out)
			for i, p := range batch {
				if i < len(lines) && !strings.Contains(lines[i], "is not owned by any package") {
					owned[p] = true
				}
			}
		default: // isArchFamily — guaranteed by the guard above
			out, _ := runCmd(30*time.Second, "pacman", append([]string{"-Qo"}, batch...)...)
			// pacman -Qo accepts multiple targets and prints "<path> is owned by <pkg> <ver>"
			// on stdout for each owned path; unowned paths only produce "error: No package owns
			// <path>" on stderr (discarded by runCmd). The path echoed before the marker is the
			// one to record — note pacman canonicalizes symlinked spellings (e.g. a queried
			// /bin/ls comes back as /usr/bin/ls), which is exactly the form the orphan check's
			// resolved-path lookup set also carries on a usr-merged system.
			for _, line := range splitLines(out) {
				if idx := strings.Index(line, " is owned by "); idx >= 0 {
					owned[line[:idx]] = true
				}
			}
		}
	}
	return owned
}

// collectPackageIntegrity mirrors the Windows "signing" category — but is structurally stronger
// here: debsums/rpm -Va checksum-verify EVERY file in EVERY installed package's manifest against
// its on-disk content, not just Authenticode-sign individual binaries (design plan §5.1).
func collectPackageIntegrity() ([]Row, error) {
	switch {
	case isDebianFamily():
		if !commandAvailable("debsums") {
			return nil, fmt.Errorf("debsums not installed — install the `debsums` package to enable this check")
		}
		out, _ := runCmd(120*time.Second, "debsums", "-c") // debsums exits non-zero when it finds mismatches — that's the interesting case, not an error
		var rows []Row
		for _, line := range splitLines(out) {
			if line != "" {
				rows = append(rows, Row{"source": "debsums_mismatch", "path": line})
			}
		}
		return rows, nil
	case isRpmFamily():
		out, _ := runCmd(120*time.Second, "rpm", "-Va")
		var rows []Row
		for _, line := range splitLines(out) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			rows = append(rows, Row{"source": "rpm_verify_mismatch", "flags": fields[0], "path": fields[len(fields)-1]})
		}
		return rows, nil
	case isArchFamily():
		// pacman -Qkk writes EVERY warning/per-file mismatch to STDERR; its stdout is only the
		// per-package "<pkg>: N total files, M altered files" summary lines (mostly "0 altered").
		// Hence runCmdStderr, not runCmd — the plain variant would capture nothing useful.
		out, _ := runCmdStderr(120*time.Second, "pacman", "-Qkk")
		var rows []Row
		for _, line := range splitLines(out) {
			// Format: "warning: <pkg>: <path> (<reason>)". Lines that don't match (e.g. a
			// stdout/stderr interleave mangle, or future format changes) are skipped.
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "warning: ")
			if !ok {
				continue
			}
			open := strings.LastIndex(rest, " (")
			if open < 0 || !strings.HasSuffix(rest, ")") {
				continue
			}
			reason := rest[open+2 : len(rest)-1]
			loc := strings.SplitN(rest[:open], ": ", 2)
			if len(loc) != 2 {
				continue
			}
			// debsums-parity inclusion rule: report only CONTENT-level mismatches (checksum
			// changes + missing files), matching what the Debian branch's `debsums -c` surfaces.
			// Everything else pacman -Qkk emits is baseline noise on a real desktop —
			// mtime/size/permissions/uid-gid drift, /boot and icon-theme symlink type changes,
			// unreadable files — and reporting it made the AI verdict alarmist about a healthy
			// customized Arch box (live 2026-09-25: 12 reported rows, mostly /boot + GID +
			// symlink noise, produced "12 package integrity violations ... immediate review").
			// A changed file's size/type lines ride along with its checksum line anyway, so no
			// real signal is lost.
			switch {
			case strings.Contains(reason, "checksum mismatch"),
				strings.Contains(reason, "No such file"):
			default:
				continue
			}
			rows = append(rows, Row{"source": "pacman_verify_mismatch", "flags": reason, "path": loc[1]})
		}
		return rows, nil
	}
	return nil, fmt.Errorf("neither debsums nor rpm nor pacman found — unsupported package manager")
}
