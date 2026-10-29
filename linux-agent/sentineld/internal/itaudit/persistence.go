package itaudit

import (
	"os"
	"path/filepath"
)

const maxInlineFileBytes = 8192

// readFileCapped reads a file's content for inline inclusion in a Row, truncating anything
// larger than maxInlineFileBytes (persistence-relevant config files are always small; a huge file
// at one of these paths would itself be a finding, but we don't need to transport megabytes of it
// to notice that).
func readFileCapped(path string) (content string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	buf := make([]byte, maxInlineFileBytes+1)
	n, _ := f.Read(buf)
	if n > maxInlineFileBytes {
		return string(buf[:maxInlineFileBytes]), true, nil
	}
	return string(buf[:n]), false, nil
}

func fileRow(source, path string) Row {
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil // doesn't exist — nothing to report, not a finding
	}
	row := Row{"source": source, "path": path, "size": info.Size(), "mtime": info.ModTime()}
	content, truncated, err := readFileCapped(path)
	if err == nil {
		row["content"] = content
		row["content_truncated"] = truncated
	}
	return row
}

func dirFileRows(source, dir string) []Row {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []Row
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if r := fileRow(source, filepath.Join(dir, e.Name())); r != nil {
			rows = append(rows, r)
		}
	}
	return rows
}

// collectPersistence mirrors the Windows "autoruns" category — every Linux boot/login/dynamic-
// load persistence surface: shell rc files, /etc/profile.d, /etc/rc.local, udev rules,
// /etc/ld.so.preload (library injection — no Windows Run-key parallel), PAM config, and kernel
// module auto-load config.
func collectPersistence() ([]Row, error) {
	var rows []Row

	for _, path := range []string{
		"/etc/profile", "/etc/bash.bashrc", "/etc/rc.local",
		"/root/.bashrc", "/root/.bash_profile", "/root/.profile",
	} {
		if r := fileRow("shell_rc", path); r != nil {
			rows = append(rows, r)
		}
	}
	rows = append(rows, dirFileRows("profile.d", "/etc/profile.d")...)
	rows = append(rows, dirFileRows("udev_rules", "/etc/udev/rules.d")...)
	rows = append(rows, dirFileRows("modules_load", "/etc/modules-load.d")...)
	rows = append(rows, dirFileRows("modprobe_d", "/etc/modprobe.d")...)
	rows = append(rows, dirFileRows("pam_d", "/etc/pam.d")...)

	// /etc/ld.so.preload — the single highest-value row in this whole category if it's ever
	// non-empty. A default Linux install ships this file absent or empty; any library path in it
	// is loaded into EVERY dynamically-linked process on the system, the classic LD_PRELOAD
	// persistence/rootkit technique.
	if r := fileRow("ld_so_preload", "/etc/ld.so.preload"); r != nil {
		rows = append(rows, r)
	}

	// Also list every home directory's rc files, not just root's.
	homeEntries, err := os.ReadDir("/home")
	if err == nil {
		for _, e := range homeEntries {
			if !e.IsDir() {
				continue
			}
			for _, rc := range []string{".bashrc", ".bash_profile", ".profile"} {
				if r := fileRow("shell_rc", filepath.Join("/home", e.Name(), rc)); r != nil {
					rows = append(rows, r)
				}
			}
		}
	}

	// An empty result here is a legitimate outcome on a minimal server, not a failure — don't
	// synthesize an error just because nothing was found.
	return rows, nil
}
