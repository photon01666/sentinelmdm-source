package itaudit

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type passwdEntry struct {
	name  string
	uid   int
	gid   int
	home  string
	shell string
}

func readPasswd() ([]passwdEntry, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []passwdEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		entries = append(entries, passwdEntry{name: fields[0], uid: uid, gid: gid, home: fields[5], shell: fields[6]})
	}
	return entries, scanner.Err()
}

// collectUsers mirrors the Windows "users" category, with `~/.ssh/authorized_keys` across every
// home directory promoted to first-class (design plan §5.1/§5.2) — SSH key backdoors are the
// dominant Linux server persistence vector and have no direct equivalent in the original
// Windows-only category list.
func collectUsers() ([]Row, error) {
	entries, err := readPasswd()
	if err != nil {
		return nil, err
	}

	var rows []Row
	for _, e := range entries {
		rows = append(rows, Row{
			"source":  "passwd",
			"name":    e.name,
			"uid":     e.uid,
			"gid":     e.gid,
			"home":    e.home,
			"shell":   e.shell,
			"is_uid0": e.uid == 0,
		})

		for _, key := range readAuthorizedKeys(e.home) {
			rows = append(rows, Row{
				"source": "authorized_keys",
				"user":   e.name,
				"home":   e.home,
				"key":    key,
			})
		}
	}

	for _, group := range []string{"sudo", "wheel"} {
		if out, err := runCmd(5*time.Second, "getent", "group", group); err == nil {
			for _, line := range splitLines(out) {
				fields := strings.Split(line, ":")
				if len(fields) < 4 || fields[3] == "" {
					continue
				}
				for _, member := range strings.Split(fields[3], ",") {
					rows = append(rows, Row{"source": "privileged_group", "group": group, "member": member})
				}
			}
		}
	}

	rows = append(rows, sudoersLines("/etc/sudoers")...)
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				rows = append(rows, sudoersLines(filepath.Join("/etc/sudoers.d", e.Name()))...)
			}
		}
	}

	// Best-effort — requires read access to /etc/shadow (root, or a sudoers-scoped wrapper per
	// design plan §1's least-privilege model). Silently skipped, not an error, when unreadable.
	rows = append(rows, shadowSetPasswordAccounts()...)

	return rows, nil
}

func readAuthorizedKeys(home string) []string {
	path := filepath.Join(home, ".ssh", "authorized_keys")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var keys []string
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		keys = append(keys, trimmed)
	}
	return keys
}

func sudoersLines(path string) []Row {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var rows []Row
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rows = append(rows, Row{"source": "sudoers", "file": path, "line": trimmed})
	}
	return rows
}

func shadowSetPasswordAccounts() []Row {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil // not root / no sudoers read wrapper for this path yet — expected on most runs
	}
	defer f.Close()

	var rows []Row
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		name, hash := fields[0], fields[1]
		// "!" / "*" / "" mean no valid password (login disabled or key-only) — only a real hash
		// is worth surfacing as "this account can log in with a password".
		if hash != "" && hash != "!" && hash != "*" && !strings.HasPrefix(hash, "!") {
			rows = append(rows, Row{"source": "shadow_password_set", "name": name})
		}
	}
	return rows
}
