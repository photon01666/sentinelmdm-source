package itaudit

import (
	"encoding/json"
	"strings"
	"time"
)

type journalEntry struct {
	Message   string `json:"MESSAGE"`
	Timestamp string `json:"__REALTIME_TIMESTAMP"`
	Unit      string `json:"_SYSTEMD_UNIT"`
}

// collectAuthEvents mirrors the Windows "events" category (failed logons, account/group changes,
// 14-day window) — journalctl for sshd (trying both the Debian "ssh" and RHEL "sshd" unit names),
// plus `last`/`lastb` for a login-history sample, the direct analog of the Windows 4624/4625
// sample rows.
func collectAuthEvents() ([]Row, error) {
	var rows []Row

	for _, unit := range []string{"sshd.service", "ssh.service"} {
		out, err := runCmd(20*time.Second, "journalctl", "-u", unit, "-o", "json", "--since", "14 days ago", "--no-pager")
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		for _, line := range splitLines(out) {
			var e journalEntry
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			msg := e.Message
			lower := strings.ToLower(msg)
			isHighValue := strings.Contains(lower, "failed password") ||
				strings.Contains(lower, "invalid user") ||
				strings.Contains(lower, "accepted publickey") ||
				strings.Contains(lower, "accepted password")
			rows = append(rows, Row{
				"source":        "journal_sshd",
				"unit":          unit,
				"message":       msg,
				"high_value":    isHighValue,
				"realtime_usec": e.Timestamp,
			})
		}
		break // found a working unit name — no need to try the other
	}

	if out, err := runCmd(10*time.Second, "last", "-F", "-n", "50"); err == nil {
		for _, line := range splitLines(out) {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "wtmp begins") {
				continue
			}
			rows = append(rows, Row{"source": "last_login_sample", "line": line})
		}
	}

	if out, err := runCmd(10*time.Second, "lastb", "-F", "-n", "50"); err == nil {
		for _, line := range splitLines(out) {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "btmp begins") {
				continue
			}
			rows = append(rows, Row{"source": "failed_login_sample", "line": line})
		}
	}

	// Account/group-membership changes (useradd/usermod/groupadd/gpasswd all log through the
	// system journal, not just sshd) — the direct analog of the Windows 4720/4732/4735 rows.
	if out, err := runCmd(20*time.Second, "journalctl", "-o", "json", "--since", "14 days ago", "--no-pager",
		"SYSLOG_IDENTIFIER=useradd", "+", "SYSLOG_IDENTIFIER=usermod", "+", "SYSLOG_IDENTIFIER=groupadd", "+", "SYSLOG_IDENTIFIER=gpasswd"); err == nil {
		for _, line := range splitLines(out) {
			var e journalEntry
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			rows = append(rows, Row{"source": "account_change", "message": e.Message, "realtime_usec": e.Timestamp})
		}
	}

	return rows, nil
}
