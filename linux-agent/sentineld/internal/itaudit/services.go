package itaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type systemdUnitJSON struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// listSystemdUnits returns every unit of the given type (service, timer, path, socket, ...),
// preferring `systemctl --output=json` (systemd >=230, effectively universal on maintained
// distros) and falling back to nothing (not a hard error) if systemctl is unavailable — this
// collector must still return a parseable, if empty, result on a non-systemd box rather than
// aborting the whole audit.
func listSystemdUnits(unitType string) ([]systemdUnitJSON, error) {
	out, err := runCmd(20*time.Second, "systemctl", "list-units", "--type="+unitType, "--all", "--output=json", "--no-pager")
	if err != nil {
		return nil, err
	}
	var units []systemdUnitJSON
	if err := json.Unmarshal([]byte(out), &units); err != nil {
		return nil, fmt.Errorf("parse systemctl json: %w", err)
	}
	return units, nil
}

// showUnitProperties runs `systemctl show <unit> -p <prop1> -p <prop2> ... --value` and returns
// the values in the same order as requested. Each call is bounded/independent so one hung unit
// can't stall the whole services category — see runCmd's timeout.
func showUnitProperties(unit string, props ...string) []string {
	args := []string{"show", unit}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	args = append(args, "--value")
	out, err := runCmd(5*time.Second, "systemctl", args...)
	if err != nil {
		return make([]string, len(props))
	}
	lines := splitLines(out)
	vals := make([]string, len(props))
	for i := range props {
		if i < len(lines) {
			vals[i] = lines[i]
		}
	}
	return vals
}

func collectServices() ([]Row, error) {
	units, err := listSystemdUnits("service")
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	rows := make([]Row, 0, len(units))
	for _, u := range units {
		vals := showUnitProperties(u.Unit, "FragmentPath", "ExecStart", "User")
		rows = append(rows, Row{
			"unit":          u.Unit,
			"load":          u.Load,
			"active":        u.Active,
			"sub":           u.Sub,
			"description":   u.Description,
			"fragment_path": vals[0],
			"exec_start":    vals[1],
			"user":          vals[2],
		})
	}
	return rows, nil
}

// collectScheduledJobs mirrors the Windows "tasks" category: cron (system + per-user + the
// periodic /etc/cron.* directories) plus systemd timers.
func collectScheduledJobs() ([]Row, error) {
	var rows []Row

	rows = append(rows, collectCronFile("/etc/crontab")...)
	rows = append(rows, collectCronDir("/etc/cron.d")...)
	rows = append(rows, collectCronDir("/var/spool/cron/crontabs")...)
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		rows = append(rows, collectCronDropinDir(fmt.Sprintf("/etc/cron.%s", period), period)...)
	}

	timers, err := listSystemdUnits("timer")
	if err == nil {
		for _, t := range timers {
			vals := showUnitProperties(t.Unit, "FragmentPath")
			rows = append(rows, Row{
				"source":        "systemd_timer",
				"unit":          t.Unit,
				"active":        t.Active,
				"description":   t.Description,
				"fragment_path": vals[0],
			})
		}
	}
	return rows, nil
}

func collectCronFile(path string) []Row {
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
		rows = append(rows, Row{"source": "crontab", "file": path, "line": trimmed})
	}
	return rows
}

func collectCronDir(dir string) []Row {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []Row
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		rows = append(rows, collectCronFile(filepath.Join(dir, e.Name()))...)
	}
	return rows
}

// collectCronDropinDir lists (not parses) scripts in /etc/cron.{hourly,daily,weekly,monthly} —
// these run as root on their period, so mere presence of an unexpected script is itself the
// signal, same treatment as the fileless_persistence category.
func collectCronDropinDir(dir, period string) []Row {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []Row
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		var mtime time.Time
		if err == nil {
			mtime = info.ModTime()
		}
		rows = append(rows, Row{
			"source": "cron." + period,
			"file":   filepath.Join(dir, e.Name()),
			"mtime":  mtime,
		})
	}
	return rows
}
