package itaudit

import (
	"os"
	"path/filepath"
	"strings"
)

// collectFilelessPersistence mirrors the Windows "wmi_persist" category — any row here is
// inherently rare on a normal server, worth a specific callout in the report rather than
// auto-assumed malicious (design plan §5.1/§5.2), same treatment as the WMI original.
func collectFilelessPersistence() ([]Row, error) {
	var rows []Row

	for _, unitType := range []string{"path", "socket"} {
		units, err := listSystemdUnits(unitType)
		if err != nil {
			continue
		}
		for _, u := range units {
			vals := showUnitProperties(u.Unit, "FragmentPath")
			rows = append(rows, Row{
				"source":        "systemd_" + unitType + "_unit",
				"unit":          u.Unit,
				"active":        u.Active,
				"fragment_path": vals[0],
			})
		}
	}

	rows = append(rows, udevRunRules("/etc/udev/rules.d")...)
	rows = append(rows, udevRunRules("/usr/lib/udev/rules.d")...)

	if r := fileRow("ld_so_preload", "/etc/ld.so.preload"); r != nil {
		rows = append(rows, r)
	}

	for _, dbusDir := range []string{"/usr/share/dbus-1/system-services", "/usr/share/dbus-1/services"} {
		entries, err := os.ReadDir(dbusDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dbusDir, e.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "Exec=") {
					rows = append(rows, Row{"source": "dbus_service_activation", "file": path, "exec": strings.TrimSpace(line)})
				}
			}
		}
	}

	return rows, nil
}

// udevRunRules greps udev rule files for RUN+= directives — a udev rule that executes a program
// on a device event is a legitimate mechanism used sparingly by real hardware drivers, but is
// also a known fileless-persistence technique (fires on hotplug/boot events, no scheduled task or
// Run-key artifact).
func udevRunRules(dir string) []Row {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var rows []Row
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "RUN+=") || strings.Contains(line, "RUN=") {
				rows = append(rows, Row{"source": "udev_run_rule", "file": path, "line": strings.TrimSpace(line)})
			}
		}
	}
	return rows
}
