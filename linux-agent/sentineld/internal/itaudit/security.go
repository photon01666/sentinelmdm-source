package itaudit

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// collectSecurity mirrors the Windows "security" category (Defender/AV/firewall/BitLocker/
// SecureBoot/ASR) — firewall state, mandatory-access-control mode, auditd/fail2ban, and
// unattended-upgrades config. Malware commonly disables these first, so a disabled/stale result
// is itself a finding here, same doctrine as the Windows Defender-state check.
func collectSecurity() ([]Row, error) {
	var rows []Row

	rows = append(rows, firewallState()...)

	if commandAvailable("getenforce") {
		out, _ := runCmd(3*time.Second, "getenforce")
		rows = append(rows, Row{"source": "selinux", "state": strings.TrimSpace(out)})
	}
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		rows = append(rows, Row{"source": "apparmor", "enabled": strings.TrimSpace(string(b)) == "Y"})
	}

	for _, svc := range []string{"auditd", "fail2ban", "unattended-upgrades"} {
		rows = append(rows, Row{"source": "service_state", "service": svc, "active": systemdIsActive(svc)})
	}

	if r := fileRow("unattended_upgrades_config", "/etc/apt/apt.conf.d/20auto-upgrades"); r != nil {
		rows = append(rows, r)
	}
	if r := fileRow("dnf_automatic_config", "/etc/dnf/automatic.conf"); r != nil {
		rows = append(rows, r)
	}

	return rows, nil
}

func systemdIsActive(unit string) bool {
	out, _ := runCmd(3*time.Second, "systemctl", "is-active", unit)
	return strings.TrimSpace(out) == "active"
}

func firewallState() []Row {
	var rows []Row
	switch {
	case commandAvailable("nft"):
		out, err := runCmd(5*time.Second, "nft", "list", "ruleset")
		rows = append(rows, Row{"source": "firewall", "backend": "nftables", "rule_count": len(splitLines(out)), "error": errString(err)})
	case commandAvailable("iptables-save"):
		out, err := runCmd(5*time.Second, "iptables-save")
		rows = append(rows, Row{"source": "firewall", "backend": "iptables", "rule_count": len(splitLines(out)), "error": errString(err)})
	}
	if commandAvailable("ufw") {
		out, _ := runCmd(5*time.Second, "ufw", "status")
		rows = append(rows, Row{"source": "firewall", "backend": "ufw", "status": strings.TrimSpace(out)})
	}
	if len(rows) == 0 {
		rows = append(rows, Row{"source": "firewall", "backend": "none_detected"})
	}
	return rows
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// collectKernelModules mirrors the Windows "drivers" category.
func collectKernelModules() ([]Row, error) {
	out, err := runCmd(10*time.Second, "lsmod")
	if err != nil {
		return nil, fmt.Errorf("lsmod: %w", err)
	}
	lines := splitLines(out)
	if len(lines) > 0 {
		lines = lines[1:] // header row: "Module  Size  Used by"
	}

	var rows []Row
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		filenameOut, _ := runCmd(3*time.Second, "modinfo", "-F", "filename", name)
		rows = append(rows, Row{
			"module":   name,
			"raw_line": line,
			"filename": strings.TrimSpace(filenameOut),
		})
	}
	return rows, nil
}

// collectHosts mirrors the Windows "hosts" category — /etc/hosts, resolver config, NSS config,
// per-user proxy env vars, and unrecognized third-party package repos.
func collectHosts() ([]Row, error) {
	var rows []Row

	for _, path := range []string{"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf"} {
		if r := fileRow("config_file", path); r != nil {
			rows = append(rows, r)
		}
	}

	for _, path := range []string{"/etc/profile", "/etc/environment", "/etc/bash.bashrc"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "http_proxy") || strings.Contains(lower, "https_proxy") {
				rows = append(rows, Row{"source": "proxy_env", "file": path, "line": strings.TrimSpace(line)})
			}
		}
	}

	rows = append(rows, dirFileRows("apt_repo", "/etc/apt/sources.list.d")...)
	rows = append(rows, dirFileRows("yum_repo", "/etc/yum.repos.d")...)

	return rows, nil
}
