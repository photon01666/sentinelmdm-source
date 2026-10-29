// Command sentineld is the Linux Remote Assist agent — see
// ssh-bastion-client-linux/README.md and the design plan for the full architecture.
// This build implements: CLI email/password enrollment (`enroll`) and the IT Audit Mode
// forensics collector (`it-audit`). The Hop-1/Hop-2 tunnel daemon (`run`) is scaffolded but not
// yet wired to a live xray/REALITY transport — see README "Status" for what's implemented vs.
// pending.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"sentineld/internal/arpwatch"
	"sentineld/internal/enroll"
	"sentineld/internal/itaudit"
)

// version is set at build time via -ldflags "-X main.version=<v>"; defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "enroll":
		if err := runEnroll(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "enroll: error:", err)
			os.Exit(1)
		}
	case "it-audit":
		if err := runITAudit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "it-audit: error:", err)
			os.Exit(1)
		}
	case "run":
		if err := runDaemon(); err != nil {
			fmt.Fprintln(os.Stderr, "run: error:", err)
			os.Exit(1)
		}
	case "arp-scan":
		if err := runArpScan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "arp-scan: error:", err)
			os.Exit(1)
		}
	case "arp-sweep-watch":
		if err := runArpSweepWatch(); err != nil {
			fmt.Fprintln(os.Stderr, "arp-sweep-watch: error:", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("sentineld", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`sentineld — SentinelMDM Remote Assist Linux agent

Usage:
  sentineld enroll              Interactively log in with your SentinelMDM email/password
                                 and link this server to your account (no dashboard token needed).
  sentineld enroll --ticket T   No-login enrollment: link this server to the account that
                                 minted the installer ticket T (baked into the install command
                                 the dashboard's "Linux Agent" dropdown copies). No sign-in
                                 prompts — the ticket is the account binding.
  sentineld it-audit [--kind K] Run the IT Audit Mode forensics collector and print JSON.
                                 --kind defaults to "all"; see ` + "`sentineld it-audit --list`" + ` for
                                 the category list.
  sentineld run                 Run the daemon (boot-resident Hop-1 tunnel + control channel).
  sentineld arp-scan             Run one network-discovery scan (parallel ping sweep of every
                                 local /22-/30 subnet, then read back the kernel ARP table) and
                                 print the result as a single compact JSON line — the Linux
                                 counterpart of the bastion's _ARP_SCAN_PS1. Needs root (the
                                 sudoers-granted arpsweep-deploy.sh wrapper provides it).
  sentineld arp-sweep-watch      Run the passive ARP-sweep detection loop: AF_PACKET capture
                                 of ARP requests in ~4s windows, ≥15 distinct targets from one
                                 source MAC queues an event to /var/lib/sentinel-ra/arpsweep/
                                 queue.json (heartbeat.json written every window). Needs root;
                                 runs as a systemd service (sentinel-arpsweep-watch.service,
                                 created by arpsweep-deploy.sh enable) until stopped.
  sentineld version             Print the build version.`)
}

// runEnroll dispatches `sentineld enroll [--ticket <t>]`: with a ticket, the no-login installer
// flow (account-bound ticket baked into the copied install command); without one, the original
// interactive email/password flow.
func runEnroll(args []string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ticket", "-t":
			if i+1 >= len(args) {
				return fmt.Errorf("--ticket requires a value")
			}
			return enroll.RunTicketEnroll(strings.TrimSpace(args[i+1]))
		default:
			return fmt.Errorf("unknown enroll option: %s", args[i])
		}
	}
	return enroll.RunInteractiveEnroll()
}

func runITAudit(args []string) error {
	kind := "all"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--kind":
			if i+1 >= len(args) {
				return fmt.Errorf("--kind requires a value")
			}
			kind = args[i+1]
			i++
		case "--list":
			for _, k := range itaudit.Kinds() {
				fmt.Println(k)
			}
			return nil
		}
	}

	result := itaudit.Collect(kind)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// runDaemon is implemented in daemon.go.

// runArpScan prints one ScanResult as a SINGLE compact JSON line — the bastion's hop2 parse
// path scans stdout lines in reverse for the last valid JSON (same contract as the Windows
// _ARP_SCAN_PS1's guaranteed-JSON-output discipline). Never pretty-print here: a multi-line
// object would fail that per-line parse.
//
// Accepts --extra-subnets <cidr1,cidr2,...> to include manually-configured VLAN subnets
// alongside auto-detected local interfaces.
func runArpScan(args []string) error {
	var extraSubnets []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--extra-subnets":
			if i+1 >= len(args) {
				return fmt.Errorf("--extra-subnets requires a comma-separated list of CIDR subnets")
			}
			for _, s := range strings.Split(args[i+1], ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					extraSubnets = append(extraSubnets, s)
				}
			}
			i++
		default:
			return fmt.Errorf("unknown arp-scan option: %s", args[i])
		}
	}
	res := arpwatch.Scan(extraSubnets...)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}

// runArpSweepWatch runs the passive sweep-detection loop until SIGINT/SIGTERM (systemd stops
// the service). Diagnostics go to stderr (journal); stdout stays untouched.
func runArpSweepWatch() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()
	return arpwatch.Watch(ctx)
}
