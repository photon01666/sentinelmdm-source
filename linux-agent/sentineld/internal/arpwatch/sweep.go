package arpwatch

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Sweep-watch constants mirror _ARP_SWEEP_LOOP_PS1's: 4s windows, ≥15 distinct target IPs from
// one source MAC = a sweep event, queue capped at 200 events.
const (
	SweepWindowSeconds = 4
	sweepThreshold     = 15
	sweepMaxQueue      = 200
	sweepSampleCap     = 8
)

// StateDir holds the persistent watcher state. Root-owned (the watcher runs as root via the
// systemd unit the libexec script creates); the drain action (also root via sudo) reads it.
var StateDir = "/var/lib/sentinel-ra/arpsweep"

// SweepEvent mirrors the Windows queue.json event object field-for-field.
type SweepEvent struct {
	MAC           string   `json:"mac"`
	TargetCount   int      `json:"targetCount"`
	SampleTargets []string `json:"sampleTargets"`
	WindowStart   string   `json:"windowStart"`
	WindowEnd     string   `json:"windowEnd"`
}

// Heartbeat mirrors the Windows heartbeat.json object.
type Heartbeat struct {
	TS            string `json:"ts"`
	WindowSeconds int    `json:"windowSeconds"`
}

// Watch runs the passive ARP-sweep detection loop: a root-only AF_PACKET socket bound to the
// ARP EtherType, captured in back-to-back ~4s windows. Each window tallies distinct target IPs
// per source MAC; a MAC with ≥15 distinct targets queues a sweep event. The box's own adapter
// MACs are excluded every window (recomputed, so adapter changes over a long-running watcher
// don't stale it) — without that the box's own scheduled ARP scan would self-alert. Runs until
// ctx is cancelled (systemd stops the service on disable / shutdown).
func Watch(ctx context.Context) error {
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)

	fmt.Fprintf(os.Stderr, "arpwatch: started (window=%ds threshold=%d state=%s)\n",
		SweepWindowSeconds, sweepThreshold, StateDir)

	buf := make([]byte, 65536)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		windowStart := time.Now()
		windowEnd := windowStart.Add(SweepWindowSeconds * time.Second)
		byMac := captureWindow(fd, buf, windowEnd)

		own := ownMacSet()
		events := make([]SweepEvent, 0)
		macs := make([]string, 0, len(byMac))
		for m := range byMac {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		for _, mac := range macs {
			if own[mac] {
				continue
			}
			targets := byMac[mac]
			if len(targets) < sweepThreshold {
				continue
			}
			sample := make([]string, 0, sweepSampleCap)
			for t := range targets {
				if len(sample) >= sweepSampleCap {
					break
				}
				sample = append(sample, t)
			}
			events = append(events, SweepEvent{
				MAC:           mac,
				TargetCount:   len(targets),
				SampleTargets: sample,
				WindowStart:   windowStart.UTC().Format(arpTimeFmt),
				WindowEnd:     windowEnd.UTC().Format(arpTimeFmt),
			})
		}
		if len(events) > 0 {
			if err := enqueueEvents(events); err != nil {
				fmt.Fprintln(os.Stderr, "arpwatch: queue write failed:", err)
			}
		}
		if err := writeHeartbeat(windowEnd); err != nil {
			fmt.Fprintln(os.Stderr, "arpwatch: heartbeat write failed:", err)
		}
	}
}

// captureWindow reads ARP frames until the window deadline (SO_RCVTIMEO) and tallies distinct
// target IPs per source MAC. Returns on timeout/error — a quiet window legitimately produces an
// empty map.
func captureWindow(fd int, buf []byte, windowEnd time.Time) map[string]map[string]bool {
	byMac := map[string]map[string]bool{}
	tv := syscall.NsecToTimeval(time.Until(windowEnd).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return byMac // EAGAIN (window elapsed) or socket error — either way the window is over
		}
		parseFrame(buf[:n], byMac)
	}
}

// parseFrame extracts {source MAC, target IP} from an ARP REQUEST frame. Ethernet header at
// offset 0 (AF_PACKET SOCK_RAW keeps the link-layer header); ARP payload at 14: OPER at +6,
// sender hardware address at +8, target protocol address at +24. Replies (opcode 2) are not
// counted — a device answering a legitimate query is not reconnaissance.
func parseFrame(frame []byte, byMac map[string]map[string]bool) {
	if len(frame) < 42 {
		return
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 { // EtherType: ARP
		return
	}
	arp := frame[14:]
	if len(arp) < 28 {
		return
	}
	if binary.BigEndian.Uint16(arp[6:8]) != 1 { // opcode: request only
		return
	}
	mac := fmtMAC(arp[8:14])
	target := net.IPv4(arp[24], arp[25], arp[26], arp[27]).String()
	m, ok := byMac[mac]
	if !ok {
		m = map[string]bool{}
		byMac[mac] = m
	}
	m[target] = true
}

// ownMacSet returns every non-loopback interface MAC (lowercase colons). Broader than the scan's
// physical-only selfMacs on purpose — matches _ARP_SWEEP_LOOP_PS1's Get-NetAdapter (all adapters)
// self-exclusion: any MAC this box owns must never be flagged as a scanner.
func ownMacSet() map[string]bool {
	out := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		mac := strings.ToLower(ifc.HardwareAddr.String())
		if mac != "00:00:00:00:00:00" {
			out[mac] = true
		}
	}
	return out
}

// enqueueEvents appends to queue.json with the same discipline as the Windows loop: a FLAT array
// of plain events rebuilt on every write (carrying forward only well-formed entries — garbage or
// stale nested structures from a previous buggy build are dropped), capped at MAX_QUEUE, written
// atomically (tmp + rename) so a concurrent drain never reads a torn file.
func enqueueEvents(events []SweepEvent) error {
	var q []SweepEvent
	queuePath := filepath.Join(StateDir, "queue.json")
	if b, err := os.ReadFile(queuePath); err == nil {
		_ = json.Unmarshal(b, &q)
	}
	q = append(q, events...)
	if len(q) > sweepMaxQueue {
		q = q[len(q)-sweepMaxQueue:]
	}
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	tmp := queuePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, queuePath)
}

func writeHeartbeat(ts time.Time) error {
	b, err := json.Marshal(Heartbeat{TS: ts.UTC().Format(arpTimeFmt), WindowSeconds: SweepWindowSeconds})
	if err != nil {
		return err
	}
	hb := filepath.Join(StateDir, "heartbeat.json")
	tmp := hb + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, hb)
}

// htons converts a 16-bit value to network byte order — syscall.Socket's protocol argument for
// AF_PACKET expects the EtherType in host byte order on the wire representation.
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func fmtMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
