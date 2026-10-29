// Package arpwatch implements the Linux Remote Assist agent's ARP network-discovery scan and
// passive ARP-sweep detection — the sentineld equivalents of the Windows bastion features
// _ARP_SCAN_PS1 and _ARP_SWEEP_LOOP_PS1 (bastion-web.py). Both speak the SAME wire contracts, so
// the bastion's last-JSON-line parsing and the server's ingestArpScanResult() /
// ingestArpSweepEvents() consume either platform identically.
//
// Privilege note: the active scan's ICMP ping sockets and the watcher's AF_PACKET capture socket
// both need root. The libexec arpsweep-deploy.sh wrapper (sudoers-granted to the Hop-2
// sentinel-support account) invokes these as root; the sentineld daemon itself never does.
package arpwatch

// arpTimeFmt matches .NET's "o" round-trip format used by the Windows PS1 scripts (7 fractional
// digits, Z suffix) so timestamps are byte-identical in shape on both platforms.
const arpTimeFmt = "2006-01-02T15:04:05.0000000Z"
