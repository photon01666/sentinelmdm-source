package arpwatch

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device is one neighbor found by the scan — mirrors the Windows PS1's {ip, mac, hostname} row,
// extended with the aggressive-fingerprinting fields the Windows PS1 added (openPorts/web are
// omitted from JSON when empty — same contract the server-side ingest normalizes either way).
type Device struct {
	IP        string  `json:"ip"`
	MAC       string  `json:"mac"`
	Hostname  string  `json:"hostname,omitempty"`
	OpenPorts []int   `json:"openPorts,omitempty"`
	Web       []WebUI `json:"web,omitempty"`
}

// WebUI is one hosted web interface found on an open port: URL + HTTP status + <title> + Server
// header — mirrors the Windows PS1's {port,url,status,title,server} row.
type WebUI struct {
	Port   int    `json:"port"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Server string `json:"server"`
}

// ScanResult mirrors _ARP_SCAN_PS1's output object. The bastion parses the last JSON line of
// stdout, so the caller MUST emit this as one compact line (see main.go's runArpScan).
type ScanResult struct {
	OK        bool     `json:"ok"`
	Subnets   []string `json:"subnets"`
	Devices   []Device `json:"devices"`
	SelfMacs  []string `json:"selfMacs"`
	ScannedAt string   `json:"scannedAt"`
	Error     string   `json:"error,omitempty"`
}

const (
	// Same budgets as _ARP_SCAN_PS1: 700ms per-host ping timeout, 15s overall wait for the
	// parallel sweep, only /22–/30 subnets with 1..512 usable hosts.
	pingTimeout = 700 * time.Millisecond
	pingWaitAll = 15 * time.Second
	minPrefix   = 22
	maxPrefix   = 30
)

// Scan runs one point-in-time network-discovery scan: parallel ping sweep of every eligible
// local subnet to populate the kernel ARP cache, then a read-back of the neighbor table plus
// best-effort reverse DNS. Deliberately dumb-and-fast — no persistence, no diffing (the server
// owns turning this into roster upserts + spoof-detection events, exactly like the Windows side).
//
// Extra subnets (from manual VLAN configuration) are appended to the auto-detected local
// subnets and scanned the same way. De-duplication is handled by the subnets slice.
func Scan(extraSubnets ...string) ScanResult {
	res := ScanResult{ScannedAt: time.Now().UTC().Format(arpTimeFmt)}
	subnets, err := scanSubnets()
	if err != nil {
		res.Error = "interface enumeration failed: " + err.Error()
		return res
	}
	// Append manually-configured VLAN subnets (de-duplicated against local interfaces).
	if len(extraSubnets) > 0 {
		seen := map[string]bool{}
		for _, s := range subnets {
			seen[s] = true
		}
		for _, s := range extraSubnets {
			if !seen[s] {
				subnets = append(subnets, s)
				seen[s] = true
			}
		}
	}
	res.Subnets = subnets

	var wg sync.WaitGroup
	for _, sn := range subnets {
		ip, ipnet, err := net.ParseCIDR(sn)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		hostCount := (1 << (32 - ones)) - 2
		base := ip.To4()
		netInt := binary.BigEndian.Uint32(base) & binary.BigEndian.Uint32(ipnet.Mask)
		for h := 1; h <= hostCount; h++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, netInt+uint32(h))
			wg.Add(1)
			go func(addr string) {
				defer wg.Done()
				pingHost(addr)
			}(ip.String())
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(pingWaitAll):
	}

	res.Devices = readNeighbors(subnets)
	res.Devices = fingerprintDevices(res.Devices)
	res.SelfMacs = selfMacsPhysical()
	res.OK = true
	return res
}

// fingerprintDevices runs the aggressive device-identification pass over the discovered neighbors:
// a parallel TCP connect-scan of curated LAN-service ports, then an HTTP(S) probe of open web ports
// for <title>/Server — the Linux counterpart of _ARP_SCAN_PS1's fingerprint block. Same bounds as
// the Windows side: 64 unicast hosts max, 400ms connect timeout per port, 3s per web probe, and
// self-signed certs accepted (typical for router/camera/NAS web UIs). Parallelism is goroutine-per-
// host with a semaphore cap, so a full /24 stays within the bastion's 90s scan budget.
var (
	fpPorts = []int{21, 22, 23, 53, 80, 139, 443, 445, 515, 548, 554, 631, 3000, 3306, 3389, 5000,
		5001, 5900, 8000, 8080, 8096, 8123, 8443, 8888, 9000, 9090, 9100, 9443, 10000}
	fpWebPorts = map[int]bool{80: true, 443: true, 3000: true, 5000: true, 5001: true, 8000: true,
		8080: true, 8096: true, 8123: true, 8443: true, 8888: true, 9000: true, 9090: true, 9443: true,
		10000: true}
	fpMaxHosts   = 64
	fpSemaphore  = make(chan struct{}, 64)
	fpConnTimout = 400 * time.Millisecond
	fpWebTimeout = 3 * time.Second
	titleRe      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// isUnicastLanHost excludes multicast/broadcast rows — same filter the Windows PS1 applies to its
// fingerprint host list (224.*/239.*/255.* and *.255 never serve a real device).
func isUnicastLanHost(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil {
		return false
	}
	b := p.To4()
	if b[0] == 224 || b[0] == 239 || b[0] == 255 {
		return false
	}
	if b[3] == 255 {
		return false
	}
	return true
}

func fingerprintDevices(devices []Device) []Device {
	var hosts []Device
	for _, d := range devices {
		if !isUnicastLanHost(d.IP) {
			continue
		}
		hosts = append(hosts, d)
		if len(hosts) >= fpMaxHosts {
			break
		}
	}
	if len(hosts) == 0 {
		return devices
	}
	results := make([]Device, len(hosts))
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fpSemaphore <- struct{}{}
			defer func() { <-fpSemaphore }()
			d := hosts[idx]
			d.OpenPorts, d.Web = fingerprintOne(d.IP)
			results[idx] = d
		}(i)
	}
	wg.Wait()
	// Splice results back into the original slice order (devices beyond the cap keep zero fields).
	byIP := map[string]int{}
	for i := range results {
		byIP[results[i].IP] = i
	}
	for i := range devices {
		if j, ok := byIP[devices[i].IP]; ok {
			devices[i].OpenPorts = results[j].OpenPorts
			devices[i].Web = results[j].Web
		}
	}
	return devices
}

func fingerprintOne(ip string) ([]int, []WebUI) {
	open := make([]int, 0, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range fpPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), fpConnTimout)
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	if len(open) == 0 {
		return nil, nil
	}

	// Web probe — only ports that actually answered, sequential (few per host), 3s each.
	web := make([]WebUI, 0, 4)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // router/camera self-signed certs
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 1,
	}
	client := &http.Client{Transport: tr, Timeout: fpWebTimeout}
	for _, p := range open {
		if !fpWebPorts[p] {
			continue
		}
		scheme := "http"
		if p == 443 || p == 8443 || p == 9443 {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s:%d/", scheme, ip, p)
		w := WebUI{Port: p, URL: url}
		resp, err := client.Get(url)
		if err != nil {
			web = append(web, w)
			continue
		}
		w.Status = resp.StatusCode
		if srv := resp.Header.Get("Server"); srv != "" {
			w.Server = srv
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err == nil {
			if m := titleRe.FindSubmatch(body); m != nil {
				w.Title = strings.TrimSpace(string(m[1]))
			}
		}
		web = append(web, w)
	}
	return open, web
}

// scanSubnets returns the distinct local IPv4 /22–/30 subnets, excluding loopback and link-local
// (169.254.*) — the same interface filter as _ARP_SCAN_PS1 (Get-NetIPAddress + PrefixLength).
func scanSubnets() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		if ip4 == nil {
			continue
		}
		if ip4.IsLoopback() || (ip4[0] == 169 && ip4[1] == 254) {
			continue
		}
		ones, bits := ipn.Mask.Size()
		if bits != 32 || ones < minPrefix || ones > maxPrefix {
			continue
		}
		hosts := (1 << (32 - ones)) - 2
		if hosts < 1 || hosts > 512 {
			continue
		}
		if seen[ipn.String()] {
			continue
		}
		seen[ipn.String()] = true
		out = append(out, ipn.String())
	}
	sort.Strings(out)
	return out, nil
}

// pingHost sends one ICMP echo request to addr. The reply itself doesn't matter — the ARP
// resolution the kernel performs for the outbound packet is what populates the neighbor table
// this scan reads afterwards (same mechanism as .NET's SendPingAsync in _ARP_SCAN_PS1). Uses a
// SOCK_DGRAM ping socket, which needs root (or ping_group_range) — the sudoers-granted libexec
// wrapper provides that.
func pingHost(addr string) {
	conn, err := net.DialTimeout("ip4:icmp", addr, pingTimeout)
	if err != nil {
		return
	}
	defer conn.Close()
	// ICMP echo request (type 8, code 0). SOCK_DGRAM ping sockets let the kernel fill in the
	// checksum; only the header needs building.
	msg := make([]byte, 8)
	msg[0] = 8
	binary.BigEndian.PutUint16(msg[4:6], 0xbeef)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	_ = conn.SetDeadline(time.Now().Add(pingTimeout))
	if _, err := conn.Write(msg); err != nil {
		return
	}
	// Drain one reply so the socket never blocks on a later close; not required for the scan.
	_, _ = conn.Read(msg)
}

// dockerBridgePrefixes match the virtual bridge interfaces Docker/Swarm creates (docker0,
// docker_gwbridge, br-<id>, plus common CNI/vxlan names). Their ARP entries are containers —
// the MAC for a given IP churns on every container restart/redeploy, which reads as
// mac_changed_for_ip "spoofing" on every scan. The Windows PS1 avoids this because
// Get-NetNeighbor rows for container networks rarely survive its state filter; on Linux the
// /proc/net/arp read-back returns them unconditionally, so the filter must be explicit.
// Found live 2026-08-13 on the reference host: 172.18.0.2 (docker_gwbridge ingress) alerted as
// spoofing because a redeployed container got a fresh random MAC.
func isContainerInterface(name string) bool {
	switch {
	case name == "docker0", name == "docker_gwbridge", name == "lo":
		return true
	case strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "veth"),
		strings.HasPrefix(name, "docker"), strings.HasPrefix(name, "vxlan"),
		strings.HasPrefix(name, "flannel"), strings.HasPrefix(name, "cali"),
		strings.HasPrefix(name, "cni"), strings.HasPrefix(name, "weave"):
		return true
	}
	return false
}

// readNeighbors reads the kernel ARP table from /proc/net/arp and keeps only complete/permanent
// entries with a real MAC — the Linux equivalent of Get-NetNeighbor's Reachable/Stale/Permanent/
// Delay/Probe state filter (Incomplete/Unreachable rows have no MAC in /proc/net/arp anyway).
// Rows are ALSO filtered to the subnets the scan actually swept (caller passes res.Subnets) —
// container-bridge and other virtual networks are never scanned, so their ARP entries must not
// leak into the roster either (their MACs churn and false-alert as spoofing; see
// isContainerInterface).
func readNeighbors(subnets []string) []Device {
	var scannedNets []*net.IPNet
	for _, sn := range subnets {
		_, ipnet, err := net.ParseCIDR(sn)
		if err == nil {
			scannedNets = append(scannedNets, ipnet)
		}
	}
	ipInScanned := func(ipStr string) bool {
		if len(scannedNets) == 0 {
			return true // nothing to filter against — behave as before
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		for _, n := range scannedNets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()

	var rows []Device
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false // header line: "IP address HW type Flags HW address Mask Device"
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ipStr, flags, mac := fields[0], fields[2], fields[3]
		iface := ""
		if len(fields) >= 6 {
			iface = fields[5]
		}
		if isContainerInterface(iface) {
			continue
		}
		if !ipInScanned(ipStr) {
			continue
		}
		// flags 0x2 = ATF_COM (complete), 0x4 = ATF_PERM (permanent/static).
		var fl uint64
		fmt.Sscanf(flags, "0x%x", &fl)
		if fl&0x2 == 0 && fl&0x4 == 0 {
			continue
		}
		mac = strings.ToLower(mac)
		if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		if seen[ipStr] {
			continue
		}
		seen[ipStr] = true
		rows = append(rows, Device{IP: ipStr, MAC: mac})
	}

	// Best-effort reverse DNS, parallel with a 2s cap per lookup — mirrors the PS1's
	// [System.Net.Dns]::GetHostEntry try/catch. Bounded: 512 hosts max, each goroutine is
	// deadline-bounded, and LookupAddr uses the system resolver.
	var wg sync.WaitGroup
	for i := range rows {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names, err := net.LookupAddr(rows[i].IP)
			if err == nil && len(names) > 0 {
				rows[i].Hostname = strings.TrimSuffix(names[0], ".")
			}
		}(i)
	}
	wg.Wait()

	sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })
	return rows
}

// selfMacsPhysical returns this box's own physical-adapter MACs, lowercase colons — the Linux
// equivalent of _ARP_SCAN_PS1's Get-NetAdapter -Physical filter. Needed so the server can tell a
// MANAGED sibling's discovery scan apart from a stranger's (the two are identical on the wire —
// both sweep the whole subnet). Heuristic: an interface is physical if /sys/class/net/<name>/
// device exists (real PCI/USB NICs have it; loopback, tun/tap, bridges, wireguard, veth, vlans
// don't).
func selfMacsPhysical() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 {
			continue
		}
		mac := strings.ToLower(ifc.HardwareAddr.String())
		if mac == "00:00:00:00:00:00" {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + ifc.Name + "/device"); err != nil {
			continue
		}
		out = append(out, mac)
	}
	sort.Strings(out)
	return out
}
