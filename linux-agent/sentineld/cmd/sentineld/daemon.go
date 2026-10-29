package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentineld/internal/config"
	"sentineld/internal/controlchannel"
	"sentineld/internal/enroll"
	"sentineld/internal/hop1"
	"sentineld/internal/xraytransport"
	"sentineld/internal/zkwrap"
)

// hop2LocalTarget MUST match sentinel-hop2.socket's ListenStream (systemd/sentinel-hop2.socket) —
// this is where Hop-1's remote-forward delivers a connection locally, i.e. Linux's counterpart to
// the Windows agent forwarding straight to 127.0.0.1:22. Deliberately NOT port 22: Linux uses a
// separate, dedicated Hop-2 sshd (design plan §3), never the box's own real admin sshd.
const hop2LocalTarget = "127.0.0.1:2222"

// hop1BastionUser is the bastion account Hop-1 authenticates as. The original choice of "sentinel-jump"
// here was wrong — that account is bastion-web.py's grant_jump_access() ProxyJump account for a
// HUMAN admin's manual `ssh -J sentinel-jump@... sentinel-support@127.0.0.1:<port>` (see the "Remote agent
// update" runbook's example), gated by a completely SEPARATE authorized_keys file
// (/data/sentinel-jump-authorized_keys, populated by grant_jump_access() with a browser-generated
// manual-access key — nothing to do with a device's own identity). The device's OWN reverse
// tunnel — what this daemon needs — authenticates as "tunnel" instead, gated by
// /data/authorized_keys, which is exactly what _create_remote_assist_session() writes the
// device's Hop-1 public key into. Confirmed by reading the Windows client's actual ssh
// invocation (TunnelRunner.cs: `args.Append($"tunnel@{_cfg.BastionHost}")`) — "sentinel-jump" was never
// "the same value the Windows client uses" as originally claimed here. Found live 2026-07-29:
// this bug meant hop1.Open() ALWAYS failed with "ssh: unable to authenticate ... no supported
// methods remain" — the device's key was never even in sentinel-jump's authorized_keys file (a stale,
// unrelated browser key from a prior manual "Regen Private Key" click was) — see docs/ARCHITECTURE.md.
const hop1BastionUser = "tunnel"

// remoteAssistProvisionEvent/hop2SessionOpenEvent/hop2SessionCloseEvent: control-channel events
// this Linux daemon needs that have no Windows-client counterpart (Windows never needed a
// provisioning push shaped like this, and never had a dormant Hop-2 to arm/disarm). Server-side
// implementation confirmed live 2026-07-29 (server.js's emitRemoteAssistProvision) — matches the
// payload shapes documented on each handler below.
const (
	remoteAssistProvisionEvent = "remote_assist_provision" // {egressUuid, nodeIndex, forwardPort}
	hop2SessionOpenEvent       = "hop2_session_open"       // {pubkey} — no TTL since 2026-08-18 (was {pubkey, ttlSeconds})
	hop2SessionCloseEvent      = "hop2_session_close"      // {}
)

type provisionPayload struct {
	EgressUUID  string `json:"egressUuid"`
	NodeIndex   int    `json:"nodeIndex"`
	ForwardPort int    `json:"forwardPort"`

	// AdminPubKey is the bastion's STANDING Hop-2 trust key (mirrors Windows' ADMIN_SUPPORT_KEY,
	// bastion-web.py's hop2_run() family) — added after reading the real bastion-web.py code
	// revealed the original design only covered the interactive "human clicked Connect" case.
	// Persisted to disk (see armHop2AdminKey below) so hop2-authkeys.sh can trust it
	// unconditionally, no TTL, for automated one-shot bastion actions (arbitrary exec, fleet
	// fan-out, IT Audit Mode "Collect all") with no human in the loop. Sent alongside the Hop-1
	// provisioning data since both arrive at "this device now has a bastion" time; server-side
	// implementers could equally split this into its own event without changing this daemon's
	// behavior beyond one extra `cc.On(...)` registration.
	AdminPubKey string `json:"adminPubKey"`
}

type hop2OpenPayload struct {
	PubKey string `json:"pubkey"`
	// TTLSeconds was removed 2026-08-18 (the armed session key has no TTL — hop2-common.sh
	// trusts it while the arm file exists). Keep the JSON unmarshal tolerant of a legacy server
	// still sending the field: unknown fields are ignored by encoding/json, so nothing to do.
}

// registerAck is the server's response to "register" (server.js ~L14461's registeredPayload).
// ZkPubKey is present (base64 DER SPKI) only when the device is owned by an account_type='public'
// user — i.e. every account-linked Linux Remote Assist device, since config.AdminAgent is always
// false for this build (see config.go) — and empty otherwise (admin-fleet devices, which this
// build never produces, but the field is still optional/absent-safe either way).
type registerAck struct {
	ZkPubKey string `json:"zkPubKey"`
}

func runDaemon() error {
	state, err := enroll.LoadEnrollmentState()
	if err != nil {
		return fmt.Errorf("no enrollment found — run `sentineld enroll` first: %w", err)
	}
	identity, err := enroll.LoadOrCreateIdentity()
	if err != nil {
		return fmt.Errorf("load device identity: %w", err)
	}

	xrayDir := filepath.Join(config.StateDir, "xray")
	mgr, err := xraytransport.NewManager(xrayDir)
	if err != nil {
		return fmt.Errorf("prepare xray: %w", err)
	}

	// Node 0 by default: the server's provision contract targets node 0 (every REALITY node
	// routes the remoteassist UUID straight to the same bastion — see emitRemoteAssistProvision in
	// server.js). PickNode returns the node's IPv6 literal when this host has a v6 route to it and
	// its IPv4 literal otherwise; runControlLoop walks the rest of the per-node address ladder
	// (same-node v4, then the next node's v6, …) when connects keep failing.
	nodeIdx := 0
	node, sni, err := xraytransport.PickNode(nodeIdx)
	if err != nil {
		return err
	}
	controlPort, err := xraytransport.FreeLocalPort()
	if err != nil {
		return fmt.Errorf("allocate control port: %w", err)
	}
	localPort, err := xraytransport.FreeLocalPort()
	if err != nil {
		return fmt.Errorf("allocate hop-1 local port: %w", err)
	}

	bootstrapOpt := xraytransport.BuildOptions{Node: node, SNI: sni, ControlPort: controlPort, LocalPort: localPort}
	bootstrapCfg := xraytransport.BuildBootstrapConfig(bootstrapOpt)
	if err := mgr.ValidateConfig(bootstrapCfg); err != nil {
		return fmt.Errorf("bootstrap xray config invalid: %w", err)
	}
	if err := mgr.Start(xrayDir, bootstrapCfg); err != nil {
		return fmt.Errorf("start xray (bootstrap): %w", err)
	}
	if !waitPort(controlPort, 10*time.Second) {
		return fmt.Errorf("xray never bound the control-channel local port %d", controlPort)
	}

	controlURL := fmt.Sprintf("http://127.0.0.1:%d", controlPort)
	extraHeaders := map[string]string{"X-Via-Reality": node}
	return runControlLoop(controlURL, extraHeaders, state, identity, mgr, xrayDir, config.RunDir, config.StateDir, localPort, controlPort, nodeIdx, node)
}

// runControlLoop is runDaemon's core state machine, split out so it can be exercised in tests
// against a local fake control-channel server (bypassing the real xray/REALITY dial, which was
// already proven correct in isolation — see internal/xraytransport's own tests) instead of
// needing a live production bastion. runDir parameterizes where the Hop-2 arm file is written
// and stateDir where the standing admin pubkey is written (production: config.RunDir/
// config.StateDir, which need root/a dedicated service account — tests use temp dirs instead).
func runControlLoop(controlURL string, extraHeaders map[string]string, state *enroll.EnrollmentState, identity *enroll.Identity, mgr *xraytransport.Manager, xrayDir, runDir, stateDir string, localPort, controlPort, nodeIdx int, curAddr string) error {
	registeredCh := make(chan registerAck, 1)
	provisionCh := make(chan provisionPayload, 1)
	hop2OpenCh := make(chan hop2OpenPayload, 8)
	hop2CloseCh := make(chan struct{}, 8)
	zkPubKeyUpdateCh := make(chan *string, 4)

	// currentZkPubKey is the account owner's EC P-256 public key (base64 DER SPKI) — present only
	// for account-linked devices owned by a "public" account (see server.js's requireRemoteAssistDevice
	// / resolveDeviceOwnerFlags: ownerIsPublicUser). Mirrors Windows' AccountLinkedSession.ZkPubKey.
	// Mutated ONLY from this goroutine (connectAndRegister runs synchronously here; the zk_pub_key
	// live-update case below hands off through zkPubKeyUpdateCh) — never touched from a cc.On(...)
	// handler callback directly, which runs on the controlchannel's own readLoop goroutine.
	var currentZkPubKey string

	// ── REALITY address ladder (IPv6-first, mirroring the Android agent's realityAddrIdx) ──────
	// xraytransport.NodeCandidates(nodeIdx) is [v6, v4] when this host has a v6 route to the node,
	// else [v4]. curAddr is the address the CURRENT xray config dials (the bootstrap config was
	// already started by runDaemon with it); applyTransport (re)starts xray against the ladder's
	// current candidate; advanceLadder moves same-node v6 → same-node v4 → next node v6 → …
	// (wrapping) once connects keep failing. The failure threshold matters: a single transient
	// blip must NOT restart xray, because that would kill a healthy Hop-1 SSH tunnel and
	// re-create the crash-loop the reconnect logic below exists to avoid (memory
	// linux-remote-assist-crash-loop). Android gates its v6 dial on a live ::/0 default; the
	// route probe inside NodeCandidates plays that role here, and the ladder is the fallback for a
	// route that exists but cannot actually carry traffic (a stale default, a broken upstream).
	const ladderAdvanceAfterFailures = 3
	addrIdx := 0
	for i, c := range xraytransport.NodeCandidates(nodeIdx) {
		if c == curAddr {
			addrIdx = i
			break
		}
	}
	consecutiveFailures := 0

	// applyTransport (re)starts xray against the ladder's current candidate: the bootstrap config
	// when no egress UUID has been provisioned yet (control channel only), the full Hop-1 config
	// once it has. Updates curAddr + the X-Via-Reality header so the server/dashboard report the
	// address actually dialed (v6 literals get the IPv6 badge server-side).
	applyTransport := func(egressUUID string) error {
		node, sni, err := xraytransport.PickNodeCandidate(nodeIdx, addrIdx)
		if err != nil {
			return err
		}
		var cfg []byte
		if egressUUID == "" {
			cfg = xraytransport.BuildBootstrapConfig(xraytransport.BuildOptions{
				Node: node, SNI: sni, ControlPort: controlPort, LocalPort: localPort,
			})
		} else {
			cfg = xraytransport.BuildConfig(xraytransport.BuildOptions{
				Node: node, SNI: sni, LocalPort: localPort, ControlPort: controlPort,
				RemoteAssistEgressUUID: egressUUID,
			})
		}
		if err := mgr.ValidateConfig(cfg); err != nil {
			return fmt.Errorf("xray config invalid for %s: %w", node, err)
		}
		if err := mgr.Start(xrayDir, cfg); err != nil {
			return fmt.Errorf("start xray against %s: %w", node, err)
		}
		if !waitPort(controlPort, 10*time.Second) {
			return fmt.Errorf("xray never bound the control-channel local port %d", controlPort)
		}
		curAddr = node
		if extraHeaders != nil {
			extraHeaders["X-Via-Reality"] = node
		}
		log.Printf("transport: dialing REALITY node %d via %s", nodeIdx, node)
		return nil
	}

	advanceLadder := func() {
		addrIdx++
		if addrIdx >= len(xraytransport.NodeCandidates(nodeIdx)) {
			nodeIdx = (nodeIdx + 1) % len(xraytransport.RealityNodes)
			addrIdx = 0
		}
	}

	// connectAndRegister dials a fresh control-channel client, wires the five event handlers onto
	// it, emits "register", and blocks for the server's ack. Called once at startup and again on
	// every reconnect (see the case <-cc.Done() branch below) — controlchannel.Client has no
	// reconnect of its own (see its doc comment) and On() handlers don't carry over to a new
	// Client, so both a fresh dial and re-registration are required each time.
	connectAndRegister := func() (*controlchannel.Client, error) {
		if extraHeaders != nil {
			// Report the address the CURRENT xray config actually dials — the ladder may have
			// moved it, and the server derives dpi.realityV6 from this header (a value containing
			// ':' ⇒ IPv6 badge + the v6 literal on the device card).
			extraHeaders["X-Via-Reality"] = curAddr
		}
		// ⚠️ Build a FRESH auth payload on EVERY connect/reconnect (never cache one): signed auth
		// carries a timestamp the server rejects if it is >60s old (verifyDeviceSignature), and a
		// pre-built map's timestamp goes stale the moment the control channel drops — every
		// reconnect then loops on "Invalid signature" forever (found live 2026-08-18: a booted
		// ISO device enrolled fine, worked ~3min, then flapped permanently; crypto/key/clock were
		// all correct — a fresh manual signature over deviceId:now verified true against the
		// server's stored key). Building per-connect also naturally drops the spent ticket: once
		// state.Ticket is cleared below, subsequent connects serialize the signed shape.
		authPayload, err := buildAuthPayload(state, identity)
		if err != nil {
			return nil, fmt.Errorf("build control-channel auth payload: %w", err)
		}
		cc, err := controlchannel.Connect(controlURL, authPayload, extraHeaders)
		if err != nil {
			return nil, fmt.Errorf("connect control channel: %w", err)
		}
		cc.On("registered", func(raw json.RawMessage) {
			log.Printf("control channel: registered (%s)", raw)
			var ack registerAck
			_ = json.Unmarshal(raw, &ack) // best-effort — a parse miss just means no zkPubKey yet
			select {
			case registeredCh <- ack:
			default:
			}
		})
		cc.On(remoteAssistProvisionEvent, func(raw json.RawMessage) {
			var p provisionPayload
			if err := json.Unmarshal(raw, &p); err != nil {
				log.Printf("%s: unparseable payload: %v", remoteAssistProvisionEvent, err)
				return
			}
			select {
			case provisionCh <- p:
			default:
			}
		})
		cc.On(hop2SessionOpenEvent, func(raw json.RawMessage) {
			var p hop2OpenPayload
			if err := json.Unmarshal(raw, &p); err != nil {
				log.Printf("%s: unparseable payload: %v", hop2SessionOpenEvent, err)
				return
			}
			hop2OpenCh <- p
		})
		cc.On(hop2SessionCloseEvent, func(json.RawMessage) {
			hop2CloseCh <- struct{}{}
		})
		// Live reassignment when the owning account changes/is removed while already connected
		// (server.js's updateDeviceOwner()) — {zkPubKey:"<b64>"} to set, {zkPubKey:null} to clear.
		// Distinct from the "registered" ack above, which only carries the CURRENT key at connect
		// time; this is the only path for a change mid-session.
		cc.On("zk_pub_key", func(raw json.RawMessage) {
			var p struct {
				ZkPubKey *string `json:"zkPubKey"`
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				log.Printf("zk_pub_key: unparseable payload: %v", err)
				return
			}
			select {
			case zkPubKeyUpdateCh <- p.ZkPubKey:
			default:
			}
		})

		if err := cc.Emit("register", map[string]any{
			"platform":      "linux",
			"agentKind":     "remote_assist",
			"deviceId":      state.DeviceID,
			"name":          hostnameOrUnknown(),
			"appVersion":    version,
			"hop1PublicKey": identity.PublicKeyOpenSSH,
		}); err != nil {
			cc.Close()
			return nil, fmt.Errorf("emit register: %w", err)
		}

		select {
		case ack := <-registeredCh:
			currentZkPubKey = ack.ZkPubKey
		case <-time.After(15 * time.Second):
			cc.Close()
			return nil, fmt.Errorf("server never acknowledged registration")
		}
		// First successful registration = the enrollment ticket (if any) was consumed server-side.
		// Clear it from the persisted state so every subsequent (re)connect uses signed auth —
		// mirroring Windows' AccountLinkedSession.MarkEnrolled()/nulling _pendingEnrollmentTicket
		// on OnConnected. A spent ticket must not ride every future handshake (multi-use quota
		// would be re-burned on any re-consume path, and the signed shape is the steady-state one).
		if state.Ticket != "" {
			if err := enroll.ClearTicketIn(stateDir); err != nil {
				log.Printf("warning: could not clear consumed enrollment ticket from disk: %v", err)
			}
			state.Ticket = ""
			// The NEXT connectAndRegister (re)builds the payload fresh, now without the spent
			// ticket — signed auth with a current timestamp. No cached map to invalidate.
		}
		// Send one device_status heartbeat immediately so the dashboard card's Network/Uptime
		// fields populate right away instead of waiting for the first statusTicker tick below.
		emitDeviceStatus(cc, currentZkPubKey)
		return cc, nil
	}

	cc, err := connectAndRegister()
	// Startup ladder: the bootstrap xray dials the FIRST candidate (the node's IPv6 literal when
	// this host has a v6 route, its IPv4 literal otherwise). If the control channel can't come up
	// over it, walk the remaining candidates in-process — same-node IPv4 first — instead of
	// exiting and letting systemd retry the identical address 10s later.
	for tries := 0; err != nil && tries < len(xraytransport.RealityNodes)*2; tries++ {
		log.Printf("initial connect failed (%v) — trying the next REALITY address", err)
		advanceLadder()
		if aerr := applyTransport(""); aerr != nil {
			log.Printf("transport: %v", aerr)
			continue
		}
		cc, err = connectAndRegister()
	}
	if err != nil {
		return err
	}
	defer func() { cc.Close() }()

	var tunnel *hop1.Tunnel
	defer func() {
		if tunnel != nil {
			tunnel.Close()
		}
	}()

	// appliedEgressUUID/appliedForwardPort/tunnelHealthy track the full xray config actually
	// applied via mgr.Start() — a repeat remote_assist_provision push with IDENTICAL parameters is
	// a no-op (skips the restart) instead of tearing down an already-healthy Hop-1 tunnel (and its
	// own control channel — see the crash-loop note on mgr.Start() below) for nothing. The server
	// keeps re-pushing this event on every register/reconnect until it observes the bastion
	// session as connected (server.js's auto-provision cooldown logic) — without this guard, a
	// device whose first hop1.Open() already succeeded but hasn't yet been observed as connected
	// by the bastion (a several-second window) gets re-provisioned, which used to restart xray and
	// re-kill its own control channel indefinitely. Found + fixed live 2026-07-29 — see docs/ARCHITECTURE.md.
	var appliedEgressUUID string
	var appliedForwardPort int
	tunnelHealthy := false

	// tunnelDiedCh signals the main loop when the currently-open Hop-1 SSH tunnel's Serve loop
	// exits on its own (network blip, bastion-side idle timeout, REALITY hiccup — anything short
	// of us tearing it down ourselves for a genuine reprovision). Found live 2026-07-29: without
	// this, tunnelHealthy stayed permanently (and wrongly) true after such a death, so the
	// idempotent-reprovision check above would keep skipping every subsequent
	// remote_assist_provision push forever — "already applied — skipping restart" — leaving the
	// tunnel down until the whole daemon process happened to restart. openHop1Tunnel/serveTunnel
	// below are shared by both the initial provision case and this self-heal path.
	tunnelDiedCh := make(chan struct{}, 1)

	serveTunnel := func(t *hop1.Tunnel) {
		go func() {
			err := t.Serve(hop2LocalTarget)
			if err != nil {
				log.Printf("hop-1 tunnel serve exited: %v", err)
			}
			select {
			case tunnelDiedCh <- struct{}{}:
			default:
			}
		}()
	}

	// openHop1Tunnel dials the Hop-1 reverse tunnel through the ALREADY-RUNNING xray local proxy
	// at forwardPort (no xray restart — xray itself doesn't need to change to simply re-dial the
	// same tunnel) and starts serving it. Returns an error without mutating any of the outer
	// tunnel/tunnelHealthy state on failure, so callers can retry later without needing to
	// unwind anything.
	openHop1Tunnel := func(forwardPort int) (*hop1.Tunnel, error) {
		signer, err := hop1.LoadSigner(identity.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load hop-1 signer: %w", err)
		}
		pinnedKey, err := hop1.ParsePinnedHostKey(xraytransport.RemoteAssistBastionKnownHostsLine)
		if err != nil {
			return nil, fmt.Errorf("parse pinned bastion host key: %w", err)
		}
		t, err := hop1.Open(
			fmt.Sprintf("127.0.0.1:%d", localPort),
			hop1BastionUser,
			signer,
			hop1.PinnedHostKeyCallback(pinnedKey),
			fmt.Sprintf("127.0.0.1:%d", forwardPort),
		)
		if err != nil {
			return nil, fmt.Errorf("open hop-1 tunnel: %w", err)
		}
		return t, nil
	}

	// statusTicker drives the periodic device_status heartbeat (uptime/network) the dashboard
	// card reads — see deviceStatusPayload's doc comment. Reads the CURRENT `cc` at each tick
	// (not a captured one), so it keeps working across reconnects. It ALSO doubles as the
	// tunnel-health retry cadence (see case <-statusTicker.C below) — a failed immediate
	// re-establish attempt (case <-tunnelDiedCh) gets retried again here every 60s until it
	// succeeds, rather than needing its own separate backoff timer.
	statusTicker := time.NewTicker(60 * time.Second)
	defer statusTicker.Stop()

	reconnectBackoff := time.Second
	for {
		select {
		case <-statusTicker.C:
			emitDeviceStatus(cc, currentZkPubKey)
			if !tunnelHealthy && appliedForwardPort != 0 {
				log.Print("hop-1 tunnel unhealthy — retrying re-establish")
				if t, err := openHop1Tunnel(appliedForwardPort); err != nil {
					log.Printf("hop-1 tunnel retry failed: %v", err)
				} else {
					tunnel = t
					tunnelHealthy = true
					serveTunnel(t)
					log.Print("hop-1 tunnel re-established")
				}
			}

		case <-tunnelDiedCh:
			// The Serve loop for the CURRENT tunnel exited on its own — mark unhealthy so the
			// idempotent-reprovision check above stops treating this as still-good, and try to
			// recover immediately (the statusTicker case above is the fallback if this attempt
			// fails too).
			tunnelHealthy = false
			tunnel = nil
			if appliedForwardPort != 0 {
				log.Print("hop-1 tunnel died — attempting immediate re-establish")
				if t, err := openHop1Tunnel(appliedForwardPort); err != nil {
					log.Printf("hop-1 tunnel immediate re-establish failed (will retry on next status tick): %v", err)
				} else {
					tunnel = t
					tunnelHealthy = true
					serveTunnel(t)
					log.Print("hop-1 tunnel re-established")
				}
			}

		case p := <-provisionCh:
			if tunnelHealthy && p.EgressUUID == appliedEgressUUID && p.ForwardPort == appliedForwardPort {
				// Nothing actually changed since the last successful apply — refresh the standing
				// admin key (cheap, idempotent) but skip the disruptive xray restart entirely.
				if p.AdminPubKey != "" {
					if err := writeAdminPubKey(stateDir, p.AdminPubKey); err != nil {
						log.Printf("provision: persist standing admin pubkey: %v", err)
					}
				}
				log.Printf("received %s: already applied (node=%d forwardPort=%d) — skipping restart", remoteAssistProvisionEvent, p.NodeIndex, p.ForwardPort)
				continue
			}
			log.Printf("received %s: node=%d forwardPort=%d", remoteAssistProvisionEvent, p.NodeIndex, p.ForwardPort)
			tunnelHealthy = false
			if tunnel != nil {
				tunnel.Close()
				tunnel = nil
			}

			if p.AdminPubKey != "" {
				if err := writeAdminPubKey(stateDir, p.AdminPubKey); err != nil {
					log.Printf("provision: persist standing admin pubkey: %v", err)
					// Not fatal to the rest of provisioning — Hop-1 can still come up; only the
					// bastion's automated one-shot exec path (forensics/IT-audit/fleet actions)
					// would be degraded until this succeeds on a later provision push.
				}
			}

			// Adopt the server's node if it differs from the ladder's current node (the provision
			// contract always sends 0 today — see server.js's emitRemoteAssistProvision); keep the
			// ladder's current address otherwise, so a box that came up on same-node IPv4 after a
			// v6 failure stays on the address that actually works instead of flapping back to v6.
			if p.NodeIndex != nodeIdx {
				nodeIdx = p.NodeIndex
				addrIdx = 0
			}
			// applyTransport → mgr.Start() always kills the previous xray subprocess before
			// launching the new one (see Manager.Start's doc comment) — since the control channel
			// is ALSO tunneled through this same xray process (both ride the bootstrap/full
			// config's shared controlPort inbound), this restart inevitably kills cc's TCP
			// connection too. That's expected and handled: the reconnect loop below
			// (case <-cc.Done()) picks it back up once xray finishes rebinding controlPort,
			// without crashing the whole process.
			if err := applyTransport(p.EgressUUID); err != nil {
				log.Printf("provision: %v", err)
				continue
			}
			if !waitPort(localPort, 10*time.Second) {
				log.Printf("provision: xray never bound the hop-1 local port %d after restart", localPort)
				continue
			}

			t, err := openHop1Tunnel(p.ForwardPort)
			if err != nil {
				log.Printf("provision: %v", err)
				continue
			}
			tunnel = t
			appliedEgressUUID = p.EgressUUID
			appliedForwardPort = p.ForwardPort
			tunnelHealthy = true
			serveTunnel(t)
			log.Printf("hop-1 tunnel established, forwarding %s -> %s", fmt.Sprintf("bastion:%d", p.ForwardPort), hop2LocalTarget)

		case p := <-hop2OpenCh:
			if err := armHop2(runDir, p); err != nil {
				log.Printf("arm hop-2: %v", err)
			} else {
				log.Print("hop-2 armed (no TTL — trusted until disarmed/overwritten/reboot)")
			}

		case <-hop2CloseCh:
			if err := disarmHop2(runDir); err != nil {
				log.Printf("disarm hop-2: %v", err)
			} else {
				log.Print("hop-2 disarmed")
			}

		case p := <-zkPubKeyUpdateCh:
			if p != nil {
				currentZkPubKey = *p
				log.Print("zk_pub_key: owner key updated")
			} else {
				currentZkPubKey = ""
				log.Print("zk_pub_key: owner key cleared")
			}

		case <-cc.Done():
			// A disconnect here is EXPECTED right after we ourselves restart xray to apply a
			// Hop-1 provision (see mgr.Start's note above) — reconnect instead of crashing the
			// whole process. Previously this returned a fatal error ("reconnect/backoff not yet
			// implemented in this build"), which meant every single provision event killed the
			// daemon and left recovery to systemd's 10s RestartSec — re-running enrollment and
			// xray bootstrap from scratch each time and never giving Hop-1 a stable window to
			// come up (an infinite crash loop, found live 2026-07-29 — see docs/ARCHITECTURE.md). This does NOT touch `tunnel` — an already-live
			// Hop-1 SSH tunnel (a plain in-process ssh.Client, independent of the control
			// channel) survives a control-channel hiccup on its own.
			log.Printf("control channel disconnected — reconnecting in %s", reconnectBackoff)
			time.Sleep(reconnectBackoff)
			newCc, err := connectAndRegister()
			if err != nil {
				consecutiveFailures++
				log.Printf("control channel reconnect failed (%d consecutive): %v", consecutiveFailures, err)
				if reconnectBackoff < 30*time.Second {
					reconnectBackoff *= 2
				}
				// Structural-failure fallback: if the same address keeps refusing to carry the
				// control channel, walk the REALITY address ladder (same-node IPv4 first, then the
				// next node's v6/v4) and restart xray against the new candidate. Only after
				// ladderAdvanceAfterFailures consecutive failures, so a transient blip can never
				// tear down an otherwise-healthy tunnel; bounded by the ladder's wraparound.
				if consecutiveFailures >= ladderAdvanceAfterFailures {
					consecutiveFailures = 0
					advanceLadder()
					if aerr := applyTransport(appliedEgressUUID); aerr != nil {
						log.Printf("transport: switch to the next REALITY address failed: %v", aerr)
					} else {
						log.Printf("transport: advanced after repeated reconnect failures — now node %d via %s", nodeIdx, curAddr)
					}
				}
				// cc is left unchanged (its Done() channel stays permanently closed), so this
				// same case fires again on the next loop iteration — sleeping first (above) is
				// what keeps that a backoff instead of a busy spin.
				continue
			}
			cc = newCc
			consecutiveFailures = 0
			reconnectBackoff = time.Second
			log.Print("control channel reconnected")
		}
	}
}

// buildAuthPayload mirrors AccountAuthClient/RemoteAssistSocket's BuildAuthPayload: an
// enrollment-ticket-carrying payload on first connect, a signed {deviceId,timestamp,signature}
// payload on every reconnect after that — see the C# comment this ports, which explains WHY the
// two shapes can't be combined (a ticket alongside a signature makes the server match the
// signed-auth branch first and reject before ever consuming the ticket).
func buildAuthPayload(state *enroll.EnrollmentState, identity *enroll.Identity) (map[string]any, error) {
	pubKeyB64, err := identity.Device.PublicKeyBase64()
	if err != nil {
		return nil, err
	}

	if state.Ticket != "" {
		return map[string]any{
			"deviceId":         state.DeviceID,
			"publicKey":        pubKeyB64,
			"enrollmentTicket": state.Ticket,
			"platform":         "linux",
			"agentKind":        "remote_assist",
			"hop1PublicKey":    identity.PublicKeyOpenSSH,
			"hwId":             stableHardwareID(),
		}, nil
	}

	timestampMs := time.Now().UnixMilli()
	sig, err := identity.Device.Sign(state.DeviceID, timestampMs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"deviceId":      state.DeviceID,
		"timestamp":     timestampMs,
		"signature":     sig,
		"publicKey":     pubKeyB64,
		"platform":      "linux",
		"agentKind":     "remote_assist",
		"hop1PublicKey": identity.PublicKeyOpenSSH,
		"hwId":          stableHardwareID(),
	}, nil
}

// armHop2/disarmHop2 write/delete the tmpfs arm file libexec/hop2-authkeys.sh gates on — this is
// the daemon-side counterpart to the already-tested Hop-2 dormant/armed mechanism (design plan
// §3). Path MUST match hop2-common.sh's HOP2_ARM_FILE.
func armHop2(runDir string, p hop2OpenPayload) error {
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(runDir, "hop2-armed.pub")
	// Content is exactly what hop2-authkeys.sh cats verbatim to sshd — must be a bare
	// "keytype base64key [comment]" line, no wrapping JSON.
	return os.WriteFile(path, []byte(p.PubKey+"\n"), 0o600)
}

func disarmHop2(runDir string) error {
	path := filepath.Join(runDir, "hop2-armed.pub")
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// writeAdminPubKey persists the bastion's STANDING Hop-2 admin key — the Linux counterpart to
// Windows' ADMIN_SUPPORT_KEY (bastion-web.py's hop2_run() family), which unlike the TTL-armed
// session key in armHop2 above is trusted unconditionally by libexec/hop2-authkeys.sh, no
// expiry. Written under stateDir (sentinel-ra-owned, e.g. config.StateDir) rather than
// /etc/sentinel-ra so the unprivileged daemon process can write it directly. Path MUST match
// hop2-common.sh's HOP2_ADMIN_PUBKEY_FILE.
func writeAdminPubKey(stateDir, pubKey string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, "bastion-support-key.pub")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(pubKey+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func waitPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func hostnameOrUnknown() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// stableHardwareID returns a stable per-OS-install identifier sent as auth.hwId — the Linux
// counterpart of Android's stableHardwareId() (SocketManager.kt) and the Windows agent's
// DeviceIdentity.HardwareId (HKLM\...\Cryptography\MachineGuid). Reads the D-Bus machine id
// (/etc/machine-id, 32 hex chars, minted at OS install, survives reboots and agent reinstalls).
// Empty string on any read failure — the server treats a missing hwId as "unknown" and the
// trial-abuse serial_hmac leg stays alert-only (never a hard gate).
func stableHardwareID() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// deviceStatusPayload builds the "device_status" event body — server.js's handler (server.js
// ~L15199) is generic across platforms and, until now, was simply never sent by this daemon at
// all, leaving the dashboard card's Network row and Uptime column permanently blank for every
// Linux Remote Assist device (found live 2026-07-29 — see docs/ARCHITECTURE.md). connection_type is hardcoded "ethernet" — detecting
// WiFi/cellular meaningfully would need extra OS-specific probing this headless-server-focused
// agent has no other use for (see the design plan's scoping decision); a wired headless box is the
// documented target, and an always-"ethernet" badge is still far more useful than the previous
// permanently-blank one.
func deviceStatusPayload() map[string]any {
	return map[string]any{
		"uptimeSecs": uptimeSeconds(),
		"network":    map[string]any{"connection_type": "ethernet"},
	}
}

// emitDeviceStatus sends the device_status heartbeat — ZK-envelope-encrypted (via zkwrap, the Go
// port of ZkPayloadHelper.cs/.kt) whenever zkPubKey is present, exactly mirroring the Windows
// client's EmitDeviceStatus(): a plain "device_status" event is dropped server-side for any
// ZK-owned device (socket.ownerIsPublicUser guard, server.js ~L15199) whether or not it's actually
// sensitive, so account-linked Linux devices — which are ALWAYS ZK-owned, since config.AdminAgent
// is always false for this build — would otherwise never get their Network/Uptime card fields
// populated at all (found live 2026-07-29). Per the ZK Security invariant, a wrap failure DROPS
// the event; it is never sent as a plaintext fallback.
func emitDeviceStatus(cc *controlchannel.Client, zkPubKey string) {
	status := deviceStatusPayload()
	if zkPubKey == "" {
		if err := cc.Emit("device_status", status); err != nil {
			log.Printf("device_status emit failed: %v", err)
		}
		return
	}
	plaintextJSON, err := json.Marshal(status)
	if err != nil {
		log.Printf("device_status: marshal failed: %v", err)
		return
	}
	wrapped := zkwrap.Wrap(zkPubKey, "device_status", plaintextJSON)
	if wrapped == nil {
		log.Print("device_status: ZK wrap failed — dropping (never sent in plaintext)")
		return
	}
	if err := cc.Emit("zk_data", wrapped); err != nil {
		log.Printf("zk_data(device_status) emit failed: %v", err)
	}
}

// uptimeSeconds reads /proc/uptime (Linux-specific — first field is seconds since boot as a
// float). Returns 0 on any read/parse failure rather than erroring — a missing uptime figure
// just means the card's Uptime column shows "—", not worth failing the whole heartbeat over.
func uptimeSeconds() int {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int(v)
}
