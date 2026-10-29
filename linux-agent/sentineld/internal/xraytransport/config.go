package xraytransport

// JSON-tagged structs mirroring xray-core's config schema — chosen over anonymous maps (unlike
// the C# client's anonymous-object + JsonSerializer approach) so a field-name typo is a compile
// error, not a silently-wrong runtime JSON key.

type xrayConfig struct {
	Log       logConfig     `json:"log"`
	Inbounds  []inbound     `json:"inbounds"`
	Outbounds []outbound    `json:"outbounds"`
	Routing   routingConfig `json:"routing"`
}

type logConfig struct {
	Loglevel string `json:"loglevel"`
}

type inbound struct {
	Tag      string           `json:"tag"`
	Listen   string           `json:"listen"`
	Port     int              `json:"port"`
	Protocol string           `json:"protocol"`
	Settings dokodemoSettings `json:"settings"`
}

type dokodemoSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

type outbound struct {
	Tag            string                `json:"tag"`
	Protocol       string                `json:"protocol"`
	Settings       vlessOutboundSettings `json:"settings"`
	StreamSettings streamSettings        `json:"streamSettings"`
}

type vlessOutboundSettings struct {
	Vnext []vnextEntry `json:"vnext"`
}

type vnextEntry struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}

type streamSettings struct {
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	RealitySettings realitySettings `json:"realitySettings"`
}

type realitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
}

type routingConfig struct {
	Rules []routingRule `json:"rules"`
}

type routingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// BuildOptions parameterizes BuildConfig — mirrors XrayTransportManager.BuildConfigJson's
// parameters (node, egressUuid, sni) plus the two local ports it allocates.
type BuildOptions struct {
	Node        string // one of RealityNodes
	SNI         string // SNIForNode(nodeIdx)
	LocalPort   int    // where the Hop-1 SSH client dials in (to-bastion-local)
	ControlPort int    // where the Socket.IO control channel dials in (to-control-local)

	// RemoteAssistEgressUUID authenticates the Hop-1 SSH-forward path — the per-account secret
	// pushed post-enrollment (design plan §7), NEVER baked into the binary. Empty until the
	// control channel (bootstrapped with RealityControlUUID alone) receives it from the server —
	// see BuildBootstrapConfig for that earlier state.
	RemoteAssistEgressUUID string

	// LogLevel defaults to "warning" in BuildConfig; exposed here so callers can temporarily bump
	// it to "info" for live debugging, mirroring the Windows client's own documented diagnostic
	// escape hatch (see the comment on the "info" bump in XrayTransportManager.cs — revert once
	// root-caused, don't leave it bumped as the steady state).
	LogLevel string
}

// BuildBootstrapConfig builds a config with ONLY the control-channel inbound — used before
// enrollment has yielded a RemoteAssistEgressUUID, so the daemon can still bring up the Socket.IO
// control channel (authenticated with the always-available RealityControlUUID) to register/
// enroll in the first place.
func BuildBootstrapConfig(opt BuildOptions) []byte {
	opt.RemoteAssistEgressUUID = ""
	return buildConfig(opt, false)
}

// BuildConfig builds the full config (Hop-1 SSH-forward inbound + control-channel inbound) —
// requires opt.RemoteAssistEgressUUID to be set.
func BuildConfig(opt BuildOptions) []byte {
	return buildConfig(opt, true)
}

func buildConfig(opt BuildOptions, includeHop1 bool) []byte {
	logLevel := opt.LogLevel
	if logLevel == "" {
		logLevel = "warning"
	}

	reality := func() realitySettings {
		return realitySettings{
			ServerName:  opt.SNI,
			Fingerprint: RealityFingerprint,
			PublicKey:   RealityPublicKey,
			ShortID:     RealityShortID,
		}
	}

	var inbounds []inbound
	var outbounds []outbound
	var rules []routingRule

	if includeHop1 {
		inbounds = append(inbounds, inbound{
			Tag: "to-bastion-local", Listen: "127.0.0.1", Port: opt.LocalPort, Protocol: "dokodemo-door",
			Settings: dokodemoAddrPort(remoteAssistBastionLocalTarget),
		})
		outbounds = append(outbounds, outbound{
			Tag: "vless-out-ra", Protocol: "vless",
			Settings: vlessOutboundSettings{Vnext: []vnextEntry{{
				Address: opt.Node, Port: 443,
				Users: []vlessUser{{ID: opt.RemoteAssistEgressUUID, Encryption: "none"}},
			}}},
			StreamSettings: streamSettings{Network: "tcp", Security: "reality", RealitySettings: reality()},
		})
		rules = append(rules, routingRule{Type: "field", InboundTag: []string{"to-bastion-local"}, OutboundTag: "vless-out-ra"})
	}

	inbounds = append(inbounds, inbound{
		Tag: "to-control-local", Listen: "127.0.0.1", Port: opt.ControlPort, Protocol: "dokodemo-door",
		Settings: dokodemoAddrPort(controlChannelLocalTarget),
	})
	outbounds = append(outbounds, outbound{
		Tag: "vless-out-control", Protocol: "vless",
		Settings: vlessOutboundSettings{Vnext: []vnextEntry{{
			Address: opt.Node, Port: 443,
			Users: []vlessUser{{ID: RealityControlUUID, Encryption: "none"}},
		}}},
		StreamSettings: streamSettings{Network: "tcp", Security: "reality", RealitySettings: reality()},
	})
	rules = append(rules, routingRule{Type: "field", InboundTag: []string{"to-control-local"}, OutboundTag: "vless-out-control"})

	cfg := xrayConfig{
		Log:       logConfig{Loglevel: logLevel},
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Routing:   routingConfig{Rules: rules},
	}
	return mustMarshalIndent(cfg)
}

func dokodemoAddrPort(hostPort string) dokodemoSettings {
	host, port := splitHostPort(hostPort)
	return dokodemoSettings{Address: host, Port: port, Network: "tcp"}
}
