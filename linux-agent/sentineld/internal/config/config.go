// Package config holds build-time/runtime constants for the Linux sentineld agent —
// the Linux analog of ssh-bastion-client/SentinelRemoteAssist/Config.cs.
package config

import "os"

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const (

	// AdminAgent selects the login endpoint family (device-admin vs public/parent),
	// mirroring Config.AdminAgent's build-flag switch on the Windows side. Default to
	// the public/parent login path — admin-fleet builds can toggle this via a build tag
	// if needed later, same pattern as the Windows agent's -PadminAgent.
	AdminAgent = false

	// StateDir is where sentineld persists its Hop-1 identity keypair, enrollment
	// state, and other runtime data. Owned by the sentinel-ra service account.
	StateDir = "/var/lib/sentinel-ra"

	// RunDir is the tmpfs directory holding the Hop-2 arm file
	// (RunDir/hop2-armed.pub) — see plan §3.
	RunDir = "/run/sentinel-ra"

	// ConfigDir holds the Hop-2 sshd config and the AuthorizedKeysCommand script.
	ConfigDir = "/etc/sentinel-ra"
)

// WebUrl is the control server the CLI enrollment flow logs into.
// Override with SENTINEL_SERVER_URL.
var WebUrl = envOr("SENTINEL_SERVER_URL", "https://app.example.com")

// LoginPath returns the account-login endpoint for the configured build variant,
// mirroring AccountAuthClient.cs's `Config.AdminAgent ? "/api/device-admin/login" : "/login"`.
func LoginPath() string {
	if AdminAgent {
		return "/api/device-admin/login"
	}
	return "/login"
}

// TotpPath returns the TOTP verification endpoint for the configured build variant.
func TotpPath() string {
	if AdminAgent {
		return "/api/device-admin/login/totp"
	}
	return "/login/totp"
}
