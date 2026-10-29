package enroll

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"

	"sentineld/internal/config"
)

// AccountAuthClient is the Go port of AccountAuthClient.cs: prelogin -> prehash-v1 (or plaintext
// fallback) -> login -> optional TOTP -> enrollment ticket. Session state (the login cookie) is
// held in the client's own cookie jar, exactly like the Windows client's CookieContainer.
type AccountAuthClient struct {
	http *http.Client
	base string
}

func NewAccountAuthClient() (*AccountAuthClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &AccountAuthClient{
		http: &http.Client{Jar: jar, Timeout: 30 * time.Second},
		base: config.WebUrl,
	}, nil
}

type preloginResp struct {
	AuthSalt   string `json:"auth_salt"`
	Scheme     string `json:"scheme"`
	Iterations int    `json:"iterations"`
	Migrate    bool   `json:"migrate"`
}

type loginResp struct {
	TotpRequired bool   `json:"totp_required"`
	Error        string `json:"error"`
}

type LoginResult struct {
	OK           bool
	TotpRequired bool
	Err          error
}

// Login mirrors AccountAuthClient.LoginAsync — identifier is an email (public build) or a
// username/email (admin build); the server itself detects "@" to decide how to look the account
// up. On a prelogin failure (network error, or the server predates /api/auth/prelogin) it falls
// through to a plaintext password POST exactly like the Kotlin/C# clients do — never silently
// fail the whole flow just because the prehash upgrade endpoint is unreachable.
func (c *AccountAuthClient) Login(identifier, password string) LoginResult {
	iterations := 600_000
	scheme, salt := "", ""
	migrate := false

	if pre, err := c.postJSON("/api/auth/prelogin", map[string]string{"identifier": identifier}); err == nil {
		var pr preloginResp
		if json.Unmarshal(pre, &pr) == nil {
			scheme = pr.Scheme
			salt = pr.AuthSalt
			migrate = pr.Migrate
			if pr.Iterations > 0 {
				iterations = pr.Iterations
			}
		}
	}
	// Connection failure at prelogin is intentionally swallowed here — fall through and let the
	// actual login POST below surface the real error, matching the C# client's try/catch-and-fall-
	// through behavior.

	var body map[string]string
	if scheme == "prehash-v1" && salt != "" && !migrate {
		authHash, err := computeAuthPrehash(password, salt, iterations)
		if err != nil {
			return LoginResult{Err: fmt.Errorf("compute auth prehash: %w", err)}
		}
		body = map[string]string{"username": identifier, "authHash": authHash}
	} else {
		body = map[string]string{"username": identifier, "password": password}
	}

	respBody, status, err := c.postJSONStatus(config.LoginPath(), body)
	if err != nil {
		return LoginResult{Err: fmt.Errorf("connection failed — check your network (%w)", err)}
	}
	if status < 200 || status >= 300 {
		return LoginResult{Err: fmt.Errorf("%s", errorOrDefault(respBody, "invalid credentials"))}
	}

	var lr loginResp
	_ = json.Unmarshal(respBody, &lr)
	return LoginResult{OK: true, TotpRequired: lr.TotpRequired}
}

// VerifyTotp mirrors AccountAuthClient.VerifyTotpAsync.
func (c *AccountAuthClient) VerifyTotp(code string) LoginResult {
	respBody, status, err := c.postJSONStatus(config.TotpPath(), map[string]string{"code": code})
	if err != nil {
		return LoginResult{Err: fmt.Errorf("connection failed — check your network (%w)", err)}
	}
	if status < 200 || status >= 300 {
		return LoginResult{Err: fmt.Errorf("%s", errorOrDefault(respBody, "invalid code"))}
	}
	return LoginResult{OK: true}
}

// RequestEnrollmentTicket mirrors AccountAuthClient.RequestEnrollmentTicketAsync — the session
// cookie from Login/VerifyTotp authorizes this call. Returns a single-use ticket consumed by
// sentineld's next Hop-1 handshake; this is the only call that creates the device<->account
// binding.
func (c *AccountAuthClient) RequestEnrollmentTicket(deviceID string) (string, error) {
	respBody, status, err := c.postJSONStatus("/api/enrollment/ticket", map[string]string{"deviceId": deviceID})
	if err != nil {
		return "", fmt.Errorf("connection failed — check your network (%w)", err)
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("%s", errorOrDefault(respBody, "registration failed"))
	}
	var tr struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(respBody, &tr); err != nil || tr.Ticket == "" {
		return "", fmt.Errorf("server returned no ticket — contact support")
	}
	return tr.Ticket, nil
}

func (c *AccountAuthClient) postJSON(path string, body any) ([]byte, error) {
	respBody, status, err := c.postJSONStatus(path, body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("http %d", status)
	}
	return respBody, nil
}

func (c *AccountAuthClient) postJSONStatus(path string, body any) ([]byte, int, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

func errorOrDefault(respBody []byte, def string) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(respBody, &e) == nil && e.Error != "" {
		return e.Error
	}
	return def
}

// computeAuthPrehash mirrors AccountAuthClient.ComputeAuthPrehash byte-for-byte:
// base64(PBKDF2-SHA256(password, utf8("sentinel-auth-v1|")+authSaltBytes, iterations, 32)).
// Must match the Kotlin/C#/server derivation exactly — see docs/ARCHITECTURE.md's auth-password-prehash
// invariant. Never send the plaintext password when this path is taken.
func computeAuthPrehash(password, authSaltB64 string, iterations int) (string, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(authSaltB64)
	if err != nil {
		return "", fmt.Errorf("decode auth_salt: %w", err)
	}
	salt := append([]byte("sentinel-auth-v1|"), saltBytes...)
	derived := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return base64.StdEncoding.EncodeToString(derived), nil
}
