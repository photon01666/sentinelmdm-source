package enroll

import (
	"encoding/hex"
	"testing"
)

// Cross-checked against Python's hashlib.pbkdf2_hmac('sha256', ...) — this derivation must
// byte-for-byte match the server's/Android's/Windows client's, per docs/ARCHITECTURE.md's
// auth-password-prehash invariant, so it's tested against an independently-computed vector
// rather than trusted on code inspection alone.
func TestPBKDF2SHA256_MatchesKnownVectors(t *testing.T) {
	cases := []struct {
		name       string
		password   string
		salt       string
		iterations int
		wantHex    string
	}{
		{
			name:       "1 iteration",
			password:   "password",
			salt:       "salt",
			iterations: 1,
			wantHex:    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
		},
		{
			name:       "4096 iterations",
			password:   "password",
			salt:       "salt",
			iterations: 4096,
			wantHex:    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pbkdf2SHA256([]byte(tc.password), []byte(tc.salt), tc.iterations, 32)
			gotHex := hex.EncodeToString(got)
			if gotHex != tc.wantHex {
				t.Errorf("pbkdf2SHA256(%q, %q, %d) = %s, want %s", tc.password, tc.salt, tc.iterations, gotHex, tc.wantHex)
			}
		})
	}
}
