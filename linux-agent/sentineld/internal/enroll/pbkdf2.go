package enroll

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// pbkdf2SHA256 is a minimal RFC 2898 PBKDF2-HMAC-SHA256 implementation, hand-rolled to avoid
// pulling in golang.org/x/crypto as a dependency (this module is stdlib-only by design — see
// go.mod). Must byte-for-byte match the server's/Android's/Windows client's derivation: see
// AccountAuthClient.cs's ComputeAuthPrehash and docs/ARCHITECTURE.md's "Client-side password pre-hashing"
// invariant.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
