package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

func deriveHMAC(seed, purpose string) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte(purpose))
	return hex.EncodeToString(h.Sum(nil))
}

// deriveBytes is a small HKDF-expand (HMAC-SHA256, counter mode).
func deriveBytes(seed, purpose string, length int) []byte {
	var out []byte
	var counter byte = 1
	for len(out) < length {
		h := hmac.New(sha256.New, []byte(seed))
		h.Write([]byte(purpose))
		h.Write([]byte{counter})
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return out[:length]
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	var out []byte
	block := uint32(1)
	for len(out) < keyLen {
		h := hmac.New(sha256.New, password)
		h.Write(salt)
		h.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := h.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			h.Reset()
			h.Write(u)
			u = h.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		block++
	}
	return out[:keyLen]
}

func totpCodeAt(secret []byte, period int64, digits int, newHash func() hash.Hash, counter int64) string {
	var msg [8]byte
	for i := 0; i < 8; i++ {
		msg[7-i] = byte(counter >> (8 * i))
	}
	mac := hmac.New(newHash, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

func aesGCMEncrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func ctEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randInt64n(q int64) int64 {
	b := randBytes(8)
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return int64(v % uint64(q))
}

func randSmallError() int64 {
	b := randBytes(1)[0]
	switch b % 3 {
	case 0:
		return -1
	case 1:
		return 0
	default:
		return 1
	}
}

// ---------------------------------------------------------------------------
// LWE (Learning With Errors) - the final gate
// ---------------------------------------------------------------------------

func generateLWE(n, m int, q int64) ([][]int64, []int64, []int64) {
	s := make([]int64, n)
	for i := range s {
		s[i] = randInt64n(q)
	}
	A := make([][]int64, m)
	b := make([]int64, m)
	for i := 0; i < m; i++ {
		A[i] = make([]int64, n)
		var sum int64
		for j := 0; j < n; j++ {
			A[i][j] = randInt64n(q)
			sum += A[i][j] * s[j]
		}
		b[i] = ((sum+randSmallError())%q + q) % q
	}
	return A, b, s
}

func verifyLWE(A [][]int64, b []int64, q int64, s []int64) bool {
	for i, row := range A {
		if len(row) != len(s) {
			return false
		}
		var sum int64
		for j := range row {
			sum += row[j] * s[j]
		}
		sum = ((sum % q) + q) % q
		diff := sum - b[i]
		if diff < 0 {
			diff = -diff
		}
		if diff > q/2 {
			diff = q - diff
		}
		if diff > 2 {
			return false
		}
	}
	return true
}

func encodeS(s []int64) string {
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.FormatInt(v, 10)
	}
	return strings.Join(parts, ",")
}

// kdfPassword is assembled from tokens the solver already holds.
// Formatting is deliberately exact (hex truncation, RawURLEncoding).
func kdfPassword(sess *sessionState) string {
	edSeed := deriveBytes(cfg.InternalSeed, "ed25519-seed-v1", 32)
	priv := ed25519.NewKeyFromSeed(edSeed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	material := sess.aesTokenHex + "::" + pubB64
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])[:20]
}
