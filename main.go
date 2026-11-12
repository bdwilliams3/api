package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	version     = "2.0.0"
	finalFlag   = "QUANTUM_STABILITY_REACHED"
	oauthClient = "k-api-confidential-client"
)

var (
	internalSeed string
	jwtSecret    []byte
	apiUser      string
	apiPass      string
)

// ---------------------------------------------------------------------------
// In-memory state (sessions are created at level 5 and carried forward)
// ---------------------------------------------------------------------------

type sessionState struct {
	createdAt   time.Time
	aesTokenHex string
	edMsg       []byte
	kdfSalt     []byte

	lweA      [][]int64
	lweB      []int64
	lweQ      int64
	lweS      []int64
	lweN      int
	lweM      int
	flagNonce []byte
	flagCT    []byte
}

type oauthCodeState struct {
	challenge string
	clientID  string
	expires   time.Time
}

type appState struct {
	mu         sync.Mutex
	sessions   map[string]*sessionState
	oauthCodes map[string]oauthCodeState
}

var st = appState{
	sessions:   map[string]*sessionState{},
	oauthCodes: map[string]oauthCodeState{},
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

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
	edSeed := deriveBytes(internalSeed, "ed25519-seed-v1", 32)
	priv := ed25519.NewKeyFromSeed(edSeed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	material := sess.aesTokenHex + "::" + pubB64
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])[:20]
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{visitors: map[string][]time.Time{}}
}

func (rl *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	var kept []time.Time
	for _, t := range rl.visitors[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		rl.visitors[key] = kept
		return false
	}
	kept = append(kept, now)
	rl.visitors[key] = kept
	return true
}

var rl = newRateLimiter()

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		path := c.Request.URL.Path
		limit, window := 120, time.Minute
		if strings.HasPrefix(path, "/api/level/") || strings.HasPrefix(path, "/api/oauth/") {
			limit, window = 30, time.Minute
		}
		if !rl.allow(ip, limit, window) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			return
		}
		c.Next()
	}
}

// ---------------------------------------------------------------------------
// Session helper
// ---------------------------------------------------------------------------

func getSession(id string) *sessionState {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return nil
	}
	if time.Since(s.createdAt) > time.Hour {
		delete(st.sessions, id)
		return nil
	}
	return s
}

// ---------------------------------------------------------------------------
// Middleware for the legacy JWT + HMAC gates
// ---------------------------------------------------------------------------

func HandshakeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		if path == "/api/level/3" {
			auth := c.GetHeader("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "JWT Bearer token required"})
				return
			}
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
			if token == nil || !token.Valid {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid/Expired JWT"})
				return
			}
		}

		if path == "/api/level/4" {
			sig := c.GetHeader("X-HMAC-Signature")
			if sig != deriveHMAC(internalSeed, "level4-access") {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "HMAC signature mismatch"})
				return
			}
		}

		c.Next()
	}
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

func init() {
	internalSeed = strings.TrimSpace(os.Getenv("INTERNAL_SEED"))
	if internalSeed == "" {
		seedBytes := make([]byte, 64)
		_, _ = rand.Read(seedBytes)
		internalSeed = hex.EncodeToString(seedBytes)
	}

	apiUser = os.Getenv("API_USER")
	if apiUser == "" {
		apiUser = "api_hunter"
	}

	apiPass = os.Getenv("API_PASS")
	if apiPass == "" {
		apiPass = "p@s5W0rD"
	}

	jwtSecret = deriveBytes(internalSeed, "jwt-signing-v1", 32)
}

func main() {
	fmt.Printf("Starting k-api version %s\n", version)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), rateLimitMiddleware(), HandshakeMiddleware())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "UP",
			"timestamp": time.Now().Unix(),
		})
	})

	r.GET("/api", func(c *gin.Context) {
		authHint := base64.StdEncoding.EncodeToString([]byte(apiUser + ":" + apiPass))
		c.Header("X-Next-Level-Auth", "Basic "+authHint)
		c.JSON(http.StatusOK, gin.H{
			"next": "/api/level/1",
		})
	})

	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != apiUser || pass != apiPass {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"x_identity_token": "lattice_explorer_v1",
			"next":             "/api/level/2",
		})
	})

	r.GET("/api/level/2", func(c *gin.Context) {
		if c.GetHeader("X-Identity-Token") != "lattice_explorer_v1" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "X-Identity-Token missing"})
			return
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "explorer",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tString, _ := token.SignedString(jwtSecret)
		c.JSON(http.StatusOK, gin.H{
			"jwt":  tString,
			"next": "/api/level/3",
		})
	})

	r.GET("/api/level/3", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"internal_seed": internalSeed,
			"next":          "/api/level/4",
		})
	})

	r.GET("/api/level/4", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"lattice_challenge": "A:[1,2], s:[3,4], e:1",
			"clearance":         deriveHMAC(internalSeed, "level5-permit"),
			"next":              "/api/level/5",
		})
	})

	r.POST("/api/level/5", func(c *gin.Context) {
		permit := c.GetHeader("X-Level-Clearance")
		if permit != deriveHMAC(internalSeed, "level5-permit") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Sequential flow violation: Level 4 clearance required"})
			return
		}
		var req struct {
			Ans int `json:"ans"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Ans != 12 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Lattice key mismatch"})
			return
		}

		key := deriveBytes(internalSeed, "aes-gcm-key-v1", 32)
		plain := randBytes(32)
		nonce, ct, err := aesGCMEncrypt(key, plain)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "crypto error"})
			return
		}

		sessionID := hex.EncodeToString(randBytes(16))
		sess := &sessionState{
			createdAt:   time.Now(),
			aesTokenHex: hex.EncodeToString(plain),
		}
		st.mu.Lock()
		st.sessions[sessionID] = sess
		st.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"status":  "Auth Success",
			"session": sessionID,
			"next":    "/api/level/6",
			"aes": gin.H{
				"nonce":      base64.StdEncoding.EncodeToString(nonce),
				"ciphertext": base64.StdEncoding.EncodeToString(ct),
			},
		})
	})

	r.POST("/api/level/6", func(c *gin.Context) {
		var req struct {
			Session string `json:"session"`
			Token   string `json:"token"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		sess := getSession(req.Session)
		if sess == nil || !ctEqual(req.Token, sess.aesTokenHex) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid token"})
			return
		}

		msg := randBytes(32)
		edSeed := deriveBytes(internalSeed, "ed25519-seed-v1", 32)
		priv := ed25519.NewKeyFromSeed(edSeed)
		pub := priv.Public().(ed25519.PublicKey)

		st.mu.Lock()
		sess.edMsg = msg
		st.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"next": "/api/level/7",
			"ed25519": gin.H{
				"public_key": base64.StdEncoding.EncodeToString(pub),
				"message":    base64.StdEncoding.EncodeToString(msg),
			},
		})
	})

	r.POST("/api/level/7", func(c *gin.Context) {
		var req struct {
			Session   string `json:"session"`
			Signature string `json:"signature"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		sess := getSession(req.Session)
		if sess == nil || len(sess.edMsg) == 0 {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
			return
		}
		sig, err := base64.StdEncoding.DecodeString(req.Signature)
		if err != nil {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
			return
		}
		edSeed := deriveBytes(internalSeed, "ed25519-seed-v1", 32)
		priv := ed25519.NewKeyFromSeed(edSeed)
		pub := priv.Public().(ed25519.PublicKey)
		if !ed25519.Verify(pub, sess.edMsg, sig) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
			return
		}

		salt := randBytes(16)
		target := pbkdf2SHA256([]byte(kdfPassword(sess)), salt, 120000, 32)
		st.mu.Lock()
		sess.kdfSalt = salt
		st.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"next": "/api/level/8",
			"kdf": gin.H{
				"algo":       "pbkdf2-hmac-sha256",
				"salt":       base64.StdEncoding.EncodeToString(salt),
				"iterations": 120000,
				"key_length": 32,
				"target":     hex.EncodeToString(target),
			},
		})
	})

	r.POST("/api/level/8", func(c *gin.Context) {
		var req struct {
			Session  string `json:"session"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		sess := getSession(req.Session)
		if sess == nil || len(sess.kdfSalt) == 0 {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
			return
		}
		got := pbkdf2SHA256([]byte(req.Password), sess.kdfSalt, 120000, 32)
		want := pbkdf2SHA256([]byte(kdfPassword(sess)), sess.kdfSalt, 120000, 32)
		if !ctEqual(hex.EncodeToString(got), hex.EncodeToString(want)) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid password"})
			return
		}

		totpSecret := deriveBytes(internalSeed, "totp-secret-v1", 20)
		c.JSON(http.StatusOK, gin.H{
			"next": "/api/level/9",
			"totp": gin.H{
				"secret":    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(totpSecret),
				"period":    60,
				"digits":    8,
				"algorithm": "sha256",
			},
		})
	})

	r.POST("/api/level/9", func(c *gin.Context) {
		var req struct {
			Session string `json:"session"`
			Code    string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		if getSession(req.Session) == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active session"})
			return
		}
		totpSecret := deriveBytes(internalSeed, "totp-secret-v1", 20)
		baseCounter := time.Now().Unix() / 60
		ok := false
		for _, delta := range []int64{-1, 0, 1} {
			if totpCodeAt(totpSecret, 60, 8, sha256.New, baseCounter+delta) == req.Code {
				ok = true
				break
			}
		}
		if !ok {
			time.Sleep(2 * time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"next": "/api/oauth/authorize",
			"oauth": gin.H{
				"client_id": oauthClient,
				"authorize": "/api/oauth/authorize",
				"token":     "/api/oauth/token",
			},
		})
	})

	r.GET("/api/oauth/authorize", func(c *gin.Context) {
		clientID := c.Query("client_id")
		challenge := c.Query("code_challenge")
		state := c.Query("state")
		if clientID != oauthClient || challenge == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid authorize request"})
			return
		}
		code := hex.EncodeToString(randBytes(24))
		st.mu.Lock()
		st.oauthCodes[code] = oauthCodeState{
			challenge: challenge,
			clientID:  clientID,
			expires:   time.Now().Add(2 * time.Minute),
		}
		st.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"code": code, "state": state})
	})

	r.POST("/api/oauth/token", func(c *gin.Context) {
		var req struct {
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			CodeVerifier string `json:"code_verifier"`
			ClientID     string `json:"client_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		if req.GrantType != "authorization_code" || req.ClientID != oauthClient {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid token request"})
			return
		}
		st.mu.Lock()
		oc, ok := st.oauthCodes[req.Code]
		delete(st.oauthCodes, req.Code)
		st.mu.Unlock()
		if !ok || time.Now().After(oc.expires) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid or expired code"})
			return
		}
		sum := sha256.Sum256([]byte(req.CodeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if !ctEqual(computed, oc.challenge) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "PKCE verification failed"})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "k-api",
			"scope": "level11",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
		})
		signed, _ := token.SignedString(jwtSecret)
		c.JSON(http.StatusOK, gin.H{
			"access_token": signed,
			"token_type":   "bearer",
			"expires_in":   600,
		})
	})

	r.POST("/api/level/11", func(c *gin.Context) {
		var req struct {
			Session string `json:"session"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		sess := getSession(req.Session)
		if sess == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active session"})
			return
		}

		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
		if err != nil || tok == nil || !tok.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		n, m, q := 8, 16, int64(251)
		A, b, s := generateLWE(n, m, q)
		key := sha256.Sum256([]byte(encodeS(s)))
		nonce, ct, err := aesGCMEncrypt(key[:], []byte(finalFlag))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "crypto error"})
			return
		}

		st.mu.Lock()
		sess.lweA, sess.lweB, sess.lweQ, sess.lweS = A, b, q, s
		sess.lweN, sess.lweM = n, m
		sess.flagNonce, sess.flagCT = nonce, ct
		st.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"next": "/api/level/11/solve",
			"lwe": gin.H{
				"n":               n,
				"m":               m,
				"q":               q,
				"A":               A,
				"b":               b,
				"flag_nonce":      base64.StdEncoding.EncodeToString(nonce),
				"flag_ciphertext": base64.StdEncoding.EncodeToString(ct),
			},
		})
	})

	r.POST("/api/level/11/solve", func(c *gin.Context) {
		var req struct {
			Session string  `json:"session"`
			S       []int64 `json:"s"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}
		sess := getSession(req.Session)
		if sess == nil || sess.lweN == 0 {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
			return
		}
		if len(req.S) != sess.lweN || !verifyLWE(sess.lweA, sess.lweB, sess.lweQ, req.S) {
			time.Sleep(time.Second)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Secret incorrect"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "Auth Success",
			"flag":   finalFlag,
		})
	})

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting k-api on :%s\n", port)
	_ = r.Run(":" + port)
}
