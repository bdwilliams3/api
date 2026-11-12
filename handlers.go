package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func registerRoutes(r *gin.Engine) {
	r.GET("/health", handleHealth)
	r.GET("/api", handleAPI)
	r.GET("/api/level/1", handleLevel1)
	r.GET("/api/level/2", handleLevel2)
	r.GET("/api/level/3", RequireJWT(), handleLevel3)
	r.GET("/api/level/4", RequireHMAC(), handleLevel4)
	r.POST("/api/level/5", handleLevel5)
	r.POST("/api/level/6", handleLevel6)
	r.POST("/api/level/7", handleLevel7)
	r.POST("/api/level/8", handleLevel8)
	r.POST("/api/level/9", handleLevel9)
	r.GET("/api/oauth/authorize", handleOAuthAuthorize)
	r.POST("/api/oauth/token", handleOAuthToken)
	r.POST("/api/level/11", RequireJWT(), handleLevel11)
	r.POST("/api/level/11/solve", handleLevel11Solve)
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "UP",
		"timestamp": time.Now().Unix(),
	})
}

func handleAPI(c *gin.Context) {
	authHint := base64.StdEncoding.EncodeToString([]byte(cfg.APIUser + ":" + cfg.APIPass))
	c.Header("X-Next-Level-Auth", "Basic "+authHint)
	c.JSON(http.StatusOK, gin.H{
		"next": "/api/level/1",
	})
}

func handleLevel1(c *gin.Context) {
	user, pass, ok := c.Request.BasicAuth()
	if !ok || user != cfg.APIUser || pass != cfg.APIPass {
		c.Header("WWW-Authenticate", "Basic realm=\"k-api\"")
		logFail(c, 1, "invalid credentials")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	logPass(c, 1)
	c.JSON(http.StatusOK, gin.H{
		"x_identity_token": "lattice_explorer_v1",
		"next":             "/api/level/2",
	})
}

func handleLevel2(c *gin.Context) {
	if c.GetHeader("X-Identity-Token") != "lattice_explorer_v1" {
		logFail(c, 2, "missing identity token")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "X-Identity-Token missing"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "explorer",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tString, _ := token.SignedString(cfg.JWTSecret)
	logPass(c, 2)
	c.JSON(http.StatusOK, gin.H{
		"jwt":  tString,
		"next": "/api/level/3",
	})
}

func handleLevel3(c *gin.Context) {
	logPass(c, 3)
	c.JSON(http.StatusOK, gin.H{
		"internal_seed": cfg.InternalSeed,
		"next":          "/api/level/4",
	})
}

func handleLevel4(c *gin.Context) {
	logPass(c, 4)
	c.JSON(http.StatusOK, gin.H{
		"lattice_challenge": "A:[1,2], s:[3,4], e:1",
		"clearance":         deriveHMAC(cfg.InternalSeed, "level5-permit"),
		"next":              "/api/level/5",
	})
}

func handleLevel5(c *gin.Context) {
	permit := c.GetHeader("X-Level-Clearance")
	if permit != deriveHMAC(cfg.InternalSeed, "level5-permit") {
		logFail(c, 5, "missing clearance")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Sequential flow violation: Level 4 clearance required"})
		return
	}
	var req struct {
		Ans int `json:"ans"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Ans != 12 {
		logFail(c, 5, "lattice answer mismatch")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Lattice key mismatch"})
		return
	}

	key := deriveBytes(cfg.InternalSeed, "aes-gcm-key-v1", 32)
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

	logPass(c, 5)
	c.JSON(http.StatusOK, gin.H{
		"status":  "Auth Success",
		"session": sessionID,
		"next":    "/api/level/6",
		"aes": gin.H{
			"nonce":      base64.StdEncoding.EncodeToString(nonce),
			"ciphertext": base64.StdEncoding.EncodeToString(ct),
		},
	})
}

func handleLevel6(c *gin.Context) {
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
		logFail(c, 6, "invalid AES token")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid token"})
		return
	}

	msg := randBytes(32)
	edSeed := deriveBytes(cfg.InternalSeed, "ed25519-seed-v1", 32)
	priv := ed25519.NewKeyFromSeed(edSeed)
	pub := priv.Public().(ed25519.PublicKey)

	st.mu.Lock()
	sess.edMsg = msg
	st.mu.Unlock()

	time.Sleep(jitterMs(150))
	logPass(c, 6)
	c.JSON(http.StatusOK, gin.H{
		"next": "/api/level/7",
		"ed25519": gin.H{
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"message":    base64.StdEncoding.EncodeToString(msg),
		},
	})
}

func handleLevel7(c *gin.Context) {
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
		logFail(c, 7, "no active challenge")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		logFail(c, 7, "signature decode failed")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
		return
	}
	edSeed := deriveBytes(cfg.InternalSeed, "ed25519-seed-v1", 32)
	priv := ed25519.NewKeyFromSeed(edSeed)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, sess.edMsg, sig) {
		logFail(c, 7, "signature verify failed")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
		return
	}

	salt := randBytes(16)
	target := pbkdf2SHA256([]byte(kdfPassword(sess)), salt, 120000, 32)
	st.mu.Lock()
	sess.kdfSalt = salt
	st.mu.Unlock()

	time.Sleep(jitterMs(150))
	logPass(c, 7)
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
}

func handleLevel8(c *gin.Context) {
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
		logFail(c, 8, "no active challenge")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
		return
	}
	got := pbkdf2SHA256([]byte(req.Password), sess.kdfSalt, 120000, 32)
	want := pbkdf2SHA256([]byte(kdfPassword(sess)), sess.kdfSalt, 120000, 32)
	if !ctEqual(hex.EncodeToString(got), hex.EncodeToString(want)) {
		logFail(c, 8, "invalid password")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid password"})
		return
	}

	totpSecret := deriveBytes(cfg.InternalSeed, "totp-secret-v1", 20)
	time.Sleep(jitterMs(150))
	logPass(c, 8)
	c.JSON(http.StatusOK, gin.H{
		"next": "/api/level/9",
		"totp": gin.H{
			"secret":    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(totpSecret),
			"period":    60,
			"digits":    8,
			"algorithm": "sha256",
		},
	})
}

func handleLevel9(c *gin.Context) {
	var req struct {
		Session string `json:"session"`
		Code    string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	sess := getSession(req.Session)
	if sess == nil {
		logFail(c, 9, "no active session")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active session"})
		return
	}
	totpSecret := deriveBytes(cfg.InternalSeed, "totp-secret-v1", 20)
	baseCounter := time.Now().Unix() / 60
	ok := false
	for _, delta := range []int64{-1, 0, 1} {
		if totpCodeAt(totpSecret, 60, 8, sha256.New, baseCounter+delta) == req.Code {
			ok = true
			break
		}
	}
	if !ok {
		logFail(c, 9, "invalid TOTP code")
		time.Sleep(2*time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid code"})
		return
	}

	st.mu.Lock()
	if sess.totpUsed == req.Code {
		st.mu.Unlock()
		logFail(c, 9, "TOTP replay")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "TOTP replay detected"})
		return
	}
	sess.totpUsed = req.Code
	st.mu.Unlock()

	time.Sleep(jitterMs(150))
	logPass(c, 9)
	c.JSON(http.StatusOK, gin.H{
		"next": "/api/oauth/authorize",
		"oauth": gin.H{
			"client_id": oauthClient,
			"authorize": "/api/oauth/authorize",
			"token":     "/api/oauth/token",
		},
	})
}

func handleOAuthAuthorize(c *gin.Context) {
	clientID := c.Query("client_id")
	challenge := c.Query("code_challenge")
	state := c.Query("state")
	if clientID != oauthClient || challenge == "" {
		logFail(c, 10, "invalid authorize request")
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
}

func handleOAuthToken(c *gin.Context) {
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
		logFail(c, 10, "invalid token request")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid token request"})
		return
	}
	st.mu.Lock()
	oc, ok := st.oauthCodes[req.Code]
	delete(st.oauthCodes, req.Code)
	st.mu.Unlock()
	if !ok || time.Now().After(oc.expires) {
		logFail(c, 10, "invalid or expired code")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid or expired code"})
		return
	}
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ctEqual(computed, oc.challenge) {
		logFail(c, 10, "PKCE verification failed")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "PKCE verification failed"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "k-api",
		"scope": "level11",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	signed, _ := token.SignedString(cfg.JWTSecret)
	time.Sleep(jitterMs(150))
	logPass(c, 10)
	c.JSON(http.StatusOK, gin.H{
		"access_token": signed,
		"token_type":   "bearer",
		"expires_in":   600,
	})
}

func handleLevel11(c *gin.Context) {
	var req struct {
		Session string `json:"session"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	sess := getSession(req.Session)
	if sess == nil {
		logFail(c, 11, "no active session")
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active session"})
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

	logPass(c, 11)
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
}

func handleLevel11Solve(c *gin.Context) {
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
		logFail(c, 11, "no active challenge")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No active challenge"})
		return
	}
	if len(req.S) != sess.lweN || !verifyLWE(sess.lweA, sess.lweB, sess.lweQ, req.S) {
		logFail(c, 11, "incorrect secret")
		time.Sleep(time.Second + jitterMs(500))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Secret incorrect"})
		return
	}
	logger.Info("flag unlocked", "ip", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{
		"status": "Auth Success",
		"flag":   finalFlag,
	})
}
