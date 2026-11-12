package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

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
// Auth middlewares
// ---------------------------------------------------------------------------

func RequireJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "JWT Bearer token required"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return cfg.JWTSecret, nil })
		if err != nil || token == nil || !token.Valid {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid/Expired JWT"})
			return
		}
		c.Next()
	}
}

func RequireHMAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		sig := c.GetHeader("X-HMAC-Signature")
		if sig != deriveHMAC(cfg.InternalSeed, "level4-access") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "HMAC signature mismatch"})
			return
		}
		c.Next()
	}
}
