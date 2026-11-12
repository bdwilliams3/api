package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// ---------------------------------------------------------------------------
// Rate limiting (token bucket per client IP)
// ---------------------------------------------------------------------------

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*visitor
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*visitor{}}
}

func (rl *rateLimiter) allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	v, ok := rl.buckets[key]
	if !ok {
		r := rate.Limit(float64(limit) / window.Seconds())
		v = &visitor{limiter: rate.NewLimiter(r, limit), lastSeen: now}
		rl.buckets[key] = v
	}
	v.lastSeen = now
	return v.limiter.Allow()
}

// startReaper removes buckets for clients that have been idle longer than
// idleTTL, preventing the map from growing without bound.
func (rl *rateLimiter) startReaper(interval, idleTTL time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			rl.mu.Lock()
			cutoff := time.Now().Add(-idleTTL)
			for k, v := range rl.buckets {
				if v.lastSeen.Before(cutoff) {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
}

var rl = newRateLimiter()

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		path := c.Request.URL.Path
		limit, window, group := 120, time.Minute, "general"
		if strings.HasPrefix(path, "/api/level/") || strings.HasPrefix(path, "/api/oauth/") {
			limit, window, group = 30, time.Minute, "challenge"
		}
		if !rl.allow(ip+":"+group, limit, window) {
			logger.Warn("rate limited", "ip", ip, "group", group, "path", path)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			return
		}
		c.Next()
	}
}

// ---------------------------------------------------------------------------
// Auth middlewares
// ---------------------------------------------------------------------------

// RequireJWT validates a Bearer JWT signed with the given secret and,
// when requiredScope is non-empty, enforces that the token carries that scope.
func RequireJWT(secret []byte, requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "JWT Bearer token required"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return secret, nil })
		if err != nil || token == nil || !token.Valid {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid/Expired JWT"})
			return
		}
		if requiredScope != "" {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || claims["scope"] != requiredScope {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient scope"})
				return
			}
		}
		c.Next()
	}
}

