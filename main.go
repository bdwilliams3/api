package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	version     = "2.0.0"
	finalFlag   = "QUANTUM_STABILITY_REACHED"
	oauthClient = "k-api-confidential-client"
)

// Config holds all runtime configuration loaded from the environment.
type Config struct {
	InternalSeed string
	APIUser      string
	APIPass      string
	JWTSecret2   []byte // signs the level-2 JWT (validates level 3)
	JWTSecret11  []byte // signs the OAuth access token (validates level 11)
}

var cfg Config

var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

func logPass(c *gin.Context, level int) {
	logger.Info("level passed", "level", level, "ip", c.ClientIP())
}

func logFail(c *gin.Context, level int, reason string) {
	logger.Warn("level failed", "level", level, "reason", reason, "ip", c.ClientIP())
}

func loadConfig() Config {
	c := Config{}

	c.InternalSeed = strings.TrimSpace(os.Getenv("INTERNAL_SEED"))
	if c.InternalSeed == "" {
		c.InternalSeed = hex.EncodeToString(randBytes(64))
	}

	c.APIUser = os.Getenv("API_USER")
	if c.APIUser == "" {
		c.APIUser = "api_hunter"
	}

	c.APIPass = os.Getenv("API_PASS")
	if c.APIPass == "" {
		c.APIPass = "p@s5W0rD"
	}

	c.JWTSecret2 = deriveBytes(c.InternalSeed, "jwt-level2-v1", 32)
	c.JWTSecret11 = deriveBytes(c.InternalSeed, "jwt-level11-v1", 32)
	return c
}

func main() {
	cfg = loadConfig()

	rl.startReaper(5*time.Minute, time.Hour)
	startStateReaper()

	fmt.Printf("Starting k-api version %s\n", version)

	gin.SetMode(gin.ReleaseMode)
	// cloudflared connects from localhost and forwards Cloudflare's
	// X-Forwarded-For header, so trust it to obtain real client IPs for
	// per-client rate limiting and logging.
	r := gin.New()
	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.Use(gin.Recovery(), rateLimitMiddleware())
	registerRoutes(r)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting k-api on :%s\n", port)
	_ = r.Run(":" + port)
}
