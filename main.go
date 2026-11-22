package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
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

	c.JWTSecret2 = deriveBytes(c.InternalSeed, "jwt-level2-v1", 32)
	c.JWTSecret11 = deriveBytes(c.InternalSeed, "jwt-level11-v1", 32)
	return c
}

func main() {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8080/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		os.Exit(0)
	}

	cfg = loadConfig()

	rl.startReaper(5*time.Minute, time.Hour)
	startStateReaper()

	fmt.Printf("Starting k-api version %s\n", version)

	gin.SetMode(gin.ReleaseMode)
	// cloudflared connects through Docker's NAT, so the container sees the
	// bridge gateway (e.g. 172.18.0.1) rather than 127.0.0.1. Trust loopback
	// plus the Docker bridge subnet so Cloudflare's X-Forwarded-For header is
	// honored for per-client rate limiting and logging.
	r := gin.New()
	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1", "172.16.0.0/12"})
	r.Use(gin.Recovery(), securityHeadersMiddleware(), rateLimitMiddleware())
	registerRoutes(r)

	fmt.Printf("Starting k-api on :%s\n", port)
	_ = r.Run(":" + port)
}
