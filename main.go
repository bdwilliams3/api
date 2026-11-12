package main

import (
	"encoding/hex"
	"fmt"
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
	JWTSecret    []byte
}

var cfg Config

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

	c.JWTSecret = deriveBytes(c.InternalSeed, "jwt-signing-v1", 32)
	return c
}

func main() {
	cfg = loadConfig()

	rl.startReaper(5*time.Minute, time.Hour)
	startStateReaper()

	fmt.Printf("Starting k-api version %s\n", version)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), rateLimitMiddleware())
	registerRoutes(r)

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting k-api on :%s\n", port)
	_ = r.Run(":" + port)
}
