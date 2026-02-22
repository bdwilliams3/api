package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

var (
	internalSeed string
	jwtSecret    []byte
	logger       *zap.Logger
	tracer       = otel.Tracer("k-api")
)

func init() {
	seedBytes := make([]byte, 64)
	rand.Read(seedBytes)
	internalSeed = hex.EncodeToString(seedBytes)
	jwtSecret = []byte(deriveKey("jwt-signing"))
	logger, _ = zap.NewProduction()
}

func deriveKey(purpose string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s-%s", internalSeed, purpose)))
	return hex.EncodeToString(h.Sum(nil))
}

// Middleware for the final production layer
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid/Expired token"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid/Expired token"})
			return
		}
		c.Next()
	}
}

func main() {
	r := gin.New()
	r.Use(gin.Recovery())

	// --- THE 5 DISCOVERY LEVELS ---

	// LEVEL 1: Basic Authentication
	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != "api_hunter" || pass != "p@s5W0rD" {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(401)
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/2"})
	})

	// LEVEL 2: Custom API Key Header
	r.GET("/api/level/2", func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != "hunter_v1" {
			c.JSON(403, gin.H{"error": "Missing X-API-Key"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/3"})
	})

	// LEVEL 3: Identity Token Validation
	r.GET("/api/level/3", func(c *gin.Context) {
		if c.GetHeader("X-Identity-Token") != "discovery_agent" {
			c.JSON(403, gin.H{"error": "Invalid Identity"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/4"})
	})

	// LEVEL 4: Signature Verification (The Hard One)
	r.GET("/api/level/4", func(c *gin.Context) {
		id := c.GetHeader("X-Identity-Token")
		sig := c.GetHeader("X-Signature")
		if id == "" || sig != deriveKey(id) {
			c.JSON(403, gin.H{"error": "Signature mismatch", "hint": "deriveKey(X-Identity-Token)"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/5"})
	})

	// LEVEL 5: JWT Acquisition
	r.POST("/login", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tString, _ := token.SignedString(jwtSecret)
		// We send the seed back here so the spider can calculate signatures for Level 4/API
		c.JSON(200, gin.H{"token": tString, "internal_challenge": internalSeed})
	})

	// FINAL PRODUCTION API
	api := r.Group("/api/v1")
	api.Use(AuthRequired()) // Final level requires the JWT from Level 5
	{
		api.GET("/status", func(c *gin.Context) {
			c.JSON(200, gin.H{"data": "Level 5 Complete: Cluster Operational"})
		})
	}

	r.Run(":8080")
}