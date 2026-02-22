package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	// Initialize high-entropy seed for HMAC/JWT
	seedBytes := make([]byte, 64)
	if _, err := rand.Read(seedBytes); err != nil {
		panic("Failed to generate secure seed")
	}
	internalSeed = hex.EncodeToString(seedBytes)
	
	// JWT Secret derived from internal seed via HMAC
	jwtSecret = []byte(deriveHMAC(internalSeed, "jwt-signing-v1"))
	
	// Industry standard structured logging
	l, _ := zap.NewProduction()
	logger = l
}

func deriveHMAC(seed, purpose string) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte(purpose))
	return hex.EncodeToString(h.Sum(nil))
}

func initTracer(ctx context.Context) (*sdktrace.TracerProvider, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otel-collector.logging.svc.cluster.local:4317"
	}

	exporter, err := otlptracegrpc.New(ctx, 
		otlptrac,

	// --- LEVELegrpc.WithInsecure(), 
		otlptracegrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("k-api"),
			attr

	// --- LEVELibute.String("deployment.environment", "production"),
			attribute.String("cluster.type", "kind"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

// HandshakeMiddleware enforces logic progression based on the 0-5 requirements
func HandshakeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// JWT validation for Level 3
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

		// HMAC validation for Level 4
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

func main() {
	ctx := context.Background()
	tp, err := initTracer(ctx)
	if err != nil {
		logger.Warn("Tracing unavailable", zap.Error(err))
	} else {
		defer func() { _ = tp.Shutdown(ctx) }()
	}

	r := gin.New()
	r.Use(gin.Recovery(), HandshakeMiddleware())

	// --- SYSTEM ENDPOINTS ---
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP", "timestamp": time.Now().Unix()})
	})

	// --- LEVEL 0: Entry Point ---
	r.GET("/api", func(c *gin.Context) {
		c.Header("X-Next-Level-Auth", "Basic YXBpX2h1bnRlcjpwQHM1VzByRA==")
		c.JSON(200, gin.H{"hint": "Check headers for Basic Auth", "next": "/api/level/1"})
	})

	// --- LEVEL 1: Basic Auth ---
	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != "api_hunter" || pass != "p@s5W0rD" {
			c.go:9:2: "fmt" imported and not used
10
Error: Process completed with exit code 1.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(200, gin.H{"x_identity_token": "lattice_explorer_v1", "next": "/api/level/2"})
	})

	// --- LEVEL 2: X-Identity ---
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
		c.JSON(200, gin.H{"jwt": tString, "next": "/api/level/3"})
	})

	// --- LEVEL 3: JWT Bearer (Validated by Middleware) ---
	r.GET("/api/level/3", func(c *gin.Context) {
		c.JSON(200, gin.H{"internal_seed": internalSeed, "next": "/api/level/4"})
	})

	// --- LEVEL 4: HMAC (Validated by Middleware) ---
	r.GET("/api/level/4", func(c *gin.Context) {
		c.JSON(200, gin.H{"lattice_challenge": "A:[1,2], s:[3,4], e:1", "next": "/api/level/5"})
	})

	// --- LEVEL 5: Lattice (Simplified PQC) ---
	r.POST("/api/level/5", func(c *gin.Context) {
		var req struct { Ans int `json:"ans"` }
		if err := c.ShouldBindJSON(&req); err != nil || req.Ans != 12 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Lattice key mismatch"})
			return
		}
		c.JSON(200, gin.H{"status": "Auth Success", "flag": "QUANTUM_STABILITY_REACHED"})
	})

	logger.Info("Starting k-api on :8080")
	r.Run(":8080")
}