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
	apiUser      string // New
	apiPass      string // New
	logger       *zap.Logger
)

func init() {
    // 1. Seed handling - TrimSpace is critical for K8s Secret injection
    internalSeed = strings.TrimSpace(os.Getenv("INTERNAL_SEED"))
    if internalSeed == "" {
        seedBytes := make([]byte, 64)
        rand.Read(seedBytes)
        internalSeed = hex.EncodeToString(seedBytes)
    }

    // 2. Auth Creds handling
    apiUser = os.Getenv("API_USER")
    if apiUser == "" { apiUser = "api_hunter" }
    
    apiPass = os.Getenv("API_PASS")
    if apiPass == "" { apiPass = "p@s5W0rD" }

    jwtSecret = []byte(deriveHMAC(internalSeed, "jwt-signing-v1"))
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
		otlptracegrpc.WithInsecure(), 
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
			attribute.String("deployment.environment", "production"),
			attribute.String("cluster.type", "kind"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

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

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "UP",
			"timestamp": time.Now().Unix(),
		})
	})

	r.GET("/api", func(c *gin.Context) {
		c.Header("X-Next-Level-Auth", "Basic YXBpX2h1bnRlcjpwQHM1VzByRA==")
		c.JSON(http.StatusOK, gin.H{
			"hint": "Check headers for Basic Auth",
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
        "clearance":         deriveHMAC(internalSeed, "level5-permit"), // New Token
        "next":              "/api/level/5",
    	})
	})

	// Replace your existing Level 5 POST handler with this:
	r.POST("/api/level/5", func(c *gin.Context) {
		// 1. Mandatory Clearance Check
		permit := c.GetHeader("X-Level-Clearance")
		if permit != deriveHMAC(internalSeed, "level5-permit") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Sequential flow violation: Level 4 clearance required",
			})
			return
		}

		// 2. Existing Lattice Math logic
		var req struct {
			Ans int `json:"ans"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Ans != 12 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Lattice key mismatch",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "Auth Success",
			"flag":   "QUANTUM_STABILITY_REACHED",
		})
	})
	

	logger.Info("Starting k-api on :8080")
	r.Run(":8080")
}