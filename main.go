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
	// Restoring INTERNAL_SEED logic
	seedBytes := make([]byte, 64)
	if _, err := rand.Read(seedBytes); err != nil {
		panic(err)
	}
	internalSeed = hex.EncodeToString(seedBytes)
	jwtSecret = []byte(deriveKey("jwt-signing"))
	
	l, _ := zap.NewProduction()
	logger = l
}

func deriveKey(purpose string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s-%s", internalSeed, purpose)))
	return hex.EncodeToString(h.Sum(nil))
}

func initTracer(ctx context.Context) (*sdktrace.TracerProvider, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otel-collector.logging.svc.cluster.local:4317"
	}

	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure(), otlptracegrpc.WithEndpoint(endpoint))
	if err != nil {
		return nil, err
	}

	// Restoring exact Resource attributes
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("k-api"),
			semconv.ServiceNamespaceKey.String("default"),
			attribute.String("deployment.environment", "production"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

func main() {
	ctx := context.Background()
	tp, _ := initTracer(ctx)
	if tp != nil {
		defer func() { _ = tp.Shutdown(ctx) }()
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// Liveness/Readiness Probe
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Level 1: Basic Auth Discovery
	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != "api_hunter" || pass != "p@s5W0rD" {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(401)
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/2"})
	})

	// Level 2: API Key Validation
	r.GET("/api/level/2", func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != "hunter_v1" {
			c.AbortWithStatusJSON(403, gin.H{"error": "Invalid API Key"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/3"})
	})

	// Level 3: Identity Token Validation
	r.GET("/api/level/3", func(c *gin.Context) {
		if c.GetHeader("X-Identity-Token") != "discovery_agent" {
			c.AbortWithStatusJSON(403, gin.H{"error": "Invalid Identity Token"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/4"})
	})

	// Level 4: Key Derivation/Signature
	r.GET("/api/level/4", func(c *gin.Context) {
		id := c.GetHeader("X-Identity-Token")
		sig := c.GetHeader("X-Signature")
		if id == "" || sig != deriveKey(id) {
			c.AbortWithStatusJSON(403, gin.H{"error": "Signature mismatch"})
			return
		}
		c.JSON(200, gin.H{"status": "success", "next_level": "/api/level/5"})
	})

	// Level 5: Login for JWT
	r.POST("/login", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		tString, _ := token.SignedString(jwtSecret)
		c.JSON(200, gin.H{
			"token": tString,
			"internal_challenge": internalSeed, // Required for Level 4 spidering
		})
	})

	// Authenticated Production API
	api := r.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatus(401)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
		if token == nil || !token.Valid {
			c.AbortWithStatus(401)
			return
		}
		c.Next()
	})
	{
		api.GET("/status", func(c *gin.Context) {
			c.JSON(200, gin.H{"data": "Cluster Operational", "level": 5})
		})
	}

	r.Run(":8080")
}