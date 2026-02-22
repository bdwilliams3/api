package main

import (
	"context" // Used in initTracer and main
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

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("k-api"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

func main() {
	// Use context for tracer initialization
	ctx := context.Background()
	tp, err := initTracer(ctx)
	if err == nil {
		defer func() { _ = tp.Shutdown(ctx) }()
	}

	r := gin.New()
	r.Use(gin.Recovery())

	// --- THE 5 DISCOVERY LEVELS ---

	// Level 1: Basic Auth
	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != "api_hunter" || pass != "p@s5W0rD" {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "next_level": "/api/level/2"})
	})

	// Level 2: API Key
	r.GET("/api/level/2", func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != "hunter_v1" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing X-API-Key"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "next_level": "/api/level/3"})
	})

	// Level 3: Identity Token
	r.GET("/api/level/3", func(c *gin.Context) {
		if c.GetHeader("X-Identity-Token") != "discovery_agent" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid Identity"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "next_level": "/api/level/4"})
	})

	// Level 4: Signature (Security Best Practice: Key Derivation)
	r.GET("/api/level/4", func(c *gin.Context) {
		id := c.GetHeader("X-Identity-Token")
		sig := c.GetHeader("X-Signature")
		if id == "" || sig != deriveKey(id) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Signature mismatch"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "next_level": "/api/level/5"})
	})

	// Level 5: JWT Generation
	r.POST("/login", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		tString, _ := token.SignedString(jwtSecret)
		c.JSON(http.StatusOK, gin.H{
			"token":              tString,
			"internal_challenge": internalSeed,
			"status":             "success",
		})
	})

	// Final Authenticated API
	api := r.Group("/api/v1")
	api.Use(func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return jwtSecret, nil })
		if token == nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Token"})
			return
		}
		c.Next()
	})
	{
		api.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"data": "Cluster Operational", "level": 5})
		})
	}

	r.Run(":8080")
}