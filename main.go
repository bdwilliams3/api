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
	"fmt"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var (
	internalSeed string
	jwtSecret    []byte
	apiUser      string
	apiPass      string
	logger       *zap.Logger
	logProvider  *log.LoggerProvider
)

func init() {
    internalSeed = strings.TrimSpace(os.Getenv("INTERNAL_SEED"))
    if internalSeed == "" {
        seedBytes := make([]byte, 64)
        rand.Read(seedBytes)
        internalSeed = hex.EncodeToString(seedBytes)
    }

    apiUser = os.Getenv("API_USER")
    if apiUser == "" { apiUser = "api_hunter" }
    
    apiPass = os.Getenv("API_PASS")
    if apiPass == "" { apiPass = "p@s5W0rD" }

    jwtSecret = []byte(deriveHMAC(internalSeed, "jwt-signing-v1"))
}

func deriveHMAC(seed, purpose string) string {
    h := hmac.New(sha256.New, []byte(seed))
    h.Write([]byte(purpose))
    return hex.EncodeToString(h.Sum(nil))
}

func getLoggerWithTrace(ctx context.Context) *zap.Logger {
	span := trace.SpanFromContext(ctx)
	fields := []zap.Field{}
	if span.SpanContext().IsValid() {
		fields = append(fields,
			zap.String("trace_id", span.SpanContext().TraceID().String()),
			zap.String("span_id", span.SpanContext().SpanID().String()),
		)
	}
	return logger.With(fields...)
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
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp, nil
}

func initLogProvider(ctx context.Context) (*log.LoggerProvider, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otel-collector.logging.svc.cluster.local:4317"
	}
	
	logExporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return nil, err
	}
	
	logProvider := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
		log.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("k-api"),
			attribute.String("deployment.environment", "production"),
			attribute.String("cluster.type", "kind"),
		)),
	)
	global.SetLoggerProvider(logProvider)
	return logProvider, nil
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
	
	// Initialize log provider FIRST so it can receive logs
	var err error
	logProvider, err = initLogProvider(ctx)
	if err != nil {
		fmt.Printf("Failed to initialize log provider: %v\n", err)
	}
	defer func() {
		if logProvider != nil {
			_ = logProvider.Shutdown(ctx)
		}
	}()

	// Then initialize tracer
	tp, err := initTracer(ctx)
	if err != nil {
		fmt.Printf("Tracing unavailable: %v\n", err)
	} else {
		defer func() { _ = tp.Shutdown(ctx) }()
	}

	// Now create zap logger for use in handlers
	var cfg zap.Config
	cfg = zap.NewProductionConfig()
	cfg.OutputPaths = []string{"stdout", "stderr"}
	logger, _ = cfg.Build()
	defer func() { _ = logger.Sync() }()

	logger.Info("Starting k-api", zap.String("version", "1.0.0"))

	r := gin.New()
	r.Use(otelgin.Middleware("k-api"))
	r.Use(gin.Recovery(), HandshakeMiddleware())

	r.GET("/health", func(c *gin.Context) {
		logger := getLoggerWithTrace(c.Request.Context())
		logger.Info("health check endpoint called")
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
		log := getLoggerWithTrace(c.Request.Context())
		if !ok || user != apiUser || pass != apiPass {
			log.Warn("failed basic auth", zap.String("user", user), zap.Bool("ok", ok))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		log.Info("basic auth succeeded", zap.String("user", user))
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