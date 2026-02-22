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
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
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
	seedBytes := make([]byte, 64)
	if _, err := rand.Read(seedBytes); err != nil {
		panic("critical: failed to generate secure seed")
	}
	internalSeed = hex.EncodeToString(seedBytes)
	jwtSecret = []byte(deriveKey("jwt-signing"))

	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
}

func deriveKey(purpose string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s-%s", internalSeed, purpose)))
	return hex.EncodeToString(h.Sum(nil))
}

func getTerminalBanner(levelNum int, customText string) string {
	border := strings.Repeat("-", 150)
	padding := strings.Repeat(" ", 26)
	return fmt.Sprintf("\n%s\nLevel %d\n%s\n%s< %s >\n%s\n",
		border, levelNum, border, padding, fmt.Sprintf("%-90s", customText), border)
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or malformed token"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid/Expired token"})
			return
		}
		c.Next()
	}
}

func SecurityCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		idToken := c.GetHeader("X-Identity-Token")
		signature := c.GetHeader("X-Signature")

		if idToken == "" || signature == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Security headers missing"})
			return
		}

		if signature != deriveKey(idToken) {
			logger.Warn("Signature mismatch", zap.String("id", idToken))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
			return
		}
		c.Next()
	}
}

func initTracer() (*sdktrace.TracerProvider, error) {
	ctx := context.Background()
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
			semconv.ServiceNamespaceKey.String("default"),
			semconv.DeploymentEnvironmentKey.String("production"),
		)),
	)
	otel.SetTracerProvider(tp)
	return tp, nil
}

func main() {
	tp, err := initTracer()
	if err != nil {
		logger.Error("failed to initialize tracer", zap.Error(err))
	} else {
		defer func() { _ = tp.Shutdown(context.Background()) }()
	}

	r := gin.New()
	r.Use(gin.Recovery())

	rate := limiter.Rate{Limit: 100, Period: time.Minute}
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	r.Use(mgin.NewMiddleware(instance))

	r.Use(func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), c.Request.URL.Path)
		defer span.End()

		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("client.ip", c.ClientIP()),
		)

		c.Request = c.Request.WithContext(ctx)
		c.Next()

		logger.Info("access",
			zap.Int("status", c.Writer.Status()),
			zap.String("path", c.Request.URL.Path),
		)
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP", "timestamp": time.Now().Unix()})
	})

	r.POST("/login", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour * 24).Unix(),
			"iat": time.Now().Unix(),
		})
		
		tString, _ := token.SignedString(jwtSecret)
		fmt.Print(getTerminalBanner(1, "SESSION_START"))
		c.JSON(http.StatusOK, gin.H{"token": tString})
	})

	api := r.Group("/api/v1")
	api.Use(AuthRequired(), SecurityCheck())
	{
		api.GET("/status", func(c *gin.Context) {
			fmt.Print(getTerminalBanner(2, "SYSTEM_READY"))
			c.JSON(http.StatusOK, gin.H{"data": "Cluster Operational"})
		})
	}
	
	r.Run(":8080")
}