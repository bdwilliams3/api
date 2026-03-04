package main

import (
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
	"github.com/golang-jwt/jwt/v5"
)

var (
	internalSeed string
	jwtSecret    []byte
	apiUser      string
	apiPass      string
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
	fmt.Println("Starting k-api version 1.0.0")

	r := gin.New()
	r.Use(gin.Recovery(), HandshakeMiddleware())

	r.GET("/health", func(c *gin.Context) {
		fmt.Println("health check endpoint called")
		c.JSON(http.StatusOK, gin.H{
			"status":    "UP",
			"timestamp": time.Now().Unix(),
		})
	})

	r.GET("/api", func(c *gin.Context) {
		fmt.Println("API root endpoint called")
		c.Header("X-Next-Level-Auth", "Basic YXBpX2h1bnRlcjpwQHM1VzByRA==")
		c.JSON(http.StatusOK, gin.H{
			"hint": "Check headers for Basic Auth",
			"next": "/api/level/1",
		})
	})

	r.GET("/api/level/1", func(c *gin.Context) {
		user, pass, ok := c.Request.BasicAuth()
		if !ok || user != apiUser || pass != apiPass {
			fmt.Printf("failed basic auth - user: %s, ok: %v\n", user, ok)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		fmt.Printf("basic auth succeeded - user: %s\n", user)
		c.JSON(http.StatusOK, gin.H{
			"x_identity_token": "lattice_explorer_v1",
			"next":             "/api/level/2",
		})
	})

	r.GET("/api/level/2", func(c *gin.Context) {
		if c.GetHeader("X-Identity-Token") != "lattice_explorer_v1" {
			fmt.Println("level/2 - X-Identity-Token missing")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "X-Identity-Token missing"})
			return
		}
		fmt.Println("level/2 - X-Identity-Token verified")
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
		fmt.Println("level/3 - internal_seed endpoint called")
		c.JSON(http.StatusOK, gin.H{
			"internal_seed": internalSeed,
			"next":          "/api/level/4",
		})
	})

	r.GET("/api/level/4", func(c *gin.Context) {
		fmt.Println("level/4 - clearance token endpoint called")
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
			fmt.Println("level/5 - invalid clearance token")
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
			fmt.Printf("level/5 - lattice answer mismatch: got %d, expected 12\n", req.Ans)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Lattice key mismatch",
			})
			return
		}

		fmt.Println("level/5 - auth success, flag unlocked")
		c.JSON(http.StatusOK, gin.H{
			"status": "Auth Success",
			"flag":   "QUANTUM_STABILITY_REACHED",
		})
	})

	fmt.Println("Starting k-api on :8080")
	r.Run(":8080")
}