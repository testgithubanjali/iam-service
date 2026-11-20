package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	visitors = make(map[string]*visitor)
	mu       sync.Mutex
)

func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()

		v, exists := visitors[ip]

		if !exists {
			v = &visitor{
				limiter: rate.NewLimiter(rate.Every(time.Minute/5), 5),
			}
			visitors[ip] = v
		}

		v.lastSeen = time.Now()

		allowed := v.limiter.Allow()

		// Remove visitors inactive for 10 minutes.
		for key, value := range visitors {
			if time.Since(value.lastSeen) > 10*time.Minute {
				delete(visitors, key)
			}
		}

		mu.Unlock()

		if !allowed {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many login attempts. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
