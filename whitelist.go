package ipwhitelist

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// IPWhiteList takes a list of IPs and checks incoming requests for matches.
func IPWhiteList(whitelist []string) gin.HandlerFunc {
	lookup := make(map[string]bool, len(whitelist))
	for _, ip := range whitelist {
		lookup[ip] = true
	}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !lookup[ip] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("IP %s denied", ip),
			})
			return
		}
	}
}
