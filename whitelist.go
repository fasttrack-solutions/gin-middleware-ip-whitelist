package ipwhitelist

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func subnetContainsIP(ip string, subnets []*net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, subnet := range subnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// ParseIPs takes a list of IPs and checks for CIDR notation
// it returns a map and a slice of subnets
func ParseIPs(list string) (map[string]bool, []*net.IPNet, error) {
	if len(list) == 0 {
		return nil, nil, nil
	}

	ips := strings.Split(list, ",")

	subnets := []*net.IPNet{}
	lookup := make(map[string]bool, len(ips))

	for _, ip := range ips {
		if strings.Contains(ip, "/") {
			_, subnet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, nil, err
			}

			subnets = append(subnets, subnet)
			continue
		}

		validIP := net.ParseIP(ip)
		if validIP == nil {
			return nil, nil, fmt.Errorf("invalid IP provided: %s", ip)
		}

		lookup[ip] = true
	}

	return lookup, subnets, nil
}

// IPWhiteList takes a map of IPs and a list of subnets and checks incoming requests for matches.
func IPWhiteList(whitelist map[string]bool, subnets []*net.IPNet) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !whitelist[ip] && !subnetContainsIP(ip, subnets) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Client IP %s denied", ip),
			})
			return
		}
	}
}
