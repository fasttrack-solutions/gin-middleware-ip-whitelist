package ipwhitelist

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIPs(t *testing.T) {
	ip := "120.110.1.1"
	ips := ip + ",10.19.0.0/16"

	lookup, subnets, err := ParseIPs(ips)
	require.NoError(t, err)

	require.Len(t, lookup, 1)
	require.Len(t, subnets, 1)

	require.True(t, lookup[ip])
	require.False(t, lookup["99.1.1.1"])

	subnet := subnets[0]

	validIP := net.ParseIP("10.19.0.5")
	require.True(t, subnet.Contains(validIP))

	invalidIP := net.ParseIP("127.0.0.1")
	require.False(t, subnet.Contains(invalidIP))
}

func TestSubnetContainsIP(t *testing.T) {
	ip1 := "10.19.0.100"
	ip2 := "120.20.20.10"
	invalidIP := "500.0.0.1"
	cidrs := "10.19.0.0/16,120.20.0.0/8"

	_, subnets, err := ParseIPs(cidrs)
	require.NoError(t, err)

	require.True(t, subnetContainsIP(ip1, subnets))
	require.True(t, subnetContainsIP(ip2, subnets))
	require.False(t, subnetContainsIP(invalidIP, subnets))
}
