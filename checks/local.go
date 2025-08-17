package checks

import (
	"net"
)

func IsLocalhost(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	if parsedIP.To4() != nil {
		return parsedIP.IsLoopback()
	}

	if parsedIP.To16() != nil {
		return parsedIP.IsLoopback()
	}
	return false
}
