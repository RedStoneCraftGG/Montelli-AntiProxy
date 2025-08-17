package checks

import (
	"net"
)

func IsPrivate(ip string) bool {
	if isIPv4(ip) {
		return isPrivateIPv4(ip)
	} else if isIPv6(ip) {
		return isPrivateIPv6(ip)
	}
	return false
}

func isIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
}

func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil && parsed.To16() != nil
}

func isPrivateIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip).To4()
	if parsedIP == nil {
		return false
	}
	privateRanges := []struct {
		start, end net.IP
	}{
		{net.ParseIP("10.0.0.0").To4(), net.ParseIP("10.255.255.255").To4()},
		{net.ParseIP("172.16.0.0").To4(), net.ParseIP("172.31.255.255").To4()},
		{net.ParseIP("192.168.0.0").To4(), net.ParseIP("192.168.255.255").To4()},
	}
	for _, r := range privateRanges {
		if bytesCompare(parsedIP, r.start) >= 0 && bytesCompare(parsedIP, r.end) <= 0 {
			return true
		}
	}
	return false
}

func isPrivateIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To16() == nil || parsedIP.To4() != nil {
		return false
	}
	// ULA: fc00::/7
	if parsedIP[0]&0xfe == 0xfc {
		return true
	}
	// LLA: fe80::/10
	if parsedIP[0] == 0xfe && (parsedIP[1]&0xc0) == 0x80 {
		return true
	}
	return false
}
