package checks

import (
	"net"
)

func IsBogonIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	bogonIPv4Ranges := []struct {
		start, end net.IP
	}{
		// 0.0.0.0/8
		{net.ParseIP("0.0.0.0").To4(), net.ParseIP("0.255.255.255").To4()},

		// 100.64.0.0/10 (CGNAT)
		{net.ParseIP("100.64.0.0").To4(), net.ParseIP("100.127.255.255").To4()},

		// 169.254.0.0/16 (link local)
		{net.ParseIP("169.254.0.0").To4(), net.ParseIP("169.254.255.255").To4()},

		// 192.0.0.0/24 (IETF Protocol Assignments)
		{net.ParseIP("192.0.0.0").To4(), net.ParseIP("192.0.0.255").To4()},

		// 192.0.2.0/24 (TEST-NET-1)
		{net.ParseIP("192.0.2.0").To4(), net.ParseIP("192.0.2.255").To4()},

		// 192.88.99.0/24 (6to4 relay, deprecated)
		{net.ParseIP("192.88.99.0").To4(), net.ParseIP("192.88.99.255").To4()},

		// 198.18.0.0/15 (benchmarking)
		{net.ParseIP("198.18.0.0").To4(), net.ParseIP("198.19.255.255").To4()},

		// 198.51.100.0/24 (TEST-NET-2)
		{net.ParseIP("198.51.100.0").To4(), net.ParseIP("198.51.100.255").To4()},

		// 203.0.113.0/24 (TEST-NET-3)
		{net.ParseIP("203.0.113.0").To4(), net.ParseIP("203.0.113.255").To4()},

		// 224.0.0.0/4 (multicast)
		{net.ParseIP("224.0.0.0").To4(), net.ParseIP("239.255.255.255").To4()},

		// 240.0.0.0/4 (reserved for future use)
		{net.ParseIP("240.0.0.0").To4(), net.ParseIP("255.255.255.254").To4()},

		// 255.255.255.255/32 (broadcast)
		{net.ParseIP("255.255.255.255").To4(), net.ParseIP("255.255.255.255").To4()},
	}

	if parsedIP.To4() != nil {
		ipv4 := parsedIP.To4()
		for _, r := range bogonIPv4Ranges {
			if bytesCompare(ipv4, r.start) >= 0 && bytesCompare(ipv4, r.end) <= 0 {
				return true
			}
		}
		return false
	}

	bogonIPv6Ranges := []struct {
		start, end net.IP
	}{
		// ::/128 (unspecified)
		{net.ParseIP("::"), net.ParseIP("::")},

		// ::1/128 (loopback)
		{net.ParseIP("::1"), net.ParseIP("::1")},

		// ::ffff:0:0/96 (IPv4-mapped)
		{net.ParseIP("::ffff:0.0.0.0"), net.ParseIP("::ffff:255.255.255.255")},

		// 64:ff9b::/96 (IPv4/IPv6 translation)

		// 100::/64 (discard prefix)
		{net.ParseIP("100::"), net.ParseIP("100::ffff:ffff:ffff:ffff")},

		// 2001:10::/28 (ORCHID)
		{net.ParseIP("2001:10::"), net.ParseIP("2001:1f:ffff:ffff:ffff:ffff:ffff:ffff")},

		// 2001:db8::/32 (documentation)
		{net.ParseIP("2001:db8::"), net.ParseIP("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")},

		// fe80::/10 (link local)
		{net.ParseIP("fe80::"), net.ParseIP("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},

		// ff00::/8 (multicast)
		{net.ParseIP("ff00::"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}

	if parsedIP.To16() != nil && parsedIP.To4() == nil {
		ipv6 := parsedIP.To16()
		for _, r := range bogonIPv6Ranges {
			if bytesCompare16(ipv6, r.start) >= 0 && bytesCompare16(ipv6, r.end) <= 0 {
				return true
			}
		}
	}

	return false
}
