package target

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func Validate(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported target scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("target has no hostname")
	}
	if allowPrivate {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("private/local targets require --allow-private-targets")
	}
	if ip := net.ParseIP(host); ip != nil && isPrivateOrLocal(ip) {
		return fmt.Errorf("private/local targets require --allow-private-targets")
	}
	return nil
}

func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
