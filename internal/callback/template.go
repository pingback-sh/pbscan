package callback

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
)

type Template struct {
	value string
}

func NewTemplate(value string) (Template, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Template{}, fmt.Errorf("callback template is required")
	}
	if !strings.Contains(value, "{token}") {
		return Template{}, fmt.Errorf("callback template must contain {token}")
	}
	probe := strings.ReplaceAll(value, "{token}", "pbscan-probe")
	u, err := url.Parse(probe)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return Template{}, fmt.Errorf("callback template must be an absolute HTTP(S) URL")
	}
	return Template{value: value}, nil
}

func FromListener(listener string) (Template, error) {
	listener = strings.TrimSpace(listener)
	if listener == "" {
		return Template{}, fmt.Errorf("listener is empty")
	}
	if !strings.Contains(listener, "://") {
		listener = "http://" + listener
	}
	u, err := url.Parse(listener)
	if err != nil || u.Hostname() == "" {
		return Template{}, fmt.Errorf("invalid listener: %q", listener)
	}
	port := ""
	if u.Port() != "" {
		port = ":" + u.Port()
	}
	// Keep the exact listener host so existing Pingback session routing works.
	// The token is carried in the path and is therefore visible in HTTP(S)
	// callbacks. Deployments that support tokenized subdomains can instead pass
	// --callback-template explicitly.
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return NewTemplate(scheme + "://" + u.Hostname() + port + "/pbscan/{token}")
}

func (t Template) String() string { return t.value }

func (t Template) URL(token string) string {
	return strings.ReplaceAll(t.value, "{token}", token)
}

func NewScanID() (string, error) {
	return randomID("pbs", 8)
}

func NewAttemptID(scanID string, index int) (string, error) {
	random, err := randomID("", 5)
	if err != nil {
		return "", err
	}
	shortScan := strings.TrimPrefix(scanID, "pbs-")
	if len(shortScan) > 8 {
		shortScan = shortScan[:8]
	}
	return fmt.Sprintf("pba-%s-%05d-%s", shortScan, index, random), nil
}

func randomID(prefix string, bytesCount int) (string, error) {
	buf := make([]byte, bytesCount)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	if prefix == "" {
		return encoded, nil
	}
	return prefix + "-" + encoded, nil
}
