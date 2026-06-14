package model

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ResponsibleRequest renders the mutated HTTP request while replacing the
// callback value with a stable marker. Sensitive request headers are redacted
// unless includeSecrets is explicitly enabled.
func (a Attempt) ResponsibleRequest(marker string, includeSecrets bool) string {
	if strings.TrimSpace(marker) == "" {
		marker = "{{PINGBACK_HTTP_PAYLOAD}}"
	}
	clone := a
	clone = ReplaceCallback(clone, marker)
	parsed, err := url.Parse(clone.TargetURL)
	if err != nil {
		return fmt.Sprintf("%s %s HTTP/1.1\n", clone.Method, clone.TargetURL)
	}
	requestTarget := parsed.RequestURI()
	if requestTarget == "" {
		requestTarget = "/"
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%s %s HTTP/1.1\n", clone.Method, requestTarget)
	fmt.Fprintf(&out, "Host: %s\n", parsed.Host)
	keys := make([]string, 0, len(clone.Headers))
	for key := range clone.Headers {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := clone.Headers[key]
		if !includeSecrets && sensitiveHeader(key) {
			value = "[REDACTED]"
		}
		fmt.Fprintf(&out, "%s: %s\n", http.CanonicalHeaderKey(key), value)
	}
	if len(clone.Body) > 0 {
		fmt.Fprintf(&out, "Content-Length: %d\n", len(clone.Body))
	}
	out.WriteString("\n")
	out.Write(clone.Body)
	return out.String()
}

func ReplaceCallback(a Attempt, replacement string) Attempt {
	old := a.CallbackURL
	clonedHeaders := make(map[string]string, len(a.Headers))
	for key, value := range a.Headers {
		clonedHeaders[key] = value
	}
	a.Headers = clonedHeaders
	a.Body = append([]byte(nil), a.Body...)
	if old == "" || old == replacement {
		a.CallbackURL = replacement
		return a
	}
	replace := func(value string) string {
		value = strings.ReplaceAll(value, url.QueryEscape(old), url.QueryEscape(replacement))
		value = strings.ReplaceAll(value, old, replacement)
		return value
	}
	a.TargetURL = replace(a.TargetURL)
	a.Body = []byte(replace(string(a.Body)))
	for key, value := range a.Headers {
		a.Headers[key] = replace(value)
	}
	a.CallbackURL = replacement
	return a
}

func sensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key":
		return true
	default:
		return false
	}
}

// ParseResponsibleRequest is kept small and dependency-free for tests and
// future report tooling.
func ParseResponsibleRequest(raw string) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewBufferString(strings.ReplaceAll(raw, "\n", "\r\n"))))
}
