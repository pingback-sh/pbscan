package input

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pingback-sh/pbscan/internal/model"
)

func URLSource(raw string) (model.Source, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return model.Source{}, err
	}
	if u.Scheme == "" || u.Host == "" {
		return model.Source{}, fmt.Errorf("URL must include scheme and host: %q", raw)
	}
	return model.Source{
		Name:    raw,
		Method:  http.MethodGet,
		URL:     u.String(),
		Headers: map[string]string{},
	}, nil
}

func URLsFromReader(r io.Reader, name string) ([]model.Source, error) {
	var out []model.Source
	s := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)
	line := 0
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		src, err := URLSource(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		src.Name = fmt.Sprintf("%s:%d", name, line)
		out = append(out, src)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func URLsFromFile(path string) ([]model.Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return URLsFromReader(f, path)
}

func RawRequestFile(path, baseURL string) (model.Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Source{}, err
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return model.Source{}, fmt.Errorf("parse raw HTTP request: %w", err)
	}
	defer req.Body.Close()
	body, err := io.ReadAll(io.LimitReader(req.Body, 4<<20))
	if err != nil {
		return model.Source{}, err
	}

	if req.URL.IsAbs() {
		// Already complete.
	} else {
		scheme := "https"
		host := req.Host
		if baseURL != "" {
			b, err := url.Parse(baseURL)
			if err != nil {
				return model.Source{}, fmt.Errorf("invalid base URL: %w", err)
			}
			scheme = b.Scheme
			host = b.Host
		}
		if host == "" {
			return model.Source{}, fmt.Errorf("raw request needs a Host header or --base-url")
		}
		req.URL.Scheme = scheme
		req.URL.Host = host
	}

	headers := make(map[string]string, len(req.Header))
	for k, values := range req.Header {
		headers[k] = strings.Join(values, ", ")
	}
	if req.Host != "" {
		headers["Host"] = req.Host
	}
	contentType := req.Header.Get("Content-Type")
	return model.Source{
		Name:        filepath.Base(path),
		Method:      req.Method,
		URL:         req.URL.String(),
		Headers:     headers,
		Body:        body,
		ContentType: contentType,
	}, nil
}
