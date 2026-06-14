package pingback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const DefaultBaseURL = "https://pingback.sh/api/v1"

type Client struct {
	BaseURL   string
	Token     string
	UserAgent string
	HTTP      *http.Client
}

type Listener struct {
	ID    int64  `json:"id"`
	Host  string `json:"host,omitempty"`
	Label string `json:"label,omitempty"`
}

type InjectionRequest struct {
	ListenerID         int64  `json:"listener_id"`
	Label              string `json:"label,omitempty"`
	VulnerabilityType  string `json:"vulnerability_type"`
	TargetURL          string `json:"target_url"`
	InjectionPoint     string `json:"injection_point"`
	RequestMethod      string `json:"request_method"`
	ResponsibleRequest string `json:"responsible_request"`
	Notes              string `json:"notes,omitempty"`
}

type Injection struct {
	CorrelationID string            `json:"correlation_id"`
	Payloads      map[string]string `json:"payloads"`
}

type HitsPage struct {
	Data        []map[string]any
	NextSinceID int64
	HasMore     bool
}

func (c *Client) Validate(ctx context.Context) error {
	_, err := c.Listeners(ctx, false)
	return err
}

func (c *Client) Listeners(ctx context.Context, includeArchived bool) ([]Listener, error) {
	query := url.Values{}
	if includeArchived {
		query.Set("include_archived", "1")
	}
	var root map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/listeners.php", query, nil, &root); err != nil {
		return nil, err
	}
	data, ok := root["data"]
	if !ok {
		return nil, nil
	}
	items, ok := data.([]any)
	if !ok {
		if obj, objectOK := data.(map[string]any); objectOK {
			items = []any{obj}
		} else {
			return nil, fmt.Errorf("PingBack listeners response has an unexpected data shape")
		}
	}
	out := make([]Listener, 0, len(items))
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			if listener, err := parseListener(obj); err == nil {
				out = append(out, listener)
			}
		}
	}
	return out, nil
}

func (c *Client) CreateListener(ctx context.Context, label string) (Listener, error) {
	body := map[string]any{"action": "create"}
	if strings.TrimSpace(label) != "" {
		body["label"] = strings.TrimSpace(label)
	}
	var root map[string]any
	if err := c.doJSON(ctx, http.MethodPost, "/listeners.php", nil, body, &root); err != nil {
		return Listener{}, err
	}
	data, ok := root["data"]
	if !ok {
		return Listener{}, fmt.Errorf("PingBack create-listener response is missing data")
	}
	listener, err := findListener(data)
	if err != nil {
		return Listener{}, err
	}
	if listener.Label == "" {
		listener.Label = label
	}
	return listener, nil
}

func (c *Client) DeleteListener(ctx context.Context, listenerID int64) error {
	if listenerID <= 0 {
		return errors.New("listener ID must be positive")
	}
	body := map[string]any{"action": "delete", "listener_id": listenerID}
	return c.doJSON(ctx, http.MethodPost, "/listeners.php", nil, body, nil)
}

func (c *Client) CreateInjection(ctx context.Context, req InjectionRequest) (Injection, error) {
	var root struct {
		Data Injection `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/injections.php", nil, req, &root); err != nil {
		return Injection{}, err
	}
	root.Data.CorrelationID = strings.TrimSpace(root.Data.CorrelationID)
	if root.Data.CorrelationID == "" {
		return Injection{}, errors.New("PingBack injection response did not include correlation_id")
	}
	if root.Data.Payloads == nil {
		return Injection{}, errors.New("PingBack injection response did not include payloads")
	}
	httpPayload := strings.TrimSpace(root.Data.Payloads["http"])
	parsed, err := url.Parse(httpPayload)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return Injection{}, errors.New("PingBack injection response did not include a valid HTTP payload")
	}
	return root.Data, nil
}

func (c *Client) Hits(ctx context.Context, listenerID, sinceID int64, limit int) (HitsPage, error) {
	if listenerID <= 0 {
		return HitsPage{}, errors.New("listener ID must be positive")
	}
	if limit < 1 || limit > 250 {
		limit = 250
	}
	query := url.Values{}
	query.Set("listener_id", strconv.FormatInt(listenerID, 10))
	query.Set("since_id", strconv.FormatInt(sinceID, 10))
	query.Set("limit", strconv.Itoa(limit))
	var root struct {
		Data []map[string]any `json:"data"`
		Meta struct {
			NextSinceID any  `json:"next_since_id"`
			HasMore     bool `json:"has_more"`
		} `json:"meta"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/hits.php", query, nil, &root); err != nil {
		return HitsPage{}, err
	}
	next := sinceID
	if parsed, ok := toInt64(root.Meta.NextSinceID); ok && parsed >= next {
		next = parsed
	}
	return HitsPage{Data: root.Data, NextSinceID: next, HasMore: root.Meta.HasMore}, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, body any, out any) error {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	parsedBase, err := url.Parse(base)
	if err != nil || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") || parsedBase.Hostname() == "" {
		return fmt.Errorf("invalid PingBack API base URL %q", base)
	}
	endpointURL := base + endpoint
	if len(query) > 0 {
		endpointURL += "?" + query.Encode()
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpointURL, payload)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(c.Token)
	if token == "" {
		return errors.New("PingBack API token is missing; run 'pbscan auth --token pba_...' once")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(c.UserAgent) != "" {
		request.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	var response *http.Response
	for attempt := 0; attempt < 4; attempt++ {
		response, err = client.Do(request)
		if err != nil {
			return fmt.Errorf("PingBack API request: %w", err)
		}
		if response.StatusCode != http.StatusTooManyRequests {
			break
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if attempt == 3 {
			return errors.New("PingBack API rate limit reached (HTTP 429); retry later or reduce the scan size")
		}
		delay := retryAfter(response.Header.Get("Retry-After"), time.Duration(attempt+1)*2*time.Second)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if payload != nil {
			encoded, _ := json.Marshal(body)
			request.Body = io.NopCloser(bytes.NewReader(encoded))
		}
	}
	if response == nil {
		return errors.New("PingBack API returned no response")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := apiErrorMessage(data)
		if message == "" {
			message = strings.TrimSpace(string(data))
		}
		if len(message) > 500 {
			message = message[:500]
		}
		if message != "" {
			return fmt.Errorf("PingBack API HTTP %d: %s", response.StatusCode, message)
		}
		return fmt.Errorf("PingBack API HTTP %d", response.StatusCode)
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode PingBack API response: %w", err)
	}
	return nil
}

func findListener(value any) (Listener, error) {
	switch data := value.(type) {
	case map[string]any:
		if listener, err := parseListener(data); err == nil {
			return listener, nil
		}
		for _, child := range data {
			if listener, err := findListener(child); err == nil {
				return listener, nil
			}
		}
	case []any:
		for _, child := range data {
			if listener, err := findListener(child); err == nil {
				return listener, nil
			}
		}
	}
	return Listener{}, errors.New("PingBack listener response did not include a valid listener")
}

func parseListener(data map[string]any) (Listener, error) {
	id, ok := firstInt64(data, "id", "listener_id")
	if !ok || id <= 0 {
		return Listener{}, errors.New("PingBack listener response did not include a valid listener ID")
	}
	return Listener{
		ID:    id,
		Host:  firstString(data, "host", "full_host", "hostname", "callback_host", "domain"),
		Label: firstString(data, "label", "name"),
	}, nil
}

func firstInt64(data map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if value, exists := data[key]; exists {
			if parsed, ok := toInt64(value); ok {
				return parsed, true
			}
		}
	}
	return 0, false
}

func toInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case float64:
		return int64(v), true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func firstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, exists := data[key]; exists {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
	}
	return ""
}

func apiErrorMessage(data []byte) string {
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "detail"} {
		if text, ok := root[key].(string); ok {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func retryAfter(value string, fallback time.Duration) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return fallback
}
