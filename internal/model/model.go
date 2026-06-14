package model

import (
	"bytes"
	"net/http"
	"time"
)

type Source struct {
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

type Attempt struct {
	ID                string            `json:"id"`
	ScanID            string            `json:"scan_id"`
	SourceName        string            `json:"source_name"`
	Method            string            `json:"method"`
	OriginalTargetURL string            `json:"original_target_url,omitempty"`
	TargetURL         string            `json:"target_url"`
	Vector            string            `json:"vector"`
	InjectionPoint    string            `json:"injection_point"`
	OriginalValue     string            `json:"original_value,omitempty"`
	CallbackURL       string            `json:"callback_url"`
	CorrelationID     string            `json:"correlation_id,omitempty"`
	Payloads          map[string]string `json:"payloads,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              []byte            `json:"body,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

type DispatchResult struct {
	AttemptID     string        `json:"attempt_id"`
	StatusCode    int           `json:"status_code,omitempty"`
	ResponseBytes int64         `json:"response_bytes,omitempty"`
	Duration      time.Duration `json:"duration"`
	Error         string        `json:"error,omitempty"`
	SentAt        time.Time     `json:"sent_at"`
}

type CallbackObservation struct {
	SeenAt time.Time      `json:"seen_at"`
	Event  map[string]any `json:"event"`
}

type Finding struct {
	Attempt   Attempt               `json:"attempt"`
	FirstSeen time.Time             `json:"first_seen"`
	LastSeen  time.Time             `json:"last_seen"`
	Events    []CallbackObservation `json:"events"`
}

type Session struct {
	Version          int                       `json:"version"`
	Mode             string                    `json:"mode,omitempty"`
	ScanID           string                    `json:"scan_id"`
	CreatedAt        time.Time                 `json:"created_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
	CallbackTemplate string                    `json:"callback_template,omitempty"`
	FeedURL          string                    `json:"feed_url,omitempty"`
	APIBaseURL       string                    `json:"api_base_url,omitempty"`
	ListenerID       int64                     `json:"listener_id,omitempty"`
	ListenerHost     string                    `json:"listener_host,omitempty"`
	LastHitID        int64                     `json:"last_hit_id,omitempty"`
	Attempts         []Attempt                 `json:"attempts"`
	Results          map[string]DispatchResult `json:"results"`
	Findings         map[string]Finding        `json:"findings"`
}

func (a Attempt) Request() (*http.Request, error) {
	req, err := http.NewRequest(a.Method, a.TargetURL, bytes.NewReader(a.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range a.Headers {
		if http.CanonicalHeaderKey(k) == "Host" {
			req.Host = v
			continue
		}
		if http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		req.Header.Set(k, v)
	}
	return req, nil
}
