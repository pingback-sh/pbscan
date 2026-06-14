package callback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

var attemptTokenPattern = regexp.MustCompile(`pba-[a-z0-9-]{8,80}`)

type FeedWatcher struct {
	URL      string
	Headers  map[string]string
	Interval time.Duration
	Timeout  time.Duration
	Client   *http.Client
}

func (w *FeedWatcher) Watch(ctx context.Context, attempts []model.Attempt, alreadyFound map[string]model.Finding, onFinding func(model.Finding)) error {
	if strings.TrimSpace(w.URL) == "" {
		return nil
	}
	lookup := make(map[string]model.Attempt, len(attempts))
	for _, attempt := range attempts {
		lookup[attempt.ID] = attempt
	}
	seen := make(map[string]struct{})
	for id, finding := range alreadyFound {
		for _, observation := range finding.Events {
			seen[eventKey(id, observation.Event)] = struct{}{}
		}
	}
	if w.Interval <= 0 {
		w.Interval = 2 * time.Second
	}
	if w.Timeout <= 0 {
		w.Timeout = 15 * time.Second
	}
	if w.Client == nil {
		w.Client = &http.Client{Timeout: w.Timeout}
	}

	var lastErr error
	hadSuccess := false
	poll := func() {
		if err := w.poll(ctx, lookup, seen, onFinding); err != nil {
			lastErr = err
			return
		}
		hadSuccess = true
		lastErr = nil
	}
	poll()

	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if !hadSuccess && lastErr != nil {
				return lastErr
			}
			return nil
		case <-ticker.C:
			poll()
		}
	}
}

func (w *FeedWatcher) poll(ctx context.Context, lookup map[string]model.Attempt, seen map[string]struct{}, onFinding func(model.Finding)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.URL, nil)
	if err != nil {
		return err
	}
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("feed returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("feed is not valid JSON: %w", err)
	}
	for _, event := range eventMaps(root) {
		encoded, err := json.Marshal(event)
		if err != nil {
			continue
		}
		for _, tokenBytes := range attemptTokenPattern.FindAll(encoded, -1) {
			id := string(tokenBytes)
			attempt, ok := lookup[id]
			if !ok {
				continue
			}
			key := eventKey(id, event)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			now := time.Now().UTC()
			if onFinding != nil {
				onFinding(model.Finding{
					Attempt:   attempt,
					FirstSeen: now,
					LastSeen:  now,
					Events:    []model.CallbackObservation{{SeenAt: now, Event: event}},
				})
			}
		}
	}
	return nil
}

func eventMaps(root any) []map[string]any {
	var out []map[string]any
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case []any:
			for _, item := range v {
				walk(item)
			}
		case map[string]any:
			before := len(out)
			for _, child := range v {
				walk(child)
			}
			if len(out) == before {
				encoded, _ := json.Marshal(v)
				if attemptTokenPattern.Match(encoded) {
					out = append(out, v)
				}
			}
		}
	}
	walk(root)
	return out
}

func eventKey(attemptID string, event map[string]any) string {
	encoded, _ := json.Marshal(event)
	sum := sha256.Sum256(encoded)
	return attemptID + ":" + hex.EncodeToString(sum[:])
}
