package pingback

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

type HitsWatcher struct {
	Client     *Client
	ListenerID int64
	Interval   time.Duration
	Limit      int
	SinceID    int64
}

func (w *HitsWatcher) Watch(ctx context.Context, attempts []model.Attempt, alreadyFound map[string]model.Finding, onFinding func(model.Finding), onCursor func(int64)) error {
	if w.Client == nil {
		return fmt.Errorf("PingBack client is required")
	}
	if w.ListenerID <= 0 {
		return fmt.Errorf("PingBack listener ID is required")
	}
	if w.Interval <= 0 {
		w.Interval = 2 * time.Second
	}
	if w.Limit < 1 || w.Limit > 250 {
		w.Limit = 250
	}
	lookup := make(map[string]model.Attempt, len(attempts))
	for _, attempt := range attempts {
		if strings.TrimSpace(attempt.CorrelationID) != "" {
			lookup[attempt.CorrelationID] = attempt
		}
	}
	seen := map[string]struct{}{}
	for _, finding := range alreadyFound {
		for _, observation := range finding.Events {
			if id := hitID(observation.Event); id != "" {
				seen[id] = struct{}{}
			}
		}
	}

	since := w.SinceID
	var lastErr error
	hadSuccess := false
	poll := func() {
		for {
			page, err := w.Client.Hits(ctx, w.ListenerID, since, w.Limit)
			if err != nil {
				lastErr = err
				return
			}
			hadSuccess = true
			lastErr = nil
			for _, hit := range page.Data {
				id := hitID(hit)
				if id != "" {
					if _, duplicate := seen[id]; duplicate {
						continue
					}
					seen[id] = struct{}{}
				}
				correlationID := correlationID(hit)
				attempt, ok := lookup[correlationID]
				if !ok {
					continue
				}
				now := time.Now().UTC()
				if onFinding != nil {
					onFinding(model.Finding{
						Attempt:   attempt,
						FirstSeen: now,
						LastSeen:  now,
						Events:    []model.CallbackObservation{{SeenAt: now, Event: hit}},
					})
				}
			}
			advanced := page.NextSinceID > since
			if advanced {
				since = page.NextSinceID
				if onCursor != nil {
					onCursor(since)
				}
			}
			if !page.HasMore || !advanced {
				return
			}
		}
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

func correlationID(hit map[string]any) string {
	for _, key := range []string{"correlation_id", "correlationId", "cid"} {
		if value, ok := hit[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	for _, value := range hit {
		if child, ok := value.(map[string]any); ok {
			if found := correlationID(child); found != "" {
				return found
			}
		}
	}
	return ""
}

func hitID(hit map[string]any) string {
	for _, key := range []string{"id", "hit_id"} {
		if value, exists := hit[key]; exists {
			encoded, _ := json.Marshal(value)
			return string(encoded)
		}
	}
	encoded, _ := json.Marshal(hit)
	return string(encoded)
}
