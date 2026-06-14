package pingback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

func TestHitsWatcherCorrelatesByCorrelationID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":5,"protocol":"dns","correlation_id":"inj-abc"}],"meta":{"next_since_id":5,"has_more":false}}`))
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "pba_test", HTTP: server.Client()}
	watcher := HitsWatcher{Client: client, ListenerID: 42, Interval: time.Millisecond, Limit: 250}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	found := make(chan model.Finding, 1)
	go func() {
		_ = watcher.Watch(ctx, []model.Attempt{{ID: "local", CorrelationID: "inj-abc"}}, nil, func(f model.Finding) {
			found <- f
			cancel()
		}, nil)
	}()
	select {
	case finding := <-found:
		if finding.Attempt.ID != "local" {
			t.Fatalf("wrong attempt: %+v", finding.Attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("no correlated finding")
	}
}
