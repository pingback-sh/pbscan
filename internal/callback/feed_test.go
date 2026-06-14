package callback

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

func TestFeedWatcherMatchesAttempt(t *testing.T) {
	attempt := model.Attempt{ID: "pba-deadbeef-00001-abcde", Vector: "query", InjectionPoint: "url"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"http_path":"/pbscan/%s"}]`, attempt.ID)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	found := make(chan model.Finding, 1)
	watcher := FeedWatcher{URL: server.URL, Interval: time.Second}
	if err := watcher.Watch(ctx, []model.Attempt{attempt}, nil, func(f model.Finding) { found <- f }); err != nil {
		t.Fatal(err)
	}
	select {
	case finding := <-found:
		if finding.Attempt.ID != attempt.ID || len(finding.Events) != 1 {
			t.Fatalf("wrong finding")
		}
	default:
		t.Fatal("no finding")
	}
}
