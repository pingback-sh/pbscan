package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

func TestDispatchSendsAttempt(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.RequestURI()
		gotHeader = r.Header.Get("X-PBScan-Attempt")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	attempt := model.Attempt{
		ID:        "pba-testscan-00001-abcde",
		Method:    http.MethodGet,
		TargetURL: server.URL + "/fetch?url=http%3A%2F%2Flistener.test",
		Headers:   map[string]string{},
	}
	s := New(Options{Threads: 1, Rate: 100, Timeout: time.Second, UserAgent: "pbscan-test", MaxResponseBytes: 1024})
	var result model.DispatchResult
	if err := s.Dispatch(context.Background(), []model.Attempt{attempt}, func(r model.DispatchResult) { result = r }); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusNoContent || result.Error != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath == "" || gotHeader != attempt.ID {
		t.Fatalf("request not received correctly: path=%q header=%q", gotPath, gotHeader)
	}
}

func TestRedirectsDisabled(t *testing.T) {
	finalHits := 0
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		finalHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirect.Close()

	s := New(Options{Threads: 1, Rate: 100, Timeout: time.Second, FollowRedirects: false, MaxResponseBytes: 1024})
	attempt := model.Attempt{ID: "pba-testscan-00002-abcde", Method: http.MethodGet, TargetURL: redirect.URL, Headers: map[string]string{}}
	var result model.DispatchResult
	if err := s.Dispatch(context.Background(), []model.Attempt{attempt}, func(r model.DispatchResult) { result = r }); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusFound || finalHits != 0 {
		t.Fatalf("redirect followed unexpectedly: result=%#v finalHits=%d", result, finalHits)
	}
}
