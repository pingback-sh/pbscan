package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pingback-sh/pbscan/internal/config"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"version"}, IO{Out: &out, Err: &errOut})
	if code != 0 || out.Len() == 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestScanRequiresAuthorization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("PBSCAN_CONFIG", path)
	var out, errOut bytes.Buffer
	code := Run([]string{"scan", "-u", "https://example.com/?url=x", "--listener", "abc.pingback.sh"}, IO{Out: &out, Err: &errOut})
	if code == 0 || !strings.Contains(errOut.String(), "authorization") {
		t.Fatalf("expected authorization error, code=%d err=%q", code, errOut.String())
	}
}

func TestInterspersedScanFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var headers bool
	var rate int
	fs.BoolVar(&headers, "headers", false, "")
	fs.IntVar(&rate, "rate", 10, "")
	args := reorderInterspersedArgs(fs, []string{"urls.txt", "--headers", "--rate", "5"})
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if !headers || rate != 5 || len(fs.Args()) != 1 || fs.Args()[0] != "urls.txt" {
		t.Fatalf("headers=%v rate=%d args=%v", headers, rate, fs.Args())
	}
}

func TestAutomaticAPIWorkflow(t *testing.T) {
	var mu sync.Mutex
	var createdListener, createdInjection, hitPolls int
	var correlationID string
	var receivedPayload string

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedPayload = r.URL.Query().Get("url")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pba_test" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/listeners.php":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			mu.Lock()
			createdListener++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"id":42,"host":"auto.pingback.sh"}}`))
		case "/injections.php":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			createdInjection++
			correlationID = "inj-auto-1"
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"correlation_id":"inj-auto-1","payloads":{"http":"https://auto.pingback.sh/cb?cid=inj-auto-1"}}}`))
		case "/hits.php":
			mu.Lock()
			hitPolls++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":[{"id":1,"protocol":"https","correlation_id":"inj-auto-1"}],"meta":{"next_since_id":1,"has_more":false}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	configPath := filepath.Join(t.TempDir(), "config.json")
	outDir := filepath.Join(t.TempDir(), "output")
	cfg := config.Default()
	cfg.APIBaseURL = api.URL
	cfg.APIToken = "pba_test"
	cfg.AuthorizedUse = true
	cfg.OutputDir = outDir
	cfg.Wait = 50 * time.Millisecond
	cfg.WaitString = "50ms"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PBSCAN_CONFIG", configPath)

	var out, errOut bytes.Buffer
	code := Run([]string{"scan", "--allow-private-targets", "--wait", "50ms", target.URL + "?url=original"}, IO{Out: &out, Err: &errOut})
	if code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if createdListener != 1 || createdInjection != 1 || hitPolls == 0 {
		t.Fatalf("listener=%d injection=%d polls=%d", createdListener, createdInjection, hitPolls)
	}
	if correlationID != "inj-auto-1" {
		t.Fatalf("correlation=%q", correlationID)
	}
	if receivedPayload != "https://auto.pingback.sh/cb?cid=inj-auto-1" {
		t.Fatalf("payload=%q", receivedPayload)
	}
	if !strings.Contains(out.String(), "[CONFIRMED]") {
		t.Fatalf("expected confirmed finding, output=%s", out.String())
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("output entries=%d err=%v", len(entries), err)
	}
}
