package pingback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pba_test" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/listeners.php":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"data":[{"id":7,"host":"abc.pingback.sh"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"id":42,"host":"scan.pingback.sh","label":"pbscan"}}`))
		case "/injections.php":
			var body InjectionRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ListenerID != 42 {
				http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"correlation_id":"inj-test","payloads":{"http":"https://scan.pingback.sh/cb?cid=inj-test","dns":"inj-test.scan.pingback.sh"}}}`))
		case "/hits.php":
			_, _ = w.Write([]byte(`{"data":[{"id":99,"protocol":"https","correlation_id":"inj-test"}],"meta":{"next_since_id":99,"has_more":false}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, Token: "pba_test", HTTP: server.Client()}
	if err := client.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	listener, err := client.CreateListener(context.Background(), "pbscan")
	if err != nil || listener.ID != 42 {
		t.Fatalf("listener=%+v err=%v", listener, err)
	}
	injection, err := client.CreateInjection(context.Background(), InjectionRequest{ListenerID: 42, VulnerabilityType: "SSRF", TargetURL: "https://target.test", InjectionPoint: "query: url", RequestMethod: "GET", ResponsibleRequest: "GET / HTTP/1.1"})
	if err != nil || injection.CorrelationID != "inj-test" {
		t.Fatalf("injection=%+v err=%v", injection, err)
	}
	page, err := client.Hits(context.Background(), 42, 0, 250)
	if err != nil || page.NextSinceID != 99 || len(page.Data) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}
