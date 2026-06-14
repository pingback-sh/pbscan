package mutate

import (
	"strings"
	"testing"

	"github.com/pingback-sh/pbscan/internal/callback"
	"github.com/pingback-sh/pbscan/internal/model"
)

func testBuilder(t *testing.T) *Builder {
	t.Helper()
	tpl, err := callback.NewTemplate("http://{token}.listener.test/pbscan/{token}")
	if err != nil {
		t.Fatal(err)
	}
	return NewBuilder("pbs-testscan", tpl)
}

func TestQueryAttempts(t *testing.T) {
	b := testBuilder(t)
	sources := []model.Source{{Name: "x", Method: "GET", URL: "https://example.com/fetch?url=a&id=1", Headers: map[string]string{}}}
	attempts, err := b.Build(sources, Options{Query: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("got %d attempts", len(attempts))
	}
	for _, attempt := range attempts {
		if !strings.Contains(attempt.TargetURL, attempt.ID) {
			t.Fatalf("callback token missing from URL: %s", attempt.TargetURL)
		}
	}
}

func TestJSONAttempts(t *testing.T) {
	b := testBuilder(t)
	sources := []model.Source{{
		Name: "raw", Method: "POST", URL: "https://example.com/api", Headers: map[string]string{"Content-Type": "application/json"},
		ContentType: "application/json", Body: []byte(`{"image":{"url":"https://old"},"items":["one",2]}`),
	}}
	attempts, err := b.Build(sources, Options{Body: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("got %d attempts", len(attempts))
	}
	if attempts[0].InjectionPoint == "" || !strings.Contains(string(attempts[0].Body), attempts[0].ID) {
		t.Fatalf("bad JSON mutation: %#v", attempts[0])
	}
}

func TestHeaderHostIsSkipped(t *testing.T) {
	b := testBuilder(t)
	sources := []model.Source{{Name: "x", Method: "GET", URL: "https://example.com/", Headers: map[string]string{}}}
	attempts, err := b.Build(sources, Options{Headers: true, HeaderNames: []string{"Host", "Referer"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].InjectionPoint != "Referer" {
		t.Fatalf("unexpected attempts: %#v", attempts)
	}
}
