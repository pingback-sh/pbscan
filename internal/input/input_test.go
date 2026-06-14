package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRawRequestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.txt")
	request := "POST /api/fetch?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nAuthorization: Bearer demo\r\nContent-Length: 24\r\n\r\n{\"url\":\"https://a.test\"}"
	if err := os.WriteFile(path, []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := RawRequestFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if src.Method != "POST" || src.URL != "https://example.com/api/fetch?x=1" {
		t.Fatalf("unexpected source: %#v", src)
	}
	if src.Headers["Authorization"] != "Bearer demo" {
		t.Fatalf("authorization header not preserved")
	}
}
