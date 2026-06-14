package callback

import "testing"

func TestFromListener(t *testing.T) {
	tpl, err := FromListener("abcd1234.pingback.sh")
	if err != nil {
		t.Fatal(err)
	}
	got := tpl.URL("pba-test")
	want := "http://abcd1234.pingback.sh/pbscan/pba-test"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestTemplateRequiresToken(t *testing.T) {
	if _, err := NewTemplate("https://example.com/callback"); err == nil {
		t.Fatal("expected error")
	}
}
