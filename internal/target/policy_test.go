package target

import "testing"

func TestValidateRejectsPrivateTargets(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/", "http://10.0.0.1/", "http://localhost/"} {
		if err := Validate(raw, false); err == nil {
			t.Fatalf("expected %s to be rejected", raw)
		}
	}
}

func TestValidateAllowsPublicAndExplicitPrivate(t *testing.T) {
	if err := Validate("https://example.com/path", false); err != nil {
		t.Fatal(err)
	}
	if err := Validate("http://127.0.0.1/", true); err != nil {
		t.Fatal(err)
	}
}
