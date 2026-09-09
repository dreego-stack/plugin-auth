package auth

import (
	"os"
	"strings"
	"testing"
)

func TestBrowserRequestsForwardDreegoCSRFToken(t *testing.T) {
	for _, path := range []string{"client/core.js", "client/passkeys.js"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "api.headers()") {
			t.Fatalf("%s does not use the shared CSRF-aware headers", path)
		}
	}
}
