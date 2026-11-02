package yolonot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMissingModelCredentialNeverContactsProvider(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(401) }))
	defer srv.Close()
	t.Setenv("YOLONOT_TEST_MISSING_KEY", "")
	cfg := (Config{Models: map[string]ModelConfig{"fixture": {URL: srv.URL, Model: "test", EnvKey: "YOLONOT_TEST_MISSING_KEY"}}}).ModelLLM("fixture")
	for _, typed := range []bool{false, true} {
		var err error
		if typed {
			_, err = decisionPost(cfg, "fixture")
		} else {
			_, err = CallLLM(cfg, "system", "fixture", 10)
		}
		if err == nil || !strings.Contains(err.Error(), "missing API key") || !strings.Contains(err.Error(), "YOLONOT_TEST_MISSING_KEY") || !strings.Contains(err.Error(), ".zshrc") {
			t.Fatalf("unhelpful error: %v", err)
		}
	}
	if calls != 0 {
		t.Fatalf("sent %d unauthenticated requests", calls)
	}
}

func TestModelAuthenticationErrorsDoNotExposeCredentials(t *testing.T) {
	for _, status := range []int{401, 403} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte("provider body secret-canary"))
		}))
		cfg := LLMConfig{URL: srv.URL, Model: "fixture", APIKey: "secret-canary"}
		for _, typed := range []bool{false, true} {
			var err error
			if typed {
				_, err = decisionPost(cfg, "fixture")
			} else {
				_, err = CallLLM(cfg, "system", "fixture", 10)
			}
			if err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), "secret-canary") {
				t.Fatalf("unsafe/unhelpful error: %v", err)
			}
		}
		srv.Close()
	}
}

func TestAnonymousModelStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	out, err := CallLLM(LLMConfig{URL: srv.URL, Model: "local"}, "system", "fixture", 10)
	if err != nil || out != "ok" {
		t.Fatalf("anonymous endpoint: %q %v", out, err)
	}
}
