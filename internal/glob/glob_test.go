package glob

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, text string
		want          bool
	}{
		{"*rm -rf /*", "rm -rf /", true},
		{"curl localhost*", "curl localhost:8080/health", true},
		{"*curl *", "curl https://example.com", true},
		{"*curl *", "kubectl get pods", false},
		{"scripts/*", "scripts/test.sh", true},
		{"scripts/*", "deploy/run.sh", false},
		{"*sudo *", "sudo rm -rf /", true},
		{"echo*", "echo hello", true},
		{"echo*", "cat file", false},
	}
	for _, tt := range tests {
		got := Match(tt.pattern, tt.text)
		if got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.text, got, tt.want)
		}
	}
}
