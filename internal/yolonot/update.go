package yolonot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// checkForUpdate checks GitHub for a newer release. Returns the new version
// string if available, or empty if current is latest (or check fails).
func checkForUpdate() string {
	if Version == "dev" {
		return ""
	}

	latest, err := fetchLatestVersion(3 * time.Second)
	if err != nil {
		return ""
	}
	clean := strings.Split(Version, "+")[0]
	if latest != "" && latest != clean && latest > clean {
		return latest
	}
	return ""
}

// fetchLatestVersion calls the GitHub releases API. Returns (tag, nil) on
// success, ("", err) on any failure — callers can present a human-friendly
// reason. Timeout is a parameter so the hint path can stay snappy while
// user-invoked `upgrade` gets a more forgiving window.
func fetchLatestVersion(timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("https://api.github.com/repos/sezaakgun/yolonot/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", errors.New("github api returned empty tag_name")
	}
	return release.TagName, nil
}

// explainFetchError turns a fetch error into a short, actionable reason.
// Stays intentionally boring — the goal is to help the user decide whether
// to retry or fall back to the manual install command.
func explainFetchError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// net/http wraps timeouts with a "Client.Timeout exceeded" marker;
	// also cover the bare DeadlineExceeded case for robustness.
	if strings.Contains(msg, "Client.Timeout") || errors.Is(err, context.DeadlineExceeded) {
		return "network timeout talking to api.github.com"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed for api.github.com (check your network)"
	}
	if strings.Contains(msg, "status 403") {
		return "GitHub API rate-limited this IP (unauthenticated limit is 60/hr)"
	}
	if strings.Contains(msg, "status 404") {
		return "release not found on GitHub"
	}
	if strings.Contains(msg, "status ") {
		return msg
	}
	return "could not reach api.github.com (" + msg + ")"
}

func printUpdateHint() {
	if newer := checkForUpdate(); newer != "" {
		fmt.Printf("  Update:   %s available (current: %s)\n", newer, Version)
		fmt.Printf("            run: yolonot upgrade\n")
	}
}

func cmdUpgrade() {
	fmt.Printf("Current version: %s\n", Version)
	fmt.Print("Checking for updates... ")

	latest, err := fetchLatestVersion(8 * time.Second)
	if err != nil {
		fmt.Println("failed")
		fmt.Printf("  Reason: %s\n", explainFetchError(err))
		fmt.Println("  Fallback: go install github.com/sezaakgun/yolonot@latest")
		return
	}

	cleanVersion := strings.Split(Version, "+")[0] // strip +dirty, +incompatible, etc.
	if latest == cleanVersion || (cleanVersion != "dev" && latest <= cleanVersion) {
		fmt.Printf("up to date (%s)\n", Version)
		return
	}

	fmt.Printf("found %s\n\n", latest)
	fmt.Printf("Upgrading to %s...\n", latest)

	cmd := exec.Command("go", "install", "github.com/sezaakgun/yolonot@"+latest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Upgrade failed: %v\n", err)
		return
	}

	fmt.Printf("\nUpgraded to %s.\n", latest)
	fmt.Println("Hooks and skill were not modified.")
	fmt.Println("If this release's notes require it, run 'yolonot install' manually.")
	fmt.Println("Restart Claude Code to load the new binary.")
}
