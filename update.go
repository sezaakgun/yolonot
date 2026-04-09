package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// checkForUpdate checks GitHub for a newer release. Returns the new version
// string if available, or empty if current is latest (or check fails/skipped).
// Caches the result for 24 hours to avoid spamming GitHub.
func checkForUpdate() string {
	if Version == "dev" {
		return ""
	}

	cacheFile := filepath.Join(YolonotDir(), "update-check")

	// Check cache — skip if checked within 24 hours
	if data, err := os.ReadFile(cacheFile); err == nil {
		parts := strings.SplitN(string(data), "\n", 2)
		if len(parts) == 2 {
			if ts, err := time.Parse(time.RFC3339, parts[0]); err == nil {
				if time.Since(ts) < 24*time.Hour {
					if parts[1] == "" || parts[1] == Version {
						return ""
					}
					return parts[1]
				}
			}
		}
	}

	// Fetch latest release from GitHub
	latest := fetchLatestVersion()

	// Cache the result
	os.MkdirAll(YolonotDir(), 0755)
	cache := time.Now().UTC().Format(time.RFC3339) + "\n" + latest
	os.WriteFile(cacheFile, []byte(cache), 0644)

	clean := strings.Split(Version, "+")[0]
	if latest != "" && latest != clean && latest > clean {
		return latest
	}
	return ""
}

func fetchLatestVersion() string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/sezaakgun/yolonot/releases/latest")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ""
	}
	return release.TagName
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

	latest := fetchLatestVersion()
	if latest == "" {
		fmt.Println("failed to check")
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

	fmt.Printf("\nUpgraded to %s. Run 'yolonot install' to update hooks.\n", latest)

	// Clear cache so next run doesn't show update hint
	os.Remove(filepath.Join(YolonotDir(), "update-check"))
}
