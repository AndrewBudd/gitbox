// Package github provides GitHub SSH public key fetching.
package github

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchUserKeys fetches SSH public keys for a GitHub user.
// GitHub exposes these at https://github.com/{username}.keys
func FetchUserKeys(username string) (string, error) {
	// Validate username to prevent path traversal
	if strings.ContainsAny(username, "/\\?&#") {
		return "", fmt.Errorf("invalid github username: %q", username)
	}

	url := fmt.Sprintf("https://github.com/%s.keys", username)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch keys for %s: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("github user %q not found", username)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github returned status %d for user %q", resp.StatusCode, username)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	data := strings.TrimSpace(string(body))
	if data == "" {
		return "", fmt.Errorf("github user %q has no public keys", username)
	}

	return data, nil
}
