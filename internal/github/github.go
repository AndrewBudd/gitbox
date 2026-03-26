// Package github provides SSH public key fetching from GitHub and GitHub Enterprise.
package github

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const DefaultHost = "github.com"

// FetchUserKeys fetches SSH public keys for a user on the given GitHub host.
// Both github.com and GitHub Enterprise expose keys at https://{host}/{username}.keys
func FetchUserKeys(host, username string) (string, error) {
	if host == "" {
		host = DefaultHost
	}

	if strings.ContainsAny(username, "/\\?&#") {
		return "", fmt.Errorf("invalid username: %q", username)
	}

	url := fmt.Sprintf("https://%s/%s.keys", host, username)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch keys from %s for %s: %w", host, username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", fmt.Errorf("user %q not found on %s", username, host)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s returned status %d for user %q", host, resp.StatusCode, username)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	data := strings.TrimSpace(string(body))
	if data == "" {
		return "", fmt.Errorf("user %q on %s has no public keys", username, host)
	}

	return data, nil
}

// DetectHost looks at the git remote "origin" and extracts the GitHub hostname.
// Returns "github.com" for public GitHub, or the enterprise hostname.
// Falls back to DefaultHost if detection fails.
func DetectHost(repoRoot string) string {
	cmd := exec.Command("git", "-C", repoRoot, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return DefaultHost
	}
	return ParseHostFromRemote(strings.TrimSpace(string(out)))
}

// SSH: git@github.com:org/repo.git or git@git.corp.com:org/repo.git
var sshRemoteRe = regexp.MustCompile(`^[\w.-]+@([\w.-]+):`)

// HTTPS: https://github.com/org/repo.git or https://git.corp.com/org/repo.git
var httpsRemoteRe = regexp.MustCompile(`^https?://([\w.-]+)/`)

// ParseHostFromRemote extracts the hostname from a git remote URL.
func ParseHostFromRemote(remoteURL string) string {
	if m := sshRemoteRe.FindStringSubmatch(remoteURL); len(m) > 1 {
		return m[1]
	}
	if m := httpsRemoteRe.FindStringSubmatch(remoteURL); len(m) > 1 {
		return m[1]
	}
	return DefaultHost
}
