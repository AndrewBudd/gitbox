// Package hook provides git pre-commit hook integration for GitBox.
package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookScript = `#!/bin/sh
# GitBox pre-commit hook
# Prevents plaintext secret source files from being committed.
# Encrypted .gitbox/secrets/*.yaml files are safe to commit.

GITBOX_DIR=".gitbox"

if [ ! -d "$GITBOX_DIR" ]; then
    exit 0
fi

# Check if any tracked secrets config exists
if [ ! -f "$GITBOX_DIR/config.yaml" ]; then
    exit 0
fi

# Get list of staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

# Check for plaintext files that should be encrypted
ERRORS=""
for file in $STAGED; do
    # Check if this file is listed in .gitbox/.tracked as a plaintext source
    if [ -f "$GITBOX_DIR/.tracked" ]; then
        if grep -qF "$file" "$GITBOX_DIR/.tracked"; then
            ERRORS="${ERRORS}  BLOCKED: ${file} (plaintext secret - must be encrypted first)\n"
        fi
    fi
done

if [ -n "$ERRORS" ]; then
    echo ""
    echo "GitBox: Blocked commit - plaintext secrets detected in staging area:"
    echo ""
    printf "$ERRORS"
    echo ""
    echo "Run 'gitbox encrypt' to encrypt secrets before committing."
    echo "The encrypted versions in .gitbox/secrets/ are safe to commit."
    exit 1
fi

# All good - .gitbox/secrets/*.yaml and .gitbox/identities/*.yaml are safe
exit 0
`

// InstallHook installs the GitBox pre-commit hook in the given repo.
// If a pre-commit hook already exists, it appends the GitBox check.
func InstallHook(repoRoot string) error {
	hookDir := filepath.Join(repoRoot, ".git", "hooks")
	if _, err := os.Stat(hookDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository (no .git/hooks found)")
	}

	hookPath := filepath.Join(hookDir, "pre-commit")

	// Check if hook already exists
	if data, err := os.ReadFile(hookPath); err == nil {
		content := string(data)
		if strings.Contains(content, "GitBox pre-commit hook") {
			return fmt.Errorf("gitbox hook already installed")
		}
		// Append to existing hook
		updated := content + "\n\n" + hookScript
		if err := os.WriteFile(hookPath, []byte(updated), 0755); err != nil {
			return fmt.Errorf("update existing hook: %w", err)
		}
		return nil
	}

	// Create new hook
	if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

// TrackFile adds a plaintext file path to the tracked list.
// The pre-commit hook uses this to block plaintext files from being committed.
func TrackFile(repoRoot, filePath string) error {
	trackedPath := filepath.Join(repoRoot, ".gitbox", ".tracked")

	var existing string
	if data, err := os.ReadFile(trackedPath); err == nil {
		existing = string(data)
		// Check if already tracked
		for _, line := range strings.Split(existing, "\n") {
			if strings.TrimSpace(line) == filePath {
				return nil // Already tracked
			}
		}
	}

	f, err := os.OpenFile(trackedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open tracked file: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintln(f, filePath)
	return err
}

// UntrackFile removes a plaintext file path from the tracked list.
func UntrackFile(repoRoot, filePath string) error {
	trackedPath := filepath.Join(repoRoot, ".gitbox", ".tracked")
	data, err := os.ReadFile(trackedPath)
	if err != nil {
		return nil // No tracked file, nothing to do
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" && strings.TrimSpace(line) != filePath {
			lines = append(lines, line)
		}
	}

	return os.WriteFile(trackedPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// EnsureGitignore adds plaintext secret paths to .gitignore.
func EnsureGitignore(repoRoot string, paths ...string) error {
	gitignorePath := filepath.Join(repoRoot, ".gitignore")

	var existing string
	if data, err := os.ReadFile(gitignorePath); err == nil {
		existing = string(data)
	}

	var toAdd []string
	for _, p := range paths {
		if !strings.Contains(existing, p) {
			toAdd = append(toAdd, p)
		}
	}

	if len(toAdd) == 0 {
		return nil
	}

	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Add a header comment if this is new content
	if !strings.Contains(existing, "# GitBox") {
		fmt.Fprintln(f, "\n# GitBox - plaintext secrets (DO NOT REMOVE)")
	}
	for _, p := range toAdd {
		fmt.Fprintln(f, p)
	}
	return nil
}
