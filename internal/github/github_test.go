package github

import "testing"

func TestParseHostFromRemote(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		// SSH format
		{"git@github.com:org/repo.git", "github.com"},
		{"git@git.corp.com:org/repo.git", "git.corp.com"},
		{"git@github.example.io:team/project.git", "github.example.io"},
		{"deploy@ghes.internal.net:infra/secrets.git", "ghes.internal.net"},

		// HTTPS format
		{"https://github.com/org/repo.git", "github.com"},
		{"https://git.corp.com/org/repo.git", "git.corp.com"},
		{"http://github.example.io/team/project.git", "github.example.io"},
		{"https://ghes.internal.net/infra/secrets.git", "ghes.internal.net"},

		// Edge cases
		{"", DefaultHost},
		{"not-a-url", DefaultHost},
	}

	for _, tt := range tests {
		got := ParseHostFromRemote(tt.remote)
		if got != tt.want {
			t.Errorf("ParseHostFromRemote(%q) = %q, want %q", tt.remote, got, tt.want)
		}
	}
}
