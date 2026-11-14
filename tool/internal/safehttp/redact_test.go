package safehttp

import "testing"

func TestRedactURLAuthorityBoundaries(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"https://user:token@host.example", "https://***@host.example"},
		{"https://user:token@host.example?mail=a@b", "https://***@host.example?mail=a@b"},
		{"https://user:token@host.example#mail=a@b", "https://***@host.example#mail=a@b"},
		{"https://user:p@ss@host.example?next=/a@b", "https://***@host.example?next=/a@b"},
		{"https://user:p@ss@host.example#next=/a@b", "https://***@host.example#next=/a@b"},
		{"https://user:bad%escape@host.example?mail=a@b", "https://***@host.example?mail=a@b"},
		{"ssh://user:token@[2001:db8::1]:22?mail=a@b", "ssh://***@[2001:db8::1]:22?mail=a@b"},
		{"https://user:token@host.example/a@b?mail=c@d#e@f", "https://***@host.example/a@b?mail=c@d#e@f"},
		{"https://host.example?mail=a@b", "https://host.example?mail=a@b"},
		{"https://host.example#mail=a@b", "https://host.example#mail=a@b"},
		{"https://host.example?next=/a@b", "https://host.example?next=/a@b"},
		{"https://host.example#next=/a@b", "https://host.example#next=/a@b"},
		{"https://host.example/a@b?mail=c@d#e@f", "https://host.example/a@b?mail=c@d#e@f"},
		{"git@host.example:repo.git", "git@host.example:repo.git"},
		{"local/path@host", "local/path@host"},
		{"https://host.example?", "https://host.example?"},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			if got := RedactURL(tt.raw); got != tt.want {
				t.Fatalf("redacted URL = %q, want %q", got, tt.want)
			}
		})
	}
}
