package detect

import (
	"strings"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// kwSupplement adds cheap pre-filter keywords for types whose regex has no literal prefix.
// A type with an empty keyword set is always evaluated.
var kwSupplement = map[string][]string{
	"aws_secret_access_key": {"aws"},
	"gcp_service_account":   {"service_account", "private_key"},
	"azure_storage_key":     {"accountkey"},
	"datadog_api_key":       {"datadog"},
	"slack_webhook":         {"hooks.slack.com"},
	"twilio_api_key":        {"ac", "sk"},
	"sendgrid_api_key":      {"sg."},
	"private_key_pem":       {"private key"},
	"jwt":                   {"eyj"},
	"db_connection_string":  {"://"},
	"basic_auth_header":     {"authorization", "://"},
	"generic_api_key":       {"api", "key", "token", "access", "secret"},
	"generic_password":      {"pass", "pwd", "pw", "-p", "kennwort", "contraseña", "senha", "wachtwoord", "пароль", "parola", "salasana"},
	// generic_high_entropy: no keyword -> always run (entropy catch-all)
}

// structuralPrefilter gates types with no literal keyword on a precomputed structural signal.
var structuralPrefilter = map[string]func(structSignals) bool{
	"telegram_bot_token": func(s structSignals) bool { return s.digitColon },
	"discord_bot_token":  func(s structSignals) bool { return s.dottedToken },
}

// structSignals are the byte-level shapes the entropy/structural filters need.
type structSignals struct {
	digitColon  bool     // >=8 digits then ':' (telegram bot id)
	dottedToken bool     // >=50-char [A-Za-z0-9_.-] run with >=2 dots (discord token)
	b64runs     [][2]int // maximal [A-Za-z0-9+/] runs >= b64min (entropy candidates)
}

// scanStructure computes every structural signal in one pass.
func scanStructure(text string, b64min int) structSignals {
	var s structSignals
	n := len(text)
	b64start, digitRun, tokStart, tokDots := -1, 0, -1, 0
	for i := 0; i < n; i++ {
		c := text[i]
		alnum := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if alnum || c == '+' || c == '/' {
			if b64start < 0 {
				b64start = i
			}
		} else {
			if b64start >= 0 && i-b64start >= b64min {
				s.b64runs = append(s.b64runs, [2]int{b64start, i})
			}
			b64start = -1
		}
		if c >= '0' && c <= '9' {
			digitRun++
		} else {
			if c == ':' && digitRun >= 8 {
				s.digitColon = true
			}
			digitRun = 0
		}
		if alnum || c == '_' || c == '-' || c == '.' {
			if tokStart < 0 {
				tokStart, tokDots = i, 0
			}
			if c == '.' {
				tokDots++
			}
		} else {
			if tokStart >= 0 && i-tokStart >= 50 && tokDots >= 2 {
				s.dottedToken = true
			}
			tokStart = -1
		}
	}
	if b64start >= 0 && n-b64start >= b64min {
		s.b64runs = append(s.b64runs, [2]int{b64start, n})
	}
	if tokStart >= 0 && n-tokStart >= 50 && tokDots >= 2 {
		s.dottedToken = true
	}
	return s
}

func normPrefix(p string) string {
	return strings.ToLower(strings.TrimRight(p, "_-./ "))
}

// keywordsFor derives the cheap substrings that must be present for a type's regex to match.
func keywordsFor(st taxonomy.SecretType) []string {
	set := map[string]bool{}
	for _, p := range st.Detection.Prefixes {
		if k := normPrefix(p); len(k) >= 2 {
			set[k] = true
		}
	}
	for _, k := range kwSupplement[st.ID] {
		set[strings.ToLower(k)] = true
	}
	// external rules (gitleaks/trufflehog) carry their own keywords
	for _, k := range st.Keywords {
		if len(k) >= 2 {
			set[strings.ToLower(k)] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
