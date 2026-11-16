package scan

import (
	"net/url"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
)

// Preserve the released nomination contract for narrowly established lexical
// evidence. This never proves provider acceptance and does not protect contextual
// guesses, semantic candidates or a name borrowed from elsewhere in an ML window.
func mlAnchoredEvidence(f model.Finding, r mlscore.Record) bool {
	stage := f.Stage
	for _, prefix := range []string{"normalized/json-string/", "normalized/yaml-scalar/", "normalized/toml-string/"} {
		stage = strings.TrimPrefix(stage, prefix)
	}
	name := strings.ToLower(r.DirectBinding)
	if (f.Type == "generic_high_entropy" && stage == "L1-entropy" || f.Type == "generic_api_key" && (stage == "L1-regex" || stage == "L1-context-key")) &&
		detect.IsSecretBindingName(name) && len(r.Value) >= 32 && len(r.Value) <= 128 && isHexCredential(r.Value) {
		return true
	}
	// The released lexical password grammar started at six bytes. Newly added
	// shorter values retain the qualified 1.5 model's ordinary drop decision.
	if f.Type == "generic_password" && stage == "L1-regex" && len(r.Value) >= 6 {
		if name == "pass" || name == "pw" || strings.HasSuffix(name, "_pass") || strings.HasSuffix(name, "_pw") || strings.HasSuffix(name, ".pass") || strings.HasSuffix(name, ".pw") {
			return true
		}
		for _, cue := range []string{"password", "passphrase", "passwd", "pwd", "passwort", "kennwort", "contraseña", "wachtwoord", "пароль", "parola", "salasana", "senha"} {
			if strings.HasSuffix(name, cue) {
				return true
			}
		}
	}
	if stage != "rule" {
		return false
	}
	switch f.Type {
	case "assemblyai-api-key", "together-api-key", "linode-api-token":
		provider := strings.Split(f.Type, "-")[0]
		return strings.HasPrefix(name, provider) && (strings.HasSuffix(name, "key") || strings.HasSuffix(name, "token"))
	case "deepgram-api-key":
		binding := strings.NewReplacer("_", "", "-", "", ".", "").Replace(name)
		return (binding == "deepgram" || binding == "deepgramapikey" || binding == "deepgramkey" || binding == "deepgramtoken") && base36Credential(r.Value, 40)
	case "twitch-client-secret":
		binding := strings.NewReplacer("_", "", "-", "", ".", "").Replace(name)
		return (binding == "twitch" || binding == "twitchclientsecret" || binding == "twitchsecret") && base36Credential(r.Value, 30)
	case "netlify-access-token":
		return strings.HasPrefix(r.Value, "nfp_") && len(r.Value) == 40
	case "sentry-dsn":
		u, err := url.Parse(r.Value)
		if err != nil || u.User == nil {
			return false
		}
		password, present := u.User.Password()
		return present && len(password) == 32 && len(u.User.Username()) == 32
	}
	return false
}

func base36Credential(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func isHexCredential(value string) bool {
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return value != ""
}
