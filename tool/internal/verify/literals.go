package verify

import "strings"

var literalSeparators = strings.NewReplacer("_", "", "-", "", ".", "")

func literalName(name string) string {
	return literalSeparators.Replace(strings.ToLower(name))
}

// Aliases identify explicit property names, never a search through sibling values.
func literalAliases(name string) []string {
	aliases := []string{literalName(name)}
	switch name {
	case "aws_secret_access_key":
		aliases = append(aliases, "secretaccesskey")
	case "aws_access_key_id":
		aliases = append(aliases, "accesskeyid")
	case "account_sid":
		aliases = append(aliases, "twilioaccountsid")
	}
	return aliases
}

func literalVars(v *Verifier, typ, value string, bindings map[string]string) (map[string]string, bool) {
	vars := map[string]string{"secret": value}
	if len(v.extractRes) > 0 && len(bindings) > 128 {
		return nil, false
	}
	for name, re := range v.extractRes {
		found := ""
		hasFound := false
		// A typed primary is authoritative even when stored under api_key.
		if literalName(name) == literalName(typ) || name == "secret" {
			found, hasFound = value, true
		}
		aliases := literalAliases(name)
		for key, raw := range bindings {
			key = literalName(key)
			for _, alias := range aliases {
				if key != alias {
					continue
				}
				if hasFound && found != raw {
					return nil, false
				}
				found, hasFound = raw, true
			}
		}
		span := re.FindStringIndex(found)
		if found == "" || span == nil || span[0] != 0 || span[1] != len(found) {
			return nil, false
		}
		vars[name] = found
	}
	return vars, true
}
