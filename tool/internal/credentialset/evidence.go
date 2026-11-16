package credentialset

// Evidence exposes only canonical roles and keyed location identities.
type Evidence struct {
	Primary []string            `json:"primary"`
	Fields  map[string][]string `json:"fields"`
}
