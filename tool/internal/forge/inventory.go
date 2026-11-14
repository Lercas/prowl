package forge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/Lercas/prowl/tool/internal/model"
)

const (
	maxListingRows = 100
	maxJSONBody    = 32 << 20
	hardMaxPages   = 4096
)

// Inventory records only the observed API result. Tokens, provider identity, atomic snapshot and
// remote absence are deliberately not inferred from a successful paginated listing.
func recordInventory(ctx context.Context, target string, gists bool, urls []string, err error) {
	names := make([]string, 0, len(urls))
	seen := make(map[string]bool, len(urls))
	for _, raw := range urls {
		name := model.SafeLocator(raw)
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	sort.Strings(names)
	raw, _ := json.Marshal(names)
	sum := sha256.Sum256(raw)
	model.CoverageFrom(ctx).RegisterScope("forge-inventory", target, struct {
		Revision           string
		Gists              bool
		MaxPages           int
		Complete           bool
		Observed           int
		RepositoriesDigest string
	}{"1.5.0-forge-v1", gists, maxPages, err == nil, len(urls), hex.EncodeToString(sum[:])})
	if err != nil {
		model.Note(ctx, "forge_inventory_incomplete", target, true)
	}
}

func registerAPI(ctx context.Context, raw string, hdr map[string]string) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	authenticated := hdr["Authorization"] != "" || hdr["PRIVATE-TOKEN"] != ""
	model.CoverageFrom(ctx).RegisterScope("forge-api", u.String(), struct {
		Revision              string
		MaxPages, Rows, Bytes int
		CredentialsConfigured bool
	}{"1.5.0-forge-v1", maxPages, maxListingRows, maxJSONBody, authenticated})
}

func validCloneEntry(raw string) bool {
	return raw != "" && len(raw) <= 4096 && !strings.ContainsAny(raw, "\x00\r\n")
}

// API overrides select a base endpoint, not an authentication URL or an implicit query filter.
func apiBase(raw string) (string, error) {
	if len(raw) > 8192 {
		return "", errors.New("repository API endpoint exceeds size limit")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsRune(raw, '#') {
		return "", errors.New("invalid repository API base endpoint")
	}
	return strings.TrimRight(raw, "/"), nil
}
