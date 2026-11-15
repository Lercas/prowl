package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/publicaudit"
	"github.com/Lercas/prowl/tool/internal/report"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/secretindex"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

const webOwnedKey = "AKIANAFGYOEYPXU1DSYP"

func TestWebFailureStartsNewAcquisitionBoundary(t *testing.T) {
	coverage := model.NewCoverage()
	ctx := model.WithCoverage(t.Context(), coverage)
	ctx = context.WithValue(ctx, responseOriginKey{}, responseOrigin{"https://foreign.invalid/old", strings.Repeat("a", 64)})
	ctx = model.WithSourceLocator(ctx, func(string) string { return "https://foreign.invalid/old" })
	ch, _ := Discover(ctx, "https://owned.invalid", Options{})
	count := 0
	for it := range ch {
		count++
		if it.Error == nil || it.Meta["digest"] != nil || it.Meta["container_digest"] != nil || strings.Contains(it.Meta["source_url"].(string), "foreign") {
			t.Fatal("failed web acquisition borrowed old response provenance")
		}
	}
	complete, _, ds := coverage.Snapshot()
	if complete || count != 1 {
		t.Fatal("unauthorized source lost incomplete disposition")
	}
	for _, d := range ds {
		if strings.Contains(d.Path, "foreign") {
			t.Fatal("web diagnostic used a foreign source locator")
		}
	}
}

type webAuditFunc func(context.Context, string, string, map[string]string) *model.PublicKeyAudit

func (f webAuditFunc) Audit(ctx context.Context, typ, key string, fields map[string]string) *model.PublicKeyAudit {
	return f(ctx, typ, key, fields)
}

func TestWebDecodedStateCannotCreateConfigurationBindings(t *testing.T) {
	const key = "13ad45b4d0a2f6ea65ecbddf6aa260f2"
	config := `const config={app_id:'ABCDEF1234',algolia_api_key:'` + key + `'};`
	engine, err := rules.Load("../../rules/saas/algolia-api-key.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
		bound        bool
	}{
		{"literal-script", config, true},
		{"escaped-string", `const data="\u0022; ` + config + ` //";`, false},
		{"assignment-in-comment", `/*window.env={app_id:'ABCDEF1234',algolia_api_key:'` + key + `'}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transform := ""
			p := scan.New(scan.Options{Detector: detect.New(tax), Rules: engine, PublicAuditor: webAuditFunc(func(_ context.Context, typ, value string, fields map[string]string) *model.PublicKeyAudit {
				calls++
				if (fields["app_id"] == "ABCDEF1234") != tc.bound {
					t.Fatalf("derived state changed ownership of an application binding: transform=%s bound=%v", transform, fields["app_id"] == "ABCDEF1234")
				}
				return publicaudit.Inconclusive("owned audit fixture")
			})})
			items := ExtractStateBlobs("<script>"+tc.script+"</script>", "https://owned.invalid/app.js")
			if len(items) == 0 {
				t.Fatal("script fixture not extracted")
			}
			for _, it := range items {
				transform, _ = it.Meta["source_transform"].(string)
				p.Findings(t.Context(), it)
			}
			if calls == 0 {
				t.Fatal("fixture did not exercise the public-key candidate")
			}
		})
	}
}

func webTestPipeline(t *testing.T) *scan.Pipeline {
	t.Helper()
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	id, err := secretindex.LoadIdentity(t.TempDir()+"/index", true)
	if err != nil {
		t.Fatal(err)
	}
	return scan.New(scan.Options{Detector: detect.New(tax), IdentityKey: bytes.Repeat([]byte{7}, 32), ValueFingerprint: id.Fingerprint, LocationFingerprint: id.Location})
}

func TestWebResponseAndViewProvenance(t *testing.T) {
	state := `{"api_key":"\u0041` + webOwnedKey[1:] + `"}`
	markup := `<script id="__NEXT_DATA__" type="application/json">` + state + `</script><script src="/bundle.js?sig=PRIVATE_BUNDLE"></script>`
	bundle := `const token="` + webOwnedKey + `";` + "\n//# sourceMappingURL=/source.map?sig=PRIVATE_MAP"
	content := `const token="` + webOwnedKey + `";`
	mapping, _ := json.Marshal(map[string]any{"version": 3, "sources": []string{"same #?秘密.js", "same #?秘密.js"}, "sourcesContent": []string{content, content}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/page?sig=PRIVATE_PAGE")
			w.WriteHeader(302)
		case "/page":
			_, _ = io.WriteString(w, markup)
		case "/bundle.js":
			_, _ = io.WriteString(w, bundle)
		case "/source.map":
			_, _ = w.Write(mapping)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	coverage := model.NewCoverage()
	ctx := model.WithProvenance(model.WithCoverage(t.Context(), coverage), map[string]any{"commit": strings.Repeat("f", 40), "digest": strings.Repeat("a", 64)})
	ch, reached := Discover(ctx, server.URL, Options{Authorized: true, MaxAssets: 20, HTTPClient: server.Client()})
	var items []model.Item
	for it := range ch {
		items = append(items, it)
	}
	complete, _, ds := coverage.Snapshot()
	if !complete || !reached.Load() {
		t.Fatalf("owned discovery incomplete: %v", ds)
	}
	pipeline := webTestPipeline(t)
	var views []model.Item
	var viewFindings []model.Finding
	counts := map[string]int{}
	for _, it := range items {
		transform, _ := it.Meta["source_transform"].(string)
		counts[transform]++
		if it.Meta["commit"] != nil || it.Meta["digest"] != textDigest(it.Text) || strings.Contains(it.ArtifactURI, "PRIVATE_") {
			t.Fatal("web item lost content digest/boundary/privacy")
		}
		source, _ := it.Meta["source_url"].(string)
		u, err := url.Parse(source)
		if err != nil || u.RawQuery != "" || u.User != nil {
			t.Fatal("web provenance exposed request selection")
		}
		container := ""
		switch u.Path {
		case "/page":
			container = markup
		case "/bundle.js":
			container = bundle
		case "/source.map":
			container = string(mapping)
		default:
			t.Fatal("unrecognized source URL")
		}
		if it.Meta["container_digest"] != textDigest(container) {
			t.Fatal("derived view replaced its HTTP container digest")
		}
		fs := pipeline.Findings(t.Context(), it)
		for _, f := range fs {
			if f.Type == "aws_access_key_id" {
				if f.Provenance["container_digest"] != it.Meta["container_digest"] {
					t.Fatal("pipeline lost container digest")
				}
				if transform == "source-map-content" {
					viewFindings = append(viewFindings, f)
				}
			}
		}
		for _, format := range []string{"json", "sarif"} {
			var out bytes.Buffer
			if err := report.Write(&out, fs, format, false); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "PRIVATE_") {
				t.Fatal("report serialized a private request URL")
			}
		}
		if transform == "source-map-content" {
			views = append(views, it)
		}
	}
	if counts["web-response"] != 3 || counts["web-state-decoded"] == 0 || len(views) != 2 || len(viewFindings) != 2 {
		t.Fatalf("fixture missed raw/derived carriers: %v", counts)
	}
	if views[0].Path != views[1].Path || views[0].ArtifactURI == views[1].ArtifactURI || views[0].IdentityPath == views[1].IdentityPath {
		t.Fatal("duplicate map source names collapsed source identity")
	}
	if viewFindings[0].SecretID != viewFindings[1].SecretID || viewFindings[0].OccurrenceID == viewFindings[1].OccurrenceID || viewFindings[0].IndexLocationID == viewFindings[1].IndexLocationID {
		t.Fatal("duplicate map entries lost report/index observation identity")
	}
	for _, f := range viewFindings {
		u, err := url.Parse(f.IndexPath)
		if err != nil || u.Scheme != "web+http" || !strings.Contains(u.Fragment, "same #?秘密.js") {
			t.Fatal("index lost synthetic view fragment")
		}
	}
}

func TestWebPrefixDigestDoesNotClaimCompleteResponse(t *testing.T) {
	client := &http.Client{Transport: ownedTransport(func(r *http.Request) (*http.Response, error) {
		resp := ownedResponse(r, 200, "AWS="+webOwnedKey)
		resp.Body = &tailFailure{strings.NewReader("AWS=" + webOwnedKey)}
		return resp, nil
	})}
	coverage := model.NewCoverage()
	ch := make(chan model.Item, 8)
	newTextFetcher(client).fetchAll(model.WithCoverage(t.Context(), coverage), ch, []string{"https://owned.invalid/key.env?sig=PRIVATE_SELECTOR"}, "code", newBudget(8), 1, &contentSeen{seen: map[uint64]bool{}}, nil)
	close(ch)
	text, errors := 0, 0
	for it := range ch {
		if it.Error != nil {
			errors++
			if it.Meta["digest"] != nil || it.Meta["container_digest"] != nil {
				t.Fatal("failure invented immutable content")
			}
			continue
		}
		text++
		if it.Meta["source_transform"] != "web-response-prefix" || it.Meta["digest"] != textDigest(it.Text) || it.Meta["container_digest"] != textDigest(it.Text) {
			t.Fatal("retained prefix has misleading provenance")
		}
	}
	complete, _, _ := coverage.Snapshot()
	if complete || text != 1 || errors != 1 {
		t.Fatal("prefix was lost or certified complete")
	}
}

func TestWebPrivateSelectorsAndContainerChangesKeepDistinctObservations(t *testing.T) {
	pipeline := webTestPipeline(t)
	var findings []model.Finding
	for _, selector := range []string{"PRIVATE_ONE", "PRIVATE_TWO"} {
		content := fetchedText{url: "https://owned.invalid/app.js?sig=" + selector, text: "AWS=" + webOwnedKey, digest: textDigest("AWS=" + webOwnedKey)}
		ch := make(chan model.Item, 1)
		sendItem(responseContext(t.Context(), content), ch, responseItem(content, "code", true))
		it := <-ch
		fs := pipeline.Findings(t.Context(), it)
		if len(fs) != 1 {
			t.Fatal("typed fixture did not produce one finding")
		}
		findings = append(findings, fs[0])
	}
	if findings[0].Path != findings[1].Path || findings[0].Fingerprint == findings[1].Fingerprint || findings[0].OccurrenceID == findings[1].OccurrenceID || findings[0].IndexLocationID == findings[1].IndexLocationID {
		t.Fatal("sanitized URL collapsed private selector identity")
	}
	it := ExtractStateBlobs(`<script id="__NEXT_DATA__">{"key":"`+webOwnedKey+`"}</script>`, "https://owned.invalid/app.js")[0]
	first := pipeline.Findings(t.Context(), it)[0]
	it.Meta["container_digest"] = strings.Repeat("b", 64)
	second := pipeline.Findings(t.Context(), it)[0]
	if first.SecretID != second.SecretID || first.Fingerprint != second.Fingerprint || first.OccurrenceID == second.OccurrenceID {
		t.Fatal("container revision did not separate a derived observation")
	}
	it.Meta["container_digest"] = "invalid digest"
	third := pipeline.Findings(t.Context(), it)[0]
	if _, ok := third.Provenance["container_digest"]; ok {
		t.Fatal("unvalidated container digest entered a report")
	}
}
