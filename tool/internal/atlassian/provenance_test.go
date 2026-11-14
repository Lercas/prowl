package atlassian

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestAcquisitionScopeProtectsContextPathAndSnapshotsSelection(t *testing.T) {
	selection := []string{"Z", "A"}
	c := model.NewCoverage()
	opts := Options{Projects: selection, MaxItems: 100, HTTPClient: &http.Client{Transport: fixtureTransport(func(*http.Request) (int, any) { return 200, nil })}}
	registerScope(model.WithCoverage(context.Background(), c), "https://owned.invalid/private-context", "jira", opts)
	before := model.NewResult(nil, c)
	selection[0] = "changed"
	if !reflect.DeepEqual(before.Scope, model.NewResult(nil, c).Scope) {
		t.Fatal("scope retained mutable options")
	}
	raw, _ := json.Marshal(before)
	if len(before.Scope) != 1 || before.Scope[0].Target != "https://owned.invalid" || strings.Contains(string(raw), "private-context") {
		t.Fatal("context path leaked")
	}
	d := model.NewCoverage()
	opts.Projects = []string{"A", "Z"}
	registerScope(model.WithCoverage(context.Background(), d), "https://owned.invalid/private-context", "jira", opts)
	if !reflect.DeepEqual(before.Scope, model.NewResult(nil, d).Scope) {
		t.Fatal("selection ordering changed scope")
	}
	d = model.NewCoverage()
	registerScope(model.WithCoverage(context.Background(), d), "https://owned.invalid/other-context", "jira", opts)
	if before.Scope[0].Policy == model.NewResult(nil, d).Scope[0].Policy {
		t.Fatal("different tenant context collapsed")
	}
}

func TestCollectedMetadataDoesNotClaimImmutableRevision(t *testing.T) {
	for _, product := range []string{"jira", "confluence"} {
		var items []model.Item
		if product == "jira" {
			s := jiraCloudMock()
			defer s.Close()
			items = collect(t, s.URL, product, Options{})
		} else {
			s := confluenceCloudMock()
			defer s.Close()
			items = collect(t, s.URL, product, Options{})
		}
		found := false
		for _, it := range items {
			if it.Error != nil {
				continue
			}
			found = true
			if it.Meta["source_url"] == "" || it.Meta["source_version"] == nil || it.Meta["digest"] != nil || it.Meta["commit"] != nil {
				t.Fatalf("invalid producer provenance: %+v", it.Meta)
			}
		}
		if !found {
			t.Fatal("positive control missing")
		}
	}
	original := map[string]any{"url": "https://u:private@owned.invalid/page?token=private", "version": "history"}
	item := model.Item{Meta: original}
	attachSourceMetadata(&item)
	if item.Meta["source_url"] != "https://owned.invalid/page" || original["source_url"] != nil {
		t.Fatal("unsafe or mutating metadata attachment")
	}
}

func TestCollectionErrorsAndBudgetsUpdateCoverageLedger(t *testing.T) {
	for _, budget := range []int{1, 10} {
		c := model.NewCoverage()
		opts := Options{Projects: []string{"P"}, CurrentOnly: true, MaxItems: budget, HTTPClient: &http.Client{Transport: fixtureTransport(func(r *http.Request) (int, any) {
			switch r.URL.Path {
			case "/rest/api/2/serverInfo":
				return 200, map[string]any{"deploymentType": "Cloud"}
			case "/rest/api/3/search/jql":
				first := cloudIssue()
				first["fields"].(map[string]any)["comment"] = nil
				return 200, map[string]any{"isLast": true, "issues": []any{first, map[string]any{"id": "2", "key": "P-2", "fields": map[string]any{"summary": "second readable content"}}}}
			}
			return 403, "private response"
		})}}
		items, _, err := Collect(model.WithCoverage(context.Background(), c), "https://owned.invalid", "jira", Auth{PAT: "private auth"}, opts)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for it := range items {
			if it.Error == nil {
				n++
			}
		}
		result := model.NewResult(nil, c)
		if n == 0 || result.Complete || len(result.Diagnostics) == 0 || len(result.Scope) != 2 {
			t.Fatalf("lost coverage/partial content: %+v", result)
		}
		if budget == 1 && n != 1 {
			t.Fatal("budget exceeded")
		}
	}
}
