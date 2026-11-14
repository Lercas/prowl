package atlassian

import (
	"errors"
	"reflect"
)

// validateResponse checks the data needed for a complete walk. Unknown metadata is deliberately
// tolerated; empty arrays and an explicitly empty body value are legitimate data, unlike null or
// missing required fields. No provider-controlled text is included in errors.
func validateResponse(out any) error {
	bad := errors.New("atlassian response is missing or has invalid required data")
	v := reflect.ValueOf(out).Elem()
	if v.IsZero() && (v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Pointer) {
		return bad
	}
	validProjects := func(projects []jiraProject) bool {
		if projects == nil {
			return false
		}
		for _, p := range projects {
			if p.Key == "" {
				return false
			}
		}
		return true
	}
	validHistories := func(histories []jiraHistory) bool {
		if histories == nil {
			return false
		}
		for _, h := range histories {
			if h.Items == nil {
				return false
			}
		}
		return true
	}
	switch p := out.(type) {
	case *jiraServerInfo:
		if p.DeploymentType == "" && p.Version == "" && p.BaseURL == "" {
			return bad
		}
	case *[]jiraProject:
		if !validProjects(*p) {
			return bad
		}
	case *jiraProjectPage:
		if !validProjects(p.Values) || p.StartAt < 0 || p.Total < 0 || p.MaxResults < 0 {
			return bad
		}
	case *jiraSearchPage:
		if p.Issues == nil || p.StartAt < 0 || p.Total < 0 || p.MaxResults < 0 {
			return bad
		}
		for _, issue := range p.Issues {
			if issue.Key == "" || issue.Fields == nil {
				return bad
			}
		}
	case *jiraCommentPage:
		if p.Comments == nil || p.StartAt < 0 || p.Total < 0 || p.MaxResults < 0 {
			return bad
		}
		for _, comment := range p.Comments {
			if comment.ID == "" || !jiraCommentBody(comment.Body) {
				return bad
			}
		}
	case *jiraChangelogPage:
		if !validHistories(p.entries()) || (p.Values != nil && p.Histories != nil) || p.StartAt < 0 || p.Total < 0 || p.MaxResults < 0 {
			return bad
		}
	case *jiraEmbeddedHistory:
		if !validHistories(p.Changelog.Histories) || p.Changelog.Values != nil || p.Changelog.Total < 0 {
			return bad
		}
	case *jiraBulkHistoryPage:
		if p.IssueChangeLogs == nil {
			return bad
		}
		for _, history := range p.IssueChangeLogs {
			if history.IssueID == "" || !validHistories(history.ChangeHistories) {
				return bad
			}
		}
	case *confSpacesPageV2:
		if p.Results == nil {
			return bad
		}
		for _, space := range p.Results {
			if space.ID == "" || space.Key == "" {
				return bad
			}
		}
	case *confSpacesPageV1:
		if p.Results == nil || p.Size < 0 || p.Limit < 0 {
			return bad
		}
		for _, space := range p.Results {
			if space.Key == "" {
				return bad
			}
		}
	case *confPagesPageV2:
		if p.Results == nil {
			return bad
		}
		for _, page := range p.Results {
			if page.ID == "" || page.Version.Number < 0 {
				return bad
			}
		}
	case *confContentPageV1:
		if p.Results == nil || p.Size < 0 || p.Limit < 0 {
			return bad
		}
		for _, page := range p.Results {
			if page.ID == "" || page.Version.Number < 0 {
				return bad
			}
		}
	case *confVersionsPageV2:
		if p.Results == nil {
			return bad
		}
		for _, version := range p.Results {
			if version.Number < 1 {
				return bad
			}
		}
	case *confVersionsPageV1:
		if p.Results == nil || p.Size < 0 || p.Limit < 0 {
			return bad
		}
		for _, version := range p.Results {
			if version.Number < 1 {
				return bad
			}
		}
	case *confPageBodyV2:
		if p.Body.Storage.Value == nil || p.Version.Number < 0 {
			return bad
		}
	case *confContentV1:
		if p.Body.Storage.Value == nil || p.Version.Number < 0 {
			return bad
		}
	}
	return nil
}
