package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type invalidNotification struct {
	name, method, params string
}

func invalidNotifications() []invalidNotification {
	const document = `{"uri":"file:///params.py","version":2,"languageId":"python","text":"clean"}`
	const change = `{"textDocument":` + document + `,"contentChanges":[{"text":"clean"}]}`
	const open = `{"textDocument":` + document + `}`
	var cases []invalidNotification
	for _, method := range []string{"didOpen", "didChange", "didSave", "didClose"} {
		for name, params := range map[string]string{
			"null":               `null`,
			"array":              `[]`,
			"missing-document":   `{}`,
			"null-document":      `{"textDocument":null}`,
			"empty-uri":          `{"textDocument":{"uri":""},"text":"clean"}`,
			"null-uri":           `{"textDocument":{"uri":null},"text":"clean"}`,
			"relative-uri":       `{"textDocument":{"uri":"params.py"},"text":"clean"}`,
			"bad-uri-escape":     `{"textDocument":{"uri":"file:///params%zz.py"},"text":"clean"}`,
			"bad-opaque-escape":  `{"textDocument":{"uri":"untitled:params%zz.py"},"text":"clean"}`,
			"bad-query-escape":   `{"textDocument":{"uri":"file:///params.py?value=%zz"},"text":"clean"}`,
			"duplicate-document": `{"textDocument":` + document + `,"textDocument":` + document + `,"text":"clean"}`,
			"duplicate-uri":      `{"textDocument":{"uri":"file:///params.py","uri":"file:///other.py"},"text":"clean"}`,
			"invalid-encoding":   `{"textDocument":{"uri":"file:///\ud800.py"},"text":"clean"}`,
		} {
			cases = append(cases, invalidNotification{method + "-" + name, "textDocument/" + method, params})
		}
	}
	for name, params := range map[string]string{
		"missing-text":     strings.Replace(open, `,"text":"clean"`, "", 1),
		"null-text":        strings.Replace(open, `"text":"clean"`, `"text":null`, 1),
		"wrong-text-type":  strings.Replace(open, `"text":"clean"`, `"text":42`, 1),
		"wrong-case-text":  strings.Replace(open, `"text":"clean"`, `"Text":"clean"`, 1),
		"missing-version":  strings.Replace(open, `,"version":2`, "", 1),
		"null-version":     strings.Replace(open, `"version":2`, `"version":null`, 1),
		"float-version":    strings.Replace(open, `"version":2`, `"version":2.5`, 1),
		"large-version":    strings.Replace(open, `"version":2`, `"version":2147483648`, 1),
		"missing-language": strings.Replace(open, `,"languageId":"python"`, "", 1),
		"null-language":    strings.Replace(open, `"languageId":"python"`, `"languageId":null`, 1),
		"duplicate-text":   strings.Replace(open, `"text":"clean"`, `"text":"old","te\u0078t":"clean"`, 1),
	} {
		cases = append(cases, invalidNotification{"didOpen-" + name, "textDocument/didOpen", params})
	}
	for name, params := range map[string]string{
		"missing-changes": strings.Replace(change, `,"contentChanges":[{"text":"clean"}]`, "", 1),
		"null-changes":    strings.Replace(change, `[{"text":"clean"}]`, `null`, 1),
		"empty-changes":   strings.Replace(change, `[{"text":"clean"}]`, `[]`, 1),
		"null-entry":      strings.Replace(change, `[{"text":"clean"}]`, `[null]`, 1),
		"missing-text":    strings.Replace(change, `[{"text":"clean"}]`, `[{}]`, 1),
		"null-text":       strings.Replace(change, `[{"text":"clean"}]`, `[{"text":null}]`, 1),
		"duplicate-text":  strings.Replace(change, `[{"text":"clean"}]`, `[{"text":"old","text":"clean"}]`, 1),
		"range":           strings.Replace(change, `[{"text":"clean"}]`, `[{"text":"clean","range":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}}}]`, 1),
		"null-range":      strings.Replace(change, `[{"text":"clean"}]`, `[{"text":"clean","range":null}]`, 1),
		"range-length":    strings.Replace(change, `[{"text":"clean"}]`, `[{"text":"clean","rangeLength":1}]`, 1),
		"invalid-first":   strings.Replace(change, `[{"text":"clean"}]`, `[{}, {"text":"clean"}]`, 1),
		"invalid-last":    strings.Replace(change, `[{"text":"clean"}]`, `[{"text":"clean"}, {}]`, 1),
		"missing-version": strings.Replace(change, `,"version":2`, "", 1),
		"null-version":    strings.Replace(change, `"version":2`, `"version":null`, 1),
	} {
		cases = append(cases, invalidNotification{"didChange-" + name, "textDocument/didChange", params})
	}
	for name, params := range map[string]string{
		"null-text":      `{"textDocument":` + document + `,"text":null}`,
		"wrong-text":     `{"textDocument":` + document + `,"text":42}`,
		"duplicate-text": `{"textDocument":` + document + `,"text":"old","text":"clean"}`,
	} {
		cases = append(cases, invalidNotification{"didSave-" + name, "textDocument/didSave", params})
	}
	return cases
}

func TestInvalidNotificationsPreserveRevision(t *testing.T) {
	for _, state := range []string{"published", "pending", "in-flight"} {
		for _, tc := range invalidNotifications() {
			t.Run(state+"/"+tc.name, func(t *testing.T) {
				e := newTestEngine(t)
				const uri = "file:///params.py"
				var buf bytes.Buffer
				w := newSafeWriter(bufio.NewWriter(&buf))
				d := newDebouncer(e, w, time.Hour)
				entered, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); d.stop() })
				var done <-chan struct{}
				if state == "published" {
					d.immediate(uri, genericSecretLine)
				} else {
					d.schedule(uri, genericSecretLine)
					if state == "in-flight" {
						var blockOnce sync.Once
						e.allow = func(_, _ string) bool {
							blockOnce.Do(func() { close(entered); <-release })
							return false
						}
						done = firePending(d, uri)
						awaitScan(t, entered)
					}
				}
				d.mu.Lock()
				previous := d.documents[uri]
				d.mu.Unlock()
				dispatch(w, e, d, tc.method, nil, json.RawMessage(tc.params))
				d.mu.Lock()
				preserved := len(d.documents) == 1 && d.documents[uri] == previous
				d.mu.Unlock()
				if !preserved {
					t.Fatal("invalid notification changed the current document revision")
				}
				if state == "pending" {
					awaitScan(t, firePending(d, uri))
				}
				releaseOnce.Do(func() { close(release) })
				if done != nil {
					awaitScan(t, done)
				}
				d.stop()
				if count, last := drainPublishes(t, &buf); count != 1 || !hasDiag(last) || last["uri"] != uri {
					t.Fatalf("invalid notification altered diagnostics: count=%d, hasDiagnostics=%v, uri=%v", count, hasDiag(last), last["uri"])
				}
			})
		}
	}
}

func TestFullSyncNotificationSnapshots(t *testing.T) {
	for _, method := range []string{"textDocument/didOpen", "textDocument/didChange", "textDocument/didSave"} {
		for _, text := range []string{genericSecretLine, ""} {
			t.Run(method+"/empty="+strconv.FormatBool(text == ""), func(t *testing.T) {
				e := newTestEngine(t)
				var buf bytes.Buffer
				w := newSafeWriter(bufio.NewWriter(&buf))
				d := newDebouncer(e, w, time.Hour)
				t.Cleanup(d.stop)
				const uri = "file:///snapshot.py"
				if method == "textDocument/didOpen" {
					d.immediate(uri, genericSecretLine)
				} else {
					dispatch(w, e, d, "textDocument/didOpen", nil, documentParams(uri, genericSecretLine, 0))
				}
				p := lifecycleParams(uri, text)
				if method == "textDocument/didChange" {
					var v map[string]any
					_ = json.Unmarshal(p, &v)
					v["contentChanges"] = []map[string]any{{"text": "first full snapshot"}, {"text": text, "extension": true}}
					p, _ = json.Marshal(v)
				}
				dispatch(w, e, d, method, nil, p)
				if method == "textDocument/didChange" {
					awaitScan(t, firePending(d, uri))
				}
				d.stop()
				if count, last := drainPublishes(t, &buf); count != 2 || hasDiag(last) != (text != "") {
					t.Fatalf("full snapshot was not applied: count=%d, hasDiagnostics=%v", count, hasDiag(last))
				}
			})
		}
	}
}

func TestInitializeAdvertisesSaveText(t *testing.T) {
	var buf bytes.Buffer
	w := newSafeWriter(bufio.NewWriter(&buf))
	dispatch(w, nil, nil, "initialize", json.RawMessage(`1`), json.RawMessage(`{}`))
	body, err := readMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result struct {
			Capabilities struct {
				Sync json.RawMessage `json:"textDocumentSync"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	var options struct {
		OpenClose bool `json:"openClose"`
		Change    int  `json:"change"`
		Save      struct {
			IncludeText bool `json:"includeText"`
		} `json:"save"`
	}
	if err := json.Unmarshal(response.Result.Capabilities.Sync, &options); err != nil || !options.OpenClose || options.Change != 1 || !options.Save.IncludeText {
		t.Fatalf("initialize does not request full sync and save text: %v", err)
	}
}

func TestNotificationStringAndVersionBoundaries(t *testing.T) {
	for _, uri := range []string{"file:///Ключ%20😀.py", "untitled:Ключ%20😀", "vscode-notebook-cell:/Ключ.py#cell"} {
		for _, version := range []int32{-2147483648, 0, 2147483647} {
			const text = "first\r\nКлюч 😀\u0000\ufffd"
			params, err := json.Marshal(map[string]any{
				"textDocument":   map[string]any{"uri": uri, "languageId": "", "version": version, "text": text, "extension": true},
				"contentChanges": []map[string]any{{"text": text}}, "text": text, "extension": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, parse := range []func(json.RawMessage) (documentUpdate, bool){openParams, changeParams} {
				update, ok := parse(params)
				if !ok || update.uri != uri || update.text != text || update.version != version || !update.hasText {
					t.Fatal("valid notification strings were changed or rejected")
				}
			}
			if gotURI, gotText, ok := saveParams(params); !ok || gotURI != uri || gotText != text {
				t.Fatal("valid save strings were changed or rejected")
			}
			if gotURI, ok := closeParams(params); !ok || gotURI != uri {
				t.Fatal("valid close URI was changed or rejected")
			}
		}
	}
}

func TestDocumentNotificationParsersRejectInvalidFields(t *testing.T) {
	for _, tc := range invalidNotifications() {
		t.Run(tc.name, func(t *testing.T) {
			p := json.RawMessage(tc.params)
			accepted := false
			switch tc.method {
			case "textDocument/didOpen":
				_, accepted = openParams(p)
			case "textDocument/didChange":
				update, ok := changeParams(p)
				if tc.name == "didChange-empty-changes" {
					if !ok || update.hasText || update.version != 2 {
						t.Fatal("empty changes must preserve text and retain their version")
					}
					return
				}
				accepted = ok
			case "textDocument/didClose":
				_, accepted = closeParams(p)
			case "textDocument/didSave":
				_, _, accepted = saveParams(p)
			}
			if accepted {
				t.Fatal("malformed notification fields were admitted by the parser")
			}
		})
	}
}
