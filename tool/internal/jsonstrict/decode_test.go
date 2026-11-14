package jsonstrict

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type responseFixture struct {
	Results []struct {
		ID     string            `json:"id"`
		Fields map[string]string `json:"fields"`
	} `json:"results"`
}

func TestUnmarshalRejectsLossyDocuments(t *testing.T) {
	for name, raw := range map[string]string{
		"second document":   `{"results":[]} {"results":[]}`,
		"trailing bytes":    `{"results":[]} secret`,
		"invalid UTF8":      "{\"results\":[{\"id\":\"\xff\"}]}",
		"unpaired high":     `{"results":[{"id":"\ud800"}]}`,
		"unpaired low":      `{"results":[{"id":"\udc00"}]}`,
		"duplicate root":    `{"results":[{"id":"secret"}],"results":[]}`,
		"folded root":       `{"results":[{"id":"secret"}],"RESULTS":[]}`,
		"unicode fold":      `{"reſults":[{"id":"secret"}],"results":[]}`,
		"escaped duplicate": `{"results":[{"id":"secret","\u0069d":"clean"}]}`,
		"folded nested":     `{"results":[{"id":"secret","ID":"clean"}]}`,
		"map duplicate":     `{"results":[{"fields":{"secret":"one","secret":"two"}}]}`,
		"unknown duplicate": `{"results":[],"metadata":{"key":1,"key":2}}`,
		"wrong scalar":      `{"results":[{"id":42}]}`,
		"wrong list":        `{"results":"secret"}`,
	} {
		t.Run(name, func(t *testing.T) {
			out := responseFixture{}
			out.Results = make([]struct {
				ID     string            `json:"id"`
				Fields map[string]string `json:"fields"`
			}, 1)
			out.Results[0].ID = "unchanged"
			before := append(out.Results[:0:0], out.Results...)
			if err := UnmarshalContext(context.Background(), []byte(raw), &out); err == nil {
				t.Fatal("ambiguous or lossy JSON accepted")
			}
			if !reflect.DeepEqual(out.Results, before) {
				t.Fatal("failed decode changed the destination")
			}
		})
	}
}

func TestUnmarshalPreservesDynamicKeysAndUnicode(t *testing.T) {
	var out responseFixture
	raw := `{"RESULTS":[{"ID":"é \ud83d\ude00 \ufffd","fields":{"key":"one","KEY":"two"}}]}`
	if err := UnmarshalContext(context.Background(), []byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Results[0].ID != "é 😀 �" || out.Results[0].Fields["key"] != "one" || out.Results[0].Fields["KEY"] != "two" {
		t.Fatalf("valid values or map keys changed: %+v", out)
	}
	for _, value := range []string{`{"results":[]}`, ` {"results":[]} \n`} {
		value = strings.ReplaceAll(value, `\n`, "\n")
		if err := UnmarshalContext(context.Background(), []byte(value), &out); err != nil || out.Results == nil || len(out.Results) != 0 {
			t.Fatalf("legitimate empty collection rejected: %v", err)
		}
	}
}

func TestDynamicNumbersAreLossless(t *testing.T) {
	var out map[string]any
	if err := UnmarshalContext(context.Background(), []byte(`{"count":9007199254740993,"huge":1e1000}`), &out); err != nil {
		t.Fatal(err)
	}
	if out["count"] != json.Number("9007199254740993") || out["huge"] != json.Number("1e1000") {
		t.Fatalf("dynamic JSON numbers rounded or rejected: %+v", out)
	}
}

func TestUnmarshalCancellationAndDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := map[string]string{"value": "unchanged"}
	if err := UnmarshalContext(ctx, []byte(`{"value":"new"}`), &out); err == nil || out["value"] != "unchanged" {
		t.Fatal("canceled decode succeeded or changed destination")
	}
	for _, dst := range []any{nil, (*responseFixture)(nil), responseFixture{}} {
		if err := UnmarshalContext(context.Background(), []byte(`{}`), dst); err == nil {
			t.Fatalf("invalid destination accepted: %T", dst)
		}
	}
}

func TestEmbeddedFieldsUseJSONDominance(t *testing.T) {
	type embedded struct {
		Value string
	}
	type second struct {
		Value string
	}
	type ambiguous struct {
		embedded
		second
	}
	var out ambiguous
	// Both fields are ambiguous to encoding/json and ignored. Different unknown keys stay distinct.
	if err := UnmarshalContext(context.Background(), []byte(`{"value":"a","VALUE":"b"}`), &out); err != nil {
		t.Fatal(err)
	}
	type shallow struct {
		embedded
		Value string
	}
	var winner shallow
	if err := UnmarshalContext(context.Background(), []byte(`{"Value":"a","value":"b"}`), &winner); err == nil {
		t.Fatal("duplicate aliases of the winning shallow field accepted")
	}
	type tagged struct {
		Value string `json:"Value"`
	}
	type taggedWinner struct {
		embedded
		tagged
	}
	var chosen taggedWinner
	if err := UnmarshalContext(context.Background(), []byte(`{"value":"a","VALUE":"b"}`), &chosen); err == nil {
		t.Fatal("duplicate aliases of the winning tagged embedded field accepted")
	}
}
