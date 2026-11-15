package credentialset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func newSet(t *testing.T) *Set {
	t.Helper()
	s, err := New(Limits{Observations: 100, Bytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func newSchema(t *testing.T, fields []Field) *Schema {
	t.Helper()
	schema, err := NewSchema(fields)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

var pair = []Field{{Name: "account", Pattern: "[a-z]+"}, {Name: "password", Aliases: []string{"pass_word"}, Pattern: "[A-Za-z0-9]+"}}

func TestCompleteCredentialFamiliesAndEvidence(t *testing.T) {
	cases := []struct {
		name   string
		fields []Field
		parts  []string
	}{
		{"aws", []Field{{Name: "aws_access_key_id", Aliases: []string{"accessKeyId"}, Pattern: "AKIA[A-Z0-9]{16}"}, {Name: "aws_secret_access_key", Aliases: []string{"secretAccessKey"}, Pattern: "[A-Za-z0-9/+]{40}"}}, []string{"AKIANAFGYOEYPXU1DSYP", strings.Repeat("Q7z/", 10)}},
		{"oauth", []Field{{Name: "client_id", Pattern: "[a-z0-9]+"}, {Name: "client_secret", Pattern: "[A-Za-z0-9]+"}, {Name: "tenant", Pattern: "[a-z]+"}}, []string{"ownedclient", "Ownedsynthetic123", "ownedtenant"}},
		{"database", []Field{{Name: "host", Pattern: `[a-z]+\.invalid`}, {Name: "username", Pattern: "[a-z]+"}, {Name: "password", Pattern: "[A-Za-z0-9]+"}}, []string{"db.invalid", "owneduser", "Syntheticpassword123"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, scope, s := context.Background(), NewScope(), newSet(t)
			schema := newSchema(t, tc.fields)
			for i, f := range tc.fields {
				name := f.Name
				if len(f.Aliases) > 0 {
					name = f.Aliases[0]
				}
				for _, location := range []string{fmt.Sprintf("location-%d-b", i), fmt.Sprintf("location-%d-a", i), fmt.Sprintf("location-%d-b", i)} {
					if err := s.Observe(ctx, scope, name, tc.parts[i], location); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := s.Seal(ctx, true); err != nil {
				t.Fatal(err)
			}
			calls := 0
			var retained map[string]string
			for anchor, role := range tc.fields {
				err := s.With(ctx, scope, schema, role.Name, tc.parts[anchor], func(values map[string]string, locations map[string][]string) error {
					calls++
					retained = values
					for i, f := range tc.fields {
						if values[f.Name] != tc.parts[i] || !reflect.DeepEqual(locations[f.Name], []string{fmt.Sprintf("location-%d-a", i), fmt.Sprintf("location-%d-b", i)}) {
							t.Fatal("incorrect role value or evidence")
						}
					}
					return nil
				})
				if err != nil || len(retained) != 0 {
					t.Fatal("resolution failed or callback map retained values", err)
				}
			}
			if calls != len(tc.fields) {
				t.Fatal("a primary role did not anchor resolution")
			}
		})
	}
}

func TestNeverJoinsForeignAcquisitionsOrInventsAnAnchor(t *testing.T) {
	ctx, a, b, s := context.Background(), NewScope(), NewScope(), newSet(t)
	if a == b {
		t.Fatal("acquisition scopes alias")
	}
	for _, v := range []struct {
		scope *Scope
		name  string
		value string
	}{{a, "account", "owned"}, {b, "password", "Owned123"}} {
		if err := s.Observe(ctx, v.scope, v.name, v.value, "same-display-location"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(ctx, true); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []*Scope{a, b, NewScope()} {
		err := s.With(ctx, scope, newSchema(t, pair), "account", "owned", func(map[string]string, map[string][]string) error {
			t.Fatal("foreign acquisition formed a credential")
			return nil
		})
		if !errors.Is(err, ErrAmbiguous) {
			t.Fatal(err)
		}
	}
}

func TestConflictAndInvalidLiteralsNeverReachConsumer(t *testing.T) {
	for _, change := range []struct{ name, value string }{{"pass_word", "Different456"}, {"password", "Owned123\n"}, {"account", "another"}} {
		t.Run(change.name+change.value, func(t *testing.T) {
			ctx, scope, s := context.Background(), NewScope(), newSet(t)
			for _, p := range []struct{ name, value string }{{"account", "owned"}, {"password", "Owned123"}, change} {
				if err := s.Observe(ctx, scope, p.name, p.value, "opaque"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Seal(ctx, true); err != nil {
				t.Fatal(err)
			}
			if err := s.With(ctx, scope, newSchema(t, pair), "account", "owned", func(map[string]string, map[string][]string) error {
				t.Fatal("conflicting or partially matched value reached consumer")
				return nil
			}); !errors.Is(err, ErrAmbiguous) {
				t.Fatal(err)
			}
		})
	}
}

func TestLifecycleBudgetAndCancellationFailClosed(t *testing.T) {
	for _, mode := range []string{"unsealed", "incomplete", "cancelled-intake", "cancelled-resolution", "closed", "limit-count", "limit-bytes", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scope, s := NewScope(), newSet(t)
			for _, p := range []struct{ n, v string }{{"account", "owned"}, {"password", "Owned123"}} {
				if err := s.Observe(ctx, scope, p.n, p.v, "opaque"); err != nil {
					t.Fatal(err)
				}
			}
			expected := ErrIncomplete
			switch mode {
			case "unsealed":
				expected = ErrUnsealed
			case "incomplete":
				if err := s.Seal(ctx, false); !errors.Is(err, ErrIncomplete) {
					t.Fatal(err)
				}
			case "cancelled-intake":
				cancel()
				if err := s.Observe(ctx, scope, "irrelevant", "more", "opaque"); !errors.Is(err, ErrIncomplete) {
					t.Fatal(err)
				}
			case "cancelled-resolution":
				if err := s.Seal(ctx, true); err != nil {
					t.Fatal(err)
				}
				cancel()
			case "closed":
				s.Close()
				expected = ErrClosed
			case "limit-count", "limit-bytes":
				if mode == "limit-count" {
					s.limits.Observations = 2
				} else {
					s.limits.Bytes = s.bytes
				}
				if err := s.Observe(ctx, scope, "irrelevant", "more", "opaque"); !errors.Is(err, ErrLimit) {
					t.Fatal(err)
				}
				expected = ErrLimit
			case "invalid":
				if err := s.Observe(ctx, scope, "invalid name", "raw-must-not-appear", "opaque"); !errors.Is(err, ErrInvalid) {
					t.Fatal(err)
				}
				expected = ErrInvalid
			}
			requestContext := context.Background()
			if mode == "cancelled-resolution" {
				requestContext = ctx
			}
			if err := s.With(requestContext, scope, newSchema(t, pair), "account", "owned", func(map[string]string, map[string][]string) error {
				t.Fatal("unsafe lifecycle reached consumer")
				return nil
			}); !errors.Is(err, expected) {
				t.Fatal(err)
			}
			if mode == "cancelled-resolution" {
				if err := s.With(ctx, scope, newSchema(t, pair), "account", "owned", nil); !errors.Is(err, expected) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSchemaSnapshotsAliasesAndRejectsOverlap(t *testing.T) {
	for _, fields := range [][]Field{nil, {{Name: "a", Pattern: "["}, {Name: "b", Pattern: "."}}, {{Name: "a", Aliases: []string{"A_B"}, Pattern: "."}, {Name: "a-b", Pattern: "."}}} {
		if _, err := NewSchema(fields); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid schema accepted", err)
		}
	}
	fields := []Field{{Name: "account", Aliases: []string{"account-id"}, Pattern: "[a-z]+"}, {Name: "password", Pattern: "[A-Za-z0-9]+"}}
	schema := newSchema(t, fields)
	fields[0].Aliases[0] = "foreign"
	if !schema.fields[0].aliases["accountid"] || schema.fields[0].aliases["foreign"] {
		t.Fatal("schema retained caller alias slice")
	}
}

func TestNoPlaintextFormattingPersistenceOrLateMutation(t *testing.T) {
	ctx, scope, s := context.Background(), NewScope(), newSet(t)
	secret := "OwnedSensitive123"
	if err := s.Observe(ctx, scope, "account", "owned", "opaque-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Observe(ctx, scope, "password", secret, "opaque-b"); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(s)
	if !errors.Is(err, ErrPrivate) || len(encoded) != 0 || strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%v %+v %#v", s, s, s), secret) {
		t.Fatal("set formatting disclosed plaintext", err)
	}
	if err := s.Seal(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Observe(ctx, scope, "password", "LateMutation", "late"); !errors.Is(err, ErrSealed) {
		t.Fatal(err)
	}
	for _, primary := range []struct{ name, value string }{{"unknown", "owned"}, {"account", "not-observed"}} {
		if err := s.With(ctx, scope, newSchema(t, pair), primary.name, primary.value, nil); !errors.Is(err, ErrAmbiguous) {
			t.Fatal(err)
		}
	}
	if err := s.With(ctx, scope, newSchema(t, pair), "account", "owned", func(values map[string]string, _ map[string][]string) error {
		values["password"] = "Mutated"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.With(ctx, scope, newSchema(t, pair), "account", "owned", func(values map[string]string, _ map[string][]string) error {
		if values["password"] != secret {
			t.Fatal("consumer mutated retained components")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentIntakeReadAndClose(t *testing.T) {
	ctx, scope, s := context.Background(), NewScope(), newSet(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range []struct{ n, v string }{{"account", "owned"}, {"password", "Owned123"}} {
				if err := s.Observe(ctx, scope, p.n, p.v, "opaque"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := s.Seal(ctx, true); err != nil {
		t.Fatal(err)
	}
	schema := newSchema(t, pair)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.With(ctx, scope, schema, "account", "owned", func(map[string]string, map[string][]string) error { return nil })
			if err != nil && !errors.Is(err, ErrClosed) {
				t.Error(err)
			}
		}()
	}
	s.Close()
	wg.Wait()
}
