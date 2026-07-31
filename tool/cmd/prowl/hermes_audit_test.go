package main

import (
	"reflect"
	"testing"
)

func TestNormalizeHermesArgsMovesPositionalTargetsAfterFlags(t *testing.T) {
	got := normalizeHermesArgs([]string{"203.0.113.10", "--authorized", "--provider", "shodan", "198.51.100.2:9119", "--active=false"})
	want := []string{"--authorized", "--provider", "shodan", "--active=false", "203.0.113.10", "198.51.100.2:9119"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeHermesArgs = %#v, want %#v", got, want)
	}
}
