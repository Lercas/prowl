package main

import (
	"reflect"
	"testing"
)

func TestHermesParserKeepsPositionalTargetsAndExplicitBooleans(t *testing.T) {
	c, targets, err := parseCommand("hermes-audit", []string{"203.0.113.10", "--authorized", "--provider", "shodan", "198.51.100.2:9119", "--active=false"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(targets, []string{"203.0.113.10", "198.51.100.2:9119"}) || !reflect.DeepEqual(c.cmd.providers, []string{"shodan"}) || !c.cmd.authorized || c.cmd.active || !c.cmd.passive {
		t.Fatalf("unexpected parser result: %+v %v", c.cmd, targets)
	}
}
