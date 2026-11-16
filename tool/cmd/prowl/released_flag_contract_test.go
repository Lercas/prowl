package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestFailOnVerifiedIsKnownFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--fail-on-verified"}, {"--fail-on", "critical"}, {"--verify"}, {"--ml"},
		{"--ml-threshold", ".3"}, {"--ocr"}, {"--ocr-url", "http://127.0.0.1:8080"},
		{"--ocr-model", "owned-model"}, {"--ocr-allow-remote"}, {"--ocr-all-pages"},
		{"--ocr-max-pages", "1"}, {"--ocr-timeout", "1s"},
	} {
		if _, _, err := parseCommand("scan", args); err != nil {
			t.Fatalf("released flag %s was rejected: %v", args[0], err)
		}
		if !strings.Contains(commandFlagHelp("scan"), args[0]) {
			t.Fatalf("released flag %s is missing from help", args[0])
		}
	}
}

func TestScanEndOfOptions(t *testing.T) {
	c, rest, err := parseCommand("scan", []string{"--format", "json", "--", "--verify", "--help"})
	if err != nil || c.verify || c.format != "json" || !reflect.DeepEqual(rest, []string{"--verify", "--help"}) {
		t.Fatal("tokens after -- changed scan options or triggered help")
	}
	_, _, err = parseCommand("scan", []string{"--help", "--"})
	var help *commandHelpRequest
	if !errors.As(err, &help) {
		t.Fatal("help before -- was not recognized")
	}
}
