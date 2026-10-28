package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/mlscore"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/scan"
	"github.com/Lercas/prowl/tool/internal/source"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	bundledrules "github.com/Lercas/prowl/tool/rules"
)

type selftestCase struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Complete bool   `json:"complete"`
	Count    int    `json:"count"`
}
type selftestResult struct {
	SchemaVersion string         `json:"schema_version"`
	Profile       string         `json:"profile"`
	Passed        bool           `json:"passed"`
	Network       bool           `json:"network"`
	Cases         []selftestCase `json:"cases"`
}

// All carriers and values are synthetic; selftest never calls a live provider.
func runSelftest(profile string, useML bool) (selftestResult, error) {
	out := selftestResult{"1.4", profile, true, false, []selftestCase{}}
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		return out, err
	}
	det := detect.New(tax)
	eng, err := rules.LoadEmbedded(bundledrules.Files)
	if err != nil {
		return out, err
	}
	var ml mlscore.Scorer
	if useML {
		ml, err = mlscore.NewEmbedded(.2, "")
		if err != nil {
			return out, err
		}
	}
	const credential = "\x41KIANAFGYOEYPXU1DSYP" // #nosec G101 -- synthetic offline self-test value, never sent to a provider
	type fixture struct {
		name, path       string
		data             []byte
		positive, mobile bool
	}
	fixtures := []fixture{}
	if profile == "web" || profile == "all" {
		fixtures = append(fixtures, fixture{"split-string", "bundle.js", []byte(`const p="AKIA";const k=p+"NAFGYOEYPXU1DSYP";`), true, false}, fixture{"encoded-string", "bundle.js", []byte(`const k=atob("` + base64.StdEncoding.EncodeToString([]byte(credential)) + `");`), true, false}, fixture{"public-example", "config.js", []byte(`const api_key="YOUR_API_KEY_HERE";`), false, false})
	}
	if profile == "mobile" || profile == "all" {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, err := zw.Create("classes.dex")
		if err != nil {
			return out, err
		}
		_, _ = w.Write([]byte("dex\n035\x00\x00" + credential + "\x00"))
		if err = zw.Close(); err != nil {
			return out, err
		}
		fixtures = append(fixtures, fixture{"dex-string", "app.apk", b.Bytes(), true, true})
		b.Reset()
		zw = zip.NewWriter(&b)
		w, err = zw.Create("assets/config.json")
		if err != nil {
			return out, err
		}
		_, _ = w.Write([]byte(`{"token":"YOUR_API_KEY_HERE"}`))
		if err = zw.Close(); err != nil {
			return out, err
		}
		fixtures = append(fixtures, fixture{"mobile-placeholder", "app.apk", b.Bytes(), false, true})
	}
	if profile == "enterprise" || profile == "all" {
		mail := "From: scanner@example.invalid\r\nTo: team@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("AWS_ACCESS_KEY_ID="+credential)) + "\r\n"
		fixtures = append(fixtures, fixture{"encoded-mail", "incident.eml", []byte(mail), true, false}, fixture{"public-identifier", "report.txt", []byte("Public document number: 20261001; password: changeme"), false, false})
	}
	if len(fixtures) == 0 {
		return out, fmt.Errorf("профиль должен быть all, web, mobile или enterprise")
	}
	for _, f := range fixtures {
		coverage := model.NewCoverage()
		ctx := scan.WithOptions(model.WithCoverage(context.Background(), coverage), scan.Options{Reconstruct: true, IdentityKey: []byte(strings.Repeat("s", 32))})
		var items <-chan model.Item
		if f.mobile {
			items, err = source.MobileBytes(ctx, f.path, f.data, source.MobileOptions{MaxBytes: 1 << 20, Strings: true})
			if err != nil {
				return out, err
			}
		} else {
			items = source.Payload(ctx, f.path, f.data, 1<<20)
		}
		fs := scan.Run(ctx, items, det, eng, nil, 2, nil, ml)
		complete, _, _ := coverage.Snapshot()
		found := false
		for _, x := range fs {
			if x.Type == "aws_access_key_id" || x.Type == "aws-access-key-id" {
				found = true
			}
			if strings.Contains(x.Redacted, credential) {
				return out, fmt.Errorf("самопроверка выявила утечку в редактированном выводе")
			}
		}
		passed := complete && ((f.positive && found) || (!f.positive && len(fs) == 0))
		out.Cases = append(out.Cases, selftestCase{f.name, passed, complete, len(fs)})
		out.Passed = out.Passed && passed
	}
	return out, nil
}
func cmdSelftest(args []string) int {
	profile := "all"
	ml := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			i++
			if i == len(args) {
				return 2
			}
			profile = args[i]
		case "--ml":
			ml = true
		default:
			fmt.Fprintln(os.Stderr, "Использование: prowl selftest [--profile all|web|mobile|enterprise] [--ml]")
			return 2
		}
	}
	r, err := runSelftest(profile, ml)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 2
	}
	if !r.Passed {
		return 1
	}
	return 0
}
