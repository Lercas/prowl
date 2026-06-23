package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
)

// prowlHome resolves the install dir from PROWL_HOME, then $XDG_CONFIG_HOME/prowl, then ~/.prowl.
func prowlHome() string {
	if h := os.Getenv("PROWL_HOME"); h != "" {
		return h
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "prowl")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".prowl"
	}
	return filepath.Join(home, ".prowl")
}

func installedRulesDir() string     { return filepath.Join(prowlHome(), "rules") }
func installedVerifiersDir() string { return filepath.Join(prowlHome(), "verifiers") }

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// shippedDir locates the bundled copy of name (rules/verifiers): the working directory, then
// alongside the binary, then a unix share path.
func shippedDir(name string) string {
	if dirExists(name) {
		return name
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		for _, c := range []string{
			filepath.Join(d, name),
			filepath.Join(d, "..", "share", "prowl", name),
		} {
			if dirExists(c) {
				return c
			}
		}
	}
	return ""
}

// discoverRulesDirs returns the rule-template dirs to scan: --rules-dir, else the installed home dir.
func discoverRulesDirs(flagDirs []string) []string {
	if len(flagDirs) > 0 {
		return flagDirs
	}
	if d := installedRulesDir(); dirExists(d) {
		return []string{d}
	}
	return nil
}

// discoverVerifierDirs returns verifier dirs: --verifiers, else the installed home dir, else ./verifiers.
func discoverVerifierDirs(flagDirs []string) []string {
	if len(flagDirs) > 0 {
		return flagDirs
	}
	if d := installedVerifiersDir(); dirExists(d) {
		return []string{d}
	}
	if dirExists("verifiers") {
		return []string{"verifiers"}
	}
	return nil
}

// installedVersion reads a target dir's manifest version; "" if not installed.
func installedVersion(dir string) (string, int) {
	m := rules.ReadManifest(dir)
	return m.Version, m.Count
}

// printVersions reports the binary version plus installed rule/verifier provenance.
func printVersions() {
	fmt.Printf("prowl %s\n", version)
	rv, rc := installedVersion(installedRulesDir())
	vv, vc := installedVersion(installedVerifiersDir())
	if rc > 0 {
		fmt.Printf("rules:     %d installed (version %s) at %s\n", rc, orNone(rv), installedRulesDir())
	} else {
		fmt.Printf("rules:     not installed — run 'prowl rules update'\n")
	}
	if vc > 0 {
		fmt.Printf("verifiers: %d installed (version %s) at %s\n", vc, orNone(vv), installedVerifiersDir())
	} else {
		fmt.Printf("verifiers: not installed — run 'prowl verifiers update'\n")
	}
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// DefaultTemplatesRepo is where `rules update` / `verifiers update` fetch from when no --source is
// given — the canonical, independently-versioned template library.
const DefaultTemplatesRepo = "https://github.com/Lercas/prowl-templates.git"

// updateInto fetches source into target, validating before install. With no source it pulls from
// DefaultTemplatesRepo, falling back to the bundled snapshot if the remote is unreachable.
//
// Trust: the default repo and bundled snapshot are trusted; an explicit --source is untrusted and
// installs only with --allow-unsigned (a MANIFEST.sha256 it ships authenticates nothing). The
// bundled/installed set is manifest-checked at load, anchored by the binary.
func updateInto(kind, source, target, now string, check, allowUnsigned bool) int {
	// Ctrl-C / SIGTERM cancels a hung remote clone (see rules.fetch's exec.CommandContext).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fromDefault := source == ""
	if fromDefault {
		source = DefaultTemplatesRepo
	}
	opts := rules.UpdateOpts{Source: source, Target: target, Now: now, Check: check, Subdir: kind, Ctx: ctx}
	switch kind {
	case "verifiers": // verifiers validate by loading
		pol := verify.LoadPolicy{} // default/bundled is trusted
		if !fromDefault {          // explicit --source: untrusted, needs --allow-unsigned
			pol = verify.LoadPolicy{Trust: verify.TrustUntrusted, AllowUnsigned: allowUnsigned}
		}
		opts.Validate = func(dir string) error { _, e := verify.LoadWithPolicy(0, pol, dir); return e }
	case "rules":
		// integrity check runs before the lint so a tampered set is refused before its regexes compile;
		// an explicit --source is untrusted regardless of any manifest it ships.
		if !fromDefault {
			pol := rules.IntegrityPolicy{Trust: rules.TrustUntrusted, AllowUnsigned: allowUnsigned}
			opts.Validate = func(dir string) error {
				if err := rules.CheckIntegrity(dir, pol); err != nil {
					return err
				}
				return rules.ValidateForUpdate(dir)
			}
		}
	}
	res, err := rules.Update(opts)
	if err != nil && fromDefault { // offline: use the bundled snapshot shipped alongside the binary
		if bundled := shippedDir(kind); bundled != "" {
			fmt.Fprintf(os.Stderr, "%s unreachable (%v); using bundled %s\n", DefaultTemplatesRepo, err, kind)
			opts.Source, opts.Subdir = bundled, ""
			// The bundled snapshot is trusted; its validate hook already uses bundled policy.
			res, err = rules.Update(opts)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "update failed:", err)
		if res != nil {
			for _, is := range res.Errors {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", is.Path, is.Msg)
			}
		}
		return 2
	}
	if !check {
		switch kind {
		case "verifiers":
			// Bless what we installed: write a fresh integrity manifest so a later load detects any
			// on-disk tampering.
			if _, gerr := verify.GenerateManifest(target); gerr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write verifier integrity manifest: %v\n", gerr)
			}
			if vs, verr := verify.Load(0, target); verr != nil {
				fmt.Fprintf(os.Stderr, "warning: installed verifiers have issues: %v\n", verr)
			} else {
				_ = vs
			}
		case "rules":
			// Same blessing for rules: a post-install tamper-check anchored by the binary, so a later
			// edit to an installed template is detectable at load — not a token that makes this dir a
			// trusted --source (an explicit --source still needs --allow-unsigned).
			if _, gerr := rules.GenerateManifest(target); gerr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write rule integrity manifest: %v\n", gerr)
			}
		}
	}
	if res.NoChange {
		fmt.Printf("%s already up to date (%d, version %s)\n", kind, res.Manifest.Count, orNone(res.Manifest.Version))
		return 0
	}
	verb := "installed"
	if check {
		verb = "available"
	}
	fmt.Printf("%s %s: +%d ~%d -%d (version %s, %d total) -> %s\n", kind, verb,
		len(res.Added), len(res.Changed), len(res.Removed), orNone(res.Manifest.Version), res.Manifest.Count, target)
	return 0
}

// rulesManifestCmd implements `prowl rules manifest [DIR]`: it (re)generates MANIFEST.sha256 to bless a
// rule dir's contents, the maintainer path that re-blesses the bundled/installed set after a legit edit
// so its load-time tamper-check passes again. With no explicit DIR, the installed set is blessed.
func rulesManifestCmd(dir string, dirGiven bool) int {
	if !dirGiven {
		if d := installedRulesDir(); dirExists(d) {
			dir = d
		}
	}
	n, err := rules.GenerateManifest(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d files) in %s\n", rules.IntegrityManifestName, n, dir)
	return 0
}
