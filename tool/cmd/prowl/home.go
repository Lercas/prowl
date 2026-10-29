package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Lercas/prowl/tool/internal/localfile"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/verify"
	bundledrules "github.com/Lercas/prowl/tool/rules"
	bundledverifiers "github.com/Lercas/prowl/tool/verifiers"
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

func validateTemplateSelection(c commonFlags) error {
	if c.bundled && (c.rulesOnly || len(c.rulesDir) > 0 || len(c.verifiers) > 0) {
		return fmt.Errorf("--bundled несовместим с --rules-only/--rules-dir/--verifiers: выберите один источник шаблонов")
	}
	return nil
}

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
func discoverRulesDirs(flagDirs []string) ([]string, error) {
	if len(flagDirs) > 0 {
		return flagDirs, nil
	}
	dir, err := localfile.FirstDirectory(installedRulesDir())
	if err != nil {
		return nil, err
	}
	if dir != "" {
		return []string{dir}, nil
	}
	return nil, nil
}

// discoverVerifierDirs returns verifier dirs: --verifiers, else the installed home dir, else ./verifiers.
func discoverVerifierDirs(flagDirs []string) ([]string, error) {
	if len(flagDirs) > 0 {
		return flagDirs, nil
	}
	dir, err := localfile.FirstDirectory(installedVerifiersDir(), "verifiers")
	if err != nil {
		return nil, err
	}
	if dir != "" {
		return []string{dir}, nil
	}
	return nil, nil
}

// installedVersion reads a target dir's manifest version; "" if not installed.
func installedVersion(dir string) (string, int, error) {
	m, err := rules.ReadManifest(dir)
	return m.Version, m.Count, err
}

// printVersions reports the binary version plus installed rule/verifier provenance.
func printVersions(mode ...bool) int {
	fmt.Printf("prowl %s\n", version)
	rv, rc, vv, vc := "", 0, "", 0
	if len(mode) == 0 || !mode[0] {
		var rerr, verr error
		rv, rc, rerr = installedVersion(installedRulesDir())
		vv, vc, verr = installedVersion(installedVerifiersDir())
		if rerr != nil || verr != nil {
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "rules metadata error:", rerr)
			}
			if verr != nil {
				fmt.Fprintln(os.Stderr, "verifiers metadata error:", verr)
			}
			return 2
		}
	}
	if rc > 0 {
		fmt.Printf("rules:     %d installed files (manifest version %s) at %s\n", rc, orNone(rv), logx.SanitizeTerminal(installedRulesDir()))
	} else {
		if eng, err := rules.LoadEmbedded(bundledrules.Files); err == nil {
			fmt.Printf("rules:     %d bundled (offline)\n", eng.Len())
		} else {
			fmt.Println("rules:     bundled integrity check failed")
		}
	}
	if vc > 0 {
		fmt.Printf("verifiers: %d installed (version %s) at %s\n", vc, orNone(vv), logx.SanitizeTerminal(installedVerifiersDir()))
	} else {
		if set, err := verify.LoadEmbedded(0, bundledverifiers.Files); err == nil {
			fmt.Printf("verifiers: %d bundled (offline)\n", set.Count())
		} else {
			fmt.Println("verifiers: bundled integrity check failed")
		}
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return logx.SanitizeTerminal(s)
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
func updateInto(kind, source, target, now string, check, allowUnsigned bool) (code int) {
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
	if err != nil && fromDefault && ctx.Err() == nil && errors.Is(err, rules.ErrSourceUnavailable) {
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
	defer func() {
		if err := res.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "update cleanup failed:", err)
			code = 2
		}
	}()
	if !check {
		if err := validateInstalledLibrary(kind, target, res.Manifest); err != nil {
			fmt.Fprintf(os.Stderr, "update incomplete: installed %s failed validation: %v\n", kind, err)
			return 2
		}
	}
	if res.NoChange {
		fmt.Printf("%s already up to date (%d files, version %s)\n", kind, res.Manifest.Count, orNone(res.Manifest.Version))
		return 0
	}
	verb := "installed"
	if check {
		verb = "available"
	}
	fmt.Printf("%s %s: +%d ~%d -%d files (version %s, %d files total) -> %s\n", kind, verb,
		len(res.Added), len(res.Changed), len(res.Removed), orNone(res.Manifest.Version), res.Manifest.Count, target)
	if res.MetadataChanged {
		if check {
			fmt.Println("Метаданные библиотеки требуют обновления.")
		} else {
			fmt.Println("Метаданные библиотеки обновлены.")
		}
	}
	return 0
}

// Qualification is read-only: a changed installed file must fail the snapshot's checksum.
func validateInstalledLibrary(kind, target string, expected rules.Manifest) error {
	actual, err := rules.ReadManifest(target)
	if err != nil {
		return err
	}
	if actual.Source != expected.Source || actual.Version != expected.Version ||
		actual.Count != expected.Count || !maps.Equal(actual.Files, expected.Files) {
		return fmt.Errorf("installed provenance differs from the validated update")
	}
	raw, present, err := localfile.ReadOptionalDirectoryFile(target, rules.IntegrityManifestName, rules.MaxIntegrityManifestSize)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("installed integrity manifest is missing")
	}
	sums, err := localfile.ParseSHA256Manifest(raw, rules.IntegrityManifestName)
	if err != nil {
		return err
	}
	if !maps.Equal(sums, expected.Files) {
		return fmt.Errorf("installed integrity differs from the validated update")
	}
	switch kind {
	case "rules":
		_, err := rules.Load(target)
		return err
	case "verifiers":
		_, err := verify.Load(0, target)
		return err
	default:
		return fmt.Errorf("unknown installed library kind")
	}
}

// rulesManifestCmd implements `prowl rules manifest [DIR]`: it (re)generates MANIFEST.sha256 to bless a
// rule dir's contents, the maintainer path that re-blesses the bundled/installed set after a legit edit
// so its load-time tamper-check passes again. With no explicit DIR, the installed set is blessed.
func rulesManifestCmd(dir string, dirGiven bool) int {
	if !dirGiven {
		d, err := localfile.FirstDirectory(installedRulesDir())
		if err != nil {
			fmt.Fprintln(os.Stderr, "manifest:", err)
			return 1
		}
		if d != "" {
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
