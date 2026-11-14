package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/forge"
	"github.com/Lercas/prowl/tool/internal/logx"
	"github.com/Lercas/prowl/tool/internal/model"
	"github.com/Lercas/prowl/tool/internal/rules"
	"github.com/Lercas/prowl/tool/internal/safehttp"
	"github.com/Lercas/prowl/tool/internal/saferegex"
	"github.com/Lercas/prowl/tool/internal/source"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
	"github.com/Lercas/prowl/tool/internal/verify"
	bundledrules "github.com/Lercas/prowl/tool/rules"
	bundledverifiers "github.com/Lercas/prowl/tool/verifiers"
)

// loadDetector builds the detector from the taxonomy, external --rules, and config overrides.
func loadDetector(c commonFlags, cfg *config.Config) (*detect.Detector, *taxonomy.Taxonomy, error) {
	var tax *taxonomy.Taxonomy
	var err error
	switch {
	case c.rulesOnly:
		tax = &taxonomy.Taxonomy{}
	case c.taxonomy != "":
		tax, err = taxonomy.Load(c.taxonomy)
	default:
		tax, err = taxonomy.LoadDefault()
	}
	if err != nil {
		return nil, nil, err
	}
	if err := taxonomy.RequireComplete(tax); err != nil {
		return nil, nil, fmt.Errorf("taxonomy: %w", err)
	}
	ruleFiles := c.rules
	// gitleaks migration: with no explicit --rules, auto-load a .gitleaks.toml from the working dir so
	// its rules join the taxonomy and their IDs line up with any .gitleaksignore.
	if len(ruleFiles) == 0 && !c.rulesOnly && !c.noAutoPolicy {
		name, err := taxonomy.DiscoverGitleaks()
		if err != nil {
			return nil, nil, err
		}
		if name != "" {
			ruleFiles = append(ruleFiles, name)
			logx.Info("auto-loaded gitleaks config", "file", name)
		}
	}
	for _, rp := range ruleFiles {
		ext, al, err := taxonomy.LoadAny(rp)
		if err != nil {
			return nil, nil, fmt.Errorf("rules %q: %w", rp, err)
		}
		if err := taxonomy.RequireComplete(ext); err != nil {
			return nil, nil, fmt.Errorf("rules %q: %w", rp, err)
		}
		tax.Types = append(tax.Types, ext.Types...)
		if cfg != nil && al != nil {
			cfg.MergeAllowlist(al.Regexes, al.Paths, al.StopWords)
		}
		logx.Info("imported external rules", "file", rp, "rules", len(ext.Types), "skipped", len(ext.Skipped))
	}
	if cfg != nil {
		origTypes := len(tax.Types)
		kept := tax.Types[:0]
		for _, t := range tax.Types {
			if cfg.TypeEnabled(t.ID) {
				kept = append(kept, t)
			}
		}
		tax.Types = kept
		// detectors.enable is restrict-to-only, so an enable list matching no real type disables every
		// taxonomy detector — warn rather than scan with zero detectors and exit 0 "clean".
		if len(cfg.Detectors.Enable) > 0 && origTypes > 0 && len(tax.Types) == 0 {
			logx.Warn("detectors.enable matched no known type — ALL taxonomy detectors are disabled",
				"enable", cfg.Detectors.Enable)
		}
		for _, cr := range cfg.Detectors.Custom {
			// saferegex caps an attacker-controlled custom-rule regex on the executing path (a bare
			// regexp.Compile would let a packed bomb OOM the scan before any finding).
			re, err := saferegex.Compile(cr.Regex)
			if err != nil {
				return nil, nil, fmt.Errorf("custom rule %q: bad regex: %w", cr.ID, err)
			}
			cat := cr.Category
			if cat == "" {
				cat = "generic"
			}
			if cfg.TypeDisabled(cr.ID) {
				continue
			}
			tax.Types = append(tax.Types, taxonomy.SecretType{
				ID: cr.ID, Name: cr.ID, Category: cat,
				Detection: taxonomy.Detection{Regex: cr.Regex}, RE: re,
			})
		}
	}
	return detect.New(tax), tax, nil
}

// loadConfiguredEngine applies config suppression to templates before candidates or verifiers run.
func loadConfiguredEngine(c commonFlags, cfg *config.Config) (*rules.Engine, error) {
	eng, err := loadEngine(c)
	if err != nil || eng == nil || cfg == nil {
		return eng, err
	}
	var disabled []string
	for _, template := range eng.Templates() {
		if cfg.TypeDisabled(template.ID) {
			disabled = append(disabled, template.ID)
		}
	}
	eng.Filter(rules.FilterOpts{ExcludeIDs: disabled})
	return eng, nil
}

// loadEngine preserves explicit isolation and otherwise falls back to the immutable snapshot.
func loadEngine(c commonFlags) (*rules.Engine, error) {
	dirs := c.rulesDir
	var err error
	if !c.rulesOnly && !c.noAutoPolicy && !c.bundled {
		dirs, err = discoverRulesDirs(dirs)
		if err != nil {
			return nil, err
		}
	}
	if c.bundled && !c.rulesOnly {
		dirs = nil
	}
	var eng *rules.Engine
	if len(dirs) == 0 {
		if c.rulesOnly || c.noAutoPolicy && !c.bundled {
			return nil, nil
		}
		eng, err = rules.LoadEmbedded(bundledrules.Files)
	} else {
		eng, err = rules.Load(dirs...)
	}
	if err != nil {
		return nil, fmt.Errorf("incomplete rule template set: %w", err)
	}
	eng.Filter(rules.FilterOpts{Tags: splitCSV(c.tags), ExcludeTags: splitCSV(c.excludeTags), Severities: splitCSV(c.ruleSeverity)})
	logx.Debug("loaded rule templates", "count", eng.Len())
	return eng, nil
}

// loadVerifySet compiles only the selected policy; verification remains explicitly opt-in.
func loadVerifySet(c commonFlags) (*verify.Set, error) {
	if !c.verify {
		return nil, nil
	}
	var dirs []string
	var err error
	if !c.bundled {
		dirs, err = discoverVerifierDirs(c.verifiers)
		if err != nil {
			return nil, err
		}
	}
	var vs *verify.Set
	if len(dirs) == 0 {
		vs, err = verify.LoadEmbedded(c.verifyTimeout, bundledverifiers.Files)
	} else {
		vs, err = verify.Load(c.verifyTimeout, dirs...)
	}
	if err != nil {
		return nil, fmt.Errorf("--verify needs a complete verifier set: %w", err)
	}
	if vs == nil || vs.Count() == 0 {
		return nil, fmt.Errorf("--verify needs verifiers, but the loaded set is empty — run 'prowl verifiers update'")
	}
	logx.Info("live-verification enabled", "verifiers", vs.Count())
	return vs, nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// setupLogging configures the global logger.
// Precedence: --silence > --log-level > --verbose > --quiet > info.
func setupLogging(c commonFlags) {
	level := slog.LevelInfo
	switch {
	case c.silence:
		level = logx.LevelSilent
	case c.logLevel != "":
		_ = level.UnmarshalText([]byte(c.logLevel))
	case c.verbose:
		level = slog.LevelDebug
	case c.quiet:
		level = slog.LevelWarn
	}
	color := !c.noColor && os.Getenv("NO_COLOR") == "" && c.logFormat != "json" && isTTY(os.Stderr)
	logx.Setup(logx.Options{Level: level, Format: c.logFormat, Color: color})
}

// rootContext returns a context cancelled on Ctrl-C / SIGTERM and, with --timeout, after that
// deadline. Caller must defer the stop func.
func rootContext(c commonFlags) (context.Context, context.CancelFunc) {
	c.coverage.SetIdentityScope(c.identityKey)
	ctx, stop := signal.NotifyContext(model.WithCoverage(context.Background(), c.coverage), scanSignals()...)
	ctx = source.WithStateDirectory(ctx, c.indexDir)
	if c.timeout > 0 {
		tctx, cancel := context.WithTimeout(ctx, c.timeout)
		return tctx, func() { cancel(); stop() }
	}
	return ctx, stop
}

// loadConfig resolves the config file (--config or auto-discovered) and applies its defaults for
// any value not set on the command line.
func loadConfig(c *commonFlags) (*config.Config, error) {
	if c.failOnVerified && !c.verify {
		// Without --verify nothing is ever confirmed live, so the gate would always pass — require it.
		return nil, fmt.Errorf("--fail-on-verified needs --verify (it gates on provider-confirmed-live secrets)")
	}
	var cfg *config.Config
	if c.config != "" {
		var err error
		if cfg, err = config.Load(c.config); err != nil {
			// An explicit --config that fails to load must abort, not fall through to an auto-discovered
			// (possibly untrusted) in-repo .prowl.yaml.
			return nil, err
		}
	}
	if cfg == nil && c.noAutoConfig {
		// repo/org scan an untrusted tree — never honor its own .prowl.yaml; only --config is trusted.
		cfg = &config.Config{}
	}
	if cfg == nil {
		var err error
		cfg, err = config.Discover()
		if err != nil {
			return nil, err
		}
		// A scanned repo's own .prowl.yaml is attacker-controlled (a fork PR, a dependency). Warn if it
		// suppresses detection so a kill-switch can't silently blind the scan; pass --config to vouch.
		if p := cfg.LoadedFrom(); p != "" {
			// Warn on every channel that can hide a finding: disabling a detector, allowlisting,
			// detection/ML tuning, and a restrict-to-only `enable` list (which narrows or zeroes
			// detection). `exclude` (path scoping) is excluded as noise.
			allow := len(cfg.Allowlist.Regexes) + len(cfg.Allowlist.Values) + len(cfg.Allowlist.StopWords) + len(cfg.Allowlist.Paths)
			tuning := cfg.Detection.GenericEntropyMin > 0 || cfg.Detection.PlaceholderMaxEntropy > 0 ||
				cfg.Detection.MaxMatchesPerFile > 0 || cfg.Performance.MLThreshold > 0
			enable := len(cfg.Detectors.Enable)
			if len(cfg.Detectors.Disable) > 0 || allow > 0 || tuning || enable > 0 {
				logx.Warn("in-repo .prowl.yaml suppresses detection — review if scanning untrusted code",
					"path", p, "disabled_detectors", len(cfg.Detectors.Disable), "allowlist_rules", allow,
					"detection_tuning", tuning, "enable_only", enable)
			}
		}
	}
	for _, is := range cfg.Issues() { // surface bad allowlist/custom regexes instead of silently dropping them
		logx.Warn("config issue", "detail", is)
	}
	c.exclude = append(c.exclude, cfg.Exclude...)
	if !c.explicitFlags["--format"] && c.format == "pretty" && cfg.Output.Format != "" {
		c.format = cfg.Output.Format
	}
	if c.failOn == "" {
		c.failOn = cfg.Output.FailOn
	}
	if !c.explicitFlags["--max-size"] && c.maxSize == 10<<20 && cfg.Performance.MaxSize > 0 {
		c.maxSize = cfg.Performance.MaxSize
	}
	if !c.explicitFlags["--workers"] && c.workers == 0 && cfg.Performance.Workers > 0 {
		c.workers = cfg.Performance.Workers
	}
	// Apply config-file detection thresholds + operational limits (zero/empty keeps the default; these
	// are process-wide). Flags win: the ML threshold and verify timeout come from config only if unset.
	detect.ApplyTuning(cfg.Detection.GenericEntropyMin, cfg.Detection.PlaceholderMaxEntropy, cfg.Detection.MaxMatchesPerFile)
	forge.SetMaxPages(cfg.Limits.OrgMaxPages)
	verify.SetConcurrency(cfg.Performance.VerifyConcurrency)
	if !c.mlThresholdSet && cfg.Performance.MLThreshold > 0 {
		c.mlThreshold = cfg.Performance.MLThreshold
	}
	if c.verifyTimeout == 0 {
		if d, err := time.ParseDuration(cfg.Performance.VerifyTimeout); err == nil && d > 0 {
			c.verifyTimeout = d
		}
	}
	if d, err := time.ParseDuration(cfg.Limits.CloneTimeout); err == nil && d > 0 {
		source.SetCloneTimeout(d)
	}
	return cfg, nil
}

// redactURL strips embedded credentials (`user:token@`) from a clone URL before logging, so a token
// injected from a CI secret store never lands in build logs.
func redactURL(raw string) string { return safehttp.RedactURL(raw) }
