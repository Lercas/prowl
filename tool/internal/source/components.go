package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lercas/prowl/tool/internal/credentialset"
	"github.com/Lercas/prowl/tool/internal/model"
)

type credentialModeKey struct{}
type credentialScopeKey struct{}

// WithCredentialScopes enables producer-declared physical-file boundaries.
// It does not authorize verification or bind other source implementations.
func WithCredentialScopes(ctx context.Context) context.Context {
	return context.WithValue(ctx, credentialModeKey{}, true)
}

func credentialRootContext(ctx context.Context) context.Context {
	if enabled, _ := ctx.Value(credentialModeKey{}).(bool); enabled {
		return context.WithValue(ctx, credentialScopeKey{}, credentialset.NewScope())
	}
	return ctx
}

func withoutCredentialScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, credentialScopeKey{}, (*credentialset.Scope)(nil))
}

// Nested repositories cannot silently share a selected parent's credentials.
func nestedCredentialRoot(ctx context.Context, rootFS *os.Root, root, path string, scopes map[string]*credentialset.Scope) error {
	if len(scopes) == 0 || path == root {
		return nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		model.Note(ctx, "cross_file_scope_unknown", path, true)
		return errors.New("credential acquisition boundary unavailable")
	}
	_, err = rootFS.Lstat(filepath.Join(rel, ".git"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(scopes) >= 10000 {
		model.Note(ctx, "cross_file_scope_unknown", path, true)
		return errors.New("credential acquisition boundary unavailable")
	}
	scopes[filepath.Clean(path)] = credentialset.NewScope()
	return nil
}

func credentialFileContext(ctx context.Context, path string, scopes map[string]*credentialset.Scope) context.Context {
	if len(scopes) == 0 {
		return ctx
	}
	path = filepath.Clean(path)
	longest := 0
	var scope *credentialset.Scope
	for root, candidate := range scopes {
		if root == "." || path == root || strings.HasPrefix(path, strings.TrimRight(root, string(filepath.Separator))+string(filepath.Separator)) {
			if scope == nil || len(root) > longest {
				longest, scope = len(root), candidate
			}
		}
	}
	return context.WithValue(ctx, credentialScopeKey{}, scope)
}
