// Command api_inventory records exported declarations without tests or comments.
// It parses every source file without applying build tags; declaration equality
// is a review aid, not a claim about equivalent runtime behavior.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type Decl struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Signature string `json:"signature"`
	SHA256    string `json:"sha256"`
	Body      string `json:"body"`
}

func encode(fs *token.FileSet, node any) string {
	var b bytes.Buffer
	if err := format.Node(&b, fs, node); err != nil {
		panic(err)
	}
	return b.String()
}
func collect(root string) map[string]Decl {
	out := map[string]Decl{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fs := token.NewFileSet()
		file, err := parser.ParseFile(fs, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range file.Decls {
			if g, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range g.Specs {
					var names []string
					switch node := spec.(type) {
					case *ast.TypeSpec:
						if node.Name.IsExported() {
							names = append(names, node.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range node.Names {
							if name.IsExported() {
								names = append(names, name.Name)
							}
						}
					}
					for _, name := range names {
						key := filepath.ToSlash(filepath.Dir(rel)) + "/" + name
						body := encode(fs, spec)
						sum := sha256.Sum256([]byte(body))
						if _, found := out[key]; found {
							panic("duplicate declaration: " + key)
						}
						out[key] = Decl{filepath.ToSlash(rel), fs.Position(spec.Pos()).Line, string(g.Tok.String()) + " " + body, hex.EncodeToString(sum[:]), body}
					}
				}
				continue
			}
			f, ok := decl.(*ast.FuncDecl)
			if !ok || !f.Name.IsExported() {
				continue
			}
			receiver := ""
			if f.Recv != nil {
				receiver = encode(fs, f.Recv.List[0].Type) + "."
			}
			key := filepath.ToSlash(filepath.Dir(rel)) + "/" + receiver + f.Name.Name
			body := encode(fs, f)
			sum := sha256.Sum256([]byte(body))
			oldBody := f.Body
			f.Body = nil
			signature := encode(fs, f)
			f.Body = oldBody
			if _, found := out[key]; found {
				panic("duplicate declaration: " + key)
			}
			out[key] = Decl{filepath.ToSlash(rel), fs.Position(f.Pos()).Line, signature, hex.EncodeToString(sum[:]), body}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return out
}
func main() {
	if len(os.Args) != 3 {
		panic("two source roots required")
	}
	out := map[string]any{"reference": collect(os.Args[1]), "candidate": collect(os.Args[2])}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
