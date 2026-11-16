// Command audit_reference_tests inventories test declarations without executing repository code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Decl struct {
	Path         string   `json:"path"`
	Line         int      `json:"line"`
	Name         string   `json:"name"`
	Hash         string   `json:"token_sha256"`
	Folded       string   `json:"string_value_token_sha256"`
	Dependencies []string `json:"dependencies"`
}
type Inventory struct {
	Declarations map[string]Decl   `json:"declarations"`
	Files        map[string]string `json:"files"`
	TestData     map[string]string `json:"testdata"`
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func tokens(b []byte) string {
	f := token.NewFileSet().AddFile("", -1, len(b))
	var s scanner.Scanner
	s.Init(f, b, nil, 0)
	var out []string
	for {
		_, t, l := s.Scan()
		if t == token.EOF {
			break
		}
		if t == token.SEMICOLON {
			l = ";"
		}
		out = append(out, fmt.Sprintf("%d:%s", t, l))
	}
	b, _ = json.Marshal(out)
	return hash(b)
}
func stringValue(n ast.Node) constant.Value {
	switch x := n.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			return constant.MakeFromLiteral(x.Value, x.Kind, 0)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			a, b := stringValue(x.X), stringValue(x.Y)
			if a.Kind() == constant.String && b.Kind() == constant.String {
				return constant.BinaryOp(a, x.Op, b)
			}
		}
	case *ast.ParenExpr:
		return stringValue(x.X)
	}
	return constant.MakeUnknown()
}
func folded(raw []byte, fs *token.FileSet, n ast.Node) string {
	start, end := fs.Position(n.Pos()).Offset, fs.Position(n.End()).Offset
	type edit struct {
		start, end int
		value      string
	}
	var edits []edit
	ast.Inspect(n, func(x ast.Node) bool {
		if x == nil {
			return false
		}
		v := stringValue(x)
		if v.Kind() == constant.String {
			edits = append(edits, edit{fs.Position(x.Pos()).Offset, fs.Position(x.End()).Offset, strconv.Quote(constant.StringVal(v))})
			return false
		}
		return true
	})
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	b := append([]byte(nil), raw[start:end]...)
	for _, e := range edits {
		b = append(append(append([]byte(nil), b[:e.start-start]...), []byte(e.value)...), b[e.end-start:]...)
	}
	return tokens(b)
}
func inventory(root string) Inventory {
	inv := Inventory{map[string]Decl{}, map[string]string{}, map[string]string{}}
	err := filepath.WalkDir(filepath.Join(root, "tool"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			if strings.Contains(filepath.ToSlash(path), "/testdata/") {
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(root, path)
				inv.TestData[filepath.ToSlash(rel)] = hash(raw)
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		inv.Files[rel] = hash(raw)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, raw, 0)
		if err != nil {
			return err
		}
		pkg := filepath.ToSlash(filepath.Dir(rel)) + "/" + f.Name.Name
		for _, d := range f.Decls {
			var names []string
			switch x := d.(type) {
			case *ast.FuncDecl:
				n := x.Name.Name
				if x.Recv != nil {
					r := x.Recv.List[0].Type
					n = "method:" + tokens(raw[fset.Position(r.Pos()).Offset:fset.Position(r.End()).Offset]) + ":" + n
				}
				names = []string{n}
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					switch z := sp.(type) {
					case *ast.ValueSpec:
						for _, n := range z.Names {
							names = append(names, n.Name)
						}
					case *ast.TypeSpec:
						names = append(names, z.Name.Name)
					}
				}
			}
			deps := map[string]bool{}
			ast.Inspect(d, func(n ast.Node) bool {
				if i, ok := n.(*ast.Ident); ok {
					deps[pkg+"/"+i.Name] = true
				}
				return true
			})
			var ds []string
			for x := range deps {
				ds = append(ds, x)
			}
			sort.Strings(ds)
			for _, name := range names {
				if name == "_" {
					continue
				}
				if name == "init" {
					name = fmt.Sprintf("init:%s:%d", rel, fset.Position(d.Pos()).Line)
				}
				key := pkg + "/" + name
				if _, exists := inv.Declarations[key]; exists {
					panic("duplicate " + key)
				}
				inv.Declarations[key] = Decl{rel, fset.Position(d.Pos()).Line, name, tokens(raw[fset.Position(d.Pos()).Offset:fset.Position(d.End()).Offset]), folded(raw, fset, d), ds}
			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	for key, d := range inv.Declarations {
		var ds []string
		for _, dep := range d.Dependencies {
			if _, ok := inv.Declarations[dep]; ok && dep != key {
				ds = append(ds, dep)
			}
		}
		d.Dependencies = ds
		inv.Declarations[key] = d
	}
	return inv
}
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: audit_reference_tests REFERENCE_ROOT CANDIDATE_ROOT")
		os.Exit(2)
	}
	out := map[string]Inventory{"reference": inventory(os.Args[1]), "candidate": inventory(os.Args[2])}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
