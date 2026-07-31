package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"strings"
	"testing"
)

func makeZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func makeTAR(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func gzipData(t *testing.T, name string, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	gw.Name = name
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func collect(t *testing.T, name string, raw []byte, limits Limits) ([]Entry, Stats, error) {
	t.Helper()
	var entries []Entry
	stats, recognized, err := Walk(name, raw, limits, func(e Entry) error {
		entries = append(entries, e)
		return nil
	})
	if !recognized {
		t.Fatalf("%s was not recognized", name)
	}
	return entries, stats, err
}

func TestZIPNestedTARGZIP(t *testing.T) {
	innerTar := makeTAR(t, map[string][]byte{"config/secret.env": []byte(`TOKEN="abc123"`)})
	tgz := gzipData(t, "", innerTar)
	outer := makeZIP(t, map[string][]byte{"bundle.tar.gz": tgz, "plain.txt": []byte("hello")})
	entries, stats, err := collect(t, "outer.zip", outer, Limits{
		MaxEntry: 1 << 20, MaxArchive: 2 << 20, MaxTotal: 8 << 20, MaxEntries: 100, MaxDepth: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Archives != 3 || len(entries) != 2 {
		t.Fatalf("stats=%+v entries=%v", stats, entries)
	}
	var joined strings.Builder
	for _, e := range entries {
		joined.WriteString(e.Path)
		joined.Write(e.Data)
	}
	if !strings.Contains(joined.String(), "bundle.tar.gz!/bundle.tar!/config/secret.env") ||
		!strings.Contains(joined.String(), `TOKEN="abc123"`) {
		t.Fatalf("nested result = %q", joined.String())
	}
}

func TestUnsafeNameAndSymlinkSkipped(t *testing.T) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, _ := zw.Create("../escape.txt")
	_, _ = io.WriteString(w, "bad")
	h := &zip.FileHeader{Name: "link", Method: zip.Store}
	h.SetMode(0o777 | fs.ModeSymlink)
	w, _ = zw.CreateHeader(h)
	_, _ = io.WriteString(w, "target")
	w, _ = zw.Create("safe.txt")
	_, _ = io.WriteString(w, "good")
	_ = zw.Close()

	entries, stats, err := collect(t, "x.zip", out.Bytes(), Limits{MaxEntry: 1 << 20, MaxArchive: 1 << 20, MaxTotal: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Path, "!/safe.txt") || stats.Skipped != 2 {
		t.Fatalf("entries=%v stats=%+v", entries, stats)
	}
}

func TestExpansionAndEntryCaps(t *testing.T) {
	bomb := makeZIP(t, map[string][]byte{"large.txt": []byte(strings.Repeat("A", 2<<20))})
	if _, _, err := collect(t, "bomb.zip", bomb, Limits{
		MaxEntry: 3 << 20, MaxArchive: 1 << 20, MaxTotal: 1 << 20,
	}); err == nil || !strings.Contains(err.Error(), "cumulative limit") {
		t.Fatalf("expansion error = %v", err)
	}

	many := makeZIP(t, map[string][]byte{"a": []byte("1"), "b": []byte("2")})
	if _, _, err := collect(t, "many.zip", many, Limits{
		MaxEntry: 1 << 20, MaxArchive: 1 << 20, MaxTotal: 4 << 20, MaxEntries: 1,
	}); err == nil || !strings.Contains(err.Error(), "entry") {
		t.Fatalf("entry cap error = %v", err)
	}
}

func TestPlainPayloadNotRecognized(t *testing.T) {
	_, recognized, err := Walk("plain.txt", []byte("hello"), Limits{}, func(Entry) error { return nil })
	if err != nil || recognized {
		t.Fatalf("plain = recognized %v, err %v", recognized, err)
	}
}
