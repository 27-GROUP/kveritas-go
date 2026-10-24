package provenance

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProjectFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		".gitignore":               "*.log\n/out/\ndata/**/*.tmp\n!keep.log\n",
		"train.py":                 "x",
		"notes.txt":                "x",
		"data/train.csv":           "x",
		"data/a/b/c.tmp":           "x",
		"run.log":                  "x",
		"keep.log":                 "x",
		"out/model.bin":            "x",
		"sub/out/model.bin":        "x",
		"sub/.gitignore":           "secret.txt\n",
		"sub/secret.txt":           "x",
		"__pycache__/a.pyc":        "x",
		".venv/lib/x.py":           "x",
		"myenv/pyvenv.cfg":         "x",
		"myenv/lib/site.py":        "x",
		".kveritas/session.json":   "x",
		"pkg.egg-info/PKG-INFO":    "x",
		".ipynb_checkpoints/a.txt": "x",
	})
	got := projectFiles(dir)
	want := []string{".gitignore", "data/train.csv", "keep.log", "notes.txt", "sub/.gitignore", "sub/out/model.bin", "train.py"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestStoreKinds(t *testing.T) {
	dir := t.TempDir()
	kv := filepath.Join(dir, ".kveritas")
	bin := string([]byte{0, 1, 2, 3, 0, 255})
	writeTree(t, dir, map[string]string{"a.txt": strings.Repeat("hello ", 1000), "w.bin": bin})
	m, err := Capture(dir, kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(kv, "objects", m.Files["a.txt"]+".zst")); err != nil {
		t.Fatal("text should be stored compressed")
	}
	if _, err := os.Stat(filepath.Join(kv, "objects", m.Files["w.bin"])); err != nil {
		t.Fatal("binary should be stored as is")
	}
	writeTree(t, dir, map[string]string{"a.txt": "changed", "w.bin": "changed"})
	if n, err := Restore(dir, kv, m); err != nil || n != 2 {
		t.Fatalf("restored %d, %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "w.bin")); string(b) != bin {
		t.Fatal("binary not restored")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.txt")); !strings.HasPrefix(string(b), "hello hello") {
		t.Fatal("text not restored")
	}
}

func TestHashCache(t *testing.T) {
	dir := t.TempDir()
	kv := filepath.Join(dir, ".kveritas")
	writeTree(t, dir, map[string]string{"a.py": "one"})
	old := time.Now().Add(-time.Hour)
	p := filepath.Join(dir, "a.py")
	os.Chtimes(p, old, old)
	m, err := Capture(dir, kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := LoadHashCache(kv).m["a.py"]; !ok || h.Hash != m.Files["a.py"] {
		t.Fatal("hash should be remembered across runs")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return
	}
	os.WriteFile(p, []byte("two"), 0644)
	os.Chtimes(p, old, old)
	if d := Compare(dir, kv, m); len(d.Modified) != 1 {
		t.Fatalf("a same-size edit with the old mtime must still be seen (ctime/inode): %+v", d)
	}
}
