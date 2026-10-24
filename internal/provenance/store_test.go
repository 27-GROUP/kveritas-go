package provenance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointRestore(t *testing.T) {
	dir := t.TempDir()
	kv := filepath.Join(dir, ".kveritas")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("train.py", "lr = 0.1\n")
	write("model.bin", "weights-50")

	m, err := Capture(dir, kv, []string{"model.bin", "model.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || len(m.Extra) != 1 {
		t.Fatalf("captured %v, extra %v", m.Files, m.Extra)
	}
	if !Compare(dir, kv, m).Clean() {
		t.Fatal("fresh checkpoint should be clean")
	}

	write("train.py", "lr = 0.5\n")
	write("model.bin", "weights-63")
	write("new.py", "x = 1\n")
	d := Compare(dir, kv, m)
	if len(d.Modified) != 2 || len(d.Added) != 1 {
		t.Fatalf("drift %+v", d)
	}

	n, err := Restore(dir, kv, m)
	if err != nil || n != 2 {
		t.Fatalf("restored %d, %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "model.bin")); string(b) != "weights-50" {
		t.Fatalf("model.bin = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.py")); err != nil {
		t.Fatal("restore must not delete files created since the checkpoint")
	}

	if m.Root([]byte("a")) == m.Root([]byte("b")) {
		t.Fatal("root must depend on the salt")
	}
	if _, err := Capture(dir, kv, []string{"../outside"}); err == nil {
		t.Fatal("files outside the project must be refused")
	}
}
