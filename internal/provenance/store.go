package provenance

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/bundle"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
)

// A checkpoint's files by content hash. The contents sit in .kveritas/objects and
// never leave the machine; only a salted root of this map is anchored.
type Manifest struct {
	Files map[string]string `json:"files"`
	Extra []string          `json:"extra,omitempty"`
}

func objectsDir(kvDir string) string { return filepath.Join(kvDir, "objects") }

func manifestPath(kvDir, id string) string {
	return filepath.Join(kvDir, "checkpoints", id+".json")
}

func cleanRel(projectDir, p string) (string, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(projectDir, p)
	}
	rel, err := filepath.Rel(projectDir, filepath.Clean(abs))
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s is outside the project folder", p)
	}
	return filepath.ToSlash(rel), nil
}

func tracked(projectDir string, extra []string) []string {
	files, _ := bundle.CollectSourceFiles(projectDir)
	seen := map[string]bool{}
	var out []string
	for _, f := range append(files, extra...) {
		f = filepath.ToSlash(f)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func Capture(projectDir, kvDir string, extra []string) (*Manifest, error) {
	m := &Manifest{Files: map[string]string{}}
	for _, p := range extra {
		rel, err := cleanRel(projectDir, p)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(filepath.Join(projectDir, rel)); err != nil {
			return nil, fmt.Errorf("cannot read %s", p)
		}
		if !slices.Contains(m.Extra, rel) {
			m.Extra = append(m.Extra, rel)
		}
	}
	if err := os.MkdirAll(objectsDir(kvDir), 0700); err != nil {
		return nil, err
	}
	for _, rel := range tracked(projectDir, m.Extra) {
		h, err := store(kvDir, filepath.Join(projectDir, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		m.Files[rel] = h
	}
	return m, nil
}

// Hashes first so an unchanged file is not copied again; the copy is hashed as it is
// written, so the stored name always matches the stored bytes.
func store(kvDir, path string) (string, error) {
	h, err := crypto.HashFile(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(objectsDir(kvDir), h)); err == nil {
		return h, nil
	}
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(objectsDir(kvDir), "tmp-")
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, sum), src); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	got := hex.EncodeToString(sum.Sum(nil))
	return got, os.Rename(tmp.Name(), filepath.Join(objectsDir(kvDir), got))
}

func SaveManifest(kvDir, id string, m *Manifest) error {
	if err := os.MkdirAll(filepath.Dir(manifestPath(kvDir, id)), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath(kvDir, id), data, 0600)
}

func LoadManifest(kvDir, id string) (*Manifest, error) {
	data, err := os.ReadFile(manifestPath(kvDir, id))
	if err != nil {
		return nil, fmt.Errorf("checkpoint %s has no saved files here", id)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Salted, so the anchored root reveals nothing about files anyone could guess.
func (m *Manifest) Root(salt []byte) string {
	_, canon, err := crypto.CanonicalHashWithBytes(m.Files)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(canon)
	return hex.EncodeToString(mac.Sum(nil))
}

type Drift struct {
	Added    []string `json:"added,omitempty"`
	Modified []string `json:"modified,omitempty"`
	Deleted  []string `json:"deleted,omitempty"`
}

func (d Drift) Clean() bool { return len(d.Added)+len(d.Modified)+len(d.Deleted) == 0 }

// Remembers each file's hash by size and modification time, so repeated comparisons
// only re-read files that changed.
type HashCache struct {
	mu sync.Mutex
	m  map[string]cachedHash
}

type cachedHash struct {
	size int64
	mod  time.Time
	hash string
}

func NewHashCache() *HashCache { return &HashCache{m: map[string]cachedHash{}} }

func (c *HashCache) hash(path string) (string, error) {
	if c == nil {
		return crypto.HashFile(path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	e, ok := c.m[path]
	c.mu.Unlock()
	if ok && e.size == st.Size() && e.mod.Equal(st.ModTime()) {
		return e.hash, nil
	}
	h, err := crypto.HashFile(path)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.m[path] = cachedHash{size: st.Size(), mod: st.ModTime(), hash: h}
	c.mu.Unlock()
	return h, nil
}

func Compare(projectDir string, m *Manifest) Drift { return CompareCached(projectDir, m, nil) }

func CompareCached(projectDir string, m *Manifest, cache *HashCache) Drift {
	var d Drift
	cur := map[string]bool{}
	for _, rel := range tracked(projectDir, m.Extra) {
		path := filepath.Join(projectDir, filepath.FromSlash(rel))
		h, err := cache.hash(path)
		if err != nil {
			continue
		}
		cur[rel] = true
		want, ok := m.Files[rel]
		switch {
		case !ok:
			d.Added = append(d.Added, rel)
		case want != h:
			d.Modified = append(d.Modified, rel)
		}
	}
	for rel := range m.Files {
		if !cur[rel] {
			d.Deleted = append(d.Deleted, rel)
		}
	}
	sort.Strings(d.Deleted)
	return d
}

// Writes back every file that differs from the checkpoint. Files created since are
// left alone: restore never deletes the author's work.
func Restore(projectDir, kvDir string, m *Manifest) (int, error) {
	n := 0
	rels := make([]string, 0, len(m.Files))
	for rel := range m.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		want := m.Files[rel]
		if _, err := cleanRel(projectDir, rel); err != nil {
			return n, err
		}
		dest := filepath.Join(projectDir, filepath.FromSlash(rel))
		if h, err := crypto.HashFile(dest); err == nil && h == want {
			continue
		}
		obj := filepath.Join(objectsDir(kvDir), want)
		if h, err := crypto.HashFile(obj); err != nil || h != want {
			return n, fmt.Errorf("saved copy of %s is missing or damaged", rel)
		}
		if err := copyFile(obj, dest); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func copyFile(src, dest string) error {
	mode := os.FileMode(0644)
	if st, err := os.Stat(dest); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".kveritas-restore-")
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
