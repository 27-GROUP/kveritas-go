package provenance

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/klauspost/compress/zstd"
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
	files := projectFiles(projectDir)
	seen := map[string]bool{}
	for _, f := range files {
		seen[f] = true
	}
	for _, f := range extra {
		if f = filepath.ToSlash(f); !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return files
}

func parallel(n int, fn func(i int)) {
	workers := min(runtime.NumCPU(), 8, n)
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
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
	cache := LoadHashCache(kvDir)
	rels := tracked(projectDir, m.Extra)
	hashes := make([]string, len(rels))
	parallel(len(rels), func(i int) {
		hashes[i], _ = store(kvDir, cache, rels[i], filepath.Join(projectDir, filepath.FromSlash(rels[i])))
	})
	for i, rel := range rels {
		if hashes[i] != "" {
			m.Files[rel] = hashes[i]
		}
	}
	return m, cache.Save()
}

func objectPath(kvDir, hash string) (string, bool) {
	raw := filepath.Join(objectsDir(kvDir), hash)
	if _, err := os.Stat(raw); err == nil {
		return raw, true
	}
	if _, err := os.Stat(raw + ".zst"); err == nil {
		return raw + ".zst", true
	}
	return "", false
}

func tempName(dir, prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return filepath.Join(dir, prefix+hex.EncodeToString(b))
}

func isText(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(f, buf)
	return !bytes.Contains(buf[:n], []byte{0})
}

// Text is stored zstd-compressed; anything else as a copy-on-write clone where the
// filesystem allows it, otherwise a plain copy. Objects are named by the hash of the
// bytes actually stored, so a file that changes mid-copy can never be mislabeled.
func store(kvDir string, cache *HashCache, rel, path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if h, ok := cache.lookup(rel, st); ok {
		if _, ok := objectPath(kvDir, h); ok {
			return h, nil
		}
	}
	text := isText(path)
	if !text {
		tmp := tempName(objectsDir(kvDir), "tmp-")
		if cloneFile(path, tmp) == nil {
			h, err := crypto.HashFile(tmp)
			if err != nil {
				os.Remove(tmp)
				return "", err
			}
			if _, ok := objectPath(kvDir, h); ok {
				os.Remove(tmp)
			} else if err := os.Rename(tmp, filepath.Join(objectsDir(kvDir), h)); err != nil {
				os.Remove(tmp)
				return "", err
			}
			if after, err := os.Stat(path); err == nil && stateOf(after) == stateOf(st) {
				cache.remember(rel, st, h)
			}
			return h, nil
		}
	}
	h, err := cache.hash(rel, path)
	if err != nil {
		return "", err
	}
	if _, ok := objectPath(kvDir, h); ok {
		return h, nil
	}
	return copyIn(kvDir, path, text)
}

var encoders = sync.Pool{New: func() any {
	zw, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true))
	return zw
}}

func copyIn(kvDir, path string, compress bool) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(objectsDir(kvDir), "tmp-")
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	sum := sha256.New()
	if compress {
		zw := encoders.Get().(*zstd.Encoder)
		defer encoders.Put(zw)
		zw.Reset(tmp)
		if _, err := io.Copy(io.MultiWriter(zw, sum), src); err != nil {
			zw.Close()
			return fail(err)
		}
		if err := zw.Close(); err != nil {
			return fail(err)
		}
	} else if _, err := io.Copy(io.MultiWriter(tmp, sum), src); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if _, ok := objectPath(kvDir, got); ok {
		os.Remove(tmp.Name())
		return got, nil
	}
	dest := filepath.Join(objectsDir(kvDir), got)
	if compress {
		dest += ".zst"
	}
	return got, os.Rename(tmp.Name(), dest)
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

func Compare(projectDir, kvDir string, m *Manifest) Drift {
	cache := LoadHashCache(kvDir)
	d := CompareCached(projectDir, m, cache)
	_ = cache.Save()
	return d
}

func CompareCached(projectDir string, m *Manifest, cache *HashCache) Drift {
	var d Drift
	rels := tracked(projectDir, m.Extra)
	hashes := make([]string, len(rels))
	parallel(len(rels), func(i int) {
		hashes[i], _ = cache.hash(rels[i], filepath.Join(projectDir, filepath.FromSlash(rels[i])))
	})
	cur := map[string]bool{}
	for i, rel := range rels {
		if hashes[i] == "" {
			continue
		}
		cur[rel] = true
		want, ok := m.Files[rel]
		switch {
		case !ok:
			d.Added = append(d.Added, rel)
		case want != hashes[i]:
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
	cache := LoadHashCache(kvDir)
	defer cache.Save()
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
		if h, err := cache.hash(rel, dest); err == nil && h == want {
			continue
		}
		if err := restoreFile(kvDir, want, dest); err != nil {
			return n, fmt.Errorf("%s: %w", rel, err)
		}
		if st, err := os.Stat(dest); err == nil {
			cache.remember(rel, st, want)
		}
		n++
	}
	return n, nil
}

var errDamaged = errors.New("saved copy is missing or damaged")

func restoreFile(kvDir, want, dest string) error {
	obj, ok := objectPath(kvDir, want)
	if !ok {
		return errDamaged
	}
	mode := os.FileMode(0644)
	if st, err := os.Stat(dest); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	tmp := tempName(filepath.Dir(dest), ".kveritas-restore-")
	if strings.HasSuffix(obj, ".zst") || cloneFile(obj, tmp) != nil {
		if err := writeObject(obj, tmp); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	if h, err := crypto.HashFile(tmp); err != nil || h != want {
		os.Remove(tmp)
		return errDamaged
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func writeObject(obj, dest string) error {
	in, err := os.Open(obj)
	if err != nil {
		return err
	}
	defer in.Close()
	var r io.Reader = in
	if strings.HasSuffix(obj, ".zst") {
		zr, err := zstd.NewReader(in, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
