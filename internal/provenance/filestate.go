package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
)

// Remembers each file's hash by size, modification time and inode, kept in
// .kveritas/filestate.json, so checkpoints and status only re-read files that changed.
type HashCache struct {
	mu    sync.Mutex
	path  string
	m     map[string]fileState
	dirty bool
}

type fileState struct {
	Size  int64  `json:"s"`
	Mod   int64  `json:"m"`
	Ino   uint64 `json:"i,omitempty"`
	Ctime int64  `json:"c,omitempty"`
	Hash  string `json:"h"`
}

func LoadHashCache(kvDir string) *HashCache {
	c := &HashCache{path: filepath.Join(kvDir, "filestate.json"), m: map[string]fileState{}}
	if data, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(data, &c.m)
	}
	return c
}

func (c *HashCache) Save() error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	data, err := json.Marshal(c.m)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	c.dirty = false
	return os.Rename(tmp, c.path)
}

func stateOf(st os.FileInfo) fileState {
	ino, ctime := fileIdentity(st)
	return fileState{Size: st.Size(), Mod: st.ModTime().UnixNano(), Ino: ino, Ctime: ctime}
}

func (c *HashCache) lookup(key string, st os.FileInfo) (string, bool) {
	if c == nil {
		return "", false
	}
	want := stateOf(st)
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if !ok || e.Size != want.Size || e.Mod != want.Mod || e.Ino != want.Ino || e.Ctime != want.Ctime {
		return "", false
	}
	return e.Hash, true
}

// A file written within the last two seconds could change again without its
// modification time moving, so it is not remembered yet.
func (c *HashCache) remember(key string, st os.FileInfo, hash string) {
	if c == nil || time.Since(st.ModTime()) < 2*time.Second {
		return
	}
	e := stateOf(st)
	e.Hash = hash
	c.mu.Lock()
	c.m[key] = e
	c.dirty = true
	c.mu.Unlock()
}

func (c *HashCache) hash(key, path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if h, ok := c.lookup(key, st); ok {
		return h, nil
	}
	h, err := crypto.HashFile(path)
	if err != nil {
		return "", err
	}
	if after, err := os.Stat(path); err == nil && stateOf(after) == stateOf(st) {
		c.remember(key, st, h)
	}
	return h, nil
}

// Hashes the given project files through the saved cache; unreadable files are left out.
func HashFilesCached(projectDir, kvDir string, rels []string) map[string]string {
	cache := LoadHashCache(kvDir)
	hashes := make([]string, len(rels))
	parallel(len(rels), func(i int) {
		hashes[i], _ = cache.hash(filepath.ToSlash(rels[i]), filepath.Join(projectDir, rels[i]))
	})
	_ = cache.Save()
	out := make(map[string]string, len(rels))
	for i, rel := range rels {
		if hashes[i] != "" {
			out[rel] = hashes[i]
		}
	}
	return out
}
