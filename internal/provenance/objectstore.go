package provenance

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

type bundleMeta struct {
	SessionID string             `json:"session_id"`
	Commits   []bundleMetaCommit `json:"commits"`
}

type bundleMetaCommit struct {
	Index int               `json:"index"`
	Event session.ProvEvent `json:"event"`
	Root  string            `json:"root"`
}

// WriteBundle writes the checkout-able object store for an Open-level run: the
// deduplicated file contents plus a manifest per snapshot. It returns the bundle's
// SHA-256 so the report can bind it. It is a no-op below the Open level.
func (r *Recorder) WriteBundle(outPath string) (string, error) {
	if r.level < Open || len(r.objects) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for hash, content := range r.objects {
		w, err := zw.Create("objects/" + hash)
		if err != nil {
			return "", err
		}
		if _, err := w.Write(content); err != nil {
			return "", err
		}
	}

	meta := bundleMeta{SessionID: r.sessionID}
	for i, m := range r.manifests {
		data, err := json.Marshal(m)
		if err != nil {
			return "", err
		}
		w, err := zw.Create(fmt.Sprintf("manifests/%d.json", i))
		if err != nil {
			return "", err
		}
		if _, err := w.Write(data); err != nil {
			return "", err
		}
		c := r.commits[i]
		meta.Commits = append(meta.Commits, bundleMetaCommit{Index: i, Event: c.Event, Root: c.Root})
	}

	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	w, err := zw.Create("meta.json")
	if err != nil {
		return "", err
	}
	if _, err := w.Write(metaData); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// Checkout materializes the tracked files of one snapshot from a bundle into
// outDir. The snapshot is selected by index or by phase name.
func Checkout(bundlePath, which, outDir string) (int, error) {
	zr, err := zip.OpenReader(bundlePath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}

	metaFile, ok := files["meta.json"]
	if !ok {
		return 0, fmt.Errorf("bundle has no meta.json")
	}
	var meta bundleMeta
	if err := readZipJSON(metaFile, &meta); err != nil {
		return 0, err
	}

	index := -1
	if n, err := strconv.Atoi(which); err == nil {
		index = n
	} else {
		for _, c := range meta.Commits {
			if c.Event.Name == which || c.Event.Kind == which {
				index = c.Index
			}
		}
	}
	if index < 0 {
		return 0, fmt.Errorf("no snapshot %q in this bundle", which)
	}

	manFile, ok := files[fmt.Sprintf("manifests/%d.json", index)]
	if !ok {
		return 0, fmt.Errorf("snapshot %d not found in bundle", index)
	}
	var manifest map[string]string
	if err := readZipJSON(manFile, &manifest); err != nil {
		return 0, err
	}

	count := 0
	for rel, ch := range manifest {
		obj, ok := files["objects/"+ch]
		if !ok {
			return count, fmt.Errorf("missing object for %s", rel)
		}
		content, err := readZipBytes(obj)
		if err != nil {
			return count, err
		}
		dest := filepath.Join(outDir, filepath.FromSlash(rel))
		if !strings.HasPrefix(filepath.Clean(dest), filepath.Clean(outDir)) {
			return count, fmt.Errorf("unsafe path in bundle: %s", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return count, err
		}
		if err := os.WriteFile(dest, content, 0644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func readZipBytes(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func readZipJSON(f *zip.File, v interface{}) error {
	data, err := readZipBytes(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
