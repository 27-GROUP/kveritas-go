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

// bundleMeta is the per-run bundle written by a Recorder.
type bundleMeta struct {
	SessionID string             `json:"session_id"`
	Commits   []bundleMetaCommit `json:"commits"`
}

type bundleMetaCommit struct {
	Index int               `json:"index"`
	Event session.ProvEvent `json:"event"`
	Root  string            `json:"root"`
}

// snapshotRef points at one snapshot inside a combined, multi-run bundle.
type snapshotRef struct {
	Run   int               `json:"run"`
	Index int               `json:"index"`
	Event session.ProvEvent `json:"event"`
	Root  string            `json:"root"`
}

// combinedMeta is the index of a merged bundle covering every run.
type combinedMeta struct {
	SessionID string        `json:"session_id"`
	Snapshots []snapshotRef `json:"snapshots"`
}

// WriteBundle writes the per-run checkout store for an Open-level run: the
// deduplicated file contents plus a manifest per snapshot. Returned as a no-op
// below the Open level.
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
	if err := writeZipJSON(zw, "meta.json", meta); err != nil {
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

// BundleInput is one run's per-run bundle, to be folded into the combined bundle.
type BundleInput struct {
	Run  int
	Path string
}

// MergeBundles folds every run's checkout store into a single zip the author can
// upload. Objects are content-addressed, so identical files across runs are stored
// once; each run's manifests are namespaced. It returns the bytes and their hash.
func MergeBundles(inputs []BundleInput) ([]byte, string, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	seen := map[string]bool{}
	var snaps []snapshotRef
	sessionID := ""

	for _, in := range inputs {
		zr, err := zip.OpenReader(in.Path)
		if err != nil {
			return nil, "", err
		}
		files := map[string]*zip.File{}
		for _, f := range zr.File {
			files[f.Name] = f
		}
		var pm bundleMeta
		if mf, ok := files["meta.json"]; ok {
			if err := readZipJSON(mf, &pm); err == nil {
				sessionID = pm.SessionID
			}
		}
		for _, c := range pm.Commits {
			snaps = append(snaps, snapshotRef{Run: in.Run, Index: c.Index, Event: c.Event, Root: c.Root})
			if mf, ok := files[fmt.Sprintf("manifests/%d.json", c.Index)]; ok {
				data, err := readZipBytes(mf)
				if err == nil {
					if err := writeZipBytes(zw, fmt.Sprintf("manifests/run%d-%d.json", in.Run, c.Index), data); err != nil {
						zr.Close()
						return nil, "", err
					}
				}
			}
		}
		for name, f := range files {
			if !strings.HasPrefix(name, "objects/") || seen[name] {
				continue
			}
			seen[name] = true
			data, err := readZipBytes(f)
			if err != nil {
				continue
			}
			if err := writeZipBytes(zw, name, data); err != nil {
				zr.Close()
				return nil, "", err
			}
		}
		zr.Close()
	}

	if err := writeZipJSON(zw, "meta.json", combinedMeta{SessionID: sessionID, Snapshots: snaps}); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// Checkout materializes the files of one snapshot from a combined bundle into
// outDir. The selector is "<run>:<snapshot>" or just "<snapshot>" (which takes the
// latest matching run); a snapshot is a phase name, "run_start"/"run_end", or an
// index.
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
	var meta combinedMeta
	if err := readZipJSON(metaFile, &meta); err != nil {
		return 0, err
	}

	wantRun := 0
	sel := which
	if strings.Contains(which, ":") {
		parts := strings.SplitN(which, ":", 2)
		if n, err := strconv.Atoi(strings.TrimPrefix(parts[0], "run")); err == nil {
			wantRun = n
		}
		sel = parts[1]
	}

	chosen := -1
	for i, s := range meta.Snapshots {
		if wantRun != 0 && s.Run != wantRun {
			continue
		}
		if s.Event.Name == sel || s.Event.Kind == sel || strconv.Itoa(s.Index) == sel {
			chosen = i
		}
	}
	if chosen < 0 {
		return 0, fmt.Errorf("no snapshot %q in this bundle", which)
	}
	s := meta.Snapshots[chosen]

	manFile, ok := files[fmt.Sprintf("manifests/run%d-%d.json", s.Run, s.Index)]
	if !ok {
		return 0, fmt.Errorf("snapshot not found in bundle")
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

func writeZipBytes(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func writeZipJSON(zw *zip.Writer, name string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeZipBytes(zw, name, data)
}
