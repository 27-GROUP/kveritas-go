package bundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/mamadouk/kveritas/internal/crypto"
)

var sourceExtensions = map[string]bool{
	".py":    true,
	".r":     true,
	".jl":    true,
	".sh":    true,
	".bash":  true,
	".rb":    true,
	".js":    true,
	".ts":    true,
	".go":    true,
	".cpp":   true,
	".c":     true,
	".h":     true,
	".hpp":   true,
	".java":  true,
	".rs":    true,
	".m":     true,
	".ipynb": true,
}

var skipDirs = map[string]bool{
	".kveritas":    true,
	"__pycache__":  true,
	".git":         true,
	"node_modules": true,
	"venv":         true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

// CollectSourceFiles walks rootDir and returns relative paths for all source files.
func CollectSourceFiles(rootDir string) ([]string, error) {
	var files []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".r" {
			ext = filepath.Ext(path)
		}
		if sourceExtensions[ext] {
			rel, err := filepath.Rel(rootDir, path)
			if err != nil {
				return nil
			}
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

// HashSourceFiles returns a map of relative path to SHA-256 hash for each file.
// Files are hashed concurrently for speed.
func HashSourceFiles(rootDir string, files []string) (map[string]string, error) {
	if len(files) == 0 {
		return map[string]string{}, nil
	}

	type hashResult struct {
		path string
		hash string
		err  error
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(files) {
		workers = len(files)
	}

	ch := make(chan string, len(files))
	results := make(chan hashResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range ch {
				h, err := crypto.HashFile(filepath.Join(rootDir, f))
				results <- hashResult{path: f, hash: h, err: err}
			}
		}()
	}

	for _, f := range files {
		ch <- f
	}
	close(ch)

	go func() {
		wg.Wait()
		close(results)
	}()

	result := make(map[string]string, len(files))
	for hr := range results {
		if hr.err != nil {
			return nil, hr.err
		}
		result[hr.path] = hr.hash
	}
	return result, nil
}

// CreateBundle creates a zip archive of the listed files and returns the SHA-256 hash of the zip.
func CreateBundle(rootDir string, files []string, outPath string) (string, error) {
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	h := sha256.New()
	w := io.MultiWriter(out, h)
	zw := zip.NewWriter(w)

	for _, f := range files {
		fw, err := zw.Create(f)
		if err != nil {
			zw.Close()
			return "", err
		}
		src, err := os.Open(filepath.Join(rootDir, f))
		if err != nil {
			zw.Close()
			return "", err
		}
		_, err = io.Copy(fw, src)
		src.Close()
		if err != nil {
			zw.Close()
			return "", err
		}
	}

	if err := zw.Close(); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifySourceIntegrity checks current files against stored hashes.
// Returns lists of modified and missing files.
func VerifySourceIntegrity(rootDir string, storedHashes map[string]string) (modified []string, missing []string, err error) {
	for f, expectedHash := range storedHashes {
		currentHash, err := crypto.HashFile(filepath.Join(rootDir, f))
		if err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, f)
				continue
			}
			return nil, nil, err
		}
		if currentHash != expectedHash {
			modified = append(modified, f)
		}
	}
	return modified, missing, nil
}
