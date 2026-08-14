package provenance

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ignoreMatcher reads .kveritasignore and decides which tracked files the author
// chose to keep out of any bundle. It supports comments, glob patterns, and
// directory patterns ending in "/".
type ignoreMatcher struct {
	patterns []string
}

func loadIgnore(root string) *ignoreMatcher {
	m := &ignoreMatcher{}
	f, err := os.Open(filepath.Join(root, ".kveritasignore"))
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m.patterns = append(m.patterns, filepath.ToSlash(line))
	}
	return m
}

func (m *ignoreMatcher) match(rel string) bool {
	if m == nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	for _, p := range m.patterns {
		if strings.HasSuffix(p, "/") {
			dir := strings.TrimSuffix(p, "/")
			if rel == dir || strings.HasPrefix(rel, dir+"/") {
				return true
			}
			continue
		}
		if rel == p {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
	}
	return false
}
