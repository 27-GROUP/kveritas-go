package provenance

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var skipDirNames = map[string]bool{
	".kveritas": true, ".git": true, ".hg": true, ".sl": true, ".svn": true,
	"__pycache__": true, ".pytest_cache": true, ".mypy_cache": true, ".ruff_cache": true,
	".ipynb_checkpoints": true, ".tox": true, ".nox": true, ".cache": true,
	"node_modules": true, "venv": true, ".venv": true, "build": true, "dist": true,
}

var skipFileNames = map[string]bool{".DS_Store": true, "Thumbs.db": true}

type ignoreRule struct {
	re     *regexp.Regexp
	negate bool
	dir    bool
}

type ignoreSet struct {
	base  string
	rules []ignoreRule
}

func loadGitignore(dir, base string) *ignoreSet {
	f, err := os.Open(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return nil
	}
	defer f.Close()
	s := &ignoreSet{base: base}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r ignoreRule
		if strings.HasPrefix(line, "!") {
			r.negate, line = true, line[1:]
		} else if strings.HasPrefix(line, `\`) {
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dir, line = true, strings.TrimSuffix(line, "/")
		}
		anchored := strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		expr := globRegexp(line)
		if anchored {
			expr = "^" + expr + "$"
		} else {
			expr = "^(?:.*/)?" + expr + "$"
		}
		if re, err := regexp.Compile(expr); err == nil {
			r.re = re
			s.rules = append(s.rules, r)
		}
	}
	return s
}

func globRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "/**") && i+3 == len(p):
			b.WriteString("/.*")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			if j := strings.IndexByte(p[i:], ']'); j > 0 {
				class := p[i+1 : i+j]
				if strings.HasPrefix(class, "!") {
					class = "^" + class[1:]
				}
				b.WriteString("[" + class + "]")
				i += j
			} else {
				b.WriteString(`\[`)
			}
		case c == '\\' && i+1 < len(p):
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// The last matching rule wins, deeper .gitignore files after the ones above them.
func ignored(sets []*ignoreSet, rel string, isDir bool) bool {
	out := false
	for _, s := range sets {
		sub := rel
		if s.base != "" {
			sub = strings.TrimPrefix(rel, s.base+"/")
		}
		for _, r := range s.rules {
			if r.dir && !isDir {
				continue
			}
			if r.re.MatchString(sub) {
				out = !r.negate
			}
		}
	}
	return out
}

func isEnvDir(path string) bool {
	for _, marker := range []string{"pyvenv.cfg", "conda-meta"} {
		if _, err := os.Lstat(filepath.Join(path, marker)); err == nil {
			return true
		}
	}
	return false
}

// Every regular file in the project, like git add -A: caches, environments and
// .gitignore'd paths are left out; symlinks are not followed.
func projectFiles(root string) []string {
	var files []string
	sets := map[string][]*ignoreSet{}
	if s := loadGitignore(root, ""); s != nil {
		sets[""] = []*ignoreSet{s}
	}
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		parent := filepath.ToSlash(filepath.Dir(rel))
		if parent == "." {
			parent = ""
		}
		inherited := sets[parent]
		if d.IsDir() {
			if skipDirNames[d.Name()] || strings.HasSuffix(d.Name(), ".egg-info") ||
				ignored(inherited, rel, true) || isEnvDir(path) {
				return filepath.SkipDir
			}
			own := inherited
			if s := loadGitignore(path, rel); s != nil {
				own = append(append([]*ignoreSet{}, inherited...), s)
			}
			sets[rel] = own
			return nil
		}
		if !d.Type().IsRegular() || skipFileNames[d.Name()] || ignored(inherited, rel, false) {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	return files
}
