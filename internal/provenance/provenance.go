// Package provenance records a run as a chain of content-addressed snapshots.
// At each boundary (run start, a phase, run end) it hashes the tracked source
// files into a Merkle root and links it to the previous one, so the result is a
// tamper-evident timeline of what the working set looked like and what changed.
// Leaves are salted and, at the default disclosure level, file names are replaced
// with stable pseudonyms, so the history proves what happened without exposing
// code or filenames.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/bundle"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const maxCommits = 512

// Level controls how much a snapshot reveals.
type Level int

const (
	Redacted Level = iota // pseudonyms, no names, no content
	Names                 // real names, still no content
	Open                  // names plus a bundle (content stored elsewhere)
)

func ParseLevel(s string) Level {
	switch s {
	case "names":
		return Names
	case "open":
		return Open
	default:
		return Redacted
	}
}

func (l Level) String() string {
	switch l {
	case Names:
		return "names"
	case Open:
		return "open"
	default:
		return "redacted"
	}
}

type leaf struct {
	hash     string
	size     int64
	withheld bool
}

// Recorder accumulates snapshots over the life of a run.
type Recorder struct {
	root   string
	salt   []byte
	level  Level
	ignore *ignoreMatcher

	names    map[string]string // real path -> pseudonym
	nameSeq  int
	prev     map[string]leaf // path -> leaf from the previous snapshot
	prevRoot string
	prevLink string
	commits  []session.ProvCommit
	withheld map[string]leaf
	trunc    bool
}

func New(root, level string, salt []byte) *Recorder {
	return &Recorder{
		root:     root,
		salt:     salt,
		level:    ParseLevel(level),
		ignore:   loadIgnore(root),
		names:    map[string]string{},
		withheld: map[string]leaf{},
	}
}

// Snapshot hashes the tracked files now and appends a commit describing the
// transition from the previous state.
func (r *Recorder) Snapshot(kind, name string) {
	if len(r.commits) >= maxCommits {
		r.trunc = true
		return
	}

	files, err := bundle.CollectSourceFiles(r.root)
	if err != nil {
		return
	}
	sort.Strings(files)

	cur := make(map[string]leaf, len(files))
	entries := make([][2]string, 0, len(files))
	for _, rel := range files {
		l, ok := r.hashLeaf(rel)
		if !ok {
			continue
		}
		if r.ignore.match(rel) {
			l.withheld = true
			r.withheld[rel] = l
		}
		cur[rel] = l
		entries = append(entries, [2]string{r.nameCommit(rel), l.hash})
	}

	root := r.treeRoot(entries)
	changed := r.diff(r.prev, cur)

	commit := session.ProvCommit{
		Index:     len(r.commits),
		Timestamp: time.Now().UTC(),
		PrevRoot:  r.prevRoot,
		Root:      root,
		Event:     session.ProvEvent{Kind: kind, Name: name},
		Changed:   changed,
		PrevLink:  r.prevLink,
	}
	commit.Link = r.link(commit)

	r.commits = append(r.commits, commit)
	r.prev = cur
	r.prevRoot = root
	r.prevLink = commit.Link
}

// Result returns the assembled provenance, or nil if nothing was recorded.
func (r *Recorder) Result() *session.Provenance {
	if len(r.commits) == 0 {
		return nil
	}
	withheld := make([]session.WithheldFile, 0, len(r.withheld))
	for path, l := range r.withheld {
		withheld = append(withheld, session.WithheldFile{
			Path:       r.display(path),
			Hash:       l.hash,
			SizeBucket: sizeBucket(l.size),
		})
	}
	sort.Slice(withheld, func(i, j int) bool { return withheld[i].Path < withheld[j].Path })

	return &session.Provenance{
		Disclosure: r.level.String(),
		Root:       r.prevRoot,
		Head:       r.prevLink,
		FileCount:  len(r.prev),
		Commits:    r.commits,
		Withheld:   withheld,
		Truncated:  r.trunc,
	}
}

// hashLeaf reads and salts a file's content. The salt keeps a published hash from
// being guessed back to known content.
func (r *Recorder) hashLeaf(rel string) (leaf, bool) {
	info, err := os.Stat(filepath.Join(r.root, rel))
	if err != nil {
		return leaf{}, false
	}
	content, err := os.ReadFile(filepath.Join(r.root, rel))
	if err != nil {
		return leaf{}, false
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(r.salt)
	h.Write(content)
	return leaf{hash: hex.EncodeToString(h.Sum(nil)), size: info.Size()}, true
}

// nameCommit is the salted path hash used inside the tree, so the root never
// embeds a cleartext filename.
func (r *Recorder) nameCommit(rel string) string {
	h := sha256.New()
	h.Write([]byte{0x03})
	h.Write(r.salt)
	h.Write([]byte(rel))
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Recorder) treeRoot(entries [][2]string) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i][0] < entries[j][0] })
	_, canon, err := crypto.CanonicalHashWithBytes(entries)
	if err != nil {
		return ""
	}
	return crypto.HashBytes(append([]byte{0x01}, canon...))
}

func (r *Recorder) link(c session.ProvCommit) string {
	_, canon, err := crypto.CanonicalHashWithBytes(c)
	if err != nil {
		return ""
	}
	return crypto.HashBytes(append([]byte{0x02}, canon...))
}

func (r *Recorder) diff(old, cur map[string]leaf) []session.ProvChange {
	var changes []session.ProvChange
	for path, l := range cur {
		prev, ok := old[path]
		if !ok {
			changes = append(changes, session.ProvChange{Op: "add", Path: r.display(path)})
		} else if prev.hash != l.hash {
			changes = append(changes, session.ProvChange{Op: "modify", Path: r.display(path)})
		}
	}
	for path := range old {
		if _, ok := cur[path]; !ok {
			changes = append(changes, session.ProvChange{Op: "delete", Path: r.display(path)})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}

// display returns the real path when names are disclosed, otherwise a stable
// pseudonym that is consistent across the whole run.
func (r *Recorder) display(rel string) string {
	if r.level >= Names {
		return rel
	}
	if p, ok := r.names[rel]; ok {
		return p
	}
	r.nameSeq++
	p := "file#" + strconv.Itoa(r.nameSeq)
	r.names[rel] = p
	return p
}

func sizeBucket(n int64) string {
	switch {
	case n < 1<<10:
		return "<1KB"
	case n < 1<<20:
		return "<1MB"
	case n < 1<<30:
		return "<1GB"
	default:
		return ">=1GB"
	}
}
