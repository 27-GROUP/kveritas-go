// Package provenance records a run as a chain of content-addressed snapshots. At
// each boundary (run start, phase, run end) it hashes the tracked files into a
// Merkle root linked to the previous one, giving a tamper-evident timeline of what
// changed. Leaves are salted per file, so a published hash cannot be guessed back
// to known content and revealing one file never exposes the others.
package provenance

import (
	"crypto/hmac"
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
	Open                  // real names plus stored content (checkout-able)
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
	hash    string
	salt    []byte
	size    int64
	content []byte
}

// Recorder accumulates snapshots over the life of a run.
type Recorder struct {
	root      string
	salt      []byte
	level     Level
	ignore    *ignoreMatcher
	sessionID string

	names    map[string]string
	nameSeq  int
	prev     map[string]string // path -> leaf hash from the previous snapshot
	prevRoot string
	prevLink string
	commits  []session.ProvCommit
	withheld map[string]withheldInfo
	trunc    bool

	keyCommits []KeyCommit         // local, holds real paths and salts for proofs
	objects    map[string][]byte   // Open level: content by content hash
	manifests  []map[string]string // Open level: per-commit path -> content hash
}

type withheldInfo struct {
	hash string
	size int64
}

func New(root, level, sessionID string, salt []byte) *Recorder {
	r := &Recorder{
		root:      root,
		salt:      salt,
		level:     ParseLevel(level),
		ignore:    loadIgnore(root),
		sessionID: sessionID,
		names:     map[string]string{},
		withheld:  map[string]withheldInfo{},
	}
	if r.level >= Open {
		r.objects = map[string][]byte{}
	}
	return r
}

// leafSalt derives a per-file salt from the session salt, so revealing one file's
// salt exposes neither the session salt nor any other file's.
func (r *Recorder) leafSalt(rel string) []byte {
	m := hmac.New(sha256.New, r.salt)
	m.Write([]byte(rel))
	return m.Sum(nil)
}

func leafHash(salt, content []byte) string {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(salt)
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func nameCommit(salt []byte, rel string) string {
	h := sha256.New()
	h.Write([]byte{0x03})
	h.Write(salt)
	h.Write([]byte(rel))
	return hex.EncodeToString(h.Sum(nil))
}

func contentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// ContentHash is the plain content hash used for public artifacts, so a verifier
// can compare it against an independently published reference hash.
func ContentHash(content []byte) string { return contentHash(content) }

// SaltedLeaf is the salted commitment used for private artifacts: the same leaf
// hashing as the tracked files, so nothing about the content leaks.
func SaltedLeaf(sessionSalt []byte, path string, content []byte) string {
	m := hmac.New(sha256.New, sessionSalt)
	m.Write([]byte(path))
	return leafHash(m.Sum(nil), content)
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

	cur := make(map[string]string, len(files))
	entries := make([][2]string, 0, len(files))
	var keyFiles []KeyEntry
	manifest := map[string]string{}

	for _, rel := range files {
		info, err := os.Stat(filepath.Join(r.root, rel))
		if err != nil {
			continue
		}
		content, err := os.ReadFile(filepath.Join(r.root, rel))
		if err != nil {
			continue
		}
		salt := r.leafSalt(rel)
		lh := leafHash(salt, content)
		nc := nameCommit(salt, rel)

		cur[rel] = lh
		entries = append(entries, [2]string{nc, lh})
		keyFiles = append(keyFiles, KeyEntry{Path: rel, Salt: hex.EncodeToString(salt), NameCommit: nc, Leaf: lh})

		withheld := r.ignore.match(rel)
		if withheld {
			r.withheld[rel] = withheldInfo{hash: lh, size: info.Size()}
		}
		// A withheld file's hash is committed, but its content never enters the bundle,
		// so a .kveritasignore file can never be reconstructed via checkout.
		if r.level >= Open && !withheld {
			ch := contentHash(content)
			r.objects[ch] = content
			manifest[rel] = ch
		}
	}

	root := treeRoot(entries)
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
	commit.Link = link(commit)

	r.commits = append(r.commits, commit)
	r.keyCommits = append(r.keyCommits, KeyCommit{Index: commit.Index, Root: root, Event: commit.Event, Files: keyFiles})
	if r.level >= Open {
		r.manifests = append(r.manifests, manifest)
	}
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
	for path, w := range r.withheld {
		withheld = append(withheld, session.WithheldFile{
			Path:       r.display(path),
			Hash:       w.hash,
			SizeBucket: sizeBucket(w.size),
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

func treeRoot(entries [][2]string) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i][0] < entries[j][0] })
	_, canon, err := crypto.CanonicalHashWithBytes(entries)
	if err != nil {
		return ""
	}
	return crypto.HashBytes(append([]byte{0x01}, canon...))
}

func link(c session.ProvCommit) string {
	_, canon, err := crypto.CanonicalHashWithBytes(c)
	if err != nil {
		return ""
	}
	return crypto.HashBytes(append([]byte{0x02}, canon...))
}

func (r *Recorder) diff(old map[string]string, cur map[string]string) []session.ProvChange {
	var changes []session.ProvChange
	for path, h := range cur {
		prev, ok := old[path]
		if !ok {
			changes = append(changes, session.ProvChange{Op: "add", Path: r.display(path)})
		} else if prev != h {
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

// SizeBucket coarsens a byte size so a report never reveals an exact file size.
func SizeBucket(n int64) string { return sizeBucket(n) }

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
