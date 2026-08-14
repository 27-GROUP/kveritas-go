package provenance

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// KeyEntry is one file's commitment as it went into a snapshot. It holds the real
// path and salt, so it stays local and is never published.
type KeyEntry struct {
	Path       string `json:"path"`
	Salt       string `json:"salt"`
	NameCommit string `json:"name_commit"`
	Leaf       string `json:"leaf"`
}

// KeyCommit mirrors a published commit but keeps the real file list. Run labels
// which run of the session it came from, so a merged multi-run keystore stays
// unambiguous.
type KeyCommit struct {
	Run   int               `json:"run,omitempty"`
	Index int               `json:"index"`
	Root  string            `json:"root"`
	Event session.ProvEvent `json:"event"`
	Files []KeyEntry        `json:"files"`
}

// Keystore is the author's local record for building selective-disclosure proofs
// later. It contains real paths and salts and must never be shared.
type Keystore struct {
	SessionID string      `json:"session_id"`
	Commits   []KeyCommit `json:"commits"`
}

func (r *Recorder) Keystore() *Keystore {
	return &Keystore{SessionID: r.sessionID, Commits: r.keyCommits}
}

func (k *Keystore) Save(path string) error {
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadKeystore(path string) (*Keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k Keystore
	return &k, json.Unmarshal(data, &k)
}

// Proof reveals a single file against a signed snapshot root. The other files in
// that snapshot appear only as their salted commitments, so nothing else leaks.
type Proof struct {
	SessionID   string            `json:"session_id"`
	Run         int               `json:"run,omitempty"`
	CommitIndex int               `json:"commit_index"`
	Root        string            `json:"root"`
	Event       session.ProvEvent `json:"event"`
	Path        string            `json:"path"`
	Salt        string            `json:"salt"`
	ContentB64  string            `json:"content_b64"`
	Entries     [][2]string       `json:"entries"`
}

// BuildProof reveals rel against the newest snapshot whose committed leaf matches
// the file's current content. It fails if the file changed since the run.
func (k *Keystore) BuildProof(projectDir, rel string) (*Proof, error) {
	content, err := os.ReadFile(filepath.Join(projectDir, rel))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	for i := len(k.Commits) - 1; i >= 0; i-- {
		c := k.Commits[i]
		for _, f := range c.Files {
			if f.Path != rel {
				continue
			}
			salt, err := hex.DecodeString(f.Salt)
			if err != nil {
				return nil, err
			}
			if leafHash(salt, content) != f.Leaf {
				return nil, fmt.Errorf("%s changed since the run; cannot prove snapshot %d", rel, c.Index)
			}
			entries := make([][2]string, 0, len(c.Files))
			for _, e := range c.Files {
				entries = append(entries, [2]string{e.NameCommit, e.Leaf})
			}
			return &Proof{
				SessionID:   k.SessionID,
				Run:         c.Run,
				CommitIndex: c.Index,
				Root:        c.Root,
				Event:       c.Event,
				Path:        rel,
				Salt:        f.Salt,
				ContentB64:  base64.StdEncoding.EncodeToString(content),
				Entries:     entries,
			}, nil
		}
	}
	return nil, fmt.Errorf("%s is not a tracked file in this session", rel)
}

// VerifyProof checks that the revealed file was part of the signed root. signedRoot
// is the root the report bound for this commit index.
func VerifyProof(p *Proof, signedRoot string) error {
	if p.Root != signedRoot {
		return fmt.Errorf("proof root does not match the signed snapshot")
	}
	salt, err := hex.DecodeString(p.Salt)
	if err != nil {
		return fmt.Errorf("bad salt: %w", err)
	}
	content, err := base64.StdEncoding.DecodeString(p.ContentB64)
	if err != nil {
		return fmt.Errorf("bad content: %w", err)
	}
	lh := leafHash(salt, content)
	nc := nameCommit(salt, p.Path)

	found := false
	for _, e := range p.Entries {
		if e[0] == nc && e[1] == lh {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("the revealed file is not in this snapshot")
	}
	if treeRoot(p.Entries) != p.Root {
		return fmt.Errorf("the snapshot entries do not reconstruct the signed root")
	}
	return nil
}
