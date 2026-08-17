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
// which run of the session it came from.
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

// ProofFile is the disclosure of one file: its content plus the snapshot's entry
// list. The other files in that snapshot appear only as their salted commitments.
type ProofFile struct {
	Path        string            `json:"path"`
	Run         int               `json:"run,omitempty"`
	CommitIndex int               `json:"commit_index"`
	Root        string            `json:"root"`
	Event       session.ProvEvent `json:"event"`
	Salt        string            `json:"salt"`
	ContentB64  string            `json:"content_b64"`
	Entries     [][2]string       `json:"entries"`
}

// Proof is a self-contained selective-disclosure proof. It embeds the report's
// signed seal, so it can be checked on its own, and reveals one or more files.
type Proof struct {
	Kind  string              `json:"kind"`
	Seal  *session.SealRecord `json:"seal,omitempty"`
	Files []ProofFile         `json:"files"`
}

// BuildProofFile reveals rel against the newest snapshot whose committed leaf
// matches the file's current content. It fails if the file changed since the run.
func (k *Keystore) BuildProofFile(projectDir, rel string) (*ProofFile, error) {
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
			return &ProofFile{
				Path:        rel,
				Run:         c.Run,
				CommitIndex: c.Index,
				Root:        c.Root,
				Event:       c.Event,
				Salt:        f.Salt,
				ContentB64:  base64.StdEncoding.EncodeToString(content),
				Entries:     entries,
			}, nil
		}
	}
	return nil, fmt.Errorf("%s is not a tracked file in this session", rel)
}

// VerifyFile checks that a revealed file reconstructs its snapshot root, and that
// the root is one the report actually signed.
func VerifyFile(pf *ProofFile, signedRoots map[string]bool) error {
	if !signedRoots[pf.Root] {
		return fmt.Errorf("the proof's snapshot is not in the signed report")
	}
	salt, err := hex.DecodeString(pf.Salt)
	if err != nil {
		return fmt.Errorf("bad salt: %w", err)
	}
	content, err := base64.StdEncoding.DecodeString(pf.ContentB64)
	if err != nil {
		return fmt.Errorf("bad content: %w", err)
	}
	lh := leafHash(salt, content)
	nc := nameCommit(salt, pf.Path)

	found := false
	for _, e := range pf.Entries {
		if e[0] == nc && e[1] == lh {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("the revealed file is not in this snapshot")
	}
	if treeRoot(pf.Entries) != pf.Root {
		return fmt.Errorf("the snapshot entries do not reconstruct the signed root")
	}
	return nil
}

// SignedRoots collects every provenance root committed in a report's canonical
// JSON, which is what a proof's root must belong to.
func SignedRoots(canonicalJSON string) map[string]bool {
	var doc struct {
		Runs []struct {
			Provenance *session.Provenance `json:"provenance"`
		} `json:"runs"`
	}
	roots := map[string]bool{}
	if json.Unmarshal([]byte(canonicalJSON), &doc) != nil {
		return roots
	}
	for _, r := range doc.Runs {
		if r.Provenance == nil {
			continue
		}
		for _, c := range r.Provenance.Commits {
			roots[c.Root] = true
		}
	}
	return roots
}
