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

type KeyEntry struct {
	Path       string `json:"path"`
	Salt       string `json:"salt"`
	NameCommit string `json:"name_commit"`
	Leaf       string `json:"leaf"`
}

type KeyCommit struct {
	Run   int               `json:"run,omitempty"`
	Index int               `json:"index"`
	Root  string            `json:"root"`
	Event session.ProvEvent `json:"event"`
	Files []KeyEntry        `json:"files"`
}

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

type Proof struct {
	Kind  string              `json:"kind"`
	Seal  *session.SealRecord `json:"seal,omitempty"`
	Files []ProofFile         `json:"files"`
}

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

type CommitRef struct {
	Run   int
	Index int
	Event session.ProvEvent
}

// Labels come from the report: nothing commits to the proof's own.
func SignedCommits(canonicalJSON string) map[string][]CommitRef {
	var doc struct {
		Runs []struct {
			Index      int                 `json:"index"`
			Provenance *session.Provenance `json:"provenance"`
		} `json:"runs"`
	}
	refs := map[string][]CommitRef{}
	if json.Unmarshal([]byte(canonicalJSON), &doc) != nil {
		return refs
	}
	for _, r := range doc.Runs {
		if r.Provenance == nil {
			continue
		}
		for _, c := range r.Provenance.Commits {
			refs[c.Root] = append(refs[c.Root], CommitRef{Run: r.Index + 1, Index: c.Index, Event: c.Event})
		}
	}
	return refs
}

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
