// Package harness records an agentic session as a hash-chained log of designated
// actions. Each entry's link binds the actor, its input and output, and the prior
// chain, so the identity, content, or order of an action cannot be altered
// undetected. Verification recomputes the chain and localizes the first failure.
package harness

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
)

const (
	GenesisFile = "genesis.json"
	ChainFile   = "chain.jsonl"
	lockFile    = "chain.lock"
)

// ServerSig is what the server hands back after signing a hash: the signature
// plus the nonce and timestamp that went into it, and the public key a verifier
// needs to check it later.
type ServerSig struct {
	Signature    string `json:"signature"`
	Nonce        string `json:"nonce"`
	SignedAt     string `json:"signed_at"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// Genesis binds the designation D and the session identity. Its Hash is the
// chain root (the previous link of the first entry) and is signed by the server.
type Genesis struct {
	SessionID       string    `json:"session_id"`
	MachineID       string    `json:"machine_id"`
	AgentIdentity   string    `json:"agent_identity"`
	OperatorID      string    `json:"operator_id"`
	Designation     string    `json:"designation"`
	DesignationHash string    `json:"designation_hash"`
	StartAt         string    `json:"start_at"`
	Nonce           string    `json:"nonce"`
	Hash            string    `json:"hash"`
	Server          ServerSig `json:"server"`
}

// Entry is one designated action in session order. TopAgent names the top-level
// agent it belongs to, AgentID a sub-agent within it, and SpawnedID (on a spawn
// result) the sub-agent that action created. Together they let the agent forest be
// rebuilt from signed facts, so attribution stays tamper-evident across sub-agents.
type Entry struct {
	Index       int    `json:"index"`
	Actor       string `json:"actor"`
	TopAgent    string `json:"top_agent,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	SpawnedID   string `json:"spawned_id,omitempty"`
	ParentActor string `json:"parent_actor,omitempty"`
	Type        string `json:"type"`
	ToolUseID   string `json:"tool_use_id,omitempty"`
	InputHash   string `json:"input_hash"`
	OutputHash  string `json:"output_hash"`
	Timestamp   string `json:"timestamp"`
	PrevLink    string `json:"prev_link"`
	Link        string `json:"link"`
}

// ActorNode is a node in the attribution tree: an actor, how many designated
// actions it took, and the sub-agents it spawned.
type ActorNode struct {
	Name     string        `json:"name"`
	Count    int           `json:"count"`
	Actions  []ActorAction `json:"actions,omitempty"`
	Children []*ActorNode  `json:"children,omitempty"`
}

// ActorAction is a bucketed count of what an actor did (reads, writes, spawns,
// and so on), for the per-agent breakdown in the session tree.
type ActorAction struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// actionOrder fixes the display order of the action buckets.
var actionOrder = []string{"turns", "reads", "writes", "commands", "spawns", "tools", "claims", "approvals", "other"}

// bucket groups a ledger entry type into a human category. The ".result" half of
// a call is folded into its action so counts reflect what was done.
func bucket(t string) string {
	if strings.HasSuffix(t, ".result") {
		return ""
	}
	switch {
	case t == "prompt" || t == "model_turn" || strings.HasSuffix(t, ".turn"):
		return "turns"
	case t == "spawn":
		return "spawns"
	case strings.Contains(t, "exec") || strings.Contains(t, "bash"):
		return "commands"
	case strings.Contains(t, "write") || strings.Contains(t, "edit") || t == "file_effect":
		return "writes"
	case strings.Contains(t, "read") || strings.Contains(t, "list") || strings.Contains(t, "grep") || strings.Contains(t, "glob"):
		return "reads"
	case strings.Contains(t, "claim"):
		return "claims"
	case strings.Contains(t, "approval"):
		return "approvals"
	case strings.HasPrefix(t, "tool_call"):
		return "tools"
	default:
		return "other"
	}
}

// ActorTree reconstructs the agent forest from the entries: each top-level agent is
// a root, and a sub-agent hangs under whichever agent spawned it. Spawn edges come
// from the signed TopAgent/AgentID/SpawnedID fields, so re-attributing or hiding an
// agent is detectable; a manual ParentActor is honored as a fallback off the hook.
func ActorTree(entries []Entry) []*ActorNode {
	topName := func(e Entry) string {
		if e.TopAgent != "" {
			return e.TopAgent
		}
		return "main"
	}
	key := func(top, id string) string { return top + "\x00" + id }

	counts := map[string]int{}
	actions := map[string]map[string]int{}
	topOf := map[string]string{}
	agentOf := map[string]string{}
	displayOf := map[string]string{}
	spawnerOf := map[string]string{}
	manualParent := map[string]string{}
	var order []string
	seen := map[string]bool{}

	for _, e := range entries {
		counts[e.Actor]++
		if b := bucket(e.Type); b != "" {
			if actions[e.Actor] == nil {
				actions[e.Actor] = map[string]int{}
			}
			actions[e.Actor][b]++
		}
		if !seen[e.Actor] {
			seen[e.Actor] = true
			order = append(order, e.Actor)
		}
		top := topName(e)
		topOf[e.Actor] = top
		if e.AgentID != "" {
			agentOf[e.Actor] = e.AgentID
			displayOf[key(top, e.AgentID)] = e.Actor
		}
		if e.SpawnedID != "" {
			spawnerOf[key(top, e.SpawnedID)] = e.AgentID
		}
		if e.ParentActor != "" {
			manualParent[e.Actor] = e.ParentActor
		}
	}

	nodes := map[string]*ActorNode{}
	get := func(name string) *ActorNode {
		if n, ok := nodes[name]; ok {
			return n
		}
		n := &ActorNode{Name: name, Count: counts[name]}
		for _, label := range actionOrder {
			if c := actions[name][label]; c > 0 {
				n.Actions = append(n.Actions, ActorAction{Label: label, Count: c})
			}
		}
		nodes[name] = n
		return n
	}

	parentOf := func(actor string) string {
		if p, ok := manualParent[actor]; ok {
			return p
		}
		aid, isSub := agentOf[actor]
		if !isSub {
			return ""
		}
		top := topOf[actor]
		spawner := spawnerOf[key(top, aid)]
		if spawner == "" {
			return top
		}
		if d, ok := displayOf[key(top, spawner)]; ok {
			return d
		}
		return top
	}

	var roots []*ActorNode
	for _, name := range order {
		n := get(name)
		if parent := parentOf(name); parent == "" {
			roots = append(roots, n)
		} else {
			get(parent).Children = append(get(parent).Children, n)
		}
	}
	return roots
}

// Seal is the closing record of a session. It pins the final chain head and
// carries the server's signature over it, so a verifier can confirm the chain
// ends exactly where the server saw it end, and no entries were quietly dropped.
type Seal struct {
	ChainHead  string    `json:"chain_head"`
	EntryCount int       `json:"entry_count"`
	SealedAt   string    `json:"sealed_at"`
	Server     ServerSig `json:"server"`
}

// Report is the complete, verifiable record of a harness session.
type Report struct {
	Version string  `json:"version"`
	Genesis Genesis `json:"genesis"`
	Entries []Entry `json:"entries"`
	Seal    Seal    `json:"seal"`
}

// Proof is a self-contained attestation that a specific prompt or output was
// recorded at a specific position in a signed session. It carries the full chain
// (hashes only) plus the revealed content for one entry; every other entry's
// content stays a hash, so nothing else is exposed.
type Proof struct {
	Kind   string `json:"kind"`
	Report Report `json:"report"`
	Index  int    `json:"entry_index"`
	Input  string `json:"revealed_input,omitempty"`
	Output string `json:"revealed_output,omitempty"`
}

// ProofResult reports whether a proof verifies and what it attests.
type ProofResult struct {
	Valid       bool
	Detail      string
	Entry       Entry
	InputMatch  bool
	OutputMatch bool
	SessionID   string
}

func findEntry(entries []Entry, index int) *Entry {
	for i := range entries {
		if entries[i].Index == index {
			return &entries[i]
		}
	}
	return nil
}

// BuildProof reveals the given entry's input and/or output content, checking each
// against the entry's committed hash so only genuinely-recorded content can be
// proven. The session must already verify.
func BuildProof(r *Report, index int, input, output []byte) (*Proof, error) {
	if res := Verify(r); res.Verdict != "VERIFIED" {
		return nil, fmt.Errorf("session does not verify (%s): %s", res.Verdict, res.Detail)
	}
	e := findEntry(r.Entries, index)
	if e == nil {
		return nil, fmt.Errorf("no entry with index %d in the session", index)
	}
	p := &Proof{Kind: "kveritas-harness-proof", Report: *r, Index: index}
	if input != nil {
		if crypto.HashBytes(input) != e.InputHash {
			return nil, fmt.Errorf("supplied input does not match entry %d's recorded input hash", index)
		}
		p.Input = base64.StdEncoding.EncodeToString(input)
	}
	if output != nil {
		if crypto.HashBytes(output) != e.OutputHash {
			return nil, fmt.Errorf("supplied output does not match entry %d's recorded output hash", index)
		}
		p.Output = base64.StdEncoding.EncodeToString(output)
	}
	if p.Input == "" && p.Output == "" {
		return nil, fmt.Errorf("nothing to prove: supply an input and/or output to reveal")
	}
	return p, nil
}

// VerifyProof checks the chain, then confirms the revealed content re-hashes to
// the committed hash at the named entry.
func VerifyProof(p *Proof) ProofResult {
	if p.Kind != "kveritas-harness-proof" {
		return ProofResult{Detail: "not a harness proof"}
	}
	if res := Verify(&p.Report); res.Verdict != "VERIFIED" {
		return ProofResult{Detail: fmt.Sprintf("session chain %s: %s", res.Verdict, res.Detail)}
	}
	e := findEntry(p.Report.Entries, p.Index)
	if e == nil {
		return ProofResult{Detail: "named entry is not in the chain"}
	}
	out := ProofResult{Entry: *e, SessionID: p.Report.Genesis.SessionID}
	if p.Input != "" {
		b, err := base64.StdEncoding.DecodeString(p.Input)
		if err != nil || crypto.HashBytes(b) != e.InputHash {
			return ProofResult{Detail: "revealed input does not match the committed input hash"}
		}
		out.InputMatch = true
	}
	if p.Output != "" {
		b, err := base64.StdEncoding.DecodeString(p.Output)
		if err != nil || crypto.HashBytes(b) != e.OutputHash {
			return ProofResult{Detail: "revealed output does not match the committed output hash"}
		}
		out.OutputMatch = true
	}
	if !out.InputMatch && !out.OutputMatch {
		return ProofResult{Detail: "proof reveals no content"}
	}
	out.Valid = true
	return out
}

// CoreHash hashes the genesis fields excluding its own Hash and the server
// signature, giving the value the server signs and the chain root.
func (g Genesis) CoreHash() (string, error) {
	core := g
	core.Hash = ""
	core.Server = ServerSig{}
	return crypto.CanonicalHash(core)
}

// linkOf computes an entry's link as the hash of the entry with an empty Link.
// PrevLink is part of the entry, so the link binds the entire prior chain.
func linkOf(e Entry) (string, error) {
	c := e
	c.Link = ""
	return crypto.CanonicalHash(c)
}

func SaveGenesis(kvDir string, g *Genesis) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(kvDir, GenesisFile), data, 0600)
}

func LoadGenesis(kvDir string) (*Genesis, error) {
	data, err := os.ReadFile(filepath.Join(kvDir, GenesisFile))
	if err != nil {
		return nil, err
	}
	var g Genesis
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func LoadChain(kvDir string) ([]Entry, error) {
	f, err := os.Open(filepath.Join(kvDir, ChainFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("corrupted chain entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

// AppendEntry links a new action onto the chain under a file lock and returns
// the committed entry with its index and link filled in.
func AppendEntry(kvDir string, e Entry) (*Entry, error) {
	unlock, err := lock(kvDir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	entries, err := LoadChain(kvDir)
	if err != nil {
		return nil, err
	}

	prev := ""
	if len(entries) == 0 {
		g, err := LoadGenesis(kvDir)
		if err != nil {
			return nil, fmt.Errorf("loading genesis: %w", err)
		}
		prev = g.Hash
		e.Index = 1
	} else {
		last := entries[len(entries)-1]
		prev = last.Link
		e.Index = last.Index + 1
	}

	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	e.PrevLink = prev
	link, err := linkOf(e)
	if err != nil {
		return nil, err
	}
	e.Link = link

	line, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(kvDir, ChainFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return &e, nil
}

// lock serializes chain appends across processes, since parallel sub-agents can
// each fire a hook at once. An exclusive-create spinlock is enough and portable.
func lock(kvDir string) (func(), error) {
	path := filepath.Join(kvDir, lockFile)
	for i := 0; i < 1000; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, fmt.Errorf("could not acquire chain lock at %s", path)
}

// Result is what verification hands back: a verdict, and on failure the exact entry
// and actor it went wrong at.
type Result struct {
	Verdict     string
	Detail      string
	FailAtIndex int
	FailAtActor string
	EntryCount  int
	ActorCounts map[string]int
}

// Verify checks the genesis signature, the full chain, and the seal signature,
// localizing the first inconsistency it finds.
func Verify(r *Report) Result {
	res := Result{ActorCounts: map[string]int{}, EntryCount: len(r.Entries)}

	if crypto.HashBytes([]byte(r.Genesis.Designation)) != r.Genesis.DesignationHash {
		res.Verdict = "TAMPERED"
		res.Detail = "designation content does not match its committed hash"
		return res
	}

	coreHash, err := r.Genesis.CoreHash()
	if err != nil {
		res.Verdict = "ERROR"
		res.Detail = err.Error()
		return res
	}
	if coreHash != r.Genesis.Hash {
		res.Verdict = "TAMPERED"
		res.Detail = "genesis hash does not match its content (identity or designation altered)"
		return res
	}
	if v := verifyServerSig(r.Genesis.Hash, r.Genesis.Server); v != "" {
		res.Verdict = "INVALID"
		res.Detail = "genesis signature: " + v
		return res
	}

	prev := r.Genesis.Hash
	for _, e := range r.Entries {
		if e.PrevLink != prev {
			res.Verdict = "TAMPERED"
			res.Detail = "chain order broken: entry does not follow the previous link"
			res.FailAtIndex = e.Index
			res.FailAtActor = e.Actor
			return res
		}
		want, err := linkOf(e)
		if err != nil {
			res.Verdict = "ERROR"
			res.Detail = err.Error()
			return res
		}
		if want != e.Link {
			res.Verdict = "TAMPERED"
			res.Detail = "entry content altered: recomputed link does not match"
			res.FailAtIndex = e.Index
			res.FailAtActor = e.Actor
			return res
		}
		res.ActorCounts[e.Actor]++
		prev = e.Link
	}

	if r.Seal.ChainHead != prev {
		res.Verdict = "TAMPERED"
		res.Detail = "seal chain head does not match the reconstructed chain (entries added or removed)"
		return res
	}
	if v := verifyServerSig(r.Seal.ChainHead, r.Seal.Server); v != "" {
		res.Verdict = "INVALID"
		res.Detail = "seal signature: " + v
		return res
	}

	res.Verdict = "VERIFIED"
	return res
}

func verifyServerSig(hash string, s ServerSig) string {
	pub, err := crypto.LoadPublicKey([]byte(s.PublicKeyPEM))
	if err != nil {
		return "cannot parse public key"
	}
	payload := crypto.Payload(hash, s.Nonce, s.SignedAt)
	if err := crypto.VerifyPSS(pub, payload, s.Signature); err != nil {
		return err.Error()
	}
	return ""
}
