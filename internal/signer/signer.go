package signer

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const EnvKey = "KVERITAS_SIGNER_KEY"

type Key struct {
	priv ed25519.PrivateKey
}

func Dir() (string, error) {
	if d := os.Getenv("KVERITAS_CONFIG_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "kveritas"), nil
}

func keyPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "signer.key"), nil
}

func parse(s string) (*Key, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signer key is not a valid key")
	}
	return &Key{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func Load() (*Key, error) {
	if v := os.Getenv(EnvKey); v != "" {
		return parse(v)
	}
	p, err := keyPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err == nil {
		return parse(string(data))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := New()
	if err != nil {
		return nil, err
	}
	return k, k.Save()
}

func New() (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

func (k *Key) Save() error {
	if os.Getenv(EnvKey) != "" {
		return fmt.Errorf("the signer key comes from %s; update that secret instead", EnvKey)
	}
	p, err := keyPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(k.Export()+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (k *Key) Export() string {
	return base64.StdEncoding.EncodeToString(k.priv.Seed())
}

func (k *Key) Public() string {
	return base64.StdEncoding.EncodeToString(k.priv.Public().(ed25519.PublicKey))
}

func (k *Key) Fingerprint() string {
	sum := sha256.Sum256(k.priv.Public().(ed25519.PublicKey))
	return hex.EncodeToString(sum[:])
}

func (k *Key) Sign(msg string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(msg)))
}

func StartMessage(sessionID, initAt string) string {
	return "kveritas-signer-start:" + sessionID + ":" + initAt
}

func SealMessage(sessionID, dataHash string) string {
	return "kveritas-signer-seal:" + sessionID + ":" + dataHash
}

func AbandonMessage(sessionID string) string {
	return "kveritas-signer-abandon:" + sessionID
}

func CleanMessage(sessionID string) string {
	return "kveritas-signer-clean:" + sessionID
}

func LinkStartMessage(at string) string {
	return "kveritas-signer-link-start:" + at
}

func LinkMessage(code string) string {
	return "kveritas-signer-link:" + code
}

func RevokeMessage(target, at string) string {
	return "kveritas-signer-revoke:" + target + ":" + at
}

type Statement struct {
	Kind        string     `json:"kind"`
	At          string     `json:"at"`
	SessionID   string     `json:"session_id"`
	DataHash    string     `json:"data_hash"`
	Signer      string     `json:"signer"`
	Keys        int        `json:"keys"`
	RevokedKeys int        `json:"revoked_keys"`
	FirstSeen   string     `json:"first_seen"`
	Started     int        `json:"started"`
	Sealed      int        `json:"sealed"`
	Abandoned   int        `json:"abandoned"`
	Open        int        `json:"open"`
	Unsealed    []Unsealed `json:"unsealed"`
	KeyList     []KeyInfo  `json:"key_list,omitempty"`
}

type KeyInfo struct {
	FP        string `json:"fp"`
	FirstSeen string `json:"first_seen"`
	Revoked   bool   `json:"revoked"`
}

type Unsealed struct {
	Session   string `json:"session"`
	Key       string `json:"key"`
	StartedAt string `json:"started_at"`
	Runs      int    `json:"runs"`
	Status    string `json:"status"`
}

type localEvent struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id"`
	Signer    string `json:"signer"`
	At        string `json:"at"`
}

func localLog() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "local-sessions.jsonl"), nil
}

func RecordLocal(k *Key, kind, sessionID string) error {
	p, err := localLog()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	line, _ := json.Marshal(localEvent{Kind: kind, SessionID: sessionID, Signer: k.Fingerprint(), At: time.Now().UTC().Format(time.RFC3339Nano)})
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

type localSession struct {
	id, startedAt, status string
}

func localSessions(k *Key) ([]localSession, string) {
	p, err := localLog()
	if err != nil {
		return nil, ""
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, ""
	}
	defer f.Close()
	fp, first := k.Fingerprint(), ""
	byID := map[string]*localSession{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e localEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Signer != fp {
			continue
		}
		if first == "" {
			first = e.At
		}
		s := byID[e.SessionID]
		switch {
		case e.Kind == "start" && s == nil:
			byID[e.SessionID] = &localSession{id: e.SessionID, startedAt: e.At, status: "open"}
			order = append(order, e.SessionID)
		case s == nil:
		case e.Kind == "seal":
			s.status = "sealed"
		case e.Kind == "abandon":
			s.status = "abandoned"
		case e.Kind == "clean":
			s.status = "cleaned"
		}
	}
	var out []localSession
	for _, id := range order {
		if s := byID[id]; s.status != "cleaned" {
			out = append(out, *s)
		}
	}
	return out, first
}

func LocalOpen(k *Key) []string {
	sessions, _ := localSessions(k)
	var open []string
	for _, s := range sessions {
		if s.status == "open" {
			open = append(open, s.id)
		}
	}
	return open
}

func LocalStatement(k *Key, sessionID, dataHash string) (string, error) {
	st := Statement{Kind: "kveritas-signer-history", At: time.Now().UTC().Format(time.RFC3339Nano),
		SessionID: sessionID, DataHash: dataHash, Signer: k.Fingerprint(), Keys: 1, Unsealed: []Unsealed{}}
	sessions, first := localSessions(k)
	st.FirstSeen = first
	found := false
	for i := range sessions {
		if sessions[i].id == sessionID {
			sessions[i].status, found = "sealed", true
		}
	}
	if !found {
		sessions = append(sessions, localSession{id: sessionID, status: "sealed"})
	}
	for _, s := range sessions {
		st.Started++
		switch s.status {
		case "sealed":
			st.Sealed++
		case "abandoned":
			st.Abandoned++
		default:
			st.Open++
		}
		if s.status != "sealed" {
			st.Unsealed = append(st.Unsealed, Unsealed{Session: s.id[:min(8, len(s.id))], Key: st.Signer[:16], StartedAt: s.startedAt, Status: s.status})
		}
	}
	data, err := json.Marshal(st)
	return string(data), err
}
