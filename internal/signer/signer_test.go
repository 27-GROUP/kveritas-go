package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestKeyPersistsAndSigns(t *testing.T) {
	t.Setenv("KVERITAS_CONFIG_DIR", t.TempDir())
	a, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load()
	if err != nil || a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("key not persisted: %v", err)
	}
	pub, _ := base64.StdEncoding.DecodeString(a.Public())
	sig, _ := base64.StdEncoding.DecodeString(a.Sign("m"))
	if !ed25519.Verify(pub, []byte("m"), sig) {
		t.Fatal("signature does not verify")
	}
	t.Setenv(EnvKey, a.Export())
	c, err := Load()
	if err != nil || c.Fingerprint() != a.Fingerprint() {
		t.Fatalf("env key differs: %v", err)
	}
}

func TestLocalStatementCountsSessions(t *testing.T) {
	t.Setenv("KVERITAS_CONFIG_DIR", t.TempDir())
	k, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range [][2]string{{"start", "s1"}, {"start", "s2"}, {"start", "s3"}, {"clean", "s3"}, {"start", "s4"}, {"clean", "s4"}} {
		if err := RecordLocal(k, e[0], e[1]); err != nil {
			t.Fatal(err)
		}
	}
	text, err := LocalStatement(k, "s1", "d")
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		t.Fatal(err)
	}
	if st.Started != 2 || st.Sealed != 1 || st.Open != 1 || len(st.Unsealed) != 1 {
		t.Fatalf("got %+v", st)
	}
	if open := LocalOpen(k); len(open) != 2 {
		t.Fatalf("open sessions: %v", open)
	}
}
