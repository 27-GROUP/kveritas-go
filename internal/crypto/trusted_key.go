package crypto

import (
	"crypto/rsa"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Next keys are trusted before use, so a rotation never makes new reports SELF-ATTESTED for older CLIs.
//
//go:embed trusted_keys.json
var trustedKeysJSON []byte

type TrustedKey struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Until        string `json:"until,omitempty"`
	PublicKeyPEM string `json:"public_key_pem"`
	key          *rsa.PublicKey
}

var (
	trustedOnce sync.Once
	trusted     []TrustedKey
)

func TrustedKeys() []TrustedKey {
	trustedOnce.Do(func() {
		var doc struct {
			Keys []TrustedKey `json:"keys"`
		}
		if json.Unmarshal(trustedKeysJSON, &doc) != nil {
			return
		}
		for _, k := range doc.Keys {
			if pk, err := LoadPublicKey([]byte(k.PublicKeyPEM)); err == nil {
				k.key = pk
				trusted = append(trusted, k)
			}
		}
	})
	return trusted
}

// A retired key counts only up to its retirement, so a later leak vouches for nothing new.
func (k TrustedKey) validAt(signedAt string) bool {
	switch k.Status {
	case "active", "next":
		return true
	case "retired":
		if k.Until == "" {
			return true
		}
		until, err := time.Parse(time.RFC3339Nano, k.Until)
		if err != nil {
			return false
		}
		at, err := time.Parse(time.RFC3339Nano, strings.Replace(strings.TrimSpace(signedAt), " ", "T", 1))
		return err == nil && !at.After(until)
	}
	return false
}

func TrustedServerKey() (*rsa.PublicKey, error) {
	for _, k := range TrustedKeys() {
		if k.Status == "active" {
			return k.key, nil
		}
	}
	return nil, fmt.Errorf("no active K-Veritas key pinned")
}

func SamePublicKey(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.N.Cmp(b.N) == 0 && a.E == b.E
}

func OriginConfirmed(embeddedPEM string, anchorPEM []byte, signedAt string) (bool, error) {
	embedded, err := LoadPublicKey([]byte(embeddedPEM))
	if err != nil {
		return false, err
	}
	if len(anchorPEM) > 0 {
		anchor, err := LoadPublicKey(anchorPEM)
		if err != nil {
			return false, err
		}
		return SamePublicKey(embedded, anchor), nil
	}
	for _, k := range TrustedKeys() {
		if SamePublicKey(embedded, k.key) && k.validAt(signedAt) {
			return true, nil
		}
	}
	return false, nil
}

func CheckpointPayload(seq int64, entryHash, at string) string {
	return fmt.Sprintf("kveritas-ledger-checkpoint:%d:%s:%s", seq, entryHash, at)
}

func CheckpointSigned(seq int64, entryHash, at, signature string) bool {
	payload := CheckpointPayload(seq, entryHash, at)
	for _, k := range TrustedKeys() {
		if k.validAt(at) && VerifyPSS(k.key, payload, signature) == nil {
			return true
		}
	}
	return false
}

func HistoryPayload(statement string) string {
	return "kveritas-signer-history:" + HashBytes([]byte(statement))
}

func HistorySigned(statement, at, signature string) bool {
	payload := HistoryPayload(statement)
	for _, k := range TrustedKeys() {
		if k.validAt(at) && VerifyPSS(k.key, payload, signature) == nil {
			return true
		}
	}
	return false
}
