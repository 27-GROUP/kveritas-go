// Package crypto implements the K-Veritas signing protocol: sign the payload
// "data_hash:nonce:signed_at" with RSA-PSS-SHA256.
package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sort"
)

const RSAKeyBits = 4096

// HashBytes returns the SHA-256 hex digest of b.
func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// HashFile returns the SHA-256 hex digest of the named file, streamed.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CanonicalHash returns the SHA-256 hex digest of v as sorted-key JSON,
// matching Python's json.dumps(sort_keys=True).
func CanonicalHash(v interface{}) (string, error) {
	b, err := sortedMarshal(v)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// CanonicalHashWithBytes also returns the raw canonical JSON, embedded in the
// seal so verifiers re-hash the exact bytes rather than rebuild the structure.
func CanonicalHashWithBytes(v interface{}) (string, []byte, error) {
	b, err := sortedMarshal(v)
	if err != nil {
		return "", nil, err
	}
	return HashBytes(b), b, nil
}

// Payload constructs the signing payload string.
func Payload(dataHash, nonce, signedAt string) string {
	return fmt.Sprintf("%s:%s:%s", dataHash, nonce, signedAt)
}

// RandomNonce returns 32 lowercase hex characters (16 random bytes).
func RandomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateKey generates a 4096-bit RSA key pair.
func GenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeyBits)
}

// MarshalPrivateKey encodes a private key as PKCS8 PEM.
func MarshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKey encodes a public key as PKIX PEM.
func MarshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadPublicKey parses a PEM-encoded RSA public key.
func LoadPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM block is not an RSA public key")
	}
	return rsaKey, nil
}

// LoadPrivateKey parses a PEM-encoded RSA private key (PKCS8 or PKCS1).
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// SignPSS returns a base64 RSA-PSS-SHA256 signature over payload. The digest is
// SHA-256 of the payload bytes, matching Python's sign over payload.encode.
func SignPSS(privKey *rsa.PrivateKey, payload string) (string, error) {
	h := sha256.Sum256([]byte(payload))
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, h[:], opts)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyPSS verifies a base64-encoded RSA-PSS-SHA256 signature over payload.
func VerifyPSS(pubKey *rsa.PublicKey, payload, sigBase64 string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	h := sha256.Sum256([]byte(payload))
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}
	return rsa.VerifyPSS(pubKey, crypto.SHA256, h[:], sigBytes, opts)
}

// sortedMarshal produces JSON with recursively sorted object keys.
func sortedMarshal(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return sortedJSON(generic)
}

func sortedJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vb, err := sortedJSON(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, kb...)
			buf = append(buf, ':')
			buf = append(buf, vb...)
			if i < len(keys)-1 {
				buf = append(buf, ',')
			}
		}
		return append(buf, '}'), nil
	case []interface{}:
		buf := []byte{'['}
		for i, item := range val {
			vb, err := sortedJSON(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
			if i < len(val)-1 {
				buf = append(buf, ',')
			}
		}
		return append(buf, ']'), nil
	default:
		return json.Marshal(v)
	}
}
