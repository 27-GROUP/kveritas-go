package crypto

import "crypto/rsa"

// trustedServerKeyPEM is the K-Veritas production signing key, pinned into the
// binary. A report is authentic only if its embedded key matches; any other key
// means self-attested.
const trustedServerKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1QL3YyMgeShx8IhTC7jb
sM0w2BnRXgsBn3+SMXKjtwHATqdekm1PlcjayJxD5fcPrOPPCqp/LoUFz5CUZzRi
6+8FTv70dHuIz5A4LAt4vcgwP+iWscPc3HzpmjpsKbTmOemqgp6RB6GNnPpxYa5X
7qU95EfEisX/GfoS9ToXtqPBwCcVWSPBX8efeC4TC58m96Fsp4mC8KIcEadbIbHN
av0JjdTJ//CMOWZSIbdzE6qvEbNFcqDB5tNU7oHfYvBeNLrvPU9TAqdbtozdhQ+D
AhfTRuJNgWEkjWD5lbOVhi4qlkweSOEMTKT3ye9Il5xEaJn4bku4eKqeS7VSZt3o
XbUcmr2H5mKcKSvt6bXmX6ajAmgi900Cm9QJlaQkJM6z2iITnyvDMgueJtFxQpC9
HNBPgPZ242NH8JgE6CNF7ToL9syanS67u7UMgIcNgeNHNcy9blGpU5annzP9gN2l
6HEMldkXNdKQRb1rDWyEJf3N/50YHnXXPmuf5sb8R/pxWNqtfO4R5UGVV92qd2Mi
1GN7lE3mbQRbPsLL/JApDXMNzNikaFfBsQK7iKxr7vIaTeZckFZWfThcYNT7Hasg
+eE4bf/olCHBCf1VIDCkDxohehdZ0WRRcgM9iK3I/0zZdaBsgdc8WuJRmb8LPP9v
8Jap/1PWjNcNku5cdW3gHLcCAwEAAQ==
-----END PUBLIC KEY-----
`

// TrustedServerKey returns the pinned K-Veritas server public key.
func TrustedServerKey() (*rsa.PublicKey, error) {
	return LoadPublicKey([]byte(trustedServerKeyPEM))
}

// SamePublicKey reports whether two RSA public keys are identical.
func SamePublicKey(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.N.Cmp(b.N) == 0 && a.E == b.E
}

// OriginConfirmed reports whether the embedded key matches the trust anchor
// (anchorPEM when non-empty, else the pinned server key). True means K-Veritas
// signed the report; false means self-attested.
func OriginConfirmed(embeddedPEM string, anchorPEM []byte) (bool, error) {
	embedded, err := LoadPublicKey([]byte(embeddedPEM))
	if err != nil {
		return false, err
	}
	var anchor *rsa.PublicKey
	if len(anchorPEM) > 0 {
		anchor, err = LoadPublicKey(anchorPEM)
	} else {
		anchor, err = TrustedServerKey()
	}
	if err != nil {
		return false, err
	}
	return SamePublicKey(embedded, anchor), nil
}
