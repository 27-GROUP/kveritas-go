package crypto

import "testing"

// A freshly generated key is not the pinned server key, so a report signed with it
// is self-attested; the pinned key matches itself.
func TestOriginConfirmed(t *testing.T) {
	trusted, err := TrustedServerKey()
	if err != nil {
		t.Fatalf("pinned key did not parse: %v", err)
	}
	trustedPEM, err := MarshalPublicKey(trusted)
	if err != nil {
		t.Fatal(err)
	}

	other, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := MarshalPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := OriginConfirmed(string(trustedPEM), nil)
	if err != nil || !ok {
		t.Errorf("pinned key should confirm origin: ok=%v err=%v", ok, err)
	}
	ok, err = OriginConfirmed(string(otherPEM), nil)
	if err != nil || ok {
		t.Errorf("author key should be self-attested: ok=%v err=%v", ok, err)
	}
	// With an explicit anchor, only that key confirms.
	ok, err = OriginConfirmed(string(otherPEM), otherPEM)
	if err != nil || !ok {
		t.Errorf("supplied anchor should confirm its own key: ok=%v err=%v", ok, err)
	}
}
