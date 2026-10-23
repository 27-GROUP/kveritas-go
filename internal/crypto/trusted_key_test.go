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

	ok, err := OriginConfirmed(string(trustedPEM), nil, "2026-10-23T03:57:44.148616+00:00")
	if err != nil || !ok {
		t.Errorf("pinned key should confirm origin: ok=%v err=%v", ok, err)
	}
	ok, err = OriginConfirmed(string(otherPEM), nil, "")
	if err != nil || ok {
		t.Errorf("author key should be self-attested: ok=%v err=%v", ok, err)
	}
	// With an explicit anchor, only that key confirms.
	ok, err = OriginConfirmed(string(otherPEM), otherPEM, "")
	if err != nil || !ok {
		t.Errorf("supplied anchor should confirm its own key: ok=%v err=%v", ok, err)
	}
}

func TestTrustedKeyList(t *testing.T) {
	keys := TrustedKeys()
	active, next := 0, 0
	for _, k := range keys {
		switch k.Status {
		case "active":
			active++
		case "next":
			next++
			ok, err := OriginConfirmed(k.PublicKeyPEM, nil, "2030-01-01T00:00:00Z")
			if err != nil || !ok {
				t.Errorf("next key %s should be trusted before it is used", k.ID)
			}
		}
	}
	if active != 1 || next != 9 {
		t.Fatalf("want 1 active and 9 next keys, got %d and %d", active, next)
	}

	retired := TrustedKey{Status: "retired", Until: "2027-01-01T00:00:00Z"}
	if !retired.validAt("2026-12-31T23:59:59.5+00:00") {
		t.Error("a retired key must still vouch for what it signed before retiring")
	}
	if retired.validAt("2027-01-02T00:00:00Z") || retired.validAt("") {
		t.Error("a retired key must not vouch for anything signed after it retired")
	}
	if (TrustedKey{Status: "revoked"}).validAt("2026-01-01T00:00:00Z") {
		t.Error("unknown status must not be trusted")
	}
}
