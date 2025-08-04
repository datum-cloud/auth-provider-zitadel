package token

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

// generateCredentialsFile creates a temporary Zitadel credentials JSON file that
// contains a randomly-generated RSA private key. It returns the full path to
// the generated file.
func generateCredentialsFile(t *testing.T) string {
	t.Helper()

	// Generate test RSA key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// Encode the key to PEM.
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	var pemBuf bytes.Buffer
	if err := pem.Encode(&pemBuf, pemBlock); err != nil {
		t.Fatalf("encode pem: %v", err)
	}

	// Build credentials JSON.
	cred := struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"key"`
		ClientID   string `json:"clientId"`
	}{
		KeyID:      "test-key-id",
		PrivateKey: pemBuf.String(),
		ClientID:   "test-client-id",
	}

	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}

	// Write to temp file.
	tmpFile, err := os.CreateTemp(t.TempDir(), "cred-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close credentials file: %v", err)
	}

	return tmpFile.Name()
}

// TestIntrospectorCaching verifies that the JWT assertion caching works as expected.
// time can be controlled without having to actually wait for an hour.
func TestIntrospectorCaching(t *testing.T) {
	baseTime := time.Date(2025, 8, 1, 12, 0, 0, 0, time.UTC)
	currentTime := baseTime

	// Override time source for deterministic testing.
	originalNow := nowFunc
	defer func() { nowFunc = originalNow }()
	nowFunc = func() time.Time {
		return currentTime
	}

	credPath := generateCredentialsFile(t)

	// Create an introspector with a *real* expiration of one hour.
	intr, err := NewIntrospector(credPath, "https://auth.example.com", time.Hour)
	if err != nil {
		t.Fatalf("create introspector: %v", err)
	}

	// First call should create and cache a new assertion.
	assertion1, err := intr.createClientAssertion()
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Second call immediately afterwards should return the cached value.
	assertion2, err := intr.createClientAssertion()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if assertion1 != assertion2 {
		t.Fatalf("expected cached assertion to be reused, got different value")
	}

	// Advance time by 30 minutes – cache should still be valid.
	currentTime = currentTime.Add(30 * time.Minute)
	assertion3, err := intr.createClientAssertion()
	if err != nil {
		t.Fatalf("30-minute call failed: %v", err)
	}
	if assertion1 != assertion3 {
		t.Fatalf("expected cache after 30m, got new assertion")
	}

	// Advance time to 55 minutes (5 minutes before expiry) – cache is considered expired.
	currentTime = baseTime.Add(55 * time.Minute)
	assertion4, err := intr.createClientAssertion()
	if err != nil {
		t.Fatalf("55-minute call failed: %v", err)
	}
	if assertion1 == assertion4 {
		t.Fatalf("expected a new assertion after cache expiry, but received cached one")
	}

	// Save the newly created assertion for further checks.
	assertionNew := assertion4

	// Subsequent call without advancing time further should reuse the new cache entry.
	assertion5, err := intr.createClientAssertion()
	if err != nil {
		t.Fatalf("post-expiry cached call failed: %v", err)
	}
	if assertionNew != assertion5 {
		t.Fatalf("expected the new assertion to be cached, but got a different value")
	}
}
