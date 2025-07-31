package privatekey

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPrivateKey reads an RSA private key for a Zitadel JSON credentials file,
// and returns the private key, client ID, and key ID.
func LoadZitadelPrivateKey(path string) (*rsa.PrivateKey, string, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("read key file: %w", err)
	}

	// Zitadel credentials JSON
	var cred struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"key"`
		ClientID   string `json:"clientId"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, "", "", fmt.Errorf("parse credentials json: %w", err)
	}
	privKey, err := parsePEMPrivateKey([]byte(cred.PrivateKey))
	if err != nil {
		return nil, "", "", fmt.Errorf("parse pem from credentials: %w", err)
	}
	return privKey, cred.ClientID, cred.KeyID, nil
}

// parsePEMPrivateKey parses a PEM encoded RSA private key.
func parsePEMPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	// Try PKCS8 first, fall back to PKCS1.
	if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if key, ok := parsedKey.(*rsa.PrivateKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("unexpected key type %T", parsedKey)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
