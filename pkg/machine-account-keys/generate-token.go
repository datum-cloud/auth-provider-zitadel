package machineaccountkeys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// MachineKey represents the structure of the Zitadel machine key
type MachineKey struct {
	Type           string `json:"type"`
	KeyID          string `json:"keyId"`
	Key            string `json:"key"`
	ExpirationDate string `json:"expirationDate"`
	UserID         string `json:"userId"`
}

// ZitadelClaims represents the JWT claims for Zitadel
type ZitadelClaims struct {
	jwt.RegisteredClaims
	// Add any additional Zitadel-specific claims here
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// GetAccessToken generates an access token for a machine account from the Zitadel instance
func GetAccessToken(machineKeyPath string, zitadelURL string, scope string, timeDuration time.Duration) (string, error) {
	logger := logf.Log.WithName("GetAccessToken")
	logger.Info("Starting access token generation", "machineKeyPath", machineKeyPath, "zitadelURL", zitadelURL, "scope", scope, "duration", timeDuration)

	// Read and parse the machine key file
	machineKey, err := readMachineKey(machineKeyPath)
	if err != nil {
		logger.Error(err, "Failed to read machine key", "path", machineKeyPath)
		log.Fatalf("Failed to read machine key: %v", err)
	}
	logger.Info("Successfully read machine key")

	// Generate JWT token
	jwtToken, err := generateJWT(machineKey, []string{zitadelURL}, timeDuration)
	if err != nil {
		logger.Error(err, "Failed to generate JWT")
		log.Fatalf("Failed to generate JWT: %v", err)
	}
	logger.Info("Successfully generated JWT token")

	// Exchange JWT for access token
	accessToken, err := exchangeJWTForAccessToken(jwtToken, zitadelURL, scope)
	if err != nil {
		logger.Error(err, "Failed to exchange JWT for access token")
		log.Fatalf("Failed to exchange JWT for access token: %v", err)
	}
	logger.Info("Successfully obtained access token")

	return accessToken, nil
}

// readMachineKey reads and parses the machine key JSON file
func readMachineKey(filepath string) (*MachineKey, error) {
	logger := logf.Log.WithName("readMachineKey")
	logger.Info("Reading machine key file", "filepath", filepath)

	data, err := os.ReadFile(filepath)
	if err != nil {
		logger.Error(err, "Failed to read machine key file", "filepath", filepath)
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	logger.Info("Successfully read machine key file")

	var machineKey MachineKey
	if err := json.Unmarshal(data, &machineKey); err != nil {
		logger.Error(err, "Failed to parse machine key JSON", "filepath", filepath)
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	logger.Info("Successfully parsed machine key")

	return &machineKey, nil
}

// parseRSAPrivateKey parses the PEM-encoded RSA private key
func parseRSAPrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	logger := logf.Log.WithName("parseRSAPrivateKey")
	logger.Info("Parsing RSA private key")

	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		logger.Error(nil, "Failed to decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	logger.Info("Successfully decoded PEM block")

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.Info("PKCS1 parsing failed, trying PKCS8 format")
		// Try PKCS8 format if PKCS1 fails
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			logger.Error(err, "Failed to parse private key in both PKCS1 and PKCS8 formats")
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			logger.Error(nil, "Parsed key is not an RSA private key")
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		logger.Info("Successfully parsed RSA private key using PKCS8 format")
		return rsaKey, nil
	}
	logger.Info("Successfully parsed RSA private key using PKCS1 format")

	return key, nil
}

// generateJWT creates and signs a JWT token using the machine key
func generateJWT(machineKey *MachineKey, audience []string, timeDuration time.Duration) (string, error) {
	logger := logf.Log.WithName("generateJWT")
	logger.Info("Generating JWT token", "audience", audience, "duration", timeDuration)

	// Parse the RSA private key
	privateKey, err := parseRSAPrivateKey(machineKey.Key)
	if err != nil {
		logger.Error(err, "Failed to parse RSA private key")
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}
	logger.Info("Successfully parsed RSA private key")

	// Create JWT claims
	now := time.Now()
	expiresAt := now.Add(timeDuration)
	logger.Info("Creating JWT claims", "expiresAt", expiresAt)

	claims := ZitadelClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    machineKey.UserID,
			Subject:   machineKey.UserID,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(expiresAt), // Token expires in 1 hour
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        machineKey.KeyID,
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set the key ID in the header
	token.Header["kid"] = machineKey.KeyID

	// Sign token with private key
	logger.Info("Signing JWT token")
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		logger.Error(err, "Failed to sign JWT token")
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	logger.Info("Successfully generated and signed JWT token")

	return tokenString, nil
}

// exchangeJWTForAccessToken exchanges a JWT for an access token using OAuth2 JWT Bearer flow
func exchangeJWTForAccessToken(jwtToken, zitadelURL, scope string) (string, error) {
	logger := logf.Log.WithName("exchangeJWTForAccessToken")
	logger.Info("Exchanging JWT for access token", "zitadelURL", zitadelURL, "scope", scope)

	// Prepare the OAuth2 token endpoint URL
	tokenURL := strings.TrimSuffix(zitadelURL, "/") + "/oauth/v2/token"
	logger.Info("Preparing OAuth2 request", "tokenURL", tokenURL)

	// Prepare the form data
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("scope", scope)
	data.Set("assertion", jwtToken)

	// Create the HTTP request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		logger.Error(err, "Failed to create HTTP request", "tokenURL", tokenURL)
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logger.Info("Making OAuth2 token request", "method", "POST", "url", tokenURL)

	// Make the HTTP request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error(err, "Failed to make HTTP request", "tokenURL", tokenURL)
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Error(closeErr, "Failed to close response body")
		}
	}()

	logger.Info("Received HTTP response", "statusCode", resp.StatusCode)

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err, "Failed to read response body")
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		logger.Error(nil, "HTTP request failed", "statusCode", resp.StatusCode)
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Parse the JSON response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		logger.Error(err, "Failed to parse token response JSON")
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		logger.Error(nil, "No access token in response")
		return "", fmt.Errorf("no access token in response")
	}

	logger.Info("Successfully obtained access token")
	return tokenResponse.AccessToken, nil
}
