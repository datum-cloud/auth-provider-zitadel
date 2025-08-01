package token

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"sync"

	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	privatekey "go.miloapis.com/auth-provider-zitadel/pkg/private-key"
)

// Function to retrieve current time, overridden in tests.
var nowFunc = time.Now

// Introspector performs OAuth2 token introspection against a Zitadel instance.
type Introspector struct {
	privateKey      *rsa.PrivateKey
	clientID, keyID string

	introspectionURL string
	domain           string
	jwtExpiration    time.Duration

	// JWT caching fields
	mu                 sync.RWMutex
	cachedAssertion    string
	assertionExpiresAt time.Time
}

// NewIntrospector constructs a new Introspector from the given Zitadel JSON Key,
// Zitadel base domain, e.g. "https://auth.example.com", and JWT expiration duration.
func NewIntrospector(privateKeyPath, domain string, jwtExpiration time.Duration) (*Introspector, error) {
	log := logf.Log.WithName("token-introspector")

	log.Info("Creating new token introspector", "private_key_path", privateKeyPath, "domain", domain, "jwt_expiration", jwtExpiration)

	if jwtExpiration <= 0 {
		log.Error(fmt.Errorf("invalid duration"), "JWT expiration duration must be positive", "duration", jwtExpiration)
		return nil, fmt.Errorf("JWT expiration duration must be positive, got %v", jwtExpiration)
	}

	privKey, clientID, keyID, err := privatekey.LoadZitadelPrivateKey(privateKeyPath)
	if err != nil {
		log.Error(err, "Failed to load Zitadel private key", "path", privateKeyPath)
		return nil, err
	}

	// When a raw PEM key is used, we expect the caller to provide both clientID and keyID.
	if strings.ToLower(filepath.Ext(privateKeyPath)) != ".json" {
		if clientID == "" || keyID == "" {
			log.Error(fmt.Errorf("missing client credentials"), "clientID and keyID must be provided when using a PEM private key")
			return nil, fmt.Errorf("clientID and keyID must be provided when using a PEM private key")
		}
	}

	if domain == "" {
		log.Error(fmt.Errorf("missing domain"), "auth provider domain must be specified")
		return nil, fmt.Errorf("auth provider domain must be specified")
	}

	// Build full introspection endpoint URL.
	introspectionURL := fmt.Sprintf("%s/oauth/v2/introspect", strings.TrimRight(domain, "/"))

	log.Info("Successfully created token introspector",
		"client_id", clientID,
		"key_id", keyID,
		"introspection_url", introspectionURL,
		"jwt_expiration", jwtExpiration)

	return &Introspector{
		privateKey:       privKey,
		clientID:         clientID,
		keyID:            keyID,
		introspectionURL: introspectionURL,
		domain:           domain,
		jwtExpiration:    jwtExpiration,
	}, nil
}

// Introspect performs the token introspection call and returns the decoded JSON body.
func (i *Introspector) Introspect(ctx context.Context, token string) (map[string]interface{}, error) {
	log := logf.Log.WithName("token-introspector").WithValues("client_id", i.clientID)

	log.V(1).Info("Starting token introspection", "url", i.introspectionURL)

	clientAssertion, err := i.createClientAssertion()
	if err != nil {
		log.Error(err, "Failed to create client assertion")
		return nil, fmt.Errorf("create client assertion: %w", err)
	}

	log.V(1).Info("Successfully created client assertion")

	form := url.Values{}
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", clientAssertion)
	form.Set("token", token)

	// Use custom client so we can pass context.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Error(err, "Failed to build HTTP request")
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.V(1).Info("Sending introspection request to Zitadel")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(err, "Introspection HTTP request failed")
		return nil, fmt.Errorf("introspection request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(closeErr, "Failed to close response body")
		}
	}()

	log.V(1).Info("Received introspection response", "status_code", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Error(fmt.Errorf("introspection HTTP error"), "Introspection request failed",
			"status_code", resp.StatusCode,
			"status", resp.Status,
			"response_body", string(body))
		return nil, fmt.Errorf("introspection failed: %s - %s", resp.Status, string(body))
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Error(err, "Failed to decode introspection response")
		return nil, fmt.Errorf("decode response: %w", err)
	}

	log.V(1).Info("Successfully decoded introspection response", "active", data["active"])
	return data, nil
}

// createClientAssertion builds the JWT used as client_assertion for token introspection.
// It uses caching to avoid expensive JWT signing operations when the cached token is still valid.
func (i *Introspector) createClientAssertion() (string, error) {
	// Try to get from cache first (fast path)
	if cachedToken, found := i.getCachedAssertion(); found {
		return cachedToken, nil
	}

	// Cache miss or expired - create new JWT (slow path)
	return i.createAndCacheAssertion()
}

// getCachedAssertion attempts to retrieve a valid cached JWT using read locks for optimal concurrency.
// Returns the cached token and true if valid, empty string and false otherwise.
func (i *Introspector) getCachedAssertion() (string, bool) {
	log := logf.Log.WithName("token-introspector").WithValues("client_id", i.clientID)

	now := nowFunc()

	// Fast path: Check cache with read lock (allows concurrent reads)
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.cachedAssertion != "" && now.Add(5*time.Minute).Before(i.assertionExpiresAt) {
		log.V(1).Info("Using cached client assertion JWT", "expires_at", i.assertionExpiresAt)
		return i.cachedAssertion, true
	}

	log.V(1).Info("Cache miss or expired", "has_cached", i.cachedAssertion != "", "expires_at", i.assertionExpiresAt)
	return "", false
}

// createAndCacheAssertion creates a new JWT and caches it using write locks.
// Implements double-check pattern to avoid duplicate JWT creation.
func (i *Introspector) createAndCacheAssertion() (string, error) {
	log := logf.Log.WithName("token-introspector").WithValues("client_id", i.clientID)

	// Acquire write lock for cache update
	i.mu.Lock()
	defer i.mu.Unlock()

	now := nowFunc()

	// Double-check pattern: another goroutine might have updated cache while we waited for write lock
	if i.cachedAssertion != "" && now.Add(5*time.Minute).Before(i.assertionExpiresAt) {
		log.V(1).Info("Using cached client assertion JWT (double-check)", "expires_at", i.assertionExpiresAt)
		return i.cachedAssertion, nil
	}

	log.V(1).Info("Creating new client assertion JWT", "key_id", i.keyID, "audience", i.domain)

	// Create and sign new JWT
	signedToken, expiresAt, err := i.buildSignedJWT(now)
	if err != nil {
		return "", fmt.Errorf("error when building signed JWT: %w", err)
	}

	// Cache the new assertion
	i.cachedAssertion = signedToken
	i.assertionExpiresAt = expiresAt

	log.V(1).Info("Successfully created and cached new client assertion JWT", "expires_at", expiresAt)
	return signedToken, nil
}

// buildSignedJWT creates and signs a new JWT token with the given issued time.
// This function contains the pure JWT creation logic without caching concerns.
func (i *Introspector) buildSignedJWT(issuedAt time.Time) (signedToken string, expiresAt time.Time, err error) {
	log := logf.Log.WithName("token-introspector").WithValues("client_id", i.clientID)

	expiresAt = issuedAt.Add(i.jwtExpiration)

	claims := jwt.MapClaims{
		"iss": i.clientID,
		"sub": i.clientID,
		"aud": i.domain,
		"exp": expiresAt.Unix(),
		"iat": issuedAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = i.keyID

	signedToken, err = token.SignedString(i.privateKey)
	if err != nil {
		log.Error(err, "Failed to sign client assertion JWT")
		return "", time.Time{}, fmt.Errorf("failed to sign client assertion JWT: %w", err)
	}

	log.V(1).Info("Successfully signed JWT", "expires_at", expiresAt)
	return signedToken, expiresAt, nil
}

// GetCachedAssertionForTesting returns the cached assertion for testing purposes.
// This method should only be used in tests.
func (i *Introspector) GetCachedAssertionForTesting() (assertion string, expiresAt time.Time, cached bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.cachedAssertion == "" {
		return "", time.Time{}, false
	}

	return i.cachedAssertion, i.assertionExpiresAt, true
}

// CreateClientAssertionForTesting exposes createClientAssertion for testing.
// This method should only be used in tests.
func (i *Introspector) CreateClientAssertionForTesting() (string, error) {
	return i.createClientAssertion()
}
