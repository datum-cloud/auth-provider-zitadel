package token

import (
	"context"
	"crypto/rsa"
	"encoding/json"

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

// Introspector performs OAuth2 token introspection against a Zitadel instance.
type Introspector struct {
	privateKey      *rsa.PrivateKey
	clientID, keyID string

	introspectionURL string
	domain           string
	jwtExpiration    time.Duration
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
func (i *Introspector) createClientAssertion() (string, error) {
	log := logf.Log.WithName("token-introspector").WithValues("client_id", i.clientID)

	log.V(1).Info("Creating client assertion JWT", "key_id", i.keyID, "audience", i.domain)

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": i.clientID,
		"sub": i.clientID,
		"aud": i.domain,
		"exp": now.Add(i.jwtExpiration).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = i.keyID

	signedToken, err := token.SignedString(i.privateKey)
	if err != nil {
		log.Error(err, "Failed to sign client assertion JWT")
		return "", err
	}

	log.V(1).Info("Successfully created and signed client assertion JWT")
	return signedToken, nil
}
