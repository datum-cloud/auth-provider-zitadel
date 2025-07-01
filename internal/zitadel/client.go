package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Client is a minimal HTTP client for talking to a ZITADEL instance.
// It is intentionally small and dependency-free so we can grow it alongside
// the features we need without pulling the full (and currently incomplete)
// official Go SDK.
//
// A Client is safe for concurrent use by multiple goroutines.
// All methods accept a context so that the caller can cancel in-flight requests.
//
// Example usage:
//
//	c := zitadel.NewClient("https://example.zitadel.cloud", "<access-token>", "Bearer")
//	resp, err := c.CreateMachineUser(ctx, zitadel.MachineUserRequest{ ... })
//
// As we expand the client we will add more methods that call new endpoints.
// Each method should mirror the REST API as closely as possible.
//
// See https://zitadel.com/docs/apis/introduction for the authoritative reference.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	tokenType  string
}

// NewClient returns a ready-to-use ZITADEL client.
//
//	baseURL   – URL of your ZITADEL instance (e.g. "https://my-org.zitadel.cloud")
//	token     – the access/ID token value (without the token type prefix)
//	tokenType – token prefix, typically "Bearer" or "Basic".
func NewClient(baseURL, token, tokenType string) *Client {
	log := logf.Log.WithName("zitadel-client")
	log.Info("Creating new ZITADEL client", "baseURL", baseURL, "tokenType", tokenType)

	c := &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
		tokenType:  tokenType,
	}

	return c
}

// do is a helper that takes care of marshalling the request body, setting
// headers, issuing the request and, if v is not nil, decoding the JSON
// response into it.
func (c *Client) do(ctx context.Context, method, path string, body interface{}, v interface{}) error {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Sending request", "method", method, "path", path)

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			log.Error(err, "Failed to marshal request body")
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/"+strings.TrimLeft(path, "/"), bodyReader)
	if err != nil {
		log.Error(err, "Failed to create request")
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", c.tokenType, c.token))
	}

	log.V(1).Info("Sending request")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Error(err, "Failed to send request")
		return fmt.Errorf("do request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error(closeErr, "Failed to close response body")
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Treat 404 specially so callers can distinguish a missing resource
		// from other kinds of errors and apply custom handling if desired.
		if resp.StatusCode == http.StatusNotFound {
			log.V(1).Info("Resource not found")
			return apierrors.NewNotFound(schema.GroupResource{Group: "zitadel", Resource: "resource"}, "")
		}
		// Read the response body for better error messages, but limit to 1 MiB so we don't
		// blow up on huge responses.
		const maxErrorBody = 1 << 20
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		log.Error(nil, "Request failed",
			"method", method,
			"path", path,
			"statusCode", resp.StatusCode,
			"response", strings.TrimSpace(string(data)))
		return fmt.Errorf("request failed: %s – %s", resp.Status, strings.TrimSpace(string(data)))
	}

	if v == nil {
		// Caller doesn't care about the response body.
		log.V(1).Info("Request completed successfully")
		return nil
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(v); err != nil {
		log.Error(err, "Failed to decode response body")
		return fmt.Errorf("decode response: %w", err)
	}

	log.V(1).Info("Request completed successfully with response")
	return nil
}
