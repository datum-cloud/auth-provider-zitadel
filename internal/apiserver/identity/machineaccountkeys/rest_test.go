package machineaccountkeys

import (
	"encoding/json"
	"testing"
)

func TestBuildDatumCredentials_EmptyKeyContent(t *testing.T) {
	testCases := []struct {
		name                   string
		introspectionProjectID string
	}{
		{name: "empty project ID", introspectionProjectID: ""},
		{name: "with project ID", introspectionProjectID: "326089123456789012"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildDatumCredentials(nil, "key-id", "client-id", "client-email", tc.introspectionProjectID)
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if got != nil {
				t.Fatalf("expected nil bytes for empty keyContent, got %q", string(got))
			}

			// Also verify with an explicit empty (non-nil) slice.
			got, err = buildDatumCredentials([]byte{}, "key-id", "client-id", "client-email", tc.introspectionProjectID)
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if got != nil {
				t.Fatalf("expected nil bytes for empty keyContent slice, got %q", string(got))
			}
		})
	}
}

func TestBuildDatumCredentials_NoScopeWhenProjectIDEmpty(t *testing.T) {
	envelope := []byte(`{"type":"sa","keyId":"k1","key":"-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n","userId":"u1"}`)

	got, err := buildDatumCredentials(envelope, "key-id-1", "client-id-1", "svc@example.com", "")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil credentials, got nil")
	}

	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("failed to unmarshal credentials: %v", err)
	}

	if _, exists := m["scope"]; exists {
		t.Fatalf("expected scope field to be absent, but it exists with value %v", m["scope"])
	}

	// Sanity check other required fields.
	if m["type"] != datumCredentialsType {
		t.Errorf("expected type=%q, got %v", datumCredentialsType, m["type"])
	}
	if m["client_id"] != "client-id-1" {
		t.Errorf("expected client_id=client-id-1, got %v", m["client_id"])
	}
	if m["private_key_id"] != "key-id-1" {
		t.Errorf("expected private_key_id=key-id-1, got %v", m["private_key_id"])
	}
	if m["client_email"] != "svc@example.com" {
		t.Errorf("expected client_email=svc@example.com, got %v", m["client_email"])
	}
	if _, ok := m["private_key"].(string); !ok {
		t.Errorf("expected private_key to be a string, got %T", m["private_key"])
	}
}

func TestBuildDatumCredentials_ScopeWhenProjectIDSet(t *testing.T) {
	envelope := []byte(`{"type":"sa","keyId":"k1","key":"-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n","userId":"u1"}`)
	const projectID = "326089123456789012"
	const wantScope = "openid profile email offline_access urn:zitadel:iam:org:project:id:326089123456789012:aud"

	got, err := buildDatumCredentials(envelope, "key-id-1", "client-id-1", "svc@example.com", projectID)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil credentials, got nil")
	}

	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("failed to unmarshal credentials: %v", err)
	}

	scope, ok := m["scope"].(string)
	if !ok {
		t.Fatalf("expected scope field to be a string, got %T (%v)", m["scope"], m["scope"])
	}
	if scope != wantScope {
		t.Errorf("unexpected scope value\n  got:  %q\n want: %q", scope, wantScope)
	}
}

func TestBuildDatumCredentials_MalformedJSON(t *testing.T) {
	bad := []byte(`{not valid json`)

	got, err := buildDatumCredentials(bad, "key-id", "client-id", "client-email", "")
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got nil (bytes=%q)", string(got))
	}
	if got != nil {
		t.Errorf("expected nil bytes on error, got %q", string(got))
	}
}
