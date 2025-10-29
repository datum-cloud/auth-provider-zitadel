package webhook

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
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

// buildTestHandler returns the HTTP handler under test along with the
// underlying introspection test server so that the caller can control the
// server's behaviour.
func buildTestHandler(t *testing.T, responseStatus int, responseBody map[string]any, kubeObjs ...client.Object) (http.Handler, *httptest.Server) {
	t.Helper()

	// Create a fake Zitadel introspection endpoint.
	introspectionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responseStatus)
		_ = json.NewEncoder(w).Encode(responseBody)
	}))

	// Build an introspector that talks to our fake server.
	credsPath := generateCredentialsFile(t)
	introspector, err := token.NewIntrospector(credsPath, introspectionSrv.URL, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("create introspector: %v", err)
	}

	// Prepare fake k8s client
	scheme := runtime.NewScheme()
	if err := authenticationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add auth scheme: %v", err)
	}
	if err := iammiloapiscomv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add iam scheme: %v", err)
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(kubeObjs...).Build()

	handler := NewAuthenticationWebhookV1(introspector, fakeClient)
	return handler, introspectionSrv
}

func TestHttpTokenAuthenticationWebhook(t *testing.T) {
	t.Parallel()

	const validToken = "dummy.jwt.token"

	tests := []struct {
		name                 string
		method               string
		token                string
		introspectionStatus  int
		introspectionPayload map[string]any
		expectHTTPCode       int
		expectAuthenticated  bool
		expectExtraApproval  bool
		expectExtraValue     string
		expectErrorSubstring string
	}{
		{
			name:           "method not allowed",
			method:         http.MethodGet,
			token:          "",
			expectHTTPCode: http.StatusMethodNotAllowed,
		},
		{
			name:                 "empty token provided",
			method:               http.MethodPost,
			token:                "", // empty token
			introspectionStatus:  http.StatusOK,
			introspectionPayload: map[string]any{"active": false}, // will not be used
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  false,
			expectErrorSubstring: "empty token provided",
		},
		{
			name:                 "introspection returns http error",
			method:               http.MethodPost,
			token:                validToken,
			introspectionStatus:  http.StatusInternalServerError,
			introspectionPayload: map[string]any{"error": "internal"},
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  false,
			expectErrorSubstring: "token introspection failed",
		},
		{
			name:                 "token inactive",
			method:               http.MethodPost,
			token:                validToken,
			introspectionStatus:  http.StatusOK,
			introspectionPayload: map[string]any{"active": false},
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  false,
			expectErrorSubstring: "jwt token is not active",
		},
		{
			name:                 "human user token active",
			method:               http.MethodPost,
			token:                validToken,
			introspectionStatus:  http.StatusOK,
			introspectionPayload: map[string]any{"active": true, "sub": "my-user", "email": "user@example.com"},
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  true,
			expectExtraApproval:  true,
			expectExtraValue:     string(iammiloapiscomv1alpha1.RegistrationApprovalStateApproved),
		},
		{
			name:                 "machine user token active",
			method:               http.MethodPost,
			token:                validToken,
			introspectionStatus:  http.StatusOK,
			introspectionPayload: map[string]any{"active": true, "sub": "machine-user", "username": "machine-user@example.com"},
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  true,
			expectExtraApproval:  true,
			expectExtraValue:     string(iammiloapiscomv1alpha1.RegistrationApprovalStateApproved),
		},
		{
			name:                 "missing email or username",
			method:               http.MethodPost,
			token:                validToken,
			introspectionStatus:  http.StatusOK,
			introspectionPayload: map[string]any{"active": true, "sub": "machine-user"},
			expectHTTPCode:       http.StatusOK,
			expectAuthenticated:  false,
			expectExtraApproval:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// For non-POST test we don't need introspection server.
			var handler http.Handler
			var srv *httptest.Server
			kubeObjs := []client.Object{}
			if tc.expectAuthenticated {
				// create fake User with approved registration
				if sub, ok := tc.introspectionPayload["sub"].(string); ok {
					kubeObjs = append(kubeObjs, &iammiloapiscomv1alpha1.User{
						TypeMeta:   metav1.TypeMeta{Kind: "User", APIVersion: "iam.miloapis.com/v1alpha1"},
						ObjectMeta: metav1.ObjectMeta{Name: sub},
						Status: iammiloapiscomv1alpha1.UserStatus{
							RegistrationApproval: iammiloapiscomv1alpha1.RegistrationApprovalStateApproved,
						},
					})
				}
			}
			handler, srv = buildTestHandler(t, tc.introspectionStatus, tc.introspectionPayload, kubeObjs...)
			defer srv.Close()

			// Build request.
			var reqBody bytes.Buffer
			if tc.method == http.MethodPost {
				review := authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: tc.token}}
				if err := json.NewEncoder(&reqBody).Encode(&review); err != nil {
					t.Fatalf("encode request: %v", err)
				}
			}
			req := httptest.NewRequest(tc.method, "/", &reqBody)
			req.Header.Set("Content-Type", "application/json")

			// Serve the request.
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectHTTPCode {
				t.Fatalf("unexpected status code: got %d want %d", rr.Code, tc.expectHTTPCode)
			}

			// Early exit for method not allowed.
			if tc.method == http.MethodGet {
				if allow := rr.Header().Get("Allow"); allow != http.MethodPost {
					t.Fatalf("unexpected Allow header: %s", allow)
				}
				return
			}

			// Decode TokenReview response.
			var resp authenticationv1.TokenReview
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if resp.Status.Authenticated != tc.expectAuthenticated {
				t.Fatalf("authenticated mismatch: got %v want %v", resp.Status.Authenticated, tc.expectAuthenticated)
			}

			if tc.expectErrorSubstring != "" {
				if !bytes.Contains([]byte(resp.Status.Error), []byte(tc.expectErrorSubstring)) {
					t.Fatalf("expected error to contain %q, got %q", tc.expectErrorSubstring, resp.Status.Error)
				}
			}

			if tc.expectAuthenticated {
				if resp.Status.User.Username == "" || resp.Status.User.UID == "" {
					t.Fatalf("expected user info to be set on success")
				}
			}

			if tc.expectExtraApproval {
				val, ok := resp.Status.User.Extra["iam.miloapis.com/registrationApproval"]
				if !ok {
					t.Fatalf("expected registrationApproval in extra")
				}
				if len(val) == 0 || val[0] != tc.expectExtraValue {
					t.Fatalf("unexpected registrationApproval value: %v", val)
				}
			}
		})
	}
}
