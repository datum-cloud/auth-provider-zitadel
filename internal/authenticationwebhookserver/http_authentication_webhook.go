package authenticationwebhookserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewUserDeactivationTokenReviewHandler returns an http.Handler that implements
// the Kubernetes webhook token authentication protocol. See
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication
// for details.
//
// Behaviour:
//  1. The handler decodes the TokenReview object from the request.
//  2. It introspects the provided token with Zutadel.
//  3. If introspection fails, the handler returns `authenticated: false`.
//  4. Otherwise, the handler returns `authenticated: true` and echoes basic
//     user information back to the API server.
func HttpTokenAuthenticationWebhook(introspector *token.Introspector) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := logf.Log.WithName("authentication-webhook").WithValues("remote_addr", r.RemoteAddr, "user_agent", r.UserAgent())

		log.V(1).Info("Received authentication request", "method", r.Method, "path", r.URL.Path)

		// Only POST is allowed as per the TokenReview API semantics.
		if r.Method != http.MethodPost {
			log.Info("Rejected request with invalid method", "method", r.Method)
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Decode the incoming TokenReview request.
		var review authenticationv1.TokenReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			log.Error(err, "Failed to decode TokenReview request")
			http.Error(w, fmt.Sprintf("failed to decode TokenReview: %v", err), http.StatusBadRequest)
			return
		}

		log.V(1).Info("Successfully decoded TokenReview request")

		// Prepare the response object
		resp := authenticationv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TokenReview",
				APIVersion: authenticationv1.SchemeGroupVersion.String(),
			},
			ObjectMeta: review.ObjectMeta,
		}

		// Ensure we always write the response exactly once on exit.
		defer writeJSON(w, &resp)

		// Helper to set a failure on the response and return.
		fail := func(msg string) {
			resp.Status = authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         msg,
			}
		}

		token := review.Spec.Token
		if token == "" {
			// If the token is empty we cannot authenticate the request.
			log.Info("Authentication failed: empty token provided")
			fail("empty token provided")
			return
		}

		log.V(1).Info("Token validation passed, starting introspection")

		// Introspect the token with the auth provider.
		data, err := introspector.Introspect(r.Context(), token)
		if err != nil {
			log.Error(err, "Token introspection failed")
			fail(fmt.Sprintf("token introspection failed: %v", err))
			return
		}

		log.V(1).Info("Token introspection completed successfully")

		// Check the "active" claim returned by the introspection endpoint.
		isJwtTokenActive, ok := data["active"].(bool)
		if !ok {
			log.Info("Authentication failed: active claim not found in introspection response")
			fail("token introspection failed: active claim not found")
			return
		}

		if !isJwtTokenActive {
			// Token is valid but *inactive* (revoked or expired).
			log.Info("Authentication failed: JWT token is not active (revoked or expired)")
			fail("jwt token is not active")
			return
		}

		// At this point the token is active – propagate user information.
		sub, _ := data["sub"].(string)
		var username string

		// Determine the username. If there is no email address,
		// we are in presence of a machine account
		if e, ok := data["email"].(string); ok && e != "" {
			username = e
		} else if u, ok := data["username"].(string); ok && u != "" {
			username = u
		} else {
			// This scenario should not be possible, but we handle it just in case.
			log.Info("Authentication failed: neither email nor username present in token claims")
			fail("token introspection failed: neither email nor username claim found")
			return
		}

		log.Info("Authentication successful", "user_id", sub)

		resp.Status = authenticationv1.TokenReviewStatus{
			Authenticated: isJwtTokenActive,
			User: authenticationv1.UserInfo{
				Username: username,
				UID:      sub,
			},
		}

		log.V(1).Info("Sending successful authentication response", "authenticated", true, "username", sub)
	})
}

// writeJSON is a small helper that writes a response as JSON with the correct
// content-type.
func writeJSON(w http.ResponseWriter, obj any) {
	log := logf.Log.WithName("authentication-webhook")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(obj); err != nil {
		log.Error(err, "Failed to encode JSON response")
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
