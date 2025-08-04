package webhook

import (
	"context"
	"fmt"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	authenticationv1 "k8s.io/api/authentication/v1"
)

type Webhook struct {
	Handler Handler
}

func NewAuthenticationWebhook(introspector *token.Introspector) *Webhook {
	return &Webhook{
		Handler: HandlerFunc(func(ctx context.Context, request Request) Response {
			log := logf.Log.WithName("authentication-webhook").WithValues()

			resp := authenticationv1.TokenReview{
				TypeMeta: metav1.TypeMeta{
					Kind:       "TokenReview",
					APIVersion: authenticationv1.SchemeGroupVersion.String(),
				},
			}

			// Helper to set a failure on the response and return.
			fail := func(msg string) {
				resp.Status = authenticationv1.TokenReviewStatus{
					Authenticated: false,
					Error:         msg,
				}
			}

			token := request.Spec.Token
			if token == "" {
				// If the token is empty we cannot authenticate the request.
				log.Info("Authentication failed: empty token provided")
				fail("empty token provided")
				return Response{TokenReview: resp}
			}

			claims, err := introspector.Introspect(ctx, token)
			if err != nil {
				log.Error(err, "Token introspection failed")
				fail(fmt.Sprintf("token introspection failed: %v", err))
				return Response{TokenReview: resp}
			}

			// Evaluate the "active" claim.
			if !claims.Active {
				// Token is valid syntactically but *inactive* (revoked or expired).
				log.Info("Authentication failed: JWT token is not active (revoked or expired)")
				fail("jwt token is not active")
				return Response{TokenReview: resp}
			}

			// At this point the token is active – determine the username.
			username, err := claims.EffectiveUsername()
			if err != nil {
				log.Info("Authentication failed: " + err.Error())
				fail("token introspection failed: " + err.Error())
				return Response{TokenReview: resp}
			}

			sub := claims.Sub

			resp.Status = authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: username,
					UID:      sub,
				},
			}

			return Response{TokenReview: resp}
		}),
	}
}
