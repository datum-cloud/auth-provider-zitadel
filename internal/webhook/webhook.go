package webhook

import (
	"context"
	"fmt"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Webhook struct {
	Handler  Handler
	Endpoint string
}

func NewAuthenticationWebhookV1(introspector *token.Introspector, kubeClient client.Client) *Webhook {
	return &Webhook{
		Handler: HandlerFunc(func(ctx context.Context, request Request) Response {
			log := logf.Log.WithName("authentication-webhook").WithValues()

			token := request.Spec.Token
			if token == "" {
				// If the token is empty we cannot authenticate the request.
				log.Info("Authentication failed: empty token provided")
				return Denied("empty token provided")
			}

			claims, err := introspector.Introspect(ctx, token)
			if err != nil {
				log.Error(err, "Token introspection failed")
				return Denied(fmt.Sprintf("token introspection failed: %v", err))
			}

			// Evaluate the "active" claim.
			if !claims.Active {
				// Token is valid syntactically but *inactive* (revoked or expired).
				log.Info("Authentication failed: JWT token is not active (revoked or expired)")
				return Denied("jwt token is not active")
			}

			// At this point the token is active – determine the username.
			username, err := claims.EffectiveUsername()
			if err != nil {
				log.Info("Authentication failed: " + err.Error())
				return Denied("token introspection failed: " + err.Error())
			}
			sub := claims.Sub

			// Get User for retrieval of Registration Approval Status
			userObj := &iammiloapiscomv1alpha1.User{}
			if err := kubeClient.Get(ctx, client.ObjectKey{Name: sub}, userObj); err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Authentication failed: user resource not found", "user", sub)
					return Denied("user resource not found")
				}
				log.Error(err, "Failed to fetch User resource", "user", sub)
				return Denied(fmt.Sprintf("failed to fetch user resource: %v", err))
			}

			return Allowed(username, sub, userObj.Status.RegistrationApproval)
		}),
		Endpoint: "/apis/authentication.k8s.io/v1/tokenreviews",
	}
}
