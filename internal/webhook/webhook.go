package webhook

import (
	"context"
	"fmt"

	internalzitadel "go.miloapis.com/auth-provider-zitadel/internal/zitadel"
	"go.miloapis.com/auth-provider-zitadel/pkg/token"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Webhook struct {
	Handler  Handler
	Endpoint string
}

type zitadelUserGetter interface {
	GetUser(ctx context.Context, userID string) (*internalzitadel.GetUserResponse, error)
}

func NewAuthenticationWebhookV1(introspector *token.Introspector, kubeClient client.Client, zitadelClient zitadelUserGetter) *Webhook {
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
			userObj, err := getOrRecoverUser(ctx, kubeClient, zitadelClient, sub)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Info("Authentication failed: user resource not found", "user", sub)
					return Denied("user resource not found")
				}
				log.Error(err, "Failed to get or recover User resource", "user", sub)
				return Denied(fmt.Sprintf("failed to recover user resource: %v", err))
			}

			return Allowed(username, sub, registrationApprovalOrPending(userObj))
		}),
		Endpoint: "/apis/authentication.k8s.io/v1/tokenreviews",
	}
}

func getOrRecoverUser(ctx context.Context, kubeClient client.Client, zitadelClient zitadelUserGetter, userID string) (*iammiloapiscomv1alpha1.User, error) {
	userObj := &iammiloapiscomv1alpha1.User{}
	if err := kubeClient.Get(ctx, client.ObjectKey{Name: userID}, userObj); err == nil {
		return userObj, nil
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("fetch user resource: %w", err)
	}

	if zitadelClient == nil {
		return nil, apierrors.NewNotFound(iammiloapiscomv1alpha1.SchemeGroupVersion.WithResource("users").GroupResource(), userID)
	}

	return recoverUserFromZitadel(ctx, kubeClient, zitadelClient, userID)
}

func recoverUserFromZitadel(ctx context.Context, kubeClient client.Client, zitadelClient zitadelUserGetter, userID string) (*iammiloapiscomv1alpha1.User, error) {
	log := logf.FromContext(ctx).WithName("authentication-webhook").WithValues("user", userID)

	resp, err := zitadelClient.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.User.Human == nil {
		return nil, fmt.Errorf("zitadel user is not a human user")
	}

	email := ""
	if resp.User.Human.Email != nil {
		email = resp.User.Human.Email.Email
	}
	if email == "" {
		return nil, fmt.Errorf("zitadel human user is missing email")
	}

	user := &iammiloapiscomv1alpha1.User{
		TypeMeta: metav1.TypeMeta{
			Kind:       "User",
			APIVersion: "iam.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: userID,
		},
		Spec: iammiloapiscomv1alpha1.UserSpec{
			Email: email,
		},
	}
	if resp.User.Human.Profile != nil {
		user.Spec.GivenName = resp.User.Human.Profile.GivenName
		user.Spec.FamilyName = resp.User.Human.Profile.FamilyName
	}

	if err := kubeClient.Create(ctx, user); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Info("User resource was created concurrently during recovery")
			existing := &iammiloapiscomv1alpha1.User{}
			if getErr := kubeClient.Get(ctx, client.ObjectKey{Name: userID}, existing); getErr != nil {
				return nil, fmt.Errorf("fetch concurrently created user resource: %w", getErr)
			}
			return existing, nil
		}
		return nil, fmt.Errorf("create user resource: %w", err)
	}

	log.Info("Recovered missing user resource from Zitadel")
	return user, nil
}

func registrationApprovalOrPending(user *iammiloapiscomv1alpha1.User) iammiloapiscomv1alpha1.RegistrationApprovalState {
	if user.Status.RegistrationApproval == "" {
		return iammiloapiscomv1alpha1.RegistrationApprovalStatePending
	}

	return user.Status.RegistrationApproval
}
