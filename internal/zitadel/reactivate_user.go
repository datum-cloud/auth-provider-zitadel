package zitadel

import (
	"context"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ReactivateUserRequest represents the request body for reactivating a user.
// Currently empty as per the API specification.
type ReactivateUserRequest struct{}

// ReactivateUser reactivates a user in ZITADEL.
// It sends a POST request to /v2/users/:userId/reactivate.
// See https://zitadel.com/docs/apis/resources/mgmt/management-service-reactivate-user for authoritative docs.
func (c *Client) ReactivateUser(ctx context.Context, userID string) error {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Reactivating user", "userID", userID)
	path := "v2/users/" + userID + "/reactivate"

	err := c.do(ctx, "POST", path, &ReactivateUserRequest{}, nil)
	if err != nil {
		log.Error(err, "Failed to reactivate user", "userID", userID)
		return err
	}

	log.Info("Successfully reactivated user", "userID", userID)
	return nil
}
