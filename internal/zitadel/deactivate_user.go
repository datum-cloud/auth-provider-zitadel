package zitadel

import (
	"context"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// DeactivateUserRequest represents the request body for deactivating a user.
// Currently empty as per the API specification.
type DeactivateUserRequest struct{}

// DeactivateUser deactivates a user in ZITADEL.
// It sends a POST request to /v2/users/:userId/deactivate.
// See https://zitadel.com/docs/apis/resources/mgmt/management-service-deactivate-user for authoritative docs.
func (c *Client) DeactivateUser(ctx context.Context, userID string) error {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Deactivating user", "userID", userID)
	path := "v2/users/" + userID + "/deactivate"

	err := c.do(ctx, "POST", path, &DeactivateUserRequest{}, nil)
	if err != nil {
		log.Error(err, "Failed to deactivate user", "userID", userID)
		return err
	}

	log.Info("Successfully deactivated user", "userID", userID)
	return nil
}
