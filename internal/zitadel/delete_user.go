package zitadel

import (
	"context"
	"fmt"
	"net/http"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// DeleteUser deletes a user by user ID.
// It wraps the "DELETE /v2/users/:userId" REST endpoint.
// See https://zitadel.com/docs/apis/resources/user_service_v2/user-service-delete-user for authoritative docs.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Deleting user", "userID", userID)

	path := fmt.Sprintf("v2/users/%s", userID)
	if err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		log.Error(err, "Failed to delete user", "userID", userID)
		return err
	}

	log.Info("Successfully deleted user", "userID", userID)
	return nil
}
