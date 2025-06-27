package zitadel

import (
	"context"
	"net/http"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// AccessTokenType enumerates the allowed values for the accessTokenType field.
type AccessTokenType string

const (
	AccessTokenTypeJWT AccessTokenType = "ACCESS_TOKEN_TYPE_JWT"
)

// MachineUserRequest mirrors the payload of the
// POST /management/v1/users/machine endpoint.
// Only the fields required by the API are present. Optional fields should be
// added as we need them.
type MachineUserRequest struct {
	UserName        string          `json:"userName"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	AccessTokenType AccessTokenType `json:"accessTokenType"`
	UserId          string          `json:"userId"`
}

// MachineUserResponse is a minimal response structure. Extend as needed when
// new response fields are required by callers.
type CreateMachineUserResponse struct {
	UserID  string             `json:"userId"`
	Details MachineUserDetails `json:"details"`
}

// Details contains metadata about the operation that created or modified a resource.
type MachineUserDetails struct {
	Sequence      string `json:"sequence"`
	ChangeDate    string `json:"changeDate"`
	ResourceOwner string `json:"resourceOwner"`
}

// CreateMachineUser creates a new machine user account.
// It wraps the "POST /management/v1/users/machine" REST endpoint.
// See https://zitadel.com/docs/apis/resources/mgmt/management-service-add-machine-user for authoritative docs.
func (c *Client) CreateMachineUser(ctx context.Context, req MachineUserRequest) (*CreateMachineUserResponse, error) {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.Info("Creating machine user", "userName", req.UserName)

	var resp CreateMachineUserResponse
	if err := c.do(ctx, http.MethodPost, "management/v1/users/machine", req, &resp); err != nil {
		log.Error(err, "Failed to create machine user", "userName", req.UserName)
		return nil, err
	}

	log.Info("Successfully created machine user", "userName", req.UserName, "userID", resp.UserID)
	return &resp, nil
}
