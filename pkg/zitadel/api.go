package zitadel

import (
	"context"
	"time"
)

// OrgIDForProject returns the Zitadel organization ID for a given project name.
// The "project-" prefix ensures the controller's org does not collide with
// infrastructure-managed organizations that use the bare project name.
func OrgIDForProject(projectName string) string {
	return "project-" + projectName
}

// Session represents a Zitadel session distilled for Kubernetes exposure.
type Session struct {
	ID            string
	UserID        string
	IP            string
	FingerprintID string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
}

// IDPLink represents an identity provider link for a user.
type IDPLink struct {
	IDPID       string
	IDPName     string
	UserID      string
	IDPUserName string
}

// User represents a Zitadel user with minimal fields.
type User struct {
	ID       string
	Username string
	Email    string
	State    string // e.g. "ACTIVE", "INACTIVE"
}

// Organization represents a Zitadel organization.
type Organization struct {
	ID   string
	Name string
}

// MachineKey represents a machine account key with complete information.
type MachineKey struct {
	ID             string     // Key ID
	CreatedDate    time.Time  // When the key was created
	ExpirationDate *time.Time // When the key expires (nil if no expiration)
}

// API is the minimal surface needed by our storage and controllers.
type API interface {
	// session management
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
	ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error)

	// organization management
	CreateOrganization(ctx context.Context, name string) (orgID string, err error)
	CreateOrganizationWithID(ctx context.Context, name, customOrgID string) (orgID string, err error)
	DeleteOrganization(ctx context.Context, orgID string) error
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)

	// user management
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetMachineUserByUsername(ctx context.Context, orgID, username string) (*User, error)
	AddMachineUserInOrganization(ctx context.Context, orgID, userID, username, displayName string) (createdUserID string, err error)
	DeleteUser(ctx context.Context, userID string) error
	DeactivateUser(ctx context.Context, orgID, userID string) error
	ReactivateUser(ctx context.Context, orgID, userID string) error

	// machine accounts and keys in organization
	ListMachineAccountsInOrganization(ctx context.Context, orgID string) ([]*User, error)
	AddMachineKeyInOrganization(ctx context.Context, orgID, userID string, publicKey []byte, expirationDate *time.Time) (keyID string, keyContent []byte, err error)
	ListMachineKeysInOrganization(ctx context.Context, orgID, userID string) ([]*MachineKey, error)
	RemoveMachineKeyInOrganization(ctx context.Context, orgID, userID, keyID string) error
}
