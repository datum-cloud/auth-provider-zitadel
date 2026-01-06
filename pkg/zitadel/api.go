package zitadel

import (
	"context"
	"time"
)

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

// API is the minimal surface needed by our storage to serve sessions and identity providers.
type API interface {
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
	ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error)
}
