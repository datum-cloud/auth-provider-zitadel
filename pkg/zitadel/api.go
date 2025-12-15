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

// API is the minimal surface needed by our storage to serve sessions.
type API interface {
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
}
