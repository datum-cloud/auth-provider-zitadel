package zitadel

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	sessionv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"golang.org/x/oauth2"
	pb "google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
)

type SDKConfig struct {
	// Domain is the ZITADEL gRPC/management host (host only, no scheme or path),
	// e.g. "auth.example.com".
	Domain string
	// Issuer is the full OIDC issuer URL (with scheme), used for discovery/token,
	// e.g. "https://auth.example.com".
	Issuer string
	// KeyPath is the path to the service user JSON key used to mint JWTs.
	KeyPath string
}

type SDKClient struct {
	sess sessionv2.SessionServiceClient
	user userv2.UserServiceClient
}

// NewSDK builds a client bound to the SessionService v2.
// It validates config (including env var fallbacks) and sets up auth via a JWT
// profile token source. The ZITADEL API scope is requested; no "openid" scope is required.
func NewSDK(ctx context.Context, cfg SDKConfig) (*SDKClient, error) {
	// env fallbacks
	if cfg.Domain == "" {
		cfg.Domain = os.Getenv("ZITADEL_API")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = os.Getenv("ZITADEL_ISSUER")
	} // e.g. https://auth.staging.env.datum.net
	if cfg.KeyPath == "" {
		cfg.KeyPath = os.Getenv("ZITADEL_KEY_PATH")
	}

	if cfg.Domain == "" || cfg.Issuer == "" || cfg.KeyPath == "" {
		klog.Error("NewSDK: missing required configuration (Domain, Issuer, or KeyPath)")
		return nil, errors.New("missing ZITADEL domain, issuer, or key path")
	}

	// Normalize/validate: Domain must be host only; Issuer must have scheme.
	host := strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	if host == "" || strings.Contains(host, "/") {
		klog.Errorf("NewSDK: invalid Domain %q; must be host only (e.g. auth.example.com)", cfg.Domain)
		return nil, errors.New("domain must be host only (e.g. auth.example.com)")
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") && !strings.HasPrefix(cfg.Issuer, "http://") {
		klog.Errorf("NewSDK: invalid Issuer %q; must include scheme", cfg.Issuer)
		return nil, errors.New("issuer must include scheme (e.g. https://auth.example.com)")
	}

	klog.V(2).Infof("NewSDK: creating ZITADEL client (host=%q, issuer scheme ok, key path provided)", host)

	conf := zitadel.New(host)

	// Use a JWT profile token source with the ZITADEL API audience scope (no "openid" needed for pure API access).
	cl, err := client.New(ctx, conf,
		client.WithAuth(func(ctx context.Context, _ string) (oauth2.TokenSource, error) {
			// We ignore the SDK-provided issuer and use the explicit cfg.Issuer instead.
			ts, err := profile.NewJWTProfileTokenSourceFromKeyFile(
				ctx,
				cfg.Issuer, // full https://... from config
				cfg.KeyPath,
				[]string{
					client.ScopeZitadelAPI(), // == urn:zitadel:iam:org:project:id:zitadel:aud
					// Alternatively: client.ScopeProjectID("<project-id>") to limit to a specific project.
				},
			)
			if err != nil {
				klog.Errorf("NewSDK: creating JWT profile token source failed: %v", err)
				return nil, err
			}

			// Optional: one-time fetch to surface OAuth errors early.
			if _, err := ts.Token(); err != nil {
				klog.Errorf("NewSDK: initial token retrieval failed: %v", err)
				return nil, err
			}

			klog.V(3).Info("NewSDK: JWT profile token source initialized")
			return oauth2.ReuseTokenSource(nil, ts), nil
		}),
	)
	if err != nil {
		klog.Errorf("NewSDK: client.New failed: %v", err)
		return nil, err
	}

	klog.V(2).Info("NewSDK: SessionServiceV2 and UserServiceV2 clients ready")
	return &SDKClient{
		sess: cl.SessionServiceV2(),
		user: cl.UserServiceV2(),
	}, nil
}

// ListSessions retrieves sessions for a given user using the v2 SessionService.
func (c *SDKClient) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	klog.V(2).Infof("ListSessions: listing sessions for userID=%q", userID)

	resp, err := c.sess.ListSessions(ctx, &sessionv2.ListSessionsRequest{
		Queries: []*sessionv2.SearchQuery{
			{Query: &sessionv2.SearchQuery_UserIdQuery{UserIdQuery: &sessionv2.UserIDQuery{Id: userID}}},
		},
	})
	if err != nil {
		klog.Errorf("ListSessions: API call failed for userID=%q: %v", userID, err)
		return nil, err
	}

	out := make([]Session, 0, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		out = append(out, Session{
			ID:            s.GetId(),
			UserID:        s.GetFactors().GetUser().GetId(),
			IP:            s.GetUserAgent().GetIp(),
			FingerprintID: s.GetUserAgent().GetFingerprintId(),
			CreatedAt:     toTime(s.GetCreationDate()),
			ExpiresAt:     toTimePtr(s.GetExpirationDate()),
		})
	}
	klog.V(2).Infof("ListSessions: found %d session(s) for userID=%q", len(out), userID)
	return out, nil
}

// GetSession fetches a single session by ID.
func (c *SDKClient) GetSession(ctx context.Context, id string) (*Session, error) {
	klog.V(2).Infof("GetSession: fetching session id=%q", id)

	r, err := c.sess.GetSession(ctx, &sessionv2.GetSessionRequest{SessionId: id})
	if err != nil {
		klog.Errorf("GetSession: API call failed for id=%q: %v", id, err)
		return nil, err
	}
	s := r.GetSession()
	res := &Session{
		ID:            s.GetId(),
		UserID:        s.GetFactors().GetUser().GetId(),
		IP:            s.GetUserAgent().GetIp(),
		FingerprintID: s.GetUserAgent().GetFingerprintId(),
		CreatedAt:     toTime(s.GetCreationDate()),
		ExpiresAt:     toTimePtr(s.GetExpirationDate()),
	}
	klog.V(3).Infof("GetSession: session id=%q fetched (user=%q)", res.ID, res.UserID)
	return res, nil
}

// DeleteSession removes a session by ID.
// The second underscore parameter is intentionally unused to keep compatibility
// with a potential wider interface; callers should pass an empty string.
func (c *SDKClient) DeleteSession(ctx context.Context, _ string, id string) error {
	klog.V(2).Infof("DeleteSession: deleting session id=%q", id)

	_, err := c.sess.DeleteSession(ctx, &sessionv2.DeleteSessionRequest{SessionId: id})
	if err != nil {
		klog.Errorf("DeleteSession: API call failed for id=%q: %v", id, err)
		return err
	}
	klog.V(2).Infof("DeleteSession: session id=%q deleted", id)
	return nil
}

// Helpers for timestamp conversion.
// toTime returns zero time when ts is nil.
func toTime(ts *pb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// toTimePtr returns nil when ts is nil; otherwise a pointer to the conversion.
func toTimePtr(ts *pb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// ListIDPLinks retrieves all identity provider links for a given user.
func (c *SDKClient) ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error) {
	klog.V(2).Infof("ListIDPLinks: listing IDP links for userID=%q", userID)

	resp, err := c.user.ListIDPLinks(ctx, &userv2.ListIDPLinksRequest{
		UserId: userID,
	})
	if err != nil {
		klog.Errorf("ListIDPLinks: API call failed for userID=%q: %v", userID, err)
		return nil, err
	}

	out := make([]IDPLink, 0, len(resp.GetResult()))
	for _, link := range resp.GetResult() {
		out = append(out, IDPLink{
			IDPID:       link.GetIdpId(),
			IDPName:     link.GetIdpId(),
			UserID:      link.GetUserId(),
			IDPUserName: link.GetUserName(),
		})
	}
	klog.V(2).Infof("ListIDPLinks: found %d IDP link(s) for userID=%q", len(out), userID)
	return out, nil
}
