package sessions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

type REST struct{ Z zitadel.API }

var _ rest.Scoper = &REST{}
var _ rest.Lister = &REST{}
var _ rest.Getter = &REST{}
var _ rest.GracefulDeleter = &REST{}
var _ rest.TableConvertor = &REST{}
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

var sessionsGR = schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "sessions"}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.Session{} }
func (r *REST) NewList() runtime.Object { return &milov1alpha1.SessionList{} }
func (r *REST) GetSingularName() string { return "session" }

func (r *REST) List(ctx context.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for List")
		return nil, apierrors.NewUnauthorized("no user in context")
	}

	// Extract target userUID from field selector if present
	// This allows staff users to query other users' sessions
	var uid string
	if options != nil && options.FieldSelector != nil {
		if targetUID, err := extractUserUIDFromFieldSelector(options.FieldSelector); err == nil && targetUID != "" {
			// Field selector specifies a target user
			// Check if the user is authorized to query other users' data
			if targetUID != u.GetUID() {
				// User is trying to query another user's sessions
				// Only staff/admin users are allowed to do this
				if !isStaffUser(u) {
					klog.V(2).InfoS("Unauthorized: non-staff user attempting to query other user's sessions",
						"requestor", u.GetUID(), "targetUID", targetUID, "groups", u.GetGroups())
					return nil, apierrors.NewForbidden(
						sessionsGR,
						"",
						fmt.Errorf("only staff users can query other users' sessions"))
				}
				klog.V(2).InfoS("Staff user querying other user's sessions",
					"requestor", u.GetUID(), "targetUID", targetUID, "groups", u.GetGroups())
			}
			uid = targetUID
		} else {
			// No valid userUID in field selector, use authenticated user's UID
			uid = u.GetUID()
			klog.V(2).InfoS("Listing sessions for authenticated user", "uid", uid)
		}
	} else {
		// No field selector, use authenticated user's UID (default behavior)
		uid = u.GetUID()
		klog.V(2).InfoS("Listing sessions for authenticated user", "uid", uid)
	}
	zs, err := r.Z.ListSessions(ctx, uid)
	if err != nil {
		klog.ErrorS(err, "Failed to list sessions", "uid", uid)
		return nil, translateErr(err, "")
	}

	out := &milov1alpha1.SessionList{
		TypeMeta: metav1.TypeMeta{Kind: "SessionList", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
	}
	now := time.Now()
	for _, s := range zs {
		out.Items = append(out.Items, milov1alpha1.Session{
			TypeMeta: metav1.TypeMeta{Kind: "Session", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
			ObjectMeta: metav1.ObjectMeta{
				Name:              s.ID,
				CreationTimestamp: metav1.NewTime(now),
			},
			Status: milov1alpha1.SessionStatus{
				UserUID:       uid,
				Provider:      "zitadel",
				IP:            s.IP,
				FingerprintID: s.FingerprintID,
				CreatedAt:     metav1.NewTime(s.CreatedAt),
				ExpiresAt:     toPtrTime(s.ExpiresAt),
			},
		})
	}
	klog.V(3).InfoS("Listed sessions", "uid", uid, "count", len(out.Items))
	return out, nil
}

func (r *REST) Get(ctx context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for Get", "name", name)
		return nil, apierrors.NewUnauthorized("no user in context")
	}
	uid := u.GetUID()
	klog.V(2).InfoS("Getting session", "name", name, "requestor", uid)
	s, err := r.Z.GetSession(ctx, name)
	if err != nil {
		klog.ErrorS(err, "Failed to get session", "name", name)
		return nil, translateErr(err, name)
	}
	if s.UserID != uid {
		klog.V(1).InfoS("Forbidden: session not owned by user", "name", name, "owner", s.UserID, "requestor", uid)
		return nil, apierrors.NewForbidden(sessionsGR, name, errors.New("not owner"))
	}
	klog.V(3).InfoS("Got session", "name", name, "owner", s.UserID)
	return &milov1alpha1.Session{
		TypeMeta:   metav1.TypeMeta{Kind: "Session", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{Name: s.ID},
		Status: milov1alpha1.SessionStatus{
			UserUID:       s.UserID,
			Provider:      "zitadel",
			IP:            s.IP,
			FingerprintID: s.FingerprintID,
			CreatedAt:     metav1.NewTime(s.CreatedAt),
			ExpiresAt:     toPtrTime(s.ExpiresAt),
		},
	}, nil
}

func (r *REST) Delete(ctx context.Context, name string, _ rest.ValidateObjectFunc, _ *metav1.DeleteOptions) (runtime.Object, bool, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for Delete", "name", name)
		return nil, false, apierrors.NewUnauthorized("no user in context")
	}
	klog.V(2).InfoS("Deleting session", "name", name, "requestor", u.GetUID())
	if err := r.Z.DeleteSession(ctx, u.GetUID(), name); err != nil {
		klog.ErrorS(err, "Failed to delete session", "name", name)
		return nil, false, translateErr(err, name)
	}
	klog.V(1).InfoS("Deleted session", "name", name)
	return &metav1.Status{Status: metav1.StatusSuccess, Code: http.StatusOK}, true, nil
}

func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(sessionsGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(sessionsGR, name, nil)
		case codes.Unauthenticated:
			return apierrors.NewUnauthorized("unauthenticated")
		case codes.DeadlineExceeded, codes.Unavailable:
			return apierrors.NewServiceUnavailable("zitadel unavailable")
		default:
			return apierrors.NewInternalError(err)
		}
	}
	return err
}

func toPtrTime(t *time.Time) *metav1.Time {
	if t == nil {
		return nil
	}
	mt := metav1.NewTime(*t)
	return &mt
}

// ConvertToTable enables kubectl table output using the default convertor.
func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(sessionsGR).ConvertToTable(ctx, obj, tableOptions)
}

// Destroy satisfies rest.Storage.
func (r *REST) Destroy() {}

// extractUserUIDFromFieldSelector extracts the userUID value from a field selector.
// Supports field selector syntax: "status.userUID=<uid>" or "userUID=<uid>"
func extractUserUIDFromFieldSelector(selector fields.Selector) (string, error) {
	if selector == nil || selector.Empty() {
		return "", fmt.Errorf("empty field selector")
	}

	// Try to match "status.userUID=<value>"
	if req, found := selector.RequiresExactMatch("status.userUID"); found {
		return req, nil
	}

	// Try to match "userUID=<value>" (alternative syntax)
	if req, found := selector.RequiresExactMatch("userUID"); found {
		return req, nil
	}

	return "", fmt.Errorf("userUID not found in field selector")
}

// isStaffUser checks if the authenticated user has staff/admin privileges.
// Staff users are identified by membership in specific groups.
func isStaffUser(u user.Info) bool {
	if u == nil {
		return false
	}

	groups := u.GetGroups()
	for _, group := range groups {
		// Check for staff/admin group membership
		// Common patterns: system:masters, staff, admin, etc.
		switch group {
		case "system:masters", "staff", "admin", "datum:staff":
			return true
		}
	}

	return false
}
