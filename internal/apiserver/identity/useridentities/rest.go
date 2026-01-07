package useridentities

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
var _ rest.TableConvertor = &REST{}
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

var userIdentitiesGR = schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "useridentities"}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.UserIdentity{} }
func (r *REST) NewList() runtime.Object { return &milov1alpha1.UserIdentityList{} }
func (r *REST) GetSingularName() string { return "useridentity" }

func (r *REST) List(ctx context.Context, _ *metainternal.ListOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for List")
		return nil, apierrors.NewUnauthorized("no user in context")
	}
	uid := u.GetUID()
	klog.V(2).InfoS("Listing identity providers for user", "uid", uid)

	idpLinks, err := r.Z.ListIDPLinks(ctx, uid)
	if err != nil {
		klog.ErrorS(err, "Failed to list identity provider links", "uid", uid)
		return nil, translateErr(err, "")
	}

	out := &milov1alpha1.UserIdentityList{
		TypeMeta: metav1.TypeMeta{Kind: "UserIdentityList", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
	}

	for _, link := range idpLinks {
		out.Items = append(out.Items, milov1alpha1.UserIdentity{
			TypeMeta: metav1.TypeMeta{Kind: "UserIdentity", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
			ObjectMeta: metav1.ObjectMeta{
				Name:              link.IDPID,
				CreationTimestamp: metav1.Now(),
			},
			Status: milov1alpha1.UserIdentityStatus{
				UserUID:      uid,
				ProviderID:   link.IDPID,
				ProviderName: link.IDPName,
				Username:     link.IDPUserName,
			},
		})
	}
	klog.V(3).InfoS("Listed identity providers", "uid", uid, "count", len(out.Items))
	return out, nil
}

func (r *REST) Get(ctx context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for Get", "name", name)
		return nil, apierrors.NewUnauthorized("no user in context")
	}
	uid := u.GetUID()
	klog.V(2).InfoS("Getting identity provider", "name", name, "requestor", uid)

	idpLinks, err := r.Z.ListIDPLinks(ctx, uid)
	if err != nil {
		klog.ErrorS(err, "Failed to list identity provider links", "uid", uid)
		return nil, translateErr(err, name)
	}

	for _, link := range idpLinks {
		if link.IDPID == name {
			klog.V(3).InfoS("Found identity provider", "name", name, "uid", uid)
			return &milov1alpha1.UserIdentity{
				TypeMeta:   metav1.TypeMeta{Kind: "UserIdentity", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
				ObjectMeta: metav1.ObjectMeta{Name: link.IDPID},
				Status: milov1alpha1.UserIdentityStatus{
					UserUID:      uid,
					ProviderID:   link.IDPID,
					ProviderName: link.IDPName,
					Username:     link.IDPUserName,
				},
			}, nil
		}
	}

	klog.V(1).InfoS("Identity provider not found", "name", name, "uid", uid)
	return nil, apierrors.NewNotFound(userIdentitiesGR, name)
}

func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(userIdentitiesGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(userIdentitiesGR, name, nil)
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

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(userIdentitiesGR).ConvertToTable(ctx, obj, tableOptions)
}

func (r *REST) Destroy() {}
