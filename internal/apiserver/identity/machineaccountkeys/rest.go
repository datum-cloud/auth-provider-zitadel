package machineaccountkeys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	projctx "go.miloapis.com/milo/pkg/request"
	internalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
)

type REST struct {
	Z                           zitadel.API
	EnableImpersonationFallback bool
}

// getProjectID attempts to find the Project/Org ID first from Milo's request context,
// and falls back to checking Kubernetes Impersonation Extras for local testing via:
// kubectl ... --as admin --as-extra=project=my-org-id
func (r *REST) getProjectID(ctx context.Context) (string, bool) {
	if orgID, ok := projctx.ProjectID(ctx); ok && orgID != "" {
		return orgID, true
	}

	// This check is only added as a safety measure, as this rest
	// should only be reachable from the ProjectRouter, which sets the project ID in the context.
	// This is used for local testing when running the apiserver outside of the ProjectRouter.
	if r.EnableImpersonationFallback {
		if userInfo, ok := request.UserFrom(ctx); ok {
			if projects, ok := userInfo.GetExtra()["project"]; ok && len(projects) > 0 {
				klog.V(4).InfoS("Found project ID from impersonation extras (local testing fallback)", "orgID", projects[0])
				return projects[0], true
			}
		}
	}

	return "", false
}

var _ rest.Creater = &REST{} //nolint:misspell
var _ rest.Getter = &REST{}
var _ rest.Lister = &REST{}
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

var machineAccountKeysGR = schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "machineaccountkeys"}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.MachineAccountKey{} }
func (r *REST) NewList() runtime.Object { return &milov1alpha1.MachineAccountKeyList{} }
func (r *REST) GetSingularName() string { return "machineaccountkey" }

// Create handles POST requests to register a machine account key in Zitadel.
// The MachineAccountKey object contains:
// - spec.machineAccountName: the machine account username (required)
// - spec.publicKey: the public key in PEM format (optional - Zitadel generates if not provided)
// - spec.expirationDate: optional expiration date (Zitadel uses default if not provided)
//
// The organization ID is extracted from the request context (set by ProjectRouter).
// The machine account user ID is looked up from Zitadel using the machine account name.
//
// Returns the MachineAccountKey with:
// - status.authProviderKeyID: the key ID from Zitadel
// - status.privateKey: the generated or provided key content/payload from Zitadel
func (r *REST) Create(
	ctx context.Context,
	obj runtime.Object,
	_ rest.ValidateObjectFunc,
	_ *metav1.CreateOptions,
) (runtime.Object, error) {
	klog.V(2).Infof("======loco3=======")

	mak, ok := obj.(*milov1alpha1.MachineAccountKey)
	if !ok {
		klog.ErrorS(nil, "Unexpected object type in Create", "type", obj)
		return nil, apierrors.NewBadRequest("invalid object type")
	}

	// Validate required fields
	if mak.Spec.MachineAccountName == "" {
		klog.ErrorS(nil, "Missing required field: machineAccountName")
		return nil, apierrors.NewBadRequest("machineAccountName is required")
	}

	// Extract organization ID from request context (set by ProjectRouter or Impersonation)
	orgID, ok := r.getProjectID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context or impersonation extras")
		return nil, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	// Look up the machine account user by username in the organization
	user, err := r.Z.GetMachineUserByUsername(ctx, orgID, mak.Spec.MachineAccountName)
	if err != nil {
		klog.ErrorS(err, "Failed to look up machine account user", "orgID", orgID, "username", mak.Spec.MachineAccountName)
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to look up machine account"))
	}

	if user == nil {
		klog.InfoS("Machine account user not found", "orgID", orgID, "username", mak.Spec.MachineAccountName)
		return nil, apierrors.NewNotFound(machineAccountKeysGR, mak.Name)
	}

	userID := user.ID

	// Convert public key to bytes (optional - Zitadel will generate if not provided)
	var publicKeyBytes []byte
	if mak.Spec.PublicKey != "" {
		publicKeyBytes = []byte(mak.Spec.PublicKey)
		// Validate public key format and content only if provided
		if err := validatePublicKey(publicKeyBytes); err != nil {
			klog.ErrorS(err, "Invalid public key", "orgID", orgID, "username", mak.Spec.MachineAccountName)
			return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid public key: %v", err))
		}
	} else {
		klog.V(2).Infof("No public key provided, Zitadel will generate one for machine account: %s", mak.Spec.MachineAccountName)
	}

	// Validate expiration date if provided (optional - Zitadel uses default if not provided)
	var expirationDate *time.Time
	if mak.Spec.ExpirationDate != nil {
		expirationDate = &mak.Spec.ExpirationDate.Time
		if expirationDate.Before(time.Now()) {
			klog.ErrorS(nil, "Expiration date is in the past", "orgID", orgID, "username", mak.Spec.MachineAccountName)
			return nil, apierrors.NewBadRequest("expiration date must be in the future")
		}
	} else {
		klog.V(2).Infof("No expiration date provided, Zitadel will use default for machine account: %s", mak.Spec.MachineAccountName)
	}

	// Register the key in Zitadel
	// If publicKey is empty, Zitadel will generate one and return it
	// If expirationDate is nil, Zitadel_sdk will use its default
	keyID, keyContent, err := r.Z.AddMachineKeyInOrganization(ctx, orgID, userID, publicKeyBytes, expirationDate)
	if err != nil {
		klog.ErrorS(err, "Failed to add machine key in Zitadel", "orgID", orgID, "userID", userID)
		return nil, translateErr(err, mak.Name)
	}

	// Populate the status with the returned key ID and key content
	mak.Status.AuthProviderKeyID = keyID
	mak.Status.PrivateKey = string(keyContent)

	klog.V(2).Infof("Machine account key created successfully: keyID=%s, machineAccount=%s, org=%s", keyID, mak.Spec.MachineAccountName, orgID)

	return mak, nil
}

// validatePublicKey validates that the public key is in valid PEM format
// and contains a valid RSA or ECDSA public key.
func validatePublicKey(publicKeyPEM []byte) error {
	if len(publicKeyPEM) == 0 {
		return fmt.Errorf("public key is empty")
	}

	// Decode PEM block
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("public key is not in valid PEM format")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Validate it's an RSA or ECDSA key
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public key type: expected RSA or ECDSA, got %T", pubKey)
	}
}

// translateErr converts gRPC errors to Kubernetes API errors.
func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(machineAccountKeysGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(machineAccountKeysGR, name, nil)
		case codes.Unauthenticated:
			return apierrors.NewUnauthorized("unauthenticated")
		case codes.InvalidArgument:
			return apierrors.NewBadRequest(st.Message())
		case codes.DeadlineExceeded, codes.Unavailable:
			return apierrors.NewServiceUnavailable("zitadel unavailable")
		default:
			return apierrors.NewInternalError(err)
		}
	}
	return err
}

// List handles GET requests to list machine account keys in an organization.
// The organization ID is extracted from the request context (set by ProjectRouter).
// Supports fieldSelector=spec.machineAccountName=<name> to filter keys for a specific machine account.
//
// Note: This is a proxy endpoint that queries Zitadel for keys.
// Keys are not stored as CRD objects; they exist only in Zitadel.
func (r *REST) List(
	ctx context.Context,
	options *internalversion.ListOptions,
) (runtime.Object, error) {
	orgID, ok := r.getProjectID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context")
		return nil, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	// Parse fieldSelector to extract optional machineAccountName filter
	var machineAccountName string

	// Get machine account name from field selector
	// kubectl usage: kubectl get machineaccountkeys --field-selector spec.machineAccountName=<name>
	if options != nil && options.FieldSelector != nil && !options.FieldSelector.Empty() {
		if val, found := options.FieldSelector.RequiresExactMatch("spec.machineAccountName"); found {
			machineAccountName = val
			klog.V(2).Infof("Got machineAccountName from fieldSelector: %q", machineAccountName)
		}
	}

	list := &milov1alpha1.MachineAccountKeyList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0",
		},
		Items: []milov1alpha1.MachineAccountKey{},
	}

	// If machineAccountName filter is provided, list keys for that specific account
	if machineAccountName != "" {
		klog.V(2).Infof("Listing machine account keys for org=%q, machineAccount=%q", orgID, machineAccountName)

		// Look up the machine account user
		user, err := r.Z.GetMachineUserByUsername(ctx, orgID, machineAccountName)
		if err != nil {
			klog.ErrorS(err, "Failed to look up machine account user", "orgID", orgID, "machineAccountName", machineAccountName)
			return nil, apierrors.NewInternalError(fmt.Errorf("failed to look up machine account"))
		}

		if user == nil {
			// User not found - return error so user knows the machine account doesn't exist
			klog.InfoS("Machine account user not found", "orgID", orgID, "machineAccountName", machineAccountName)
			return nil, apierrors.NewNotFound(
				schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "machineaccounts"},
				machineAccountName,
			)
		}

		// List keys for this user from Zitadel
		machineKeys, err := r.Z.ListMachineKeysInOrganization(ctx, orgID, user.ID)
		if err != nil {
			klog.ErrorS(err, "Failed to list machine account keys", "orgID", orgID, "userID", user.ID)
			return nil, apierrors.NewInternalError(fmt.Errorf("failed to list machine account keys"))
		}

		// Convert MachineKey objects to MachineAccountKey objects
		for _, mk := range machineKeys {
			item := milov1alpha1.MachineAccountKey{
				ObjectMeta: metav1.ObjectMeta{
					Name: machineAccountName + ":" + mk.ID,
					// Set creation timestamp from the key's creation date
					CreationTimestamp: metav1.NewTime(mk.CreatedDate),
				},
				Spec: milov1alpha1.MachineAccountKeySpec{
					MachineAccountName: machineAccountName,
					// Include optional fields if they exist
					ExpirationDate: nil,
				},
				Status: milov1alpha1.MachineAccountKeyStatus{
					AuthProviderKeyID: mk.ID,
				},
			}
			// Add expiration date to spec if it exists
			if mk.ExpirationDate != nil {
				item.Spec.ExpirationDate = &metav1.Time{Time: *mk.ExpirationDate}
			}
			list.Items = append(list.Items, item)
		}

		klog.V(2).Infof("Listed %d machine account keys for org=%q, machineAccount=%q", len(machineKeys), orgID, machineAccountName)
		return list, nil
	}

	// If no machineAccountName filter, return empty list
	// (listing all keys across all users would be expensive and requires listing all users first)
	klog.V(2).Infof("Listing machine account keys for org=%q (no machineAccountName filter, returning empty list)", orgID)
	return list, nil
}

// Get handles GET requests to retrieve a specific machine account key.
// The name format is "{machineAccountName}:{keyID}".
// This method is currently a no-op since keys are not persistently stored as objects.
// Use List with fieldSelector to get keys for a specific machine account instead.
func (r *REST) Get(
	ctx context.Context,
	name string,
	options *metav1.GetOptions,
) (runtime.Object, error) {
	// Keys are proxied through to Zitadel and not stored as persistent objects.
	// To retrieve keys, use List with fieldSelector=spec.machineAccountName=<account>
	klog.ErrorS(nil, "Get is not supported for machineaccountkeys; use List with fieldSelector instead", "name", name)
	return nil, apierrors.NewNotFound(machineAccountKeysGR, name)
}

// ConvertToTable converts the object to a table for kubectl display.
func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name"},
			{Name: "Machine Account", Type: "string"},
			{Name: "Key ID", Type: "string"},
			{Name: "Created", Type: "string"},
			{Name: "Expires", Type: "string"},
		},
	}

	if list, ok := obj.(*milov1alpha1.MachineAccountKeyList); ok {
		for _, item := range list.Items {
			expiresStr := "<none>"
			if item.Spec.ExpirationDate != nil {
				expiresStr = item.Spec.ExpirationDate.String()
			}
			table.Rows = append(table.Rows, metav1.TableRow{
				Cells: []interface{}{
					item.Name,
					item.Spec.MachineAccountName,
					item.Status.AuthProviderKeyID,
					item.CreationTimestamp.String(),
					expiresStr,
				},
				Object: runtime.RawExtension{Object: &item},
			})
		}
		return table, nil
	}

	if mak, ok := obj.(*milov1alpha1.MachineAccountKey); ok {
		expiresStr := "<none>"
		if mak.Spec.ExpirationDate != nil {
			expiresStr = mak.Spec.ExpirationDate.String()
		}
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				mak.Name,
				mak.Spec.MachineAccountName,
				mak.Status.AuthProviderKeyID,
				mak.CreationTimestamp.String(),
				expiresStr,
			},
			Object: runtime.RawExtension{Object: mak},
		})
		return table, nil
	}

	return table, nil
}

// Delete handles DELETE requests to remove a machine account key from Zitadel.
// The resource name should be in format: "{machineAccountName}:{keyID}"
// Example: "my-service-account:326102453042806786"
//
// The organization ID is extracted from the request context.
func (r *REST) Delete(
	ctx context.Context,
	name string,
	deleteValidation rest.ValidateObjectFunc,
	options *metav1.DeleteOptions,
) (runtime.Object, bool, error) {
	orgID, ok := r.getProjectID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context")
		return nil, false, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	// Parse name format: "{machineAccountName}:{keyID}"
	// Using ":" as separator to avoid RBAC sub-resource issues (which "/" causes)
	parts := strings.Split(name, ":")
	if len(parts) != 2 {
		klog.ErrorS(nil, "Invalid resource name format", "name", name)
		return nil, false, apierrors.NewBadRequest("resource name must be in format: {machineAccountName}:{keyID}")
	}

	machineAccountName := parts[0]
	keyID := parts[1]

	klog.InfoS("Deleting machine account key from Zitadel", "keyID", keyID, "machineAccount", machineAccountName, "orgID", orgID)

	klog.InfoS("Deleting machine account key from Zitadel", "keyID", keyID, "machineAccount", machineAccountName, "orgID", orgID)

	// Look up the machine account user by name
	user, err := r.Z.GetMachineUserByUsername(ctx, orgID, machineAccountName)
	if err != nil {
		klog.ErrorS(err, "Failed to look up machine account user", "orgID", orgID, "machineAccountName", machineAccountName)
		return nil, false, apierrors.NewInternalError(fmt.Errorf("failed to look up machine account"))
	}

	if user == nil {
		klog.InfoS("Machine account user not found", "orgID", orgID, "machineAccountName", machineAccountName)
		return nil, false, apierrors.NewNotFound(machineAccountKeysGR, name)
	}

	// Remove the key from Zitadel
	err = r.Z.RemoveMachineKeyInOrganization(ctx, orgID, user.ID, keyID)
	if err != nil {
		klog.ErrorS(err, "Failed to remove machine key from Zitadel", "orgID", orgID, "userID", user.ID, "keyID", keyID)
		return nil, false, translateErr(err, name)
	}

	klog.V(2).Infof("Machine account key deleted successfully: keyID=%s, machineAccount=%s, org=%s", keyID, machineAccountName, orgID)

	// Return the deleted object (empty in this case as it's proxy-managed)
	return &milov1alpha1.MachineAccountKey{}, true, nil
}

// Destroy satisfies rest.Storage.
func (r *REST) Destroy() {}
