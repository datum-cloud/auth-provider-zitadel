package serviceaccountkeys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	internalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
)

type REST struct {
	Z                           zitadel.API
	EnableImpersonationFallback bool
	// IntrospectionProjectID is the Zitadel project ID the authn webhook's
	// introspection client is a member of. When set, generated service
	// account credentials include an audience scope for this project so
	// their tokens can be introspected. When empty, no scope field is
	// emitted (caller-supplied keys or older deployments).
	IntrospectionProjectID string
}

// getOrgID resolves the Zitadel organization ID from the request context.
func (r *REST) getOrgID(ctx context.Context) (string, bool) {
	var projectName string

	if userInfo, ok := request.UserFrom(ctx); ok {
		extras := userInfo.GetExtra()
		if kinds := extras["iam.miloapis.com/parent-type"]; len(kinds) > 0 && kinds[0] == "Project" {
			if names := extras["iam.miloapis.com/parent-name"]; len(names) > 0 && names[0] != "" {
				projectName = names[0]
			}
		}

		if projectName == "" && r.EnableImpersonationFallback {
			if projects := extras["project"]; len(projects) > 0 && projects[0] != "" {
				klog.V(4).InfoS("Found project name from impersonation extras (local testing fallback)", "projectName", projects[0])
				projectName = projects[0]
			}
		}
	}

	if projectName == "" {
		return "", false
	}

	return zitadel.OrgIDForProject(projectName), true
}

var _ rest.Creater = &REST{} //nolint:misspell
var _ rest.Getter = &REST{}
var _ rest.Lister = &REST{}
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

var serviceAccountKeysGR = schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "serviceaccountkeys"}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.ServiceAccountKey{} }
func (r *REST) NewList() runtime.Object { return &milov1alpha1.ServiceAccountKeyList{} }
func (r *REST) GetSingularName() string { return "serviceaccountkey" }

// Create handles POST requests to register a service account key in Zitadel.
func (r *REST) Create(
	ctx context.Context,
	obj runtime.Object,
	_ rest.ValidateObjectFunc,
	_ *metav1.CreateOptions,
) (runtime.Object, error) {
	sak, ok := obj.(*milov1alpha1.ServiceAccountKey)
	if !ok {
		klog.ErrorS(nil, "Unexpected object type in Create", "type", obj)
		return nil, apierrors.NewBadRequest("invalid object type")
	}

	if sak.Spec.ServiceAccountUserName == "" {
		klog.ErrorS(nil, "Missing required field: serviceAccountUserName")
		return nil, apierrors.NewBadRequest("serviceAccountUserName is required")
	}

	orgID, ok := r.getOrgID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context or impersonation extras")
		return nil, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	user, err := r.Z.GetMachineUserByUsername(ctx, orgID, sak.Spec.ServiceAccountUserName)
	if err != nil {
		klog.ErrorS(err, "Failed to look up service account user", "orgID", orgID, "username", sak.Spec.ServiceAccountUserName)
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to look up service account"))
	}

	if user == nil {
		klog.InfoS("Service account user not found", "orgID", orgID, "username", sak.Spec.ServiceAccountUserName)
		return nil, apierrors.NewNotFound(serviceAccountKeysGR, sak.Name)
	}

	userID := user.ID

	var publicKeyBytes []byte
	if sak.Spec.PublicKey != "" {
		publicKeyBytes = []byte(sak.Spec.PublicKey)
		if err := validatePublicKey(publicKeyBytes); err != nil {
			klog.ErrorS(err, "Invalid public key", "orgID", orgID, "username", sak.Spec.ServiceAccountUserName)
			return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid public key: %v", err))
		}
	} else {
		klog.V(2).Infof("No public key provided, Zitadel will generate one for service account: %s", sak.Spec.ServiceAccountUserName)
	}

	var expirationDate *time.Time
	if sak.Spec.ExpirationDate != nil {
		expirationDate = &sak.Spec.ExpirationDate.Time
		if expirationDate.Before(time.Now()) {
			klog.ErrorS(nil, "Expiration date is in the past", "orgID", orgID, "username", sak.Spec.ServiceAccountUserName)
			return nil, apierrors.NewBadRequest("expiration date must be in the future")
		}
	} else {
		klog.V(2).Infof("No expiration date provided, Zitadel will use default for service account: %s", sak.Spec.ServiceAccountUserName)
	}

	keyID, keyContent, err := r.Z.AddMachineKeyInOrganization(ctx, orgID, userID, publicKeyBytes, expirationDate)
	if err != nil {
		klog.ErrorS(err, "Failed to add service account key in Zitadel", "orgID", orgID, "userID", userID)
		return nil, translateErr(err, sak.Name)
	}

	credsJSON, err := buildDatumCredentials(keyContent, keyID, userID, sak.Spec.ServiceAccountUserName, r.IntrospectionProjectID)
	if err != nil {
		klog.ErrorS(err, "Failed to build Datum credentials response", "orgID", orgID, "userID", userID, "keyID", keyID)
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to build credentials response"))
	}

	sak.Status.AuthProviderKeyID = keyID
	sak.Status.PrivateKey = string(credsJSON)

	klog.V(2).Infof("Service account key created successfully: keyID=%s, serviceAccount=%s, org=%s", keyID, sak.Spec.ServiceAccountUserName, orgID)

	return sak, nil
}

func (r *REST) listAndAddKeysToList(ctx context.Context, list *milov1alpha1.ServiceAccountKeyList, orgID, userID, serviceAccountName string) error {
	machineKeys, err := r.Z.ListMachineKeysInOrganization(ctx, orgID, userID)
	if err != nil {
		klog.ErrorS(err, "Failed to list service account keys", "orgID", orgID, "userID", userID)
		return apierrors.NewInternalError(fmt.Errorf("failed to list service account keys"))
	}

	addKeysToList(list, serviceAccountName, machineKeys)
	return nil
}

func addKeysToList(list *milov1alpha1.ServiceAccountKeyList, serviceAccountName string, machineKeys []*zitadel.MachineKey) {
	for _, mk := range machineKeys {
		item := milov1alpha1.ServiceAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:              mk.ID,
				CreationTimestamp: metav1.NewTime(mk.CreatedDate),
			},
			Spec: milov1alpha1.ServiceAccountKeySpec{
				ServiceAccountUserName: serviceAccountName,
				ExpirationDate:         nil,
			},
			Status: milov1alpha1.ServiceAccountKeyStatus{
				AuthProviderKeyID: mk.ID,
			},
		}
		if mk.ExpirationDate != nil {
			item.Spec.ExpirationDate = &metav1.Time{Time: *mk.ExpirationDate}
		}
		list.Items = append(list.Items, item)
	}
}

const datumCredentialsType = "datum_service_account"

const defaultServiceAccountScopes = "openid profile email offline_access"

type datumCredentials struct {
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type zitadelKeyEnvelope struct {
	Key string `json:"key"`
}

func buildDatumCredentials(keyContent []byte, keyID, clientID, clientEmail, introspectionProjectID string) ([]byte, error) {
	if len(keyContent) == 0 {
		return nil, nil
	}

	var env zitadelKeyEnvelope
	if err := json.Unmarshal(keyContent, &env); err != nil {
		return nil, fmt.Errorf("parse zitadel key envelope: %w", err)
	}

	creds := datumCredentials{
		Type:         datumCredentialsType,
		ClientID:     clientID,
		PrivateKeyID: keyID,
		PrivateKey:   env.Key,
		ClientEmail:  clientEmail,
	}
	if introspectionProjectID != "" {
		creds.Scope = defaultServiceAccountScopes + " urn:zitadel:iam:org:project:id:" + introspectionProjectID + ":aud"
	}

	return json.Marshal(creds)
}

func validatePublicKey(publicKeyPEM []byte) error {
	if len(publicKeyPEM) == 0 {
		return fmt.Errorf("public key is empty")
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("public key is not in valid PEM format")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	switch pubKey.(type) {
	case *rsa.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public key type: expected RSA or ECDSA, got %T", pubKey)
	}
}

func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(serviceAccountKeysGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(serviceAccountKeysGR, name, nil)
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

// List handles GET requests to list service account keys in an organization.
func (r *REST) List(
	ctx context.Context,
	options *internalversion.ListOptions,
) (runtime.Object, error) {
	orgID, ok := r.getOrgID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context")
		return nil, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	var serviceAccountName string
	if options != nil && options.FieldSelector != nil && !options.FieldSelector.Empty() {
		if val, found := options.FieldSelector.RequiresExactMatch("spec.serviceAccountUserName"); found {
			serviceAccountName = val
			klog.V(2).Infof("Got serviceAccountName from fieldSelector: %q", serviceAccountName)
		}
	}

	list := &milov1alpha1.ServiceAccountKeyList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0",
		},
		Items: []milov1alpha1.ServiceAccountKey{},
	}

	if serviceAccountName != "" {
		klog.V(2).Infof("Listing service account keys for org=%q, serviceAccount=%q", orgID, serviceAccountName)

		user, err := r.Z.GetMachineUserByUsername(ctx, orgID, serviceAccountName)
		if err != nil {
			klog.ErrorS(err, "Failed to look up service account user", "orgID", orgID, "serviceAccountName", serviceAccountName)
			return nil, apierrors.NewInternalError(fmt.Errorf("failed to look up service account"))
		}

		if user == nil {
			klog.InfoS("Service account user not found", "orgID", orgID, "serviceAccountName", serviceAccountName)
			return nil, apierrors.NewNotFound(
				schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "serviceaccounts"},
				serviceAccountName,
			)
		}

		if err := r.listAndAddKeysToList(ctx, list, orgID, user.ID, serviceAccountName); err != nil {
			return nil, err
		}

		klog.V(2).Infof("Listed %d service account keys for org=%q, serviceAccount=%q", len(list.Items), orgID, serviceAccountName)
		return list, nil
	}

	klog.V(2).Infof("Listing all service account keys for org=%q (no filter provided)", orgID)

	serviceAccounts, err := r.Z.ListMachineAccountsInOrganization(ctx, orgID)
	if err != nil {
		klog.ErrorS(err, "Failed to list service accounts", "orgID", orgID)
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to list service accounts"))
	}

	for _, account := range serviceAccounts {
		if err := r.listAndAddKeysToList(ctx, list, orgID, account.ID, account.Username); err != nil {
			return nil, err
		}
	}

	klog.V(2).Infof("Listed %d service account(s) with total %d key(s) for org=%q", len(serviceAccounts), len(list.Items), orgID)
	return list, nil
}

// Get handles GET requests to retrieve a specific service account key.
func (r *REST) Get(
	ctx context.Context,
	name string,
	options *metav1.GetOptions,
) (runtime.Object, error) {
	keyID := name
	klog.InfoS("Getting service account key from Zitadel", "keyID", keyID)

	listResult, err := r.List(ctx, nil)
	if err != nil {
		return nil, err
	}

	list, ok := listResult.(*milov1alpha1.ServiceAccountKeyList)
	if !ok {
		klog.ErrorS(nil, "Unexpected return type from List", "type", listResult)
		return nil, apierrors.NewInternalError(fmt.Errorf("unexpected return type from list"))
	}

	for _, item := range list.Items {
		if item.Status.AuthProviderKeyID == keyID {
			klog.V(2).Infof("Retrieved service account key: keyID=%s, serviceAccount=%s", keyID, item.Spec.ServiceAccountUserName)
			return &item, nil
		}
	}

	klog.InfoS("Service account key not found", "keyID", keyID)
	return nil, apierrors.NewNotFound(serviceAccountKeysGR, name)
}

// ConvertToTable converts the object to a table for kubectl display.
func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name"},
			{Name: "Service Account", Type: "string"},
			{Name: "Key ID", Type: "string"},
			{Name: "Created", Type: "string"},
			{Name: "Expires", Type: "string"},
		},
	}

	if list, ok := obj.(*milov1alpha1.ServiceAccountKeyList); ok {
		for _, item := range list.Items {
			expiresStr := "<none>"
			if item.Spec.ExpirationDate != nil {
				expiresStr = item.Spec.ExpirationDate.String()
			}
			table.Rows = append(table.Rows, metav1.TableRow{
				Cells: []interface{}{
					item.Name,
					item.Spec.ServiceAccountUserName,
					item.Status.AuthProviderKeyID,
					item.CreationTimestamp.String(),
					expiresStr,
				},
				Object: runtime.RawExtension{Object: &item},
			})
		}
		return table, nil
	}

	if sak, ok := obj.(*milov1alpha1.ServiceAccountKey); ok {
		expiresStr := "<none>"
		if sak.Spec.ExpirationDate != nil {
			expiresStr = sak.Spec.ExpirationDate.String()
		}
		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				sak.Name,
				sak.Spec.ServiceAccountUserName,
				sak.Status.AuthProviderKeyID,
				sak.CreationTimestamp.String(),
				expiresStr,
			},
			Object: runtime.RawExtension{Object: sak},
		})
		return table, nil
	}

	return table, nil
}

// Delete handles DELETE requests to remove a service account key from Zitadel.
func (r *REST) Delete(
	ctx context.Context,
	name string,
	deleteValidation rest.ValidateObjectFunc,
	options *metav1.DeleteOptions,
) (runtime.Object, bool, error) {
	orgID, ok := r.getOrgID(ctx)
	if !ok || orgID == "" {
		klog.ErrorS(nil, "Missing organization ID in request context")
		return nil, false, apierrors.NewBadRequest("request must be made within a project context (/projects/{projectID}/control-plane/...) or use --as-extra=project={orgID} for testing")
	}

	keyID := name
	klog.InfoS("Deleting service account key from Zitadel", "keyID", keyID, "orgID", orgID)

	keyObj, err := r.Get(ctx, keyID, nil)
	if err != nil {
		return nil, false, err
	}

	key, ok := keyObj.(*milov1alpha1.ServiceAccountKey)
	if !ok {
		klog.ErrorS(nil, "Unexpected return type from Get", "type", keyObj)
		return nil, false, apierrors.NewInternalError(fmt.Errorf("unexpected return type from get"))
	}

	serviceAccountName := key.Spec.ServiceAccountUserName

	user, err := r.Z.GetMachineUserByUsername(ctx, orgID, serviceAccountName)
	if err != nil {
		klog.ErrorS(err, "Failed to look up service account user", "orgID", orgID, "serviceAccountName", serviceAccountName)
		return nil, false, apierrors.NewInternalError(fmt.Errorf("failed to look up service account"))
	}

	if user == nil {
		klog.InfoS("Service account user not found", "orgID", orgID, "serviceAccountName", serviceAccountName)
		return nil, false, apierrors.NewNotFound(serviceAccountKeysGR, name)
	}

	err = r.Z.RemoveMachineKeyInOrganization(ctx, orgID, user.ID, keyID)
	if err != nil {
		klog.ErrorS(err, "Failed to remove service account key from Zitadel", "orgID", orgID, "userID", user.ID, "keyID", keyID)
		return nil, false, translateErr(err, name)
	}

	klog.V(2).Infof("Service account key deleted successfully: keyID=%s, serviceAccount=%s, org=%s", keyID, serviceAccountName, orgID)

	return key, true, nil
}

// Destroy satisfies rest.Storage.
func (r *REST) Destroy() {}
