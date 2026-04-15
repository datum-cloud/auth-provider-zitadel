// Package machineaccounts provides an etcd-backed REST storage implementation
// for the identity.miloapis.com/machineaccounts resource.
package machineaccounts

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metatable "k8s.io/apimachinery/pkg/api/meta/table"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage"

	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// REST implements a RESTStorage for MachineAccount objects backed by etcd.
type REST struct {
	*genericregistry.Store
}

// Storage bundles the main REST storage and its status subresource.
type Storage struct {
	MachineAccount *REST
	Status         *StatusREST
}

// NewStorage returns a REST storage object (and its status subresource) that
// works against an etcd backend.
//
// The etcd key prefix is derived automatically from optsGetter (supplied by
// RecommendedOptions.Etcd) — no hardcoded prefix.
func NewStorage(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter) (*Storage, error) {
	strategy := NewStrategy(scheme)
	statusStrategy := NewStatusStrategy(strategy)

	gr := identityv1alpha1.Resource("machineaccounts")
	singular := identityv1alpha1.Resource("machineaccount")

	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &identityv1alpha1.MachineAccount{} },
		NewListFunc:               func() runtime.Object { return &identityv1alpha1.MachineAccountList{} },
		PredicateFunc:             MatchMachineAccount,
		DefaultQualifiedResource:  gr,
		SingularQualifiedResource: singular,

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,

		TableConvertor: rest.NewDefaultTableConvertor(gr),
	}

	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    GetAttrs,
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, fmt.Errorf("complete machineaccounts store: %w", err)
	}

	mainREST := &REST{store}

	// Build the status subresource store: same backing store, different strategy.
	statusStore := *store
	statusStore.CreateStrategy = nil
	statusStore.DeleteStrategy = nil
	statusStore.UpdateStrategy = statusStrategy

	return &Storage{
		MachineAccount: mainREST,
		Status:         &StatusREST{store: &statusStore},
	}, nil
}

// NamespaceScoped returns false — MachineAccount is cluster-scoped.
func (r *REST) NamespaceScoped() bool { return false }

// ShortNames returns the short names for the resource so kubectl accepts "ma".
func (r *REST) ShortNames() []string { return []string{"ma"} }

// ConvertToTable renders MachineAccount objects for kubectl table output.
func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return machineAccountToTable(ctx, obj, tableOptions)
}

// Destroy cleans up resources on shutdown.
func (r *REST) Destroy() {
	r.Store.Destroy()
}

// StatusREST implements the REST endpoint for changing the status of a MachineAccount.
type StatusREST struct {
	store *genericregistry.Store
}

var _ rest.Patcher = &StatusREST{}

// New creates a new MachineAccount object.
func (r *StatusREST) New() runtime.Object {
	return &identityv1alpha1.MachineAccount{}
}

// Destroy cleans up resources on shutdown.  The underlying store is shared
// with REST so we intentionally do not destroy it here.
func (r *StatusREST) Destroy() {}

// Get retrieves the object from storage; required to support Patch on the
// status subresource.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters only the status subset of a MachineAccount.
func (r *StatusREST) Update(
	ctx context.Context,
	name string,
	objInfo rest.UpdatedObjectInfo,
	createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc,
	forceAllowCreate bool,
	options *metav1.UpdateOptions,
) (runtime.Object, bool, error) {
	// Status subresources must never create on update.
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}

// GetAttrs returns the labels and fields of a MachineAccount for filtering.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	ma, ok := obj.(*identityv1alpha1.MachineAccount)
	if !ok {
		return nil, nil, fmt.Errorf("given object is not a MachineAccount")
	}
	return labels.Set(ma.ObjectMeta.Labels), generic.ObjectMetaFieldsSet(&ma.ObjectMeta, false), nil
}

// MatchMachineAccount is the predicate used by the etcd store to filter watch events.
func MatchMachineAccount(label labels.Selector, field fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    field,
		GetAttrs: GetAttrs,
	}
}

// machineAccountToTable converts MachineAccount objects to a kubectl Table.
func machineAccountToTable(_ context.Context, obj runtime.Object, _ runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{Name: "Name", Type: "string", Format: "name"},
			{Name: "State", Type: "string"},
			{Name: "Email", Type: "string"},
			{Name: "Ready", Type: "string"},
			{Name: "Age", Type: "string"},
		},
	}

	if m, err := meta.ListAccessor(obj); err == nil {
		table.ResourceVersion = m.GetResourceVersion()
		table.Continue = m.GetContinue()
		table.RemainingItemCount = m.GetRemainingItemCount()
	} else if m, err := meta.CommonAccessor(obj); err == nil {
		table.ResourceVersion = m.GetResourceVersion()
	}

	var err error
	table.Rows, err = metatable.MetaToTableRow(obj, func(obj runtime.Object, m metav1.Object, name, age string) ([]interface{}, error) {
		ma, ok := obj.(*identityv1alpha1.MachineAccount)
		if !ok {
			return []interface{}{name, "", "", "", age}, nil
		}
		ready := ""
		for _, c := range ma.Status.Conditions {
			if c.Type == "Ready" {
				ready = string(c.Status)
				break
			}
		}
		return []interface{}{name, ma.Spec.State, ma.Status.Email, ready, age}, nil
	})
	return table, err
}
