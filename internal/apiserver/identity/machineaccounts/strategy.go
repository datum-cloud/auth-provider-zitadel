package machineaccounts

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"

	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// machineAccountStrategy implements create/update/delete behavior for MachineAccount.
type machineAccountStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy returns a new strategy for MachineAccount backed by the given scheme.
func NewStrategy(typer runtime.ObjectTyper) *machineAccountStrategy {
	return &machineAccountStrategy{typer, names.SimpleNameGenerator}
}

// NamespaceScoped returns false because MachineAccount is cluster-scoped.
func (s *machineAccountStrategy) NamespaceScoped() bool { return false }

// PrepareForCreate clears transient fields and applies defaults before the
// object is persisted for the first time.
func (s *machineAccountStrategy) PrepareForCreate(_ context.Context, obj runtime.Object) {
	ma := obj.(*identityv1alpha1.MachineAccount)
	// Status is owned by the controller via the status subresource; clear on create.
	ma.Status = identityv1alpha1.MachineAccountStatus{}
	// Default state to Active if not explicitly set.
	if ma.Spec.State == "" {
		ma.Spec.State = "Active"
	}
}

// Validate validates a new MachineAccount.
func (s *machineAccountStrategy) Validate(_ context.Context, obj runtime.Object) field.ErrorList {
	ma := obj.(*identityv1alpha1.MachineAccount)
	return validateMachineAccountSpec(ma)
}

// WarningsOnCreate returns warnings for creation — none currently.
func (s *machineAccountStrategy) WarningsOnCreate(_ context.Context, _ runtime.Object) []string {
	return nil
}

// Canonicalize is a no-op for MachineAccount.
func (s *machineAccountStrategy) Canonicalize(_ runtime.Object) {}

// AllowCreateOnUpdate returns false — MachineAccount cannot be created via PUT.
func (s *machineAccountStrategy) AllowCreateOnUpdate() bool { return false }

// AllowUnconditionalUpdate returns false — updates must include a resourceVersion.
func (s *machineAccountStrategy) AllowUnconditionalUpdate() bool { return false }

// PrepareForUpdate preserves the status subresource on spec updates and ensures
// state is never silently cleared.
func (s *machineAccountStrategy) PrepareForUpdate(_ context.Context, obj, old runtime.Object) {
	newMA := obj.(*identityv1alpha1.MachineAccount)
	oldMA := old.(*identityv1alpha1.MachineAccount)
	// Status is managed only via the status subresource; carry it forward.
	newMA.Status = oldMA.Status
	// If state was explicitly cleared, restore the default.
	if newMA.Spec.State == "" {
		newMA.Spec.State = "Active"
	}
}

// ValidateUpdate validates an update to MachineAccount.
func (s *machineAccountStrategy) ValidateUpdate(_ context.Context, obj, _ runtime.Object) field.ErrorList {
	ma := obj.(*identityv1alpha1.MachineAccount)
	return validateMachineAccountSpec(ma)
}

// WarningsOnUpdate returns warnings for updates — none currently.
func (s *machineAccountStrategy) WarningsOnUpdate(_ context.Context, _, _ runtime.Object) []string {
	return nil
}

// validateMachineAccountSpec checks that spec.state is one of the allowed values.
func validateMachineAccountSpec(ma *identityv1alpha1.MachineAccount) field.ErrorList {
	var errs field.ErrorList
	switch ma.Spec.State {
	case "Active", "Inactive":
		// valid
	default:
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "state"),
			ma.Spec.State,
			`must be "Active" or "Inactive"`,
		))
	}
	return errs
}

// machineAccountStatusStrategy handles updates via the /status subresource.
type machineAccountStatusStrategy struct {
	*machineAccountStrategy
}

// NewStatusStrategy returns a status-only strategy for MachineAccount.
func NewStatusStrategy(base *machineAccountStrategy) *machineAccountStatusStrategy {
	return &machineAccountStatusStrategy{base}
}

// PrepareForCreate is a no-op; the status subresource does not support create.
func (s *machineAccountStatusStrategy) PrepareForCreate(_ context.Context, _ runtime.Object) {}

// PrepareForUpdate on the status subresource drops spec changes: only status
// fields may change via /status.
func (s *machineAccountStatusStrategy) PrepareForUpdate(_ context.Context, obj, old runtime.Object) {
	newMA := obj.(*identityv1alpha1.MachineAccount)
	oldMA := old.(*identityv1alpha1.MachineAccount)
	// Preserve spec; only status may change via the status subresource.
	newMA.Spec = oldMA.Spec
}

// Validate is a no-op for status updates.
func (s *machineAccountStatusStrategy) Validate(_ context.Context, _ runtime.Object) field.ErrorList {
	return nil
}

// ValidateUpdate is a no-op for status updates.
func (s *machineAccountStatusStrategy) ValidateUpdate(_ context.Context, _, _ runtime.Object) field.ErrorList {
	return nil
}

// compile-time interface checks
var _ rest.RESTCreateStrategy = (*machineAccountStrategy)(nil)
var _ rest.RESTUpdateStrategy = (*machineAccountStrategy)(nil)
var _ rest.RESTDeleteStrategy = (*machineAccountStrategy)(nil)
