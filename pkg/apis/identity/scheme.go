package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// Install registers provider group/version bindings for Milo Session types.
func Install(s *runtime.Scheme) {
	_ = milov1alpha1.AddToScheme(s)

	// Register valid field selectors for MachineAccountKey so the generic API server
	// passes them through to the REST handler instead of intercepting them.
	_ = s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{
			Group:   milov1alpha1.SchemeGroupVersion.Group,
			Version: milov1alpha1.SchemeGroupVersion.Version,
			Kind:    "MachineAccountKey",
		},
		func(label, value string) (string, string, error) {
			switch label {
			case "spec.machineAccountUserName", "metadata.name":
				return label, value, nil
			default:
				return "", "", nil
			}
		},
	)
}
