package install

import (
	"k8s.io/apimachinery/pkg/runtime"

	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// Install registers provider group/version bindings for Milo Session types.
func Install(s *runtime.Scheme) {
	_ = milov1alpha1.AddToScheme(s)
}
