package install

import (
	"k8s.io/apimachinery/pkg/runtime"

	v1alpha1 "go.miloapis.com/auth-provider-zitadel/pkg/apis/identity/v1alpha1"
)

// Install registers provider group/version bindings for Milo Session types.
func Install(s *runtime.Scheme) {
	_ = v1alpha1.AddToScheme(s)
}
