package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	milov1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// GroupName is the API group served by the aggregated apiserver for Zitadel sessions.
const GroupName = "zitadel.identity.miloapis.com"

// SchemeGroupVersion is the group version used to register these objects.
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

// AddToScheme binds Milo public identity types to this provider's group/version so we
// can reuse Milo types while emitting provider-scoped objects without duplicating schemas.
func AddToScheme(s *runtime.Scheme) error {
	s.AddKnownTypeWithName(SchemeGroupVersion.WithKind("Session"), &milov1.Session{})
	s.AddKnownTypeWithName(SchemeGroupVersion.WithKind("SessionList"), &milov1.SessionList{})
	return nil
}
