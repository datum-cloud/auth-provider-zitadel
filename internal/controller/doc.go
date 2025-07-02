package controller

// These RBAC rules are needed for project control plane discovery.
// +kubebuilder:rbac:groups=infrastructure.miloapis.com,resources=projectcontrolplanes,verbs=get;list;watch
