/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"crypto/tls"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"

	mulicluster "go.miloapis.com/milo/pkg/multicluster-runtime"
)

// GlobalConfig holds configuration that's shared across all commands
type GlobalConfig struct {
	Development bool
	LogLevel    string
	LogFormat   string
}

// ZitadelConfig holds configuration for connecting to a Zitadel instance
// +kubebuilder:object:generate=true
// It is consumed by the controller command to initialise the internal Zitadel
// HTTP client that reconciler implementations can re-use.
// All fields are plain strings so they can be easily provided via flags or
// environment variables.
type ZitadelConfig struct {
	// BaseURL is the root URL of the Zitadel instance, e.g.
	// "https://my-org.zitadel.cloud".
	BaseURL string

	// MachineAccountKeyPath is the path to the machine account key file generated by Zitadel.
	// This is used to authenticate the controller to the Zitadel API.
	MachineAccountKeyPath string
}

type MetricsConfig struct {
	Addr          string
	CertPath      string
	CertName      string
	CertKey       string
	SecureMetrics bool
}

type WebhookConfig struct {
	CertPath string
	CertName string
	CertKey  string
}

type LeaderElectionConfig struct {
	Enabled         bool
	ID              string
	Namespace       string
	ResourceLock    string
	LeaseDuration   time.Duration
	RenewDeadline   time.Duration
	RetryPeriod     time.Duration
	ReleaseOnCancel bool
}

// ControllerConfig holds controller-specific configuration
type ControllerConfig struct {
	LeaderElection            LeaderElectionConfig
	Metrics                   MetricsConfig
	Webhook                   WebhookConfig
	ProbeAddr                 string
	EnableHTTP2               bool
	TlsOpts                   []func(*tls.Config)
	UpstreamClusterKubeconfig string
	ServerConfigFile          string
	EmailAddressSuffix        string

	// Zitadel connection details
	Zitadel ZitadelConfig
}

// NewControllerConfig returns a ControllerConfig with sensible defaults
func NewControllerConfig() *ControllerConfig {
	return &ControllerConfig{
		ProbeAddr:   ":8081",
		EnableHTTP2: false,
		LeaderElection: LeaderElectionConfig{
			Enabled:         false,
			ID:              "auth-provider-zitadel-leader",
			Namespace:       "",               // Use default namespace if empty
			ResourceLock:    "leases",         // Default to leases
			LeaseDuration:   15 * time.Second, // Default lease duration
			RenewDeadline:   10 * time.Second, // Default renew deadline
			RetryPeriod:     2 * time.Second,  // Default retry period
			ReleaseOnCancel: false,            // Default to false for safety
		},
		Metrics: MetricsConfig{
			CertName:      "tls.crt",
			CertKey:       "tls.key",
			SecureMetrics: true,
			Addr:          "0",
		},
		Webhook: WebhookConfig{
			CertName: "tls.crt",
			CertKey:  "tls.key",
		},
	}
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true

type AuthProviderZitadel struct {
	metav1.TypeMeta

	Discovery                    DiscoveryConfig                    `json:"discovery"`
	DownstreamResourceManagement DownstreamResourceManagementConfig `json:"downstreamResourceManagement"`
}

// +k8s:deepcopy-gen=true

type DownstreamResourceManagementConfig struct {
	// KubeconfigPath is the path to the kubeconfig file to use when managing
	// downstream resources. When not provided, the operator will use the
	// in-cluster config.
	KubeconfigPath string `json:"kubeconfigPath"`
}

func (c *DownstreamResourceManagementConfig) RestConfig() (*rest.Config, error) {
	if c.KubeconfigPath == "" {
		return ctrl.GetConfig()
	}

	return clientcmd.BuildConfigFromFlags("", c.KubeconfigPath)
}

// +k8s:deepcopy-gen=true

type DiscoveryConfig struct {
	// Mode is the mode that the operator should use to discover clusters.
	//
	// Defaults to "single"
	Mode mulicluster.Provider `json:"mode"`

	// InternalServiceDiscovery will result in the operator to connect to internal
	// service addresses for projects.
	InternalServiceDiscovery bool `json:"internalServiceDiscovery"`

	// DiscoveryKubeconfigPath is the path to the kubeconfig file to use for
	// project discovery. When not provided, the operator will use the in-cluster
	// config.
	DiscoveryKubeconfigPath string `json:"discoveryKubeconfigPath"`

	// ProjectKubeconfigPath is the path to the kubeconfig file to use as a
	// template when connecting to project control planes. When not provided,
	// the operator will use the in-cluster config.
	ProjectKubeconfigPath string `json:"projectKubeconfigPath"`
}

func SetDefaults_DiscoveryConfig(obj *DiscoveryConfig) {
	if obj.Mode == "" {
		obj.Mode = mulicluster.ProviderSingle
	}
}

func (c *DiscoveryConfig) DiscoveryRestConfig() (*rest.Config, error) {
	if c.DiscoveryKubeconfigPath == "" {
		return ctrl.GetConfig()
	}

	return clientcmd.BuildConfigFromFlags("", c.DiscoveryKubeconfigPath)
}

func (c *DiscoveryConfig) ProjectRestConfig() (*rest.Config, error) {
	if c.ProjectKubeconfigPath == "" {
		return ctrl.GetConfig()
	}

	return clientcmd.BuildConfigFromFlags("", c.ProjectKubeconfigPath)
}

func init() {
	SchemeBuilder.Register(&AuthProviderZitadel{})
}
