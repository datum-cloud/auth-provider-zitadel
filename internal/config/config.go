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
)

// GlobalConfig holds configuration that's shared across all commands
type GlobalConfig struct {
	Development bool
	LogLevel    string
	LogFormat   string
}

// MetricsConfig holds metrics server configuration
type MetricsConfig struct {
	BindAddress   string
	SecureServing bool
	CertPath      string
	CertName      string
	CertKey       string
}

// WebhookConfig holds webhook server configuration
type WebhookConfig struct {
	CertPath string
	CertName string
	CertKey  string
}

// LeaderElectionConfig holds leader election configuration
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

	// Token is the access token (without the type prefix) that the controller
	// will use when calling the Zitadel API.
	Token string

	// TokenType is the type/prefix of the access token, typically "Bearer".
	// If left empty, the controller will default it to "Bearer".
	TokenType string
}

// ControllerConfig holds controller-specific configuration
type ControllerConfig struct {
	MetricsAddr   string
	ProbeAddr     string
	SecureMetrics bool
	EnableHTTP2   bool

	// Leader election configuration
	LeaderElection LeaderElectionConfig

	// Certificate configurations
	Metrics MetricsConfig
	Webhook WebhookConfig

	// Zitadel connection details
	Zitadel ZitadelConfig
}

// NewControllerConfig returns a ControllerConfig with sensible defaults
func NewControllerConfig() *ControllerConfig {
	return &ControllerConfig{
		MetricsAddr:   "0",
		ProbeAddr:     ":8081",
		SecureMetrics: true,
		EnableHTTP2:   false,
		LeaderElection: LeaderElectionConfig{
			Enabled:         false,
			ID:              "28f116c3.my.domain",
			Namespace:       "",               // Use default namespace if empty
			ResourceLock:    "leases",         // Default to leases
			LeaseDuration:   15 * time.Second, // Default lease duration
			RenewDeadline:   10 * time.Second, // Default renew deadline
			RetryPeriod:     2 * time.Second,  // Default retry period
			ReleaseOnCancel: false,            // Default to false for safety
		},
		Metrics: MetricsConfig{
			CertName: "tls.crt",
			CertKey:  "tls.key",
		},
		Webhook: WebhookConfig{
			CertName: "tls.crt",
			CertKey:  "tls.key",
		},
		Zitadel: ZitadelConfig{
			TokenType: "Bearer",
		},
	}
}

// GetTLSOptions returns TLS configuration options based on HTTP2 settings
func (c *ControllerConfig) GetTLSOptions() []func(*tls.Config) {
	var tlsOpts []func(*tls.Config)

	if !c.EnableHTTP2 {
		// Disable HTTP/2 for security reasons
		disableHTTP2 := func(config *tls.Config) {
			config.NextProtos = []string{"http/1.1"}
		}
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	return tlsOpts
}
