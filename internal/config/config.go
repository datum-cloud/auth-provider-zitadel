package config

import (
	"crypto/tls"
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

// ControllerConfig holds controller-specific configuration
type ControllerConfig struct {
	MetricsAddr          string
	ProbeAddr            string
	EnableLeaderElection bool
	LeaderElectionID     string
	SecureMetrics        bool
	EnableHTTP2          bool

	// Certificate configurations
	Metrics MetricsConfig
	Webhook WebhookConfig
}

// NewControllerConfig returns a ControllerConfig with sensible defaults
func NewControllerConfig() *ControllerConfig {
	return &ControllerConfig{
		MetricsAddr:          "0",
		ProbeAddr:            ":8081",
		EnableLeaderElection: false,
		LeaderElectionID:     "28f116c3.my.domain",
		SecureMetrics:        true,
		EnableHTTP2:          false,
		Metrics: MetricsConfig{
			CertName: "tls.crt",
			CertKey:  "tls.key",
		},
		Webhook: WebhookConfig{
			CertName: "tls.crt",
			CertKey:  "tls.key",
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
