package config

import "time"

// WebhookServerConfig holds the configuration for the webhook server.
type WebhookServerConfig struct {
	CertDir                string
	CertFile               string
	KeyFile                string
	WebhookPort            int
	AuthenticationEndpoint string
	ZitadelPrivateKey      string
	ZitadelDomain          string
	JwtExpiration          time.Duration
	MetricsBindAddress     string
}

// NewWebhookServerConfig creates a new WebhookServerConfig with default values.
func NewWebhookServerConfig() *WebhookServerConfig {
	return &WebhookServerConfig{
		CertDir:                "/etc/certs",
		CertFile:               "server.crt",
		KeyFile:                "server.key",
		WebhookPort:            9443,
		AuthenticationEndpoint: "/authenticate",
	}
}
