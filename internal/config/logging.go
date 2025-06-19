package config

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// InitializeLogging sets up logging based on the global configuration
func InitializeLogging(cfg *GlobalConfig) error {
	opts := zap.Options{
		Development: cfg.Development,
	}

	// Configure log format - console format enables development mode
	if cfg.LogFormat == "console" {
		opts.Development = true
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	return nil
}
