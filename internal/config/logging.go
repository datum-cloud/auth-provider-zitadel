package config

import (
	"strings"

	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// InitializeLogging sets up logging based on the global configuration
func InitializeLogging(cfg *GlobalConfig) error {
	// Map human-friendly log levels to zap/zapr levels. zap uses negative
	// numbers for Debug levels, which map to logr verbosity levels (e.g. V(1)
	// corresponds to zapcore.DebugLevel). By allowing users to specify
	// "debug" we ensure that log.V(1) and above are emitted.
	var level zapcore.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn", "warning":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		// Fallback to info if an unknown level is provided.
		level = zapcore.InfoLevel
	}

	// If klog verbosity is enabled (e.g., -v>=1), honor it by enabling debug-level logs
	if klog.V(1).Enabled() {
		level = zapcore.DebugLevel
	}

	opts := zap.Options{
		Development: cfg.Development,
		Level:       level,
	}

	// Configure log format - console format enables development mode
	if cfg.LogFormat == "console" {
		opts.Development = true
	}

	// If verbosity is enabled via klog (-v>=1), also enable development mode to avoid sampling
	if klog.V(1).Enabled() {
		opts.Development = true
	}

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	return nil
}
