package controller

import (
	"crypto/tls"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// NewControllerCommand creates the controller subcommand
func NewControllerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	cfg := config.NewControllerConfig()

	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run the Kubernetes controller manager",
		Long: `Run the Kubernetes controller manager that watches for custom resources
and manages the auth provider lifecycle.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runController(cfg, globalConfig)
		},
	}

	// Controller-specific flags
	cmd.Flags().StringVar(&cfg.MetricsAddr, "metrics-bind-address", cfg.MetricsAddr,
		"The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	cmd.Flags().StringVar(&cfg.ProbeAddr, "health-probe-bind-address", cfg.ProbeAddr,
		"The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&cfg.EnableLeaderElection, "leader-elect", cfg.EnableLeaderElection,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	cmd.Flags().BoolVar(&cfg.SecureMetrics, "metrics-secure", cfg.SecureMetrics,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	cmd.Flags().BoolVar(&cfg.EnableHTTP2, "enable-http2", cfg.EnableHTTP2,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	// Certificate flags
	cmd.Flags().StringVar(&cfg.Webhook.CertPath, "webhook-cert-path", cfg.Webhook.CertPath,
		"The directory that contains the webhook certificate.")
	cmd.Flags().StringVar(&cfg.Webhook.CertName, "webhook-cert-name", cfg.Webhook.CertName,
		"The name of the webhook certificate file.")
	cmd.Flags().StringVar(&cfg.Webhook.CertKey, "webhook-cert-key", cfg.Webhook.CertKey,
		"The name of the webhook key file.")
	cmd.Flags().StringVar(&cfg.Metrics.CertPath, "metrics-cert-path", cfg.Metrics.CertPath,
		"The directory that contains the metrics server certificate.")
	cmd.Flags().StringVar(&cfg.Metrics.CertName, "metrics-cert-name", cfg.Metrics.CertName,
		"The name of the metrics server certificate file.")
	cmd.Flags().StringVar(&cfg.Metrics.CertKey, "metrics-cert-key", cfg.Metrics.CertKey,
		"The name of the metrics server key file.")

	return cmd
}

func runController(cfg *config.ControllerConfig, globalConfig *config.GlobalConfig) error {
	setupLog := ctrl.Log.WithName("setup")
	setupLog.Info("Starting controller manager")

	// Get TLS options
	tlsOpts := cfg.GetTLSOptions()
	if !cfg.EnableHTTP2 {
		setupLog.Info("disabling http/2")
	}

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

	// Setup webhook certificate watcher
	if len(cfg.Webhook.CertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", cfg.Webhook.CertPath, "webhook-cert-name", cfg.Webhook.CertName, "webhook-cert-key", cfg.Webhook.CertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(cfg.Webhook.CertPath, cfg.Webhook.CertName),
			filepath.Join(cfg.Webhook.CertPath, cfg.Webhook.CertKey),
		)
		if err != nil {
			return fmt.Errorf("failed to initialize webhook certificate watcher: %w", err)
		}
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	if webhookCertWatcher != nil {
		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   cfg.MetricsAddr,
		SecureServing: cfg.SecureMetrics,
		TLSOpts:       tlsOpts,
	}

	if cfg.SecureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(cfg.Metrics.CertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", cfg.Metrics.CertPath, "metrics-cert-name", cfg.Metrics.CertName, "metrics-cert-key", cfg.Metrics.CertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(cfg.Metrics.CertPath, cfg.Metrics.CertName),
			filepath.Join(cfg.Metrics.CertPath, cfg.Metrics.CertKey),
		)
		if err != nil {
			return fmt.Errorf("failed to initialize metrics certificate watcher: %w", err)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: cfg.ProbeAddr,
		LeaderElection:         cfg.EnableLeaderElection,
		LeaderElectionID:       cfg.LeaderElectionID,
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	// +kubebuilder:scaffold:builder

	if metricsCertWatcher != nil {
		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {
			return fmt.Errorf("unable to add metrics certificate watcher to manager: %w", err)
		}
	}

	if webhookCertWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {
			return fmt.Errorf("unable to add webhook certificate watcher to manager: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}
