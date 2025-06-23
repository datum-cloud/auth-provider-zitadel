package actionsserver

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
	"go.miloapis.com/auth-provider-zitadel/internal/httpactionsserver"
	actions "go.miloapis.com/auth-provider-zitadel/pkg/zitadel-actions/signature"
	iamiamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewActionsServerCommand creates the cobra command to start the actions HTTP server.
// This thin wrapper lives under cmd/ and delegates the actual server implementation
// to the internal/httpactionsserver package.
func NewActionsServerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	log := logf.Log.WithName("actions-server-cmd")
	cfg := httpactionsserver.NewServerConfig()

	cmd := &cobra.Command{
		Use:   "actions-server",
		Short: "Run the HTTP server that exposes zitadel v2/actions webhook endpoints",
		Long: `Start a lightweight HTTP server that provides the v1/actions/create-user-account endpoint.
If a TLS certificate and key are provided, the server will start in HTTPS mode. Otherwise, it will fall back to HTTP.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info("Starting actions server",
				"addr", cfg.Addr,
				"tlsEnabled", cfg.CertFile != "" && cfg.KeyFile != "",
				"http2Disabled", cfg.DisableHTTP2,
				"signatureValidation", !cfg.DisableSignatureValidation,
			)

			// Load kubeconfig
			log.Info("Loading kubeconfig", "path", cfg.Kubeconfig)
			k8sConfig, err := clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
			if err != nil {
				log.Error(err, "Failed to load kubeconfig", "path", cfg.Kubeconfig)
				return fmt.Errorf("unable to load kubeconfig from %s: %w", cfg.Kubeconfig, err)
			}
			log.V(1).Info("Successfully loaded kubeconfig")

			// Build a scheme that knows about IAM APIs
			log.Info("Building Kubernetes scheme with IAM APIs")
			scheme := runtime.NewScheme()
			utilruntime.Must(iamiamv1alpha1.AddToScheme(scheme))
			log.V(1).Info("Successfully built Kubernetes scheme")

			log.Info("Creating Kubernetes client")
			k8sClient, err := client.New(k8sConfig, client.Options{Scheme: scheme})
			if err != nil {
				log.Error(err, "Failed to create Kubernetes client")
				return err
			}
			log.V(1).Info("Successfully created Kubernetes client")

			// If signature validation is enabled, validate the Zitadel Webhook Payload
			log.Info("Configuring signature validation", "enabled", !cfg.DisableSignatureValidation)
			var validateSignatureFunc httpactionsserver.ValidateSignatureFunc
			if cfg.DisableSignatureValidation {
				log.Info("Signature validation disabled, using noop validator")
				validateSignatureFunc = actions.NoopValidatePayload
			} else {
				if cfg.SigningKey == "" {
					log.Error(nil, "Signing key is required when signature validation is enabled")
					return fmt.Errorf("signing key is required when signature validation is enabled")
				}
				log.Info("Using Zitadel signature validation")
				validateSignatureFunc = actions.ValidatePayload
			}

			// Start the server
			log.Info("Starting HTTP actions server")
			return httpactionsserver.RunServer(cfg, k8sClient, validateSignatureFunc)
		},
	}

	// Server flags
	cmd.Flags().StringVar(&cfg.Addr, "addr", cfg.Addr, "The address the HTTP server binds to (e.g. :8080)")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", cfg.CertFile, "Path to the TLS certificate file (optional)")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "Path to the TLS private key file (optional)")
	cmd.Flags().BoolVar(&cfg.DisableHTTP2, "disable-http2", cfg.DisableHTTP2, "Disable HTTP/2 when serving with TLS (forces http/1.1)")
	cmd.Flags().StringVar(&cfg.Kubeconfig, "kubeconfig", "", "Path to the kubeconfig file.")
	cmd.Flags().StringVar(&cfg.SigningKey, "signing-key", "", "Signing key for validating Zitadel webhook signatures. Provided by Zitadel when creating the Webhook Target.")
	cmd.Flags().BoolVar(&cfg.DisableSignatureValidation, "disable-signature-validation", cfg.DisableSignatureValidation, "Disable signature validation of Zitadel webhook payloadsb")

	return cmd
}
