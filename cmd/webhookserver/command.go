package webhookserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	authenticationwebhookserver "go.miloapis.com/auth-provider-zitadel/internal/authenticationwebhookserver"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
	token "go.miloapis.com/auth-provider-zitadel/pkg/token"
)

// NewAuthenticationWebhookServerCommand returns a cobra command that starts the UserDeactivation
// TokenReview webhook server.
func NewAuthenticationWebhookServerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	var (
		addr                   string
		certFile               string
		keyFile                string
		insecure               bool
		authenticationEndpoint string

		zitadelPrivateKey string
		zitadelDomain     string
		jwtExpiration     time.Duration
	)

	cmd := &cobra.Command{
		Use:   "auth-webhook",
		Short: "Runs the User Authentication TokenReview webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logf.Log.WithName("authentication-webhook")

			log.Info("Starting authentication webhook server",
				"addr", addr,
				"domain", zitadelDomain,
				"private_key_path", zitadelPrivateKey,
				"jwt_expiration", jwtExpiration,
				"tls_enabled", certFile != "" && keyFile != "")

			introspector, err := token.NewIntrospector(zitadelPrivateKey, zitadelDomain, jwtExpiration)
			if err != nil {
				log.Error(err, "Failed to create auth provider introspector")
				return fmt.Errorf("failed to create auth provider introspector: %w", err)
			}
			log.Info("Successfully created token introspector")

			mux := http.NewServeMux()
			mux.Handle(authenticationEndpoint, authenticationwebhookserver.HttpTokenAuthenticationWebhook(introspector))

			srv := &http.Server{
				Addr:      addr,
				Handler:   mux,
				TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			}

			// Graceful shutdown
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			go func() {
				<-stop
				log.Info("Received interrupt signal, shutting down server gracefully")
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Error(err, "Error during server shutdown")
				}
				log.Info("Server shutdown completed")
			}()

			if certFile == "" || keyFile == "" {
				if !insecure {
					log.Error(fmt.Errorf("missing TLS configuration"), "TLS certificate and key files are required for secure operation")
					return fmt.Errorf("TLS certificate and key files are required for secure operation. Use --insecure flag only for local development")
				}
				// For local development only – run HTTP.
				log.Info("WARNING: Starting HTTP server without TLS - use only for local testing!", "addr", addr)
				cmd.PrintErrln("WARNING: running webhook without TLS – use only for local testing!")
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Error(err, "HTTP server failed")
					return err
				}
				return nil
			}

			log.Info("Starting HTTPS server", "addr", addr, "cert_file", certFile, "key_file", keyFile)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Error(err, "HTTPS server failed")
				return err
			}
			return nil
		},
	}

	// Network & Kubernetes flags.
	cmd.Flags().StringVar(&addr, "addr", ":8443", "address the server listens on")
	cmd.Flags().StringVar(&certFile, "tls-cert-file", "", "path to TLS certificate file")
	cmd.Flags().StringVar(&keyFile, "tls-private-key-file", "", "path to TLS private key file")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "allow running without TLS (DANGEROUS: for local development only)")
	cmd.Flags().StringVar(&authenticationEndpoint, "authentication-endpoint", "/authenticate", "path to the authentication endpoint")

	// Zitadel introspection flags.
	cmd.Flags().StringVar(&zitadelPrivateKey, "zitadel-private-key", "private-key.json", "path to Zitadel private key JSON")
	cmd.Flags().StringVar(&zitadelDomain, "zitadel-domain", "https://your_domain", "base URL of the Auth Provider instance (e.g., https://auth.example.com)")
	cmd.Flags().DurationVar(&jwtExpiration, "jwt-expiration", time.Hour, "JWT token expiration duration (e.g., 1h, 30m, 2h30m)")

	return cmd
}
