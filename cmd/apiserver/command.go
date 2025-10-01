package apiserver

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	openapi "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/registry/rest"
	genericserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	compatibility "k8s.io/component-base/compatibility"
	"k8s.io/klog/v2"
	openapicommon "k8s.io/kube-openapi/pkg/common"
	generatedopenapi "k8s.io/kubernetes/pkg/generated/openapi"

	registrysessions "go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/sessions"
	"go.miloapis.com/auth-provider-zitadel/internal/config"
	identityinstall "go.miloapis.com/auth-provider-zitadel/pkg/apis/identity"
	identityv1alpha1 "go.miloapis.com/auth-provider-zitadel/pkg/apis/identity/v1alpha1"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	miloidentity "go.miloapis.com/milo/pkg/apis/identity"
	milov1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewAPIServerCommand creates a cobra command that runs the aggregated API server
// for the zitadel.identity.milo.io/v1alpha1 group.
func NewAPIServerCommand(global *config.GlobalConfig) *cobra.Command {
	log := logf.Log.WithName("apiserver-cmd")

	var (
		tlsCertFile string
		tlsKeyFile  string
		securePort  int
		kubeconfig  string
		// Zitadel configuration (flags with env fallbacks)
		zitadelIssuer  string
		zitadelAPI     string
		zitadelKeyPath string
	)

	cmd := &cobra.Command{
		Use:   "apiserver",
		Short: "Run aggregated API server for Zitadel sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.InitializeLogging(global); err != nil {
				return fmt.Errorf("init logging: %w", err)
			}
			// Route klog through the controller-runtime logger and ensure flushing on exit
			klog.SetLogger(logf.Log.WithName("klog"))
			klog.EnableContextualLogging(true)
			defer klog.Flush()
			log.Info("Starting aggregated API server")

			scheme := runtime.NewScheme()
			identityinstall.Install(scheme)
			miloidentity.Install(scheme)
			_ = clientgoscheme.AddToScheme(scheme)

			codecs := serializer.NewCodecFactory(scheme)

			ro := genericoptions.NewRecommendedOptions("/unused/registry", nil)
			// Ensure we don't try to bind to privileged port 443; default to 8443 and allow override via flag
			ro.SecureServing.BindPort = securePort
			if tlsCertFile != "" && tlsKeyFile != "" {
				ro.SecureServing.ServerCert.CertKey.CertFile = tlsCertFile
				ro.SecureServing.ServerCert.CertKey.KeyFile = tlsKeyFile
			}
			// If flag not provided, fall back to env vars
			if kubeconfig == "" {
				if v := os.Getenv("KUBECONFIG"); v != "" {
					kubeconfig = v
				}
			}

			// Configure delegating authn/authz on RecommendedOptions BEFORE ApplyTo so internal controllers use it
			authn := genericoptions.NewDelegatingAuthenticationOptions()
			authn.RequestHeader.UIDHeaders = []string{"x-remote-uid"}
			authz := genericoptions.NewDelegatingAuthorizationOptions()
			if kubeconfig != "" {
				log.Info("Using kubeconfig", "path", kubeconfig)
				authn.RemoteKubeConfigFile = kubeconfig
				authz.RemoteKubeConfigFile = kubeconfig
				authn.RemoteKubeConfigFileOptional = false
				authz.RemoteKubeConfigFileOptional = false
			}
			ro.Authentication = authn
			ro.Authorization = authz
			ro.Etcd = nil
			ro.Admission = nil
			ro.CoreAPI = nil
			ro.Audit = nil
			ro.Features.EnablePriorityAndFairness = false

			cfg := genericserver.NewRecommendedConfig(codecs)
			if err := ro.ApplyTo(cfg); err != nil {
				return fmt.Errorf("apply recommended options: %w", err)
			}
			// Ensure EffectiveVersion is non-nil to avoid nil deref in Complete()
			if cfg.EffectiveVersion == nil {
				cfg.EffectiveVersion = compatibility.NewEffectiveVersionFromString("", "", "")
			}
			// Enable OpenAPI and provide minimal definitions set
			cfg.SkipOpenAPIInstallation = false
			getOpenAPIDefinitions := func(ref openapicommon.ReferenceCallback) map[string]openapicommon.OpenAPIDefinition {
				base := generatedopenapi.GetOpenAPIDefinitions(ref)
				id := milov1.GetOpenAPIDefinitions(ref)
				for k, v := range id {
					base[k] = v
				}
				return base
			}
			cfg.OpenAPIConfig = genericserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, openapi.NewDefinitionNamer(scheme))
			cfg.OpenAPIConfig.Info.Title = "Zitadel Sessions API"
			cfg.OpenAPIConfig.Info.Version = "v1alpha1"
			cfg.OpenAPIV3Config = genericserver.DefaultOpenAPIV3Config(getOpenAPIDefinitions, openapi.NewDefinitionNamer(scheme))

			// Note: secure serving is configured by flags of the apiserver library; we default to its settings.

			srv, err := cfg.Complete().New("zitadel-sessions-apiserver", genericserver.NewEmptyDelegate())
			if err != nil {
				return fmt.Errorf("build server: %w", err)
			}

			zc, err := zitadel.NewSDK(context.Background(), zitadel.SDKConfig{
				Issuer:  zitadelIssuer,
				Domain:  zitadelAPI,
				KeyPath: zitadelKeyPath,
			})
			if err != nil {
				return fmt.Errorf("init zitadel sdk: %w", err)
			}

			storage := map[string]rest.Storage{"sessions": &registrysessions.REST{Z: zc}}

			agi := genericserver.NewDefaultAPIGroupInfo(identityv1alpha1.GroupName, scheme, metav1.ParameterCodec, codecs)
			agi.VersionedResourcesStorageMap = map[string]map[string]rest.Storage{"v1alpha1": storage}
			if err := srv.InstallAPIGroup(&agi); err != nil {
				return fmt.Errorf("install api group: %w", err)
			}

			log.Info("Aggregated API server is starting")
			return srv.PrepareRun().RunWithContext(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-private-key-file", "", "Path to TLS private key")
	cmd.Flags().IntVar(&securePort, "secure-port", 8443, "Secure serving port")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig for delegating authn/authz and request-header config lookups")
	cmd.Flags().StringVar(&zitadelIssuer, "zitadel-issuer", "", "Zitadel issuer URL")
	cmd.Flags().StringVar(&zitadelAPI, "zitadel-api", "", "Zitadel API base URL")
	cmd.Flags().StringVar(&zitadelKeyPath, "zitadel-key", "", "Path to Zitadel machine account key")

	// Wire klog flags to this command so users can set verbosity with -v=N
	goFS := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(goFS)
	cmd.Flags().AddGoFlagSet(goFS)

	return cmd
}
