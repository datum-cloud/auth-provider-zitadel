package zitadelapiserver

import (
	"context"
	"flag"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/apis/apiserver"
	authorizerfactory "k8s.io/apiserver/pkg/authorization/authorizerfactory"
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
// for the identity.miloapis.com/v1alpha1 group.
func NewAPIServerCommand(global *config.GlobalConfig) *cobra.Command {
	log := logf.Log.WithName("apiserver-cmd")

	var (
		tlsCertFile string
		tlsKeyFile  string
		securePort  int
		// RequestHeader front-proxy trust configuration
		requestHeaderCAFile           string
		requestHeaderAllowedNames     []string
		requestHeaderUsernameHeaders  []string
		requestHeaderGroupHeaders     []string
		requestHeaderUIDHeaders       []string
		requestHeaderExtraHeadersPref []string
		// Zitadel configuration (flags with env fallbacks)
		zitadelIssuer  string
		zitadelAPI     string
		zitadelKeyPath string
	)

	cmd := &cobra.Command{
		Use:   "apiserver",
		Short: "Run API server for Zitadel sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := config.InitializeLogging(global); err != nil {
				return fmt.Errorf("init logging: %w", err)
			}
			// Route klog through the controller-runtime logger and ensure flushing on exit
			klog.EnableContextualLogging(true)
			defer klog.Flush()
			log.Info("Starting API server")

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
			// Configure RequestHeader authn to trust Milo as a front-proxy
			authn := genericoptions.NewDelegatingAuthenticationOptions()
			authn.SkipInClusterLookup = true
			authn.Anonymous = &apiserver.AnonymousAuthConfig{Enabled: false}
			authn.RequestHeader.ClientCAFile = requestHeaderCAFile
			authn.RequestHeader.AllowedNames = requestHeaderAllowedNames
			authn.RequestHeader.UsernameHeaders = requestHeaderUsernameHeaders
			authn.RequestHeader.GroupHeaders = requestHeaderGroupHeaders
			authn.RequestHeader.UIDHeaders = requestHeaderUIDHeaders
			authn.RequestHeader.ExtraHeaderPrefixes = requestHeaderExtraHeadersPref
			ro.Authentication = authn
			// Use an allow-all authorizer so Milo acts as PDP
			ro.Authorization = nil
			ro.Etcd = nil
			ro.Admission = nil
			ro.CoreAPI = nil
			ro.Audit = nil
			ro.Features.EnablePriorityAndFairness = false

			cfg := genericserver.NewRecommendedConfig(codecs)
			if err := ro.ApplyTo(cfg); err != nil {
				return fmt.Errorf("apply recommended options: %w", err)
			}

			// Always-allow authorizer (treat Milo front-proxy as PDP)
			cfg.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
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
			cfg.OpenAPIConfig.Info.Title = "Milo Sessions API"
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

			log.Info("API server is starting")
			return srv.PrepareRun().RunWithContext(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS certificate")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-private-key-file", "", "Path to TLS private key")
	cmd.Flags().IntVar(&securePort, "secure-port", 8443, "Secure serving port")
	// RequestHeader trust configuration flags
	cmd.Flags().StringVar(&requestHeaderCAFile, "requestheader-client-ca-file", "", "Path to PEM CA bundle that signs Milo's proxy client cert")
	cmd.Flags().StringSliceVar(&requestHeaderAllowedNames, "requestheader-allowed-names", nil, "Allowed CNs for Milo proxy client cert; empty means any signed by CA")
	cmd.Flags().StringSliceVar(&requestHeaderUsernameHeaders, "requestheader-username-headers", nil, "Header names to determine user identity")
	cmd.Flags().StringSliceVar(&requestHeaderGroupHeaders, "requestheader-group-headers", nil, "Header names to determine user groups")
	cmd.Flags().StringSliceVar(&requestHeaderUIDHeaders, "requestheader-uid-headers", nil, "Header names to determine user UID")
	cmd.Flags().StringSliceVar(&requestHeaderExtraHeadersPref, "requestheader-extra-headers-prefix", nil, "Header name prefixes to determine user extra info")
	cmd.Flags().StringVar(&zitadelIssuer, "zitadel-issuer", "", "Zitadel issuer URL")
	cmd.Flags().StringVar(&zitadelAPI, "zitadel-api", "", "Zitadel API base URL")
	cmd.Flags().StringVar(&zitadelKeyPath, "zitadel-key", "", "Path to Zitadel machine account key")

	// Wire klog flags to this command so users can set verbosity with -v=N
	goFS := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(goFS)
	cmd.Flags().AddGoFlagSet(goFS)

	return cmd
}
