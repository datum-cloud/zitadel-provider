package webhookserver

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"go.miloapis.com/auth-provider-zitadel/internal/config"
	webhook "go.miloapis.com/auth-provider-zitadel/internal/webhook"
	token "go.miloapis.com/auth-provider-zitadel/pkg/token"
)

// NewAuthenticationWebhookServerCommand returns a cobra command that starts the UserDeactivation
// TokenReview webhook server.
func NewAuthenticationWebhookServerCommand(globalConfig *config.GlobalConfig) *cobra.Command {
	cfg := config.NewWebhookServerConfig()

	cmd := &cobra.Command{
		Use:   "authn-webhook",
		Short: "Runs the User Authentication TokenReview webhook server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWebhookServer(cmd, cfg)
		},
	}

	// Network & Kubernetes flags.
	cmd.Flags().IntVar(&cfg.WebhookPort, "webhook-port", 9443, "Port for the webhook server")
	cmd.Flags().StringVar(&cfg.CertDir, "cert-dir", "/etc/certs", "Directory that contains the TLS certs to use for serving the webhook")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", "", "Filename in the directory that contains the TLS cert")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", "", "Filename in the directory that contains the TLS private key")

	// Zitadel introspection flags.
	cmd.Flags().StringVar(&cfg.ZitadelPrivateKey, "zitadel-private-key", "private-key.json", "path to Zitadel private key JSON")
	cmd.Flags().StringVar(&cfg.ZitadelDomain, "zitadel-domain", "https://your_domain", "base URL of the Auth Provider instance (e.g., https://auth.example.com)")
	cmd.Flags().DurationVar(&cfg.JwtExpiration, "jwt-expiration", time.Hour, "JWT token expiration duration (e.g., 1h, 30m, 2h30m)")
	cmd.Flags().DurationVar(&cfg.JwtRefreshBefore, "jwt-refresh-before", 5*time.Minute, "Leeway before JWT expiry to consider cache invalid and force refresh (e.g., 5m)")

	// Metrics flags.
	cmd.Flags().StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", ":8080", "address the metrics endpoint binds to")

	// Email verification flags.
	cmd.Flags().StringVar(&cfg.EmailVerificationTemplate, "email-verification-template", cfg.EmailVerificationTemplate,
		"EmailTemplate resource for signup verification mail; empty disables the endpoint")
	cmd.Flags().StringVar(&cfg.NotificationNamespace, "notification-namespace", "milo-system",
		"Namespace in which Email resources are created")
	cmd.Flags().StringSliceVar(&cfg.EmailVerificationAllowedOrigins, "email-verification-allowed-origins", nil,
		"Allowlisted origins for returnTo, e.g. https://auth.example.net,http://localhost:3000")
	cmd.Flags().IntVar(&cfg.EmailVerificationExpiryMinutes, "email-verification-expiry-minutes", 60,
		"Code lifetime shown to users; must match Zitadel's configured lifetime")
	cmd.Flags().IntVar(&cfg.EmailVerificationUserLookupAttempts, "email-verification-user-lookup-attempts", 5,
		"Retry count when the verification request arrives before create-user-account has provisioned the Milo User")
	cmd.Flags().DurationVar(&cfg.EmailVerificationUserLookupBaseWait, "email-verification-user-lookup-base-wait", 200*time.Millisecond,
		"Initial backoff between email-verification user lookup retries")
	cmd.Flags().StringVar(&cfg.ClientCAFile, "client-ca-file", cfg.ClientCAFile,
		"CA bundle used to verify client certificates (mTLS)")

	return cmd
}

func runWebhookServer(cmd *cobra.Command, cfg *config.WebhookServerConfig) error {
	logf.SetLogger(zap.New(zap.JSONEncoder()))
	log := logf.Log.WithName("authentication-webhook")

	log.Info("Starting authentication webhook server",
		"cert_dir", cfg.CertDir,
		"cert_file", cfg.CertFile,
		"key_file", cfg.KeyFile,
		"webhook_port", cfg.WebhookPort,
	)

	log.Info("Creating auth provider introspector",
		"zitadel-private-key", cfg.ZitadelPrivateKey,
		"zitadel-domain", cfg.ZitadelDomain,
		"jwt-expiration", cfg.JwtExpiration,
		"jwt-cache-leeway", cfg.JwtRefreshBefore,
	)

	log.Info("Metrics bind address",
		"metrics-bind-address", cfg.MetricsBindAddress,
	)

	introspector, err := token.NewIntrospector(cfg.ZitadelPrivateKey, cfg.ZitadelDomain, cfg.JwtExpiration, cfg.JwtRefreshBefore)
	if err != nil {
		log.Error(err, "Failed to create auth provider introspector")
		return fmt.Errorf("failed to create auth provider introspector: %w", err)
	}
	log.Info("Successfully created token introspector")

	// Setup Kubernetes client config
	restConfig, err := k8sconfig.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get rest config: %w", err)
	}

	runtimeScheme := runtime.NewScheme()
	if err := authenticationv1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add authenticationv1 scheme: %w", err)
	}
	if err := iamv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add iam scheme: %w", err)
	}
	if err := notificationv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add notification scheme: %w", err)
	}

	log.Info("Creating manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Scheme: runtimeScheme,
		Metrics: server.Options{
			BindAddress: cfg.MetricsBindAddress,
		},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			CertDir:      cfg.CertDir,
			CertName:     cfg.CertFile,
			KeyName:      cfg.KeyFile,
			ClientCAName: cfg.ClientCAFile,
			Port:         cfg.WebhookPort,
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to create manager: %w", err)
	}

	log.Info("Setting up webhook server")
	hookServer := mgr.GetWebhookServer()

	webhookv1 := webhook.NewAuthenticationWebhookV1(introspector)
	hookServer.Register(webhookv1.Endpoint, webhookv1)

	if cfg.EmailVerificationTemplate != "" {
		// Uncached client: this reads a single User per request. The manager's cached
		// client would start an informer over every User for no benefit.
		directClient, err := client.New(restConfig, client.Options{Scheme: runtimeScheme})
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}
		verify := webhook.NewEmailVerificationHandler(directClient, webhook.EmailVerificationConfig{
			TemplateName:          cfg.EmailVerificationTemplate,
			NotificationNamespace: cfg.NotificationNamespace,
			AllowedOrigins:        cfg.EmailVerificationAllowedOrigins,
			ExpiryMinutes:         cfg.EmailVerificationExpiryMinutes,
			UserLookupAttempts:    cfg.EmailVerificationUserLookupAttempts,
			UserLookupBaseWait:    cfg.EmailVerificationUserLookupBaseWait,
		})
		hookServer.Register(verify.Endpoint, verify)
		log.Info("Registered email verification endpoint",
			"endpoint", verify.Endpoint,
			"allowedOrigins", cfg.EmailVerificationAllowedOrigins)
	} else {
		log.Info("Email verification endpoint disabled; no template configured")
	}

	log.Info("Starting manager")
	return mgr.Start(cmd.Context())
}
