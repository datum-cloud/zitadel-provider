package webhook

import (
	"context"
	"fmt"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Webhook struct {
	Handler  Handler
	Endpoint string
}

func NewAuthenticationWebhookV1(introspector *token.Introspector) *Webhook {
	return &Webhook{
		Handler: HandlerFunc(func(ctx context.Context, request Request) Response {
			log := logf.Log.WithName("authentication-webhook").WithValues()

			token := request.Spec.Token
			if token == "" {
				// If the token is empty we cannot authenticate the request.
				log.Info("Authentication failed: empty token provided")
				return Denied("empty token provided")
			}

			claims, err := introspector.Introspect(ctx, token)
			if err != nil {
				log.Error(err, "Token introspection failed")
				return Denied(fmt.Sprintf("token introspection failed: %v", err))
			}

			// Evaluate the "active" claim.
			if !claims.Active {
				// Token is valid syntactically but *inactive* (revoked or expired).
				log.Info("Authentication failed: JWT token is not active (revoked or expired)")
				return Denied("jwt token is not active")
			}

			// At this point the token is active – determine the username.
			username, err := claims.EffectiveUsername()
			if err != nil {
				log.Info("Authentication failed: " + err.Error())
				return Denied("token introspection failed: " + err.Error())
			}
			sub := claims.Sub

			// Email presence is the human/machine discriminator, matching
			// EffectiveUsername. nil leaves the key off for machine identities;
			// see Allowed for why absence and false are not interchangeable.
			var emailVerified *bool
			if claims.Email != "" {
				verified := claims.EmailVerified
				emailVerified = &verified
			}

			return Allowed(username, sub, emailVerified)
		}),
		Endpoint: "/apis/authentication.k8s.io/v1/tokenreviews",
	}
}
