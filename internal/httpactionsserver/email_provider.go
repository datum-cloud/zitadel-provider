package httpactionsserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// defaultEmailVerificationExpiryMinutes mirrors Zitadel's configured code
// lifetime. It is a COPY of state we do not own: the payload carries no expiry,
// so if the lifetime is changed in Zitadel this number silently starts lying to
// users. Keep them in step, or drop the line from the template.
const defaultEmailVerificationExpiryMinutes = 15

// Notification event types Zitadel's HTTP email provider emits.
//
// This set is INCOMPLETE and knowingly so. Wave 0's probe triggered only two
// flows against v4.12.2; invite, phone/OTP and domain-claim events were never
// exercised, and POST /v2/users/{id}/email/_resend 404s on that version so no
// distinct resend event was observed. Anything absent here lands in
// dispatchUnknown, which is how the rest of the set gets discovered in staging.
const (
	EventTypeEmailCodeAdded    = "user.human.email.code.added"
	EventTypePasswordCodeAdded = "user.human.password.code.added"
)

// LogMsgUnmappedNotificationEvent is the ALERTING CONTRACT for a dropped
// notification mail. Alert on this exact string.
//
// It is a log message rather than a metric because this binary exposes no
// /metrics endpoint — cmd/actionsserver serves the action routes only, and the
// controller-runtime registry used by internal/controller belongs to a
// different binary. A counter registered here would be scraped by nothing.
//
// Do not reword it without updating the alert.
const LogMsgUnmappedNotificationEvent = "UNMAPPED notification event type - email dropped"

// dispatchResult distinguishes three outcomes that must not be collapsed.
type dispatchResult int

const (
	// dispatchUnknown: we have never seen this event type. Activating the HTTP
	// provider disables SMTP, so this handler is the ONLY delivery path — an
	// unknown type is mail nobody will ever receive. Alert.
	dispatchUnknown dispatchResult = iota
	// dispatchDisabled: we know the event and an operator deliberately left its
	// template unset. Skip quietly, matching PasskeyAddedEmailTemplate's
	// "unconfigured means skip" posture.
	dispatchDisabled
	// dispatchMapped: send it.
	dispatchMapped
)

// emailProviderPayload is the body Zitadel's HTTP email provider POSTs,
// transcribed from a byte-exact v4.12.2 capture during Wave 0.
//
// templateData is deliberately NOT modelled. It carries Zitadel's PRE-RENDERED
// strings — subject, greeting, body text, and a url pointing at Zitadel's own
// login UI (/ui/login/mail/verification) that auth-ui replaces. We render from
// args instead, so the wording and the link are ours.
type emailProviderPayload struct {
	ContextInfo emailProviderContext `json:"contextInfo"`
	Args        emailProviderArgs    `json:"args"`
}

type emailProviderContext struct {
	EventType string `json:"eventType"`
	// RecipientEmailAddress is a literal address. No User resource exists at
	// signup time, which is why this receiver needs no milo lookup and why the
	// Email is addressed by EmailAddress rather than UserRef.
	RecipientEmailAddress string `json:"recipientEmailAddress"`
}

// emailProviderArgs is Zitadel's structured variable bag.
//
// A STRUCT, not a map[string]string, and that is load-bearing: args.loginNames
// is a JSON ARRAY sitting among sixteen strings, so a map[string]string decode
// fails outright. A struct ignores the fields we do not name.
//
// VerifiedEmail is deliberately absent: it is "" on a verification mail,
// because the address is not verified yet. Using it as a recipient sends mail
// to nobody.
type emailProviderArgs struct {
	Code               string `json:"code"`
	DisplayName        string `json:"displayName"`
	PreferredLoginName string `json:"preferredLoginName"`
	LoginName          string `json:"loginName"`
	UserID             string `json:"userID"`
	OrgID              string `json:"orgID"`
}

// eventTypeEnvelope is the minimal decode used for routing before the full
// parse. Kept separate so an unmapped or unconfigured event never pays for
// decoding a payload it will not use.
type eventTypeEnvelope struct {
	ContextInfo struct {
		EventType string `json:"eventType"`
	} `json:"contextInfo"`
}

// extractEventType reads contextInfo.eventType from the raw body.
//
// The caller must have validated the signature over these RAW bytes first: the
// MAC covers them exactly, so decoding and re-encoding invalidates it.
func extractEventType(body []byte) (string, error) {
	var envelope eventTypeEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("decode notification envelope: %w", err)
	}
	if envelope.ContextInfo.EventType == "" {
		return "", errors.New("payload carries no contextInfo.eventType")
	}
	return envelope.ContextInfo.EventType, nil
}

// resolveEmailTemplate maps a notification event type to the EmailTemplate that
// renders it.
func (s *Server) resolveEmailTemplate(eventType string) (string, dispatchResult) {
	var name string
	switch eventType {
	case EventTypeEmailCodeAdded:
		name = s.config.EmailVerificationTemplate
	case EventTypePasswordCodeAdded:
		name = s.config.PasswordResetTemplate
	default:
		return "", dispatchUnknown
	}
	if name == "" {
		return "", dispatchDisabled
	}
	return name, dispatchMapped
}

// emailProviderHandler receives Zitadel's HTTP email provider POSTs and turns
// them into milo Email resources.
//
// It acks unconditionally. A non-200 makes Zitadel retry a message we still
// cannot handle, and the mail is already lost either way — retrying only
// multiplies the noise.
func (s *Server) emailProviderHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("emailProviderHandler")

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// The email provider's signing key is NOT the Actions signing key. Zitadel
	// generates it when the provider is created (POST /admin/v1/email/http) and
	// returns it once, in that response.
	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.EmailProviderSigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}

	eventType, err := extractEventType(bodyBytes)
	if err != nil {
		log.Error(err, "Failed to read event type from payload")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	template, result := s.resolveEmailTemplate(eventType)
	switch result {
	case dispatchUnknown:
		log.Error(nil, LogMsgUnmappedNotificationEvent,
			"eventType", eventType,
			"consequence", "SMTP is disabled once the HTTP provider is active, so nothing else will deliver this")
		w.WriteHeader(http.StatusOK)
		return
	case dispatchDisabled:
		log.V(1).Info("Event type known but no template configured; skipping", "eventType", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	if err := s.sendProviderEmail(r.Context(), template, bodyBytes); err != nil {
		// Logged, not returned: Zitadel only needs the ack, matching every
		// other handler's fire-and-forget posture.
		log.Error(err, "Failed to create Email resource", "eventType", eventType, "template", template)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

// sendProviderEmail turns a notification payload into a milo Email resource.
func (s *Server) sendProviderEmail(ctx context.Context, template string, body []byte) error {
	var payload emailProviderPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode email provider payload: %w", err)
	}

	recipient := payload.ContextInfo.RecipientEmailAddress
	if recipient == "" {
		return errors.New("payload carries no contextInfo.recipientEmailAddress")
	}
	if payload.Args.Code == "" {
		return errors.New("payload carries no args.code")
	}

	// The verification code is unique per request, so (userID, code) is a
	// natural idempotency key: a redelivered POST collides on name and is
	// treated as success rather than sending a second mail.
	name := emailResourceName(payload.Args.UserID, payload.Args.Code)

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.config.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{Name: template},
			// Addressed literally: there is no User resource to reference at
			// signup time.
			Recipient: notificationv1alpha1.EmailRecipient{EmailAddress: recipient},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayNameFor(payload.Args, recipient)},
				{Name: "Code", Value: payload.Args.Code},
				{Name: "ActionUrl", Value: s.verificationURL(payload.Args)},
				{Name: "ExpiryMinutes", Value: strconv.Itoa(s.expiryMinutes())},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}

	if err := s.k8sClient.Create(ctx, email); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// A redelivery of a message already turned into an Email.
			return nil
		}
		return fmt.Errorf("failed to create Email resource %q: %w", name, err)
	}
	return nil
}

// emailResourceName builds a deterministic, DNS-1123-safe name from the
// idempotency key.
func emailResourceName(userID, code string) string {
	return strings.ToLower(fmt.Sprintf("email-%s-%s", userID, code))
}

// displayNameFor picks the friendliest available name, falling back to the
// recipient address so the greeting is never empty.
func displayNameFor(args emailProviderArgs, recipient string) string {
	for _, candidate := range []string{args.DisplayName, args.PreferredLoginName, args.LoginName} {
		if candidate != "" {
			return candidate
		}
	}
	return recipient
}

// verificationURL builds the link from OUR configured template.
//
// Named placeholders rather than a positional format string: with two
// same-typed values, a Sprintf template silently produces a wrong-but-valid URL
// if the arguments are ordered wrong, and nothing would catch it before a user
// clicked it.
//
// Zitadel's own templateData.url is ignored — it targets Zitadel's built-in
// login UI, which auth-ui replaces.
func (s *Server) verificationURL(args emailProviderArgs) string {
	return strings.NewReplacer(
		"{code}", args.Code,
		"{userID}", args.UserID,
		"{orgID}", args.OrgID,
	).Replace(s.config.EmailVerificationURLTemplate)
}

func (s *Server) expiryMinutes() int {
	if s.config.EmailVerificationExpiryMinutes > 0 {
		return s.config.EmailVerificationExpiryMinutes
	}
	return defaultEmailVerificationExpiryMinutes
}
