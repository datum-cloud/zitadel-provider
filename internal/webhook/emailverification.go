package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// EmailVerificationEndpoint is the path auth-ui posts to.
const EmailVerificationEndpoint = "/v1/email/verification"

// EmailVerificationConfig is the operator-supplied half of the contract. Everything
// here is fixed at startup precisely so a request cannot influence it.
type EmailVerificationConfig struct {
	TemplateName          string
	NotificationNamespace string
	// AllowedOrigins is the returnTo allowlist. An empty list rejects everything,
	// which is the safe direction: a missing config must not become "allow any host".
	AllowedOrigins []string
	ExpiryMinutes  int
	// UserLookupAttempts and UserLookupBaseWait bound the retry in userWithRetry
	// below, which absorbs the signup race against create-user-account.
	UserLookupAttempts int
	UserLookupBaseWait time.Duration
}

type EmailVerificationHandler struct {
	Endpoint string

	client client.Client
	cfg    EmailVerificationConfig
}

func NewEmailVerificationHandler(c client.Client, cfg EmailVerificationConfig) *EmailVerificationHandler {
	return &EmailVerificationHandler{Endpoint: EmailVerificationEndpoint, client: c, cfg: cfg}
}

type emailVerificationRequest struct {
	UserID   string `json:"userId"`
	Code     string `json:"code"`
	ReturnTo string `json:"returnTo"`
}

func (h *EmailVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("emailVerificationHandler")

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req emailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.UserID == "" || req.Code == "" || req.ReturnTo == "" {
		http.Error(w, "userId, code and returnTo are required", http.StatusBadRequest)
		return
	}

	if !h.originAllowed(req.ReturnTo) {
		// Deliberately does not echo the value: this is the phishing guard, and the
		// rejected origin is attacker-controlled input.
		log.Info("Rejected returnTo outside the allowlist", "userId", req.UserID)
		http.Error(w, "returnTo is not allowed", http.StatusBadRequest)
		return
	}

	user, err := h.userWithRetry(r.Context(), req.UserID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("No User for verification mail", "userId", req.UserID)
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		log.Error(err, "Failed to read User", "userId", req.UserID)
		http.Error(w, "failed to read user", http.StatusInternalServerError)
		return
	}

	if err := h.createEmail(r.Context(), user, req); err != nil {
		// Bounded, not the raw error: req.Code (a bearer credential) is embedded in the
		// Email resource's Variables, and an apiserver validation rejection's message
		// ("Invalid value: ...") can echo a submitted field value straight back — every
		// other log site in this handler is deliberately clean of request-controlled
		// content (see the returnTo-rejection comment above). ReasonForError is a short,
		// fixed-vocabulary reason (e.g. "Invalid", "Timeout", "Forbidden"), never the code.
		reason := apierrors.ReasonForError(err)
		log.Error(fmt.Errorf("apiserver rejected Email create: %s", reason),
			"Failed to create verification Email", "userId", req.UserID)
		http.Error(w, "failed to create email", http.StatusInternalServerError)
		return
	}

	log.Info("Created verification Email", "userId", req.UserID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// originAllowed compares parsed scheme+host, not string prefixes: a prefix test
// admits "https://auth.example.test.evil.com" for an allowlisted
// "https://auth.example.test".
func (h *EmailVerificationHandler) originAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	got := u.Scheme + "://" + u.Host
	for _, allowed := range h.cfg.AllowedOrigins {
		a, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if got == a.Scheme+"://"+a.Host {
			return true
		}
	}
	return false
}

// userWithRetry absorbs the signup race: create-user-account provisions the milo User
// from the same Zitadel event that produced this code, so the User can be moments
// behind the request.
func (h *EmailVerificationHandler) userWithRetry(ctx context.Context, id string) (*iamv1alpha1.User, error) {
	attempts := h.cfg.UserLookupAttempts
	if attempts < 1 {
		attempts = 1
	}
	baseWait := h.cfg.UserLookupBaseWait
	if baseWait < 0 {
		baseWait = 0
	}

	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		user := &iamv1alpha1.User{}
		err := h.client.Get(ctx, client.ObjectKey{Name: id}, user)
		if err == nil {
			return user, nil
		}
		last = err
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * baseWait):
		}
	}
	return nil, last
}

func (h *EmailVerificationHandler) createEmail(ctx context.Context, user *iamv1alpha1.User, req emailVerificationRequest) error {
	displayName := strings.TrimSpace(user.Spec.GivenName + " " + user.Spec.FamilyName)
	if displayName == "" {
		displayName = user.Spec.Email
	}

	actionURL, err := buildActionURL(req.ReturnTo, req.Code, req.UserID)
	if err != nil {
		return fmt.Errorf("build action url: %w", err)
	}

	email := &notificationv1alpha1.Email{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Email",
			APIVersion: "notification.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("email-verification-%s", uuid.NewUUID()),
			Namespace: h.cfg.NotificationNamespace,
		},
		Spec: notificationv1alpha1.EmailSpec{
			TemplateRef: notificationv1alpha1.TemplateReference{Name: h.cfg.TemplateName},
			// Addressed by literal address, not UserRef: we already resolved it, and
			// UserRef would make delivery fail later if the User is reaped between
			// creation and send.
			Recipient: notificationv1alpha1.EmailRecipient{EmailAddress: user.Spec.Email},
			Variables: []notificationv1alpha1.EmailVariable{
				{Name: "UserName", Value: displayName},
				{Name: "Code", Value: req.Code},
				{Name: "ActionUrl", Value: actionURL},
				{Name: "ExpiryMinutes", Value: strconv.Itoa(h.cfg.ExpiryMinutes)},
			},
			Priority: notificationv1alpha1.EmailPriorityHigh,
		},
	}
	return h.client.Create(ctx, email)
}

func buildActionURL(returnTo, code, userID string) (string, error) {
	u, err := url.Parse(returnTo)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("userId", userID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
