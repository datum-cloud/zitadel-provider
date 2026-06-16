package httpactionsserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

type mockZitadelAPI struct {
	listSessionsFunc func(ctx context.Context, userID string) ([]zitadel.Session, error)
}

func (m *mockZitadelAPI) ListSessions(ctx context.Context, userID string) ([]zitadel.Session, error) {
	if m.listSessionsFunc != nil {
		return m.listSessionsFunc(ctx, userID)
	}
	return nil, nil
}
func (m *mockZitadelAPI) GetSession(ctx context.Context, sessionID string) (*zitadel.Session, error) {
	return nil, nil
}
func (m *mockZitadelAPI) DeleteSession(ctx context.Context, userID, sessionID string) error {
	return nil
}
func (m *mockZitadelAPI) ListIDPLinks(ctx context.Context, userID string) ([]zitadel.IDPLink, error) {
	return nil, nil
}
func (m *mockZitadelAPI) CreateOrganization(ctx context.Context, name string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) CreateOrganizationWithID(ctx context.Context, name, customOrgID string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) DeleteOrganization(ctx context.Context, orgID string) error { return nil }
func (m *mockZitadelAPI) GetOrganization(ctx context.Context, orgID string) (*zitadel.Organization, error) {
	return nil, nil
}
func (m *mockZitadelAPI) GetUserByID(ctx context.Context, userID string) (*zitadel.User, error) {
	return nil, nil
}
func (m *mockZitadelAPI) GetMachineUserByUsername(ctx context.Context, orgID, username string) (*zitadel.User, error) {
	return nil, nil
}
func (m *mockZitadelAPI) AddMachineUserInOrganization(ctx context.Context, orgID, userID, username, displayName string) (string, error) {
	return "", nil
}
func (m *mockZitadelAPI) DeleteUser(ctx context.Context, userID string) error            { return nil }
func (m *mockZitadelAPI) DeactivateUser(ctx context.Context, orgID, userID string) error { return nil }
func (m *mockZitadelAPI) ReactivateUser(ctx context.Context, orgID, userID string) error { return nil }
func (m *mockZitadelAPI) ListMachineAccountsInOrganization(ctx context.Context, orgID string) ([]*zitadel.User, error) {
	return nil, nil
}
func (m *mockZitadelAPI) AddMachineKeyInOrganization(ctx context.Context, orgID, userID string, publicKey []byte, expirationDate *time.Time) (string, []byte, error) {
	return "", nil, nil
}
func (m *mockZitadelAPI) ListMachineKeysInOrganization(ctx context.Context, orgID, userID string) ([]*zitadel.MachineKey, error) {
	return nil, nil
}
func (m *mockZitadelAPI) RemoveMachineKeyInOrganization(ctx context.Context, orgID, userID, keyID string) error {
	return nil
}

// logEntry captures a single structured log record emitted during a test.
type logEntry struct {
	msg string
	kv  map[string]any
}

// captureSink is a minimal logr.LogSink that records Info records so tests can
// assert on structured fields instead of scraping stdout.
type captureSink struct {
	entries *[]logEntry
}

func (s captureSink) Init(logr.RuntimeInfo) {}
func (s captureSink) Enabled(int) bool      { return true }
func (s captureSink) Info(_ int, msg string, kvs ...any) {
	kv := make(map[string]any, len(kvs)/2)
	for i := 0; i+1 < len(kvs); i += 2 {
		key, _ := kvs[i].(string)
		kv[key] = kvs[i+1]
	}
	*s.entries = append(*s.entries, logEntry{msg: msg, kv: kv})
}
func (s captureSink) Error(_ error, msg string, kvs ...any) { s.Info(0, msg, kvs...) }
func (s captureSink) WithValues(...any) logr.LogSink        { return s }
func (s captureSink) WithName(string) logr.LogSink          { return s }

// newTestScheme builds a runtime.Scheme that includes all API groups used by
// the handler under test.
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = iamv1alpha1.AddToScheme(s)
	_ = notificationv1alpha1.AddToScheme(s)
	return s
}

// findEntry returns the first captured entry with the given message, or nil.
func findEntry(entries []logEntry, msg string) *logEntry {
	for i := range entries {
		if entries[i].msg == msg {
			return &entries[i]
		}
	}
	return nil
}

func TestSessionAddedHandler(t *testing.T) {
	tests := []struct {
		name           string
		reqPayload     sessionAddedRequest
		mockSessions   []zitadel.Session
		wantSuspicious bool
		wantDevice     string
		wantBrowser    string
	}{
		{
			name: "First login ever (no previous sessions)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
			},
			wantSuspicious: false,
		},
		{
			name: "Same IP and UA (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: false,
		},
		{
			name: "Different IP (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "2.2.2.2",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "2.2.2.2",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "Mac",
			wantBrowser:    "Chrome",
		},
		{
			name: "Different Browser (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "iPhone",
			wantBrowser:    "Firefox",
		},
		{
			name: "Mobile Firefox and oidc_session.added (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "031d5d16-1258-4681-afb8-579fbc3871bb",
						Description:   "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Firefox/100.0",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-prev",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "iPhone",
			wantBrowser:    "Firefox",
		},
		{
			name: "Different Fingerprint ID but same IP and UA (suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "new-fingerprint",
						Description:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:            "sess-prev",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "old-fingerprint",
					CreatedAt:     time.Now().Add(-1 * time.Hour),
				},
			},
			wantSuspicious: true,
			wantDevice:     "Mac",
			wantBrowser:    "Chrome",
		},
		{
			// Regression: the most-recent *other* session has a rotated
			// fingerprint, but the current fingerprint reappears in an older
			// session — a returning device, so this must NOT be flagged.
			name: "Returning fingerprint seen in older session (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:            "1.1.1.1",
						FingerprintID: "known-fingerprint",
						Description:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:            "sess-curr",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "known-fingerprint",
					CreatedAt:     time.Now(),
				},
				{
					ID:            "sess-recent",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "rotated-fingerprint",
					CreatedAt:     time.Now().Add(-1 * time.Hour),
				},
				{
					ID:            "sess-old",
					UserID:        "user-1",
					IP:            "1.1.1.1",
					UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					FingerprintID: "known-fingerprint",
					CreatedAt:     time.Now().Add(-24 * time.Hour),
				},
			},
		},
		{
			name: "IP and UA match different past sessions in history (not suspicious)",
			reqPayload: sessionAddedRequest{
				AggregateID: "sess-curr",
				EventType:   "oidc_session.added",
				UserID:      "user-1",
				EventPayload: struct {
					UserID    string     `json:"userID"`
					SessionID string     `json:"sessionID"`
					UserAgent *userAgent `json:"userAgent"`
				}{
					UserID: "user-1",
					UserAgent: &userAgent{
						IP:          "1.1.1.1",
						Description: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					},
				},
			},
			mockSessions: []zitadel.Session{
				{
					ID:        "sess-curr",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now(),
				},
				{
					ID:        "sess-recent",
					UserID:    "user-1",
					IP:        "2.2.2.2",
					UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36",
					CreatedAt: time.Now().Add(-1 * time.Hour),
				},
				{
					ID:        "sess-old",
					UserID:    "user-1",
					IP:        "1.1.1.1",
					UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
					CreatedAt: time.Now().Add(-2 * time.Hour),
				},
			},
			wantSuspicious: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockZitadelAPI{
				listSessionsFunc: func(ctx context.Context, userID string) ([]zitadel.Session, error) {
					return tt.mockSessions, nil
				},
			}

			server := &Server{
				// SuspiciousLoginEmailTemplate is intentionally empty so the
				// email path is skipped and no k8s User lookup is needed.
				config:            &ServerConfig{},
				validateSignature: func(payload []byte, header string, signingKey string) error { return nil },
				zitadelClient:     mockClient,
				k8sClient:         fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
			}

			payloadBytes, err := json.Marshal(tt.reqPayload)
			if err != nil {
				t.Fatalf("failed to marshal request payload: %v", err)
			}

			var entries []logEntry
			ctx := logf.IntoContext(context.Background(), logr.New(captureSink{entries: &entries}))
			req := httptest.NewRequest(http.MethodPost, "/v1/actions/session-added", bytes.NewReader(payloadBytes)).WithContext(ctx)
			w := httptest.NewRecorder()

			server.sessionAddedHandler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status OK, got %d. Body: %s", w.Code, w.Body.String())
			}

			susp := findEntry(entries, "Suspicious login detected")
			isSuspicious := susp != nil
			if isSuspicious != tt.wantSuspicious {
				t.Errorf("expected suspicious to be %v, got %v. Captured entries: %+v", tt.wantSuspicious, isSuspicious, entries)
			}

			if tt.wantSuspicious {
				if susp.kv["device"] != tt.wantDevice {
					t.Errorf("expected device %q, got %v", tt.wantDevice, susp.kv["device"])
				}
				if susp.kv["browser"] != tt.wantBrowser {
					t.Errorf("expected browser %q, got %v", tt.wantBrowser, susp.kv["browser"])
				}
			}
		})
	}
}

func TestSessionAddedHandlerErrorPaths(t *testing.T) {
	const validBody = `{"event_type":"oidc_session.added","aggregateID":"sess-curr","event_payload":{"userID":"user-1"}}`

	okSig := func(payload []byte, header, signingKey string) error { return nil }
	failSig := func(payload []byte, header, signingKey string) error { return errors.New("bad signature") }

	mock := &mockZitadelAPI{
		listSessionsFunc: func(ctx context.Context, userID string) ([]zitadel.Session, error) {
			return nil, nil
		},
	}

	tests := []struct {
		name       string
		method     string
		body       string
		sig        ValidateSignatureFunc
		client     zitadel.API
		wantStatus int
	}{
		{
			name:       "wrong method returns 405",
			method:     http.MethodGet,
			body:       validBody,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "signature failure returns 401",
			method:     http.MethodPost,
			body:       validBody,
			sig:        failSig,
			client:     mock,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid json returns 400",
			method:     http.MethodPost,
			body:       "{not-json",
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unsupported event type returns 400",
			method:     http.MethodPost,
			body:       `{"event_type":"user.added","event_payload":{"userID":"user-1"}}`,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing userID returns 400",
			method:     http.MethodPost,
			body:       `{"event_type":"oidc_session.added"}`,
			sig:        okSig,
			client:     mock,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "nil zitadel client returns 503",
			method:     http.MethodPost,
			body:       validBody,
			sig:        okSig,
			client:     nil,
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				config:            &ServerConfig{},
				validateSignature: tt.sig,
				zitadelClient:     tt.client,
				k8sClient:         fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
			}

			req := httptest.NewRequest(tt.method, "/v1/actions/session-added", bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			server.sessionAddedHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestSendSuspiciousLoginEmail(t *testing.T) {
	const (
		userID    = "362926680773230861"
		namespace = "milo-system"
		template  = "emailtemplates.notification.miloapis.com-usersuspiciousemailtemplate"
	)

	user := &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: userID},
		Spec: iamv1alpha1.UserSpec{
			GivenName:  "Jane",
			FamilyName: "Doe",
			Email:      "jane.doe@example.com",
		},
	}

	t.Run("skips when template not configured", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
		s := &Server{
			config:    &ServerConfig{NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		var entries []logEntry
		log := logr.New(captureSink{entries: &entries})
		if err := sendSuspiciousLoginEmail(context.Background(), log, s, userID, "2026-06-05T12:00:00Z", "1.2.3.4", "Mac", "Safari", "Brazil"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if findEntry(entries, "Suspicious login email template not configured; skipping notification") == nil {
			t.Error("expected skip log entry, got none")
		}
		// Confirm no Email resource was created.
		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 0 {
			t.Errorf("expected 0 emails, got %d", len(emails.Items))
		}
	})

	t.Run("returns error when user not found", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
		s := &Server{
			config:    &ServerConfig{SuspiciousLoginEmailTemplate: template, NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		log := logr.New(captureSink{entries: &[]logEntry{}})
		err := sendSuspiciousLoginEmail(context.Background(), log, s, "nonexistent-user", "2026-06-05T12:00:00Z", "1.2.3.4", "Mac", "Safari", "Brazil")
		if err == nil {
			t.Error("expected error for missing user, got nil")
		}
	})

	t.Run("creates Email resource with correct fields", func(t *testing.T) {
		k8s := fake.NewClientBuilder().
			WithScheme(newTestScheme()).
			WithObjects(user).
			Build()
		s := &Server{
			config:    &ServerConfig{SuspiciousLoginEmailTemplate: template, NotificationNamespace: namespace},
			k8sClient: k8s,
		}
		var entries []logEntry
		log := logr.New(captureSink{entries: &entries})

		if err := sendSuspiciousLoginEmail(context.Background(), log, s, userID, "2026-06-05T12:00:00Z", "186.158.228.76", "Mac", "Safari", "Brazil"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 1 {
			t.Fatalf("expected 1 Email resource, got %d", len(emails.Items))
		}
		e := emails.Items[0]

		if e.Namespace != namespace {
			t.Errorf("expected namespace %q, got %q", namespace, e.Namespace)
		}
		if e.Spec.TemplateRef.Name != template {
			t.Errorf("expected template %q, got %q", template, e.Spec.TemplateRef.Name)
		}
		if e.Spec.Recipient.UserRef.Name != userID {
			t.Errorf("expected userRef.name %q, got %q", userID, e.Spec.Recipient.UserRef.Name)
		}
		if e.Spec.Priority != notificationv1alpha1.EmailPriorityHigh {
			t.Errorf("expected priority high, got %q", e.Spec.Priority)
		}

		vars := make(map[string]string, len(e.Spec.Variables))
		for _, v := range e.Spec.Variables {
			vars[v.Name] = v.Value
		}
		checks := map[string]string{
			"UserName":  "Jane Doe",
			"Email":     "jane.doe@example.com",
			"IpAddress": "186.158.228.76",
			"Location":  "Brazil",
			"Browser":   "Safari",
			"Device":    "Mac",
		}
		for k, want := range checks {
			if got := vars[k]; got != want {
				t.Errorf("variable %q: expected %q, got %q", k, want, got)
			}
		}
		if vars["SignInTime"] == "" {
			t.Error("expected non-empty SignInTime variable")
		}
		if findEntry(entries, "Suspicious login notification email created") == nil {
			t.Error("expected success log entry, got none")
		}
	})
}

func TestParseDeviceAndBrowser(t *testing.T) {
	tests := []struct {
		ua          string
		wantDevice  string
		wantBrowser string
	}{
		{
			ua:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantDevice:  "Windows PC",
			wantBrowser: "Chrome",
		},
		{
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			wantDevice:  "Mac",
			wantBrowser: "Safari",
		},
		{
			ua:          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			wantDevice:  "iPhone",
			wantBrowser: "Safari",
		},
		{
			ua:          "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			wantDevice:  "Android Device",
			wantBrowser: "Chrome",
		},
		{
			ua:          "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
			wantDevice:  "Linux PC",
			wantBrowser: "Firefox",
		},
		{
			ua:          "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15",
			wantDevice:  "iPad",
			wantBrowser: "Firefox",
		},
		{
			ua:          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			wantDevice:  "Mac",
			wantBrowser: "Edge",
		},
		{
			ua:          "Unknown user agent",
			wantDevice:  "Unknown Device",
			wantBrowser: "Unknown Browser",
		},
		{
			ua:          "Safari, 26.3.1, ,  Apple, Macintosh, , WebKit, 605.1.15, , Mac OS, 10.15.7, ",
			wantDevice:  "Mac",
			wantBrowser: "Safari",
		},
		{
			ua:          "Chrome, 148.0.7778.166, , mobile, Apple, iPhone, , WebKit, 605.1.15, , iOS, 26.1.0, ",
			wantDevice:  "iPhone",
			wantBrowser: "Chrome",
		},
	}

	for _, tt := range tests {
		gotDevice := parseDevice(tt.ua)
		gotBrowser := parseBrowser(tt.ua)
		if gotDevice != tt.wantDevice {
			t.Errorf("parseDevice(%q) = %q, want %q", tt.ua, gotDevice, tt.wantDevice)
		}
		if gotBrowser != tt.wantBrowser {
			t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, gotBrowser, tt.wantBrowser)
		}
	}
}
