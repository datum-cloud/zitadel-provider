package httpactionsserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
)

func TestPasskeyAddedHandlerErrorPaths(t *testing.T) {
	const validBody = `{"aggregateID":"user-1","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","userID":"user-1","event_payload":{"webAuthNTokenId":"pk-abc123","webAuthNTokenName":"MacBook Touch ID"}}`

	okSig := func(payload []byte, header, signingKey string) error { return nil }
	failSig := func(payload []byte, header, signingKey string) error { return errors.New("bad signature") }

	tests := []struct {
		name       string
		method     string
		body       string
		sig        ValidateSignatureFunc
		wantStatus int
	}{
		{
			name:       "wrong method returns 405",
			method:     http.MethodGet,
			body:       validBody,
			sig:        okSig,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "signature failure returns 401",
			method:     http.MethodPost,
			body:       validBody,
			sig:        failSig,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid json returns 400",
			method:     http.MethodPost,
			body:       "{not-json",
			sig:        okSig,
			wantStatus: http.StatusBadRequest,
		},
		{
			// token.added is confirmed live and bindable too, but this
			// handler is intentionally bound to token.verified only (see
			// EventTypePasskeyVerified's doc comment) — token.added must
			// still be rejected as unsupported here.
			name:       "token.added (enrollment start, not completion) is rejected as unsupported event type",
			method:     http.MethodPost,
			body:       `{"event_type":"user.human.passwordless.token.added","userID":"user-1"}`,
			sig:        okSig,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "token.removed is rejected as unsupported event type",
			method:     http.MethodPost,
			body:       `{"event_type":"user.human.passwordless.token.removed","userID":"user-1"}`,
			sig:        okSig,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing userID returns 400",
			method:     http.MethodPost,
			body:       `{"event_type":"user.human.passwordless.token.verified"}`,
			sig:        okSig,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				config:            &ServerConfig{},
				validateSignature: tt.sig,
				k8sClient:         fake.NewClientBuilder().WithScheme(newTestScheme()).Build(),
			}

			req := httptest.NewRequest(tt.method, "/v1/actions/passkey-added", bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			server.passkeyAddedHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestPasskeyAddedHandlerSuccess(t *testing.T) {
	const (
		userID    = "362926680773230861"
		namespace = "milo-system"
		template  = "emailtemplates.notification.miloapis.com-userpasskeyaddedemailtemplate"
	)
	const validBody = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","userID":"362926680773230861","event_payload":{"webAuthNTokenId":"pk-abc123","webAuthNTokenName":"MacBook Touch ID"}}`

	okSig := func(payload []byte, header, signingKey string) error { return nil }
	user := &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: userID},
		Spec: iamv1alpha1.UserSpec{
			GivenName:  "Jane",
			FamilyName: "Doe",
			Email:      "jane.doe@example.com",
		},
	}

	t.Run("template unconfigured returns 200 with no Email created", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		server := &Server{
			config:            &ServerConfig{NotificationNamespace: namespace},
			validateSignature: okSig,
			k8sClient:         k8s,
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-added", bytes.NewReader([]byte(validBody)))
		w := httptest.NewRecorder()
		server.passkeyAddedHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 0 {
			t.Errorf("expected 0 emails, got %d", len(emails.Items))
		}
	})

	t.Run("template configured creates exactly one Email with the pinned variable set", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		server := &Server{
			config:            &ServerConfig{PasskeyAddedEmailTemplate: template, NotificationNamespace: namespace},
			validateSignature: okSig,
			k8sClient:         k8s,
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-added", bytes.NewReader([]byte(validBody)))
		w := httptest.NewRecorder()
		server.passkeyAddedHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}

		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 1 {
			t.Fatalf("expected exactly 1 Email resource, got %d", len(emails.Items))
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

		// Cross-lane contract: the variable set must be exactly these five
		// names — no more, no less — to match the merged user-passkey-added
		// template.
		if len(e.Spec.Variables) != 5 {
			t.Fatalf("expected exactly 5 variables, got %d: %+v", len(e.Spec.Variables), e.Spec.Variables)
		}
		vars := make(map[string]string, len(e.Spec.Variables))
		for _, v := range e.Spec.Variables {
			vars[v.Name] = v.Value
		}
		for _, name := range []string{"UserName", "PasskeyName", "AddedTime", "Browser", "Device"} {
			if _, ok := vars[name]; !ok {
				t.Errorf("missing required variable %q", name)
			}
		}

		if vars["UserName"] != "Jane Doe" {
			t.Errorf("UserName = %q, want %q", vars["UserName"], "Jane Doe")
		}
		if vars["AddedTime"] == "" {
			t.Error("expected non-empty AddedTime variable")
		}
		// The bound event is token.verified (HumanWebAuthNVerifiedEvent),
		// whose payload carries the user-assigned name as
		// webAuthNTokenName — the fixture body sets it to "MacBook Touch
		// ID", so it must land here verbatim.
		if vars["PasskeyName"] != "MacBook Touch ID" {
			t.Errorf("PasskeyName = %q, want %q", vars["PasskeyName"], "MacBook Touch ID")
		}
		// Browser and Device have no source at all in this event
		// (HumanWebAuthNVerifiedEvent carries key material and the token
		// name, not user-agent data) and must come through empty rather
		// than fabricated.
		if vars["Browser"] != "" {
			t.Errorf("Browser = %q, want empty (not derivable from this event)", vars["Browser"])
		}
		if vars["Device"] != "" {
			t.Errorf("Device = %q, want empty (not derivable from this event)", vars["Device"])
		}
	})

	t.Run("falls back to the speculative name field when webAuthNTokenName is absent", func(t *testing.T) {
		// Documents the fallback path in passkeyAddedRequest.passkeyName:
		// webAuthNTokenName is the confirmed field, but if the live Actions
		// v2 envelope ever ships a bare "name" instead, it's still picked
		// up rather than silently dropped.
		const bodyWithFallbackName = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","userID":"362926680773230861","event_payload":{"webAuthNTokenId":"pk-abc123","name":"Fallback Name"}}`
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		server := &Server{
			config:            &ServerConfig{PasskeyAddedEmailTemplate: template, NotificationNamespace: namespace},
			validateSignature: okSig,
			k8sClient:         k8s,
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-added", bytes.NewReader([]byte(bodyWithFallbackName)))
		w := httptest.NewRecorder()
		server.passkeyAddedHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 1 {
			t.Fatalf("expected exactly 1 Email resource, got %d", len(emails.Items))
		}
		vars := make(map[string]string, len(emails.Items[0].Spec.Variables))
		for _, v := range emails.Items[0].Spec.Variables {
			vars[v.Name] = v.Value
		}
		if vars["PasskeyName"] != "Fallback Name" {
			t.Errorf("PasskeyName = %q, want %q", vars["PasskeyName"], "Fallback Name")
		}
	})

	t.Run("webAuthNTokenName takes priority over the fallback name field", func(t *testing.T) {
		const bodyWithBoth = `{"aggregateID":"362926680773230861","event_type":"user.human.passwordless.token.verified","created_at":"2026-07-21T12:00:00Z","userID":"362926680773230861","event_payload":{"webAuthNTokenId":"pk-abc123","webAuthNTokenName":"Primary Name","name":"Fallback Name"}}`
		k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).WithObjects(user).Build()
		server := &Server{
			config:            &ServerConfig{PasskeyAddedEmailTemplate: template, NotificationNamespace: namespace},
			validateSignature: okSig,
			k8sClient:         k8s,
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/actions/passkey-added", bytes.NewReader([]byte(bodyWithBoth)))
		w := httptest.NewRecorder()
		server.passkeyAddedHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
		}
		emails := &notificationv1alpha1.EmailList{}
		if err := k8s.List(context.Background(), emails); err != nil {
			t.Fatalf("list emails: %v", err)
		}
		if len(emails.Items) != 1 {
			t.Fatalf("expected exactly 1 Email resource, got %d", len(emails.Items))
		}
		vars := make(map[string]string, len(emails.Items[0].Spec.Variables))
		for _, v := range emails.Items[0].Spec.Variables {
			vars[v.Name] = v.Value
		}
		if vars["PasskeyName"] != "Primary Name" {
			t.Errorf("PasskeyName = %q, want %q", vars["PasskeyName"], "Primary Name")
		}
	})
}
