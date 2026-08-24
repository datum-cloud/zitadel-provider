package httpactionsserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A-B1b-1. The route, the signature check and the dispatch decision. The
// payload parse and Email create land in A-B1b-2.

func newEmailProviderServer(t *testing.T, cfg *ServerConfig, validate ValidateSignatureFunc) *Server {
	t.Helper()
	if validate == nil {
		validate = func([]byte, string, string) error { return nil }
	}
	return &Server{config: cfg, validateSignature: validate}
}

func postEmailProvider(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/actions/email-provider", strings.NewReader(body))
	req.Header.Set("Zitadel-Signature", "t=1,v1=deadbeef")
	rec := httptest.NewRecorder()
	s.emailProviderHandler(rec, req)
	return rec
}

func envelope(eventType string) string {
	return `{"contextInfo":{"eventType":"` + eventType + `"},"args":{"code":"WL7S2F"}}`
}

// An unmapped event type must NOT 500. Zitadel would retry a message we still
// cannot map, and the mail is already lost. Ack, and log the alerting contract.
func TestEmailProvider_UnmappedEventType_Acks200(t *testing.T) {
	s := newEmailProviderServer(t, &ServerConfig{EmailVerificationTemplate: "tpl"}, nil)

	rec := postEmailProvider(t, s, envelope("user.human.phone.code.added"))

	if rec.Code != http.StatusOK {
		t.Fatalf("unmapped event must ack 200 so Zitadel does not retry, got %d", rec.Code)
	}
}

// A known event whose template is deliberately unset is a quiet skip, not an
// alert. Collapsing it with "unknown" would make the alert cry wolf on a
// configuration choice.
func TestEmailProvider_KnownButUnconfigured_Acks200(t *testing.T) {
	s := newEmailProviderServer(t, &ServerConfig{}, nil) // no templates set

	rec := postEmailProvider(t, s, envelope(EventTypeEmailCodeAdded))

	if rec.Code != http.StatusOK {
		t.Fatalf("unconfigured event must ack 200, got %d", rec.Code)
	}
}

func TestEmailProvider_BadSignature_Rejects401(t *testing.T) {
	s := newEmailProviderServer(t, &ServerConfig{EmailVerificationTemplate: "tpl"},
		func([]byte, string, string) error { return errors.New("bad signature") })

	rec := postEmailProvider(t, s, envelope(EventTypeEmailCodeAdded))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid signature must be rejected 401, got %d", rec.Code)
	}
}

// The signature is validated with the EMAIL PROVIDER's key, not the Actions
// key. They are different secrets: Zitadel generates the provider key at
// creation and returns it once. Wiring the Actions key would reject every mail.
func TestEmailProvider_UsesEmailProviderSigningKey(t *testing.T) {
	var got string
	s := newEmailProviderServer(t,
		&ServerConfig{
			SigningKey:                "actions-key",
			EmailProviderSigningKey:   "email-provider-key",
			EmailVerificationTemplate: "tpl",
		},
		func(_ []byte, _ string, key string) error { got = key; return nil },
	)

	postEmailProvider(t, s, envelope(EventTypeEmailCodeAdded))

	if got != "email-provider-key" {
		t.Fatalf("handler must validate with the email provider key, got %q", got)
	}
}

// The signature covers the RAW bytes, so the handler must validate before it
// decodes — a decode-then-re-encode would invalidate the MAC.
func TestEmailProvider_ValidatesRawBodyBytes(t *testing.T) {
	body := envelope(EventTypeEmailCodeAdded)
	var seen string
	s := newEmailProviderServer(t, &ServerConfig{EmailVerificationTemplate: "tpl"},
		func(payload []byte, _ string, _ string) error { seen = string(payload); return nil })

	postEmailProvider(t, s, body)

	if seen != body {
		t.Fatalf("validator must see the raw body verbatim\n got: %s\nwant: %s", seen, body)
	}
}

func TestEmailProvider_NonPost_Rejects405(t *testing.T) {
	s := newEmailProviderServer(t, &ServerConfig{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/actions/email-provider", nil)
	rec := httptest.NewRecorder()

	s.emailProviderHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must be rejected 405, got %d", rec.Code)
	}
}

func TestEmailProvider_MissingEventType_Rejects400(t *testing.T) {
	s := newEmailProviderServer(t, &ServerConfig{}, nil)

	rec := postEmailProvider(t, s, `{"contextInfo":{}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a payload with no eventType must be rejected 400, got %d", rec.Code)
	}
}

func TestResolveEmailTemplate(t *testing.T) {
	s := &Server{config: &ServerConfig{
		EmailVerificationTemplate: "verify-tpl",
		// PasswordResetTemplate deliberately unset.
	}}

	for _, tc := range []struct {
		name      string
		eventType string
		wantName  string
		wantRes   dispatchResult
	}{
		{"mapped", EventTypeEmailCodeAdded, "verify-tpl", dispatchMapped},
		{"known but unconfigured", EventTypePasswordCodeAdded, "", dispatchDisabled},
		{"unknown", "user.human.invite.code.added", "", dispatchUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, res := s.resolveEmailTemplate(tc.eventType)
			if name != tc.wantName || res != tc.wantRes {
				t.Fatalf("got (%q, %v), want (%q, %v)", name, res, tc.wantName, tc.wantRes)
			}
		})
	}
}

// A-B1b-2. The payload parse and Email create.

// capturedPayload is a byte-exact v4.12.2 capture from Wave 0's probe, with
// synthetic identifiers. loginNames is kept deliberately: it is the array field
// that makes a map[string]string decode fail, so it is the reason the args
// struct is a struct.
const capturedPayload = `{
  "contextInfo": {
    "eventType": "user.human.email.code.added",
    "provider": { "id": "385506071726260259", "description": "datum-http-email" },
    "recipientEmailAddress": "probe@example.test"
  },
  "templateData": {
    "subject": "Verify email",
    "greeting": "Hello Wave Two,",
    "url": "https://auth.localtest.me:30000/ui/login/mail/verification?code=WL7S2F&userID=385506184100053027",
    "buttonText": "Verify email"
  },
  "args": {
    "changeDate": "2026-08-09T11:39:03.765691Z",
    "code": "WL7S2F",
    "displayName": "Wave Two",
    "lastEmail": "probe@example.test",
    "loginName": "probe@example.test",
    "loginNames": ["probe@example.test"],
    "orgID": "377553834483974206",
    "preferredLoginName": "probe@example.test",
    "userID": "385506184100053027",
    "verifiedEmail": ""
  }
}`

func newSendingServer(t *testing.T) (*Server, client.Client) {
	t.Helper()
	k8s := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	return &Server{
		config: &ServerConfig{
			EmailVerificationTemplate:    "verify-tpl",
			EmailVerificationURLTemplate: "https://auth.example.test/verify-email?code={code}&userID={userID}",
			NotificationNamespace:        "default",
		},
		k8sClient:         k8s,
		validateSignature: func([]byte, string, string) error { return nil },
	}, k8s
}

func listProviderEmails(t *testing.T, c client.Client) *notificationv1alpha1.EmailList {
	t.Helper()
	var list notificationv1alpha1.EmailList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list emails: %v", err)
	}
	return &list
}

func varsOf(e notificationv1alpha1.Email) map[string]string {
	out := map[string]string{}
	for _, v := range e.Spec.Variables {
		out[v.Name] = v.Value
	}
	return out
}

// The whole path, against the real captured shape.
func TestEmailProvider_CapturedPayload_CreatesEmail(t *testing.T) {
	s, k8s := newSendingServer(t)

	rec := postEmailProvider(t, s, capturedPayload)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	list := listProviderEmails(t, k8s)
	if len(list.Items) != 1 {
		t.Fatalf("expected exactly one Email, got %d", len(list.Items))
	}
	e := list.Items[0]

	if e.Spec.TemplateRef.Name != "verify-tpl" {
		t.Errorf("templateRef = %q", e.Spec.TemplateRef.Name)
	}
	// Addressed literally: no User resource exists at signup time.
	if e.Spec.Recipient.EmailAddress != "probe@example.test" {
		t.Errorf("recipient = %q, want the literal address from contextInfo", e.Spec.Recipient.EmailAddress)
	}
	if e.Spec.Recipient.UserRef.Name != "" {
		t.Errorf("must not reference a User resource, got %q", e.Spec.Recipient.UserRef.Name)
	}

	vars := varsOf(e)
	if vars["UserName"] != "Wave Two" {
		t.Errorf("UserName = %q", vars["UserName"])
	}
	if vars["Code"] != "WL7S2F" {
		t.Errorf("Code = %q", vars["Code"])
	}
	if vars["ExpiryMinutes"] != "15" {
		t.Errorf("ExpiryMinutes = %q", vars["ExpiryMinutes"])
	}
}

// args.loginNames is an ARRAY. A map[string]string decode fails on it; a struct
// ignores it. This exists so nobody "simplifies" the args type into a map.
func TestEmailProvider_ArgsWithArrayField_StillDecodes(t *testing.T) {
	var payload emailProviderPayload
	if err := json.Unmarshal([]byte(capturedPayload), &payload); err != nil {
		t.Fatalf("the args struct must tolerate loginNames being an array: %v", err)
	}
	if payload.Args.Code != "WL7S2F" {
		t.Fatalf("code = %q", payload.Args.Code)
	}

	var asMap struct {
		Args map[string]string `json:"args"`
	}
	if err := json.Unmarshal([]byte(capturedPayload), &asMap); err == nil {
		t.Fatal("expected map[string]string to FAIL on args; if this ever passes, the payload shape changed")
	}
}

// Our URL, not Zitadel's. templateData.url points at Zitadel's own login UI,
// which auth-ui replaces — following it would 404 the user.
func TestEmailProvider_BuildsOwnActionURL(t *testing.T) {
	s, k8s := newSendingServer(t)

	postEmailProvider(t, s, capturedPayload)

	vars := varsOf(listProviderEmails(t, k8s).Items[0])
	want := "https://auth.example.test/verify-email?code=WL7S2F&userID=385506184100053027"
	if vars["ActionUrl"] != want {
		t.Fatalf("ActionUrl = %q, want %q", vars["ActionUrl"], want)
	}
	if strings.Contains(vars["ActionUrl"], "localtest.me") || strings.Contains(vars["ActionUrl"], "/ui/login/") {
		t.Fatal("ActionUrl must not come from templateData.url (Zitadel's own login UI)")
	}
}

// A redelivered POST must not send a second mail.
func TestEmailProvider_DuplicateDelivery_CreatesOneEmail(t *testing.T) {
	s, k8s := newSendingServer(t)

	postEmailProvider(t, s, capturedPayload)
	rec := postEmailProvider(t, s, capturedPayload)

	if rec.Code != http.StatusOK {
		t.Fatalf("redelivery must still ack 200, got %d", rec.Code)
	}
	if n := len(listProviderEmails(t, k8s).Items); n != 1 {
		t.Fatalf("expected one Email after a redelivery, got %d", n)
	}
}

// verifiedEmail is "" on a verification mail — it is not verified yet. The
// recipient must come from contextInfo, never from args.
func TestEmailProvider_RecipientNeverFromVerifiedEmail(t *testing.T) {
	s, k8s := newSendingServer(t)

	postEmailProvider(t, s, capturedPayload)

	if got := listProviderEmails(t, k8s).Items[0].Spec.Recipient.EmailAddress; got == "" {
		t.Fatal("recipient must be the literal contextInfo address, not the empty args.verifiedEmail")
	}
}

func TestDisplayNameFor_FallsBackToRecipient(t *testing.T) {
	for _, tc := range []struct {
		name string
		args emailProviderArgs
		want string
	}{
		{"display name wins", emailProviderArgs{DisplayName: "Wave Two", PreferredLoginName: "p@e.test"}, "Wave Two"},
		{"preferred login next", emailProviderArgs{PreferredLoginName: "p@e.test"}, "p@e.test"},
		{"login name next", emailProviderArgs{LoginName: "l@e.test"}, "l@e.test"},
		{"recipient last", emailProviderArgs{}, "fallback@e.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayNameFor(tc.args, "fallback@e.test"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
