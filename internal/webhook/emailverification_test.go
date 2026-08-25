package webhook

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	notificationv1alpha1 "go.miloapis.com/milo/pkg/apis/notification/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := iamv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := notificationv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newHandler(t *testing.T, objs ...client.Object) (*EmailVerificationHandler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	h := NewEmailVerificationHandler(c, EmailVerificationConfig{
		TemplateName:          "verify-tpl",
		NotificationNamespace: "default",
		AllowedOrigins:        []string{"https://auth.example.test", "http://localhost:3000"},
		ExpiryMinutes:         60,
		UserLookupAttempts:    5,
		UserLookupBaseWait:    200 * time.Millisecond,
	})
	return h, c
}

func testUser() *iamv1alpha1.User {
	return &iamv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-1"},
		Spec: iamv1alpha1.UserSpec{
			Email: "person@example.test", GivenName: "Ada", FamilyName: "Lovelace",
		},
	}
}

func post(t *testing.T, h *EmailVerificationHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/email/verification", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func emails(t *testing.T, c client.Client) []notificationv1alpha1.Email {
	t.Helper()
	var list notificationv1alpha1.EmailList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func varsOf(e notificationv1alpha1.Email) map[string]string {
	out := map[string]string{}
	for _, v := range e.Spec.Variables {
		out[v.Name] = v.Value
	}
	return out
}

// The recipient must come from milo, never from the request. This is the property
// that bounds what a compromised auth-ui can do.
func TestEmailVerification_RecipientComesFromMilo(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	list := emails(t, c)
	if len(list) != 1 {
		t.Fatalf("expected one Email, got %d", len(list))
	}
	if got := list[0].Spec.Recipient.EmailAddress; got != "person@example.test" {
		t.Fatalf("recipient = %q, want the address from milo", got)
	}
	if got := list[0].Spec.TemplateRef.Name; got != "verify-tpl" {
		t.Fatalf("template = %q, want the configured one", got)
	}
}

func TestEmailVerification_BuildsAllTemplateVariables(t *testing.T) {
	h, c := newHandler(t, testUser())

	post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)

	v := varsOf(emails(t, c)[0])
	if v["UserName"] != "Ada Lovelace" {
		t.Errorf("UserName = %q", v["UserName"])
	}
	if v["Code"] != "ABC123" {
		t.Errorf("Code = %q", v["Code"])
	}
	if v["ExpiryMinutes"] != "60" {
		t.Errorf("ExpiryMinutes = %q", v["ExpiryMinutes"])
	}
	want := "https://auth.example.test/id/signup/complete?code=ABC123&userId=user-1"
	if v["ActionUrl"] != want {
		t.Errorf("ActionUrl = %q, want %q", v["ActionUrl"], want)
	}
}

// A foreign returnTo would mail a REAL code pointing at an attacker domain.
func TestEmailVerification_RejectsUnallowlistedReturnTo(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://evil.example/steal"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("no Email may be created for a rejected origin, got %d", n)
	}
}

// Prefix matching must not admit "https://auth.example.test.evil.com".
func TestEmailVerification_AllowlistMatchesOriginNotPrefix(t *testing.T) {
	h, c := newHandler(t, testUser())

	rec := post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test.evil.com/x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for lookalike host, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestEmailVerification_UnknownUserIs404AndSendsNothing(t *testing.T) {
	h, c := newHandler(t)

	rec := post(t, h, `{"userId":"nobody","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if n := len(emails(t, c)); n != 0 {
		t.Fatalf("expected no Email, got %d", n)
	}
}

func TestEmailVerification_MissingFieldsRejected(t *testing.T) {
	h, _ := newHandler(t, testUser())

	for name, body := range map[string]string{
		"no userId":   `{"code":"A","returnTo":"https://auth.example.test/x"}`,
		"no code":     `{"userId":"user-1","returnTo":"https://auth.example.test/x"}`,
		"no returnTo": `{"userId":"user-1","code":"A"}`,
		"malformed":   `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := post(t, h, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rec.Code)
			}
		})
	}
}

// Display name falls back to the address when the profile has no name.
func TestEmailVerification_UserNameFallsBackToEmail(t *testing.T) {
	u := testUser()
	u.Spec.GivenName, u.Spec.FamilyName = "", ""
	h, c := newHandler(t, u)

	post(t, h, `{"userId":"user-1","code":"ABC123","returnTo":"https://auth.example.test/id/signup/complete"}`)

	if got := varsOf(emails(t, c)[0])["UserName"]; got != "person@example.test" {
		t.Fatalf("UserName = %q, want the email address", got)
	}
}

func TestEmailVerification_RejectsNonPost(t *testing.T) {
	h, _ := newHandler(t, testUser())
	req := httptest.NewRequest(http.MethodGet, "/v1/email/verification", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
