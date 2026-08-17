package webhook

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"

	"go.miloapis.com/auth-provider-zitadel/pkg/token"
)

// generateCredentialsFile creates a temporary Zitadel credentials JSON file that
// contains a randomly-generated RSA private key. It returns the full path to
// the generated file.
func generateCredentialsFile(t *testing.T) string {
	t.Helper()

	// Generate test RSA key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	// Encode the key to PEM.
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	var pemBuf bytes.Buffer
	if err := pem.Encode(&pemBuf, pemBlock); err != nil {
		t.Fatalf("encode pem: %v", err)
	}

	// Build credentials JSON.
	cred := struct {
		KeyID      string `json:"keyId"`
		PrivateKey string `json:"key"`
		ClientID   string `json:"clientId"`
	}{
		KeyID:      "test-key-id",
		PrivateKey: pemBuf.String(),
		ClientID:   "test-client-id",
	}

	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}

	// Write to temp file.
	tmpFile, err := os.CreateTemp(t.TempDir(), "cred-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close credentials file: %v", err)
	}

	return tmpFile.Name()
}

// buildTestHandler returns the HTTP handler under test along with the
// underlying introspection test server so that the caller can control the
// server's behaviour.
func buildTestHandler(t *testing.T, responseStatus int, responseBody map[string]any) (http.Handler, *httptest.Server) {
	t.Helper()

	// Create a fake Zitadel introspection endpoint.
	introspectionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responseStatus)
		_ = json.NewEncoder(w).Encode(responseBody)
	}))

	// Build an introspector that talks to our fake server.
	credsPath := generateCredentialsFile(t)
	introspector, err := token.NewIntrospector(credsPath, introspectionSrv.URL, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("create introspector: %v", err)
	}

	handler := NewAuthenticationWebhookV1(introspector)
	return handler, introspectionSrv
}

// ptr returns a pointer to v, so table entries can express the difference
// between "expect this extra key to be absent" (nil) and "expect this exact
// value" (non-nil).
func ptr[T any](v T) *T { return &v }

func TestHttpTokenAuthenticationWebhook(t *testing.T) {
	t.Parallel()

	const validToken = "dummy.jwt.token"

	tests := []struct {
		name                 string
		method               string
		token                string
		introspectionStatus  int
		introspectionPayload map[string]any
		expectHTTPCode       int
		expectAuthenticated  bool
		expectErrorSubstring string
		// expectRegistrationApproval is the value the
		// iam.miloapis.com/registrationApproval extra key must carry. It is
		// always stamped, so there is no "absent" case here.
		expectRegistrationApproval string
		// expectEmailVerified is the value the iam.miloapis.com/emailVerified
		// extra key must carry, or nil when the key must be ABSENT entirely.
		// Absence is not a don't-care: downstream policy admits on a missing
		// key, so these expectations pin the security-relevant behaviour.
		expectEmailVerified *string
	}{
		{
			name:           "method not allowed",
			method:         http.MethodGet,
			token:          "",
			expectHTTPCode: http.StatusMethodNotAllowed,
		},
		{
			name:                       "empty token provided",
			method:                     http.MethodPost,
			token:                      "", // empty token
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": false}, // will not be used
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        false,
			expectErrorSubstring:       "empty token provided",
			expectRegistrationApproval: "Rejected",
			// Nothing was authenticated, so there is no identity to describe.
			expectEmailVerified: nil,
		},
		{
			name:                       "introspection returns http error",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusInternalServerError,
			introspectionPayload:       map[string]any{"error": "internal"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        false,
			expectErrorSubstring:       "token introspection failed",
			expectRegistrationApproval: "Rejected",
			expectEmailVerified:        nil,
		},
		{
			name:                       "token inactive",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": false},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        false,
			expectErrorSubstring:       "jwt token is not active",
			expectRegistrationApproval: "Rejected",
			expectEmailVerified:        nil,
		},
		{
			// Pre-existing case, kept as-is: a human whose introspection body
			// carries no email_verified claim at all. Zitadel tags that claim
			// omitempty, so this is also what an unverified human looks like on
			// the wire. It must fail closed to "false", never to an absent key.
			name:                       "human user token active",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "my-user", "email": "user@example.com"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        ptr("false"),
		},
		{
			name:                       "human user with verified email",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "verified-user", "email": "verified@example.com", "email_verified": true},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        ptr("true"),
		},
		{
			name:                       "human user with unverified email",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "unverified-user", "email": "unverified@example.com", "email_verified": false},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        ptr("false"),
		},
		{
			// Explicit fail-closed case: the claim is missing entirely while
			// other human claims are present. Distinct from "human user token
			// active" only in intent, and worth keeping separate so nobody
			// "fixes" this into an absent key later.
			name:                       "human user with email_verified claim absent fails closed",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "claimless-user", "email": "claimless@example.com", "username": "claimless@example.com", "client_id": "portal-client"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        ptr("false"),
		},
		{
			name:                       "machine user token active",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "machine-user", "username": "machine-user@example.com"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			// No email claim: a machine identity, admitted downstream by the
			// key's absence.
			expectEmailVerified: nil,
		},
		{
			// Client-credentials shape: client_id present, no email. client_id
			// alone must not be mistaken for a human — a human's token carries
			// one too (see "human user with email_verified claim absent").
			name:                       "machine identity with client_id and no email",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "sa-user", "client_id": "service-account-client"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        nil,
		},
		{
			// A machine identity that somehow reports email_verified without an
			// email claim is still a machine: the key stays off. Guards against
			// a future refactor keying off email_verified instead of email.
			name:                       "machine identity ignores stray email_verified claim",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "sa-user", "client_id": "service-account-client", "email_verified": true},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        true,
			expectRegistrationApproval: "Approved",
			expectEmailVerified:        nil,
		},
		{
			name:                       "missing email or username",
			method:                     http.MethodPost,
			token:                      validToken,
			introspectionStatus:        http.StatusOK,
			introspectionPayload:       map[string]any{"active": true, "sub": "machine-user"},
			expectHTTPCode:             http.StatusOK,
			expectAuthenticated:        false,
			expectRegistrationApproval: "Rejected",
			expectEmailVerified:        nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, srv := buildTestHandler(t, tc.introspectionStatus, tc.introspectionPayload)
			defer srv.Close()

			// Build request.
			var reqBody bytes.Buffer
			if tc.method == http.MethodPost {
				review := authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: tc.token}}
				if err := json.NewEncoder(&reqBody).Encode(&review); err != nil {
					t.Fatalf("encode request: %v", err)
				}
			}
			req := httptest.NewRequest(tc.method, "/", &reqBody)
			req.Header.Set("Content-Type", "application/json")

			// Serve the request.
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tc.expectHTTPCode {
				t.Fatalf("unexpected status code: got %d want %d", rr.Code, tc.expectHTTPCode)
			}

			// Early exit for method not allowed.
			if tc.method == http.MethodGet {
				if allow := rr.Header().Get("Allow"); allow != http.MethodPost {
					t.Fatalf("unexpected Allow header: %s", allow)
				}
				return
			}

			// Decode TokenReview response.
			var resp authenticationv1.TokenReview
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if resp.Status.Authenticated != tc.expectAuthenticated {
				t.Fatalf("authenticated mismatch: got %v want %v", resp.Status.Authenticated, tc.expectAuthenticated)
			}

			if tc.expectErrorSubstring != "" {
				if !bytes.Contains([]byte(resp.Status.Error), []byte(tc.expectErrorSubstring)) {
					t.Fatalf("expected error to contain %q, got %q", tc.expectErrorSubstring, resp.Status.Error)
				}
			}

			if tc.expectAuthenticated {
				if resp.Status.User.Username == "" || resp.Status.User.UID == "" {
					t.Fatalf("expected user info to be set on success")
				}
			}

			extra := resp.Status.User.Extra

			// registrationApproval is always stamped; assert it in every case so
			// the emailVerified work cannot regress it unnoticed.
			approval, ok := extra["iam.miloapis.com/registrationApproval"]
			if !ok {
				t.Fatalf("expected iam.miloapis.com/registrationApproval to be present, extra=%v", extra)
			}
			if len(approval) != 1 || approval[0] != tc.expectRegistrationApproval {
				t.Fatalf("registrationApproval mismatch: got %v want [%s]", approval, tc.expectRegistrationApproval)
			}

			// Presence of emailVerified is itself the assertion: downstream
			// policy admits when the key is missing, so a spuriously absent key
			// on a human silently defeats the gate.
			verified, present := extra["iam.miloapis.com/emailVerified"]
			if tc.expectEmailVerified == nil {
				if present {
					t.Fatalf("expected iam.miloapis.com/emailVerified to be ABSENT (machine identity or denied request), got %v", verified)
				}
			} else {
				if !present {
					t.Fatalf("expected iam.miloapis.com/emailVerified to be present with value %q, but the key was absent; a human must never be admitted by omission", *tc.expectEmailVerified)
				}
				if len(verified) != 1 || verified[0] != *tc.expectEmailVerified {
					t.Fatalf("emailVerified mismatch: got %v want [%s]", verified, *tc.expectEmailVerified)
				}
			}
		})
	}
}
