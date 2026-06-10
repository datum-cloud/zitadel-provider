package httpactionsserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = iammiloapiscomv1alpha1.AddToScheme(s)
	return s
}

func newMembership(name, userSub, groupName string, ready metav1.ConditionStatus) *iammiloapiscomv1alpha1.GroupMembership {
	return &iammiloapiscomv1alpha1.GroupMembership{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "milo-system"},
		Spec: iammiloapiscomv1alpha1.GroupMembershipSpec{
			UserRef:  iammiloapiscomv1alpha1.UserReference{Name: userSub},
			GroupRef: iammiloapiscomv1alpha1.GroupReference{Name: groupName, Namespace: "milo-system"},
		},
		Status: iammiloapiscomv1alpha1.GroupMembershipStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: ready},
			},
		},
	}
}

func userRefIndex(o client.Object) []string {
	return []string{o.(*iammiloapiscomv1alpha1.GroupMembership).Spec.UserRef.Name}
}

func TestCustomizeJwtHandler_Groups(t *testing.T) {
	tests := []struct {
		name        string
		userSub     string
		memberships []*iammiloapiscomv1alpha1.GroupMembership
		wantGroups  []string
		wantEmail   string
	}{
		{
			name:    "active membership emitted, other user's membership excluded",
			userSub: "user-abc",
			memberships: []*iammiloapiscomv1alpha1.GroupMembership{
				newMembership("staff", "user-abc", "staff-users", metav1.ConditionTrue),
				newMembership("other", "other-user", "staff-users", metav1.ConditionTrue),
			},
			wantGroups: []string{"staff-users"},
			wantEmail:  "test@example.com",
		},
		{
			name:    "inactive membership excluded",
			userSub: "user-abc",
			memberships: []*iammiloapiscomv1alpha1.GroupMembership{
				newMembership("pending", "user-abc", "pending-group", metav1.ConditionFalse),
			},
			wantGroups: nil,
			wantEmail:  "test@example.com",
		},
		{
			name:        "user with no memberships gets empty groups claim",
			userSub:     "user-abc",
			memberships: nil,
			wantGroups:  nil,
			wantEmail:   "test@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := make([]client.Object, len(tc.memberships))
			for i, m := range tc.memberships {
				objs[i] = m
			}
			k8sClient := fake.NewClientBuilder().
				WithScheme(newScheme()).
				WithIndex(&iammiloapiscomv1alpha1.GroupMembership{}, "spec.userRef.name", userRefIndex).
				WithObjects(objs...).
				Build()

			srv := NewServer(NewServerConfig(), k8sClient, func(payload []byte, header, signingKey string) error { return nil })

			body, _ := json.Marshal(map[string]any{
				"userinfo": map[string]any{"sub": tc.userSub},
				"function": "function/preaccesstoken",
				"user":     map[string]any{"human": map[string]any{"email": tc.wantEmail}},
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/actions/customize-jwt", bytes.NewReader(body))
			w := httptest.NewRecorder()
			srv.customizeJwtHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}

			var resp CustomizeJwtHandlerResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			claims := map[string]any{}
			for _, c := range resp.AppendClaims {
				claims[c.Key] = c.Value
			}

			if claims["email"] != tc.wantEmail {
				t.Errorf("email: got %v, want %v", claims["email"], tc.wantEmail)
			}

			var gotGroups []string
			if g, ok := claims["groups"]; ok {
				if arr, ok := g.([]any); ok {
					for _, v := range arr {
						gotGroups = append(gotGroups, v.(string))
					}
				}
			}
			if len(gotGroups) != len(tc.wantGroups) {
				t.Fatalf("groups: got %v, want %v", gotGroups, tc.wantGroups)
			}
			for i := range gotGroups {
				if gotGroups[i] != tc.wantGroups[i] {
					t.Errorf("groups[%d]: got %q, want %q", i, gotGroups[i], tc.wantGroups[i])
				}
			}
		})
	}
}
