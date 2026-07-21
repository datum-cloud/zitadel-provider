package passkeys

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// fakeZitadelAPI stubs zitadel.API. Only ListPasskeys is implemented; any
// other call panics via the embedded nil interface — this resource never
// calls anything else.
type fakeZitadelAPI struct {
	zitadel.API
	listPasskeys func(ctx context.Context, userID string) ([]zitadel.Passkey, error)
}

func (f *fakeZitadelAPI) ListPasskeys(ctx context.Context, userID string) ([]zitadel.Passkey, error) {
	return f.listPasskeys(ctx, userID)
}

func TestRESTList(t *testing.T) {
	t.Run("self-scope: lists the caller's own passkeys", func(t *testing.T) {
		r := &REST{Z: &fakeZitadelAPI{listPasskeys: func(_ context.Context, uid string) ([]zitadel.Passkey, error) {
			if uid != "caller-uid" {
				t.Fatalf("ListPasskeys called with uid %q, want caller-uid", uid)
			}
			return []zitadel.Passkey{{ID: "pk-1", Name: "Laptop", State: "AUTH_FACTOR_STATE_READY"}}, nil
		}}}
		ctx := request.WithUser(context.Background(), &user.DefaultInfo{UID: "caller-uid"})

		obj, err := r.List(ctx, &internalversion.ListOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		list := obj.(*milov1alpha1.PasskeyList)
		if len(list.Items) != 1 || list.Items[0].Name != "pk-1" || list.Items[0].Status.State != milov1alpha1.PasskeyStateActive {
			t.Errorf("List() = %+v, want one Active pk-1", list.Items)
		}
		if list.Items[0].Status.UserUID != "caller-uid" {
			t.Errorf("Status.UserUID = %q, want caller-uid", list.Items[0].Status.UserUID)
		}
		if list.Items[0].Status.DisplayName != "Laptop" {
			t.Errorf("Status.DisplayName = %q, want Laptop", list.Items[0].Status.DisplayName)
		}
	})

	t.Run("cross-user without MiloSAR configured is forbidden", func(t *testing.T) {
		r := &REST{Z: &fakeZitadelAPI{listPasskeys: func(context.Context, string) ([]zitadel.Passkey, error) {
			t.Fatal("ListPasskeys must not be called when cross-user lookup is rejected")
			return nil, nil
		}}, MiloSAR: nil}
		ctx := request.WithUser(context.Background(), &user.DefaultInfo{UID: "caller-uid"})
		opts := &internalversion.ListOptions{FieldSelector: fields.OneTermEqualSelector("status.userUID", "other-uid")}

		_, err := r.List(ctx, opts)
		if err == nil {
			t.Fatal("expected an error for cross-user lookup without MiloSAR, got nil")
		}
	})
}

func TestPasskeyState(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"ready maps to Active", "AUTH_FACTOR_STATE_READY", "Active"},
		{"not_ready maps to Inactive", "AUTH_FACTOR_STATE_NOT_READY", "Inactive"},
		{"removed maps to Inactive", "AUTH_FACTOR_STATE_REMOVED", "Inactive"},
		{"unspecified maps to Inactive", "AUTH_FACTOR_STATE_UNSPECIFIED", "Inactive"},
		{"unknown future state maps to Inactive", "AUTH_FACTOR_STATE_SOMETHING_NEW", "Inactive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := passkeyState(tt.raw); got != tt.want {
				t.Errorf("passkeyState(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
