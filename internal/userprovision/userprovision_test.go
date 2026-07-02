package userprovision

import (
	"context"
	"testing"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEnsureUserCreatesThenTreatsDuplicateAsSuccess(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	if err := iammiloapiscomv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(s).Build()

	u := NewUser("362926680773230861", "jane@example.com", "Jane", "Doe")
	created, err := EnsureUser(ctx, c, u)
	if err != nil || !created {
		t.Fatalf("first EnsureUser: created=%v err=%v", created, err)
	}

	var got iammiloapiscomv1alpha1.User
	if err := c.Get(ctx, types.NamespacedName{Name: "362926680773230861"}, &got); err != nil {
		t.Fatalf("get created user: %v", err)
	}
	if got.Spec.Email != "jane@example.com" || got.Spec.GivenName != "Jane" || got.Spec.FamilyName != "Doe" {
		t.Fatalf("wrong spec: %+v", got.Spec)
	}

	created, err = EnsureUser(ctx, c, NewUser("362926680773230861", "jane@example.com", "Jane", "Doe"))
	if err != nil {
		t.Fatalf("duplicate EnsureUser must not error: %v", err)
	}
	if created {
		t.Fatal("duplicate EnsureUser must report created=false")
	}
}
