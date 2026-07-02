// Package userprovision builds and creates platform User resources for
// Zitadel human users. It is the single construction path shared by the
// actions webhook handler and the invariant sweeper.
package userprovision

import (
	"context"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewUser builds the User CR for a Zitadel human user. The CR name is the
// Zitadel user ID (aggregate ID).
func NewUser(zitadelUserID, email, givenName, familyName string) *iammiloapiscomv1alpha1.User {
	return &iammiloapiscomv1alpha1.User{
		TypeMeta: metav1.TypeMeta{
			Kind:       "User",
			APIVersion: "iam.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: zitadelUserID,
		},
		Spec: iammiloapiscomv1alpha1.UserSpec{
			Email:      email,
			GivenName:  givenName,
			FamilyName: familyName,
		},
	}
}

// EnsureUser creates the User CR, treating AlreadyExists as success.
func EnsureUser(ctx context.Context, c client.Client, user *iammiloapiscomv1alpha1.User) (bool, error) {
	if err := c.Create(ctx, user); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
