package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// Install registers provider group/version bindings for Milo identity types and
// declares which field selectors the aggregated apiserver should pass through to
// the REST handlers (otherwise the generic apiserver rejects them at request
// validation with "is not a known field selector: only metadata.name,
// metadata.namespace").
func Install(s *runtime.Scheme) {
	_ = milov1alpha1.AddToScheme(s)

	_ = s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{
			Group:   milov1alpha1.SchemeGroupVersion.Group,
			Version: milov1alpha1.SchemeGroupVersion.Version,
			Kind:    "ServiceAccountKey",
		},
		func(label, value string) (string, string, error) {
			switch label {
			case "spec.serviceAccountUserName", "metadata.name":
				return label, value, nil
			default:
				return "", "", nil
			}
		},
	)

	// Sessions, UserIdentities, and Passkeys are listed by callers using
	// status.userUID=<uid> for cross-user lookups (gated by SAR in the REST
	// handler). Without this registration the apiserver pre-rejects the
	// selector before the handler ever sees it.
	userScopedSelector := func(label, value string) (string, string, error) {
		switch label {
		case "status.userUID", "metadata.name", "metadata.namespace":
			return label, value, nil
		default:
			return "", "", nil
		}
	}

	_ = s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{
			Group:   milov1alpha1.SchemeGroupVersion.Group,
			Version: milov1alpha1.SchemeGroupVersion.Version,
			Kind:    "Session",
		},
		userScopedSelector,
	)

	_ = s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{
			Group:   milov1alpha1.SchemeGroupVersion.Group,
			Version: milov1alpha1.SchemeGroupVersion.Version,
			Kind:    "UserIdentity",
		},
		userScopedSelector,
	)

	_ = s.AddFieldLabelConversionFunc(
		schema.GroupVersionKind{
			Group:   milov1alpha1.SchemeGroupVersion.Group,
			Version: milov1alpha1.SchemeGroupVersion.Version,
			Kind:    "Passkey",
		},
		userScopedSelector,
	)
}
