package webhook

import (
	"strconv"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys stamped into TokenReview's status.user.extra. Milo's
// ValidatingAdmissionPolicies read these off the authenticated userInfo, which
// is why they are stamped here at all: a policy that had to look the identity's
// User resource up per admission request would need an informer cache and a
// custom admission plugin instead of a declarative CEL expression.
const (
	registrationApprovalExtraKey = "iam.miloapis.com/registrationApproval"
	emailVerifiedExtraKey        = "iam.miloapis.com/emailVerified"
)

func Denied(reason string) Response {
	return authenticationResponse(false, "", "", reason, iammiloapiscomv1alpha1.RegistrationApprovalStateRejected, nil)
}

func Errored(err error) Response {
	return authenticationResponse(false, "", "", err.Error(), iammiloapiscomv1alpha1.RegistrationApprovalStateRejected, nil)
}

// Allowed builds an authenticated TokenReview response for the given identity.
//
// emailVerified is a tri-state and the nil case is load-bearing: pass a non-nil
// pointer for human identities (the value being the verification state, however
// unflattering) and nil for machine identities, which email verification does
// not apply to. Callers must not pass nil to mean "we could not determine the
// state" — see authenticationResponse for what nil actually causes downstream.
func Allowed(username, uid string, emailVerified *bool) Response {
	return authenticationResponse(true, username, uid, "", iammiloapiscomv1alpha1.RegistrationApprovalStateApproved, emailVerified)
}

func authenticationResponse(authenticated bool, username, uid, evaluationError string, state iammiloapiscomv1alpha1.RegistrationApprovalState, emailVerified *bool) Response {
	extra := map[string]authenticationv1.ExtraValue{
		registrationApprovalExtraKey: {string(state)},
	}

	// Presence, not just value, is the signal here.
	//
	// Milo's policies are written defensively against extra keys they may not
	// find, in the shape the registrationApproval policy already uses:
	//
	//	!has(request.userInfo.extra) ||
	//	  !('iam.miloapis.com/emailVerified' in request.userInfo.extra) ||
	//	  request.userInfo.extra['iam.miloapis.com/emailVerified'][0] == 'true'
	//
	// An ABSENT key therefore ADMITS. Absence has to mean "this identity is not
	// a human and email verification is not a meaningful question about it" —
	// it must never come to mean "we could not tell", because those two read
	// identically to the policy and only one of them is safe.
	//
	// So the contract is asymmetric on purpose:
	//
	//   - Machine identities (ServiceAccounts, client-credentials clients) carry
	//     no email claim, so the key is omitted and they are admitted by
	//     absence. There is no email to verify and nothing to gate on.
	//
	//   - Human identities ALWAYS get the key, set to "true" or "false". A human
	//     is never left without it, because omitting it would hand them the
	//     machine exemption and silently admit exactly the account the gate
	//     exists to stop.
	//
	// The fail-closed direction matters more than it looks. Zitadel's
	// introspection body is marshalled from zitadel/oidc's
	// oidc.IntrospectionResponse, where email_verified is tagged omitempty — an
	// unverified human and a human whose email_verified claim Zitadel never
	// emitted both arrive here as false. Collapsing that to "false" makes an
	// upstream regression loud: every human gets gated, someone notices within
	// minutes, and the fix is flipping the feature gate off. Collapsing it to an
	// absent key instead would make the same regression silent — the gate would
	// report healthy while admitting everyone it was deployed to stop.
	if emailVerified != nil {
		extra[emailVerifiedExtraKey] = authenticationv1.ExtraValue{strconv.FormatBool(*emailVerified)}
	}

	return Response{
		TokenReview: authenticationv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TokenReview",
				APIVersion: authenticationv1.SchemeGroupVersion.String(),
			},
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: authenticated,
				User: authenticationv1.UserInfo{
					Username: username,
					UID:      uid,
					Extra:    extra,
				},
				Error: evaluationError,
			},
		},
	}
}
