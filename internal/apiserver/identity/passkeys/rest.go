package passkeys

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternal "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.miloapis.com/auth-provider-zitadel/internal/apiserver/identity/utils"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	milov1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"
)

// REST serves identity.miloapis.com/v1alpha1.Passkey backed by Zitadel,
// list-only (no DELETE — passkey mutations live in auth-ui). Cross-user
// reads follow the sessions/useridentities MiloSAR pattern.
//
// MiloSAR, when set, is consulted on List requests that include a
// `status.userUID=<uid>` field selector targeting a user other than the
// caller. The handler asks milo via SubjectAccessReview whether the caller
// can `get iam.miloapis.com/users/<uid>` and proceeds iff allowed.
//
// If MiloSAR is nil, cross-user lookups are rejected with a clear error;
// self-only behavior is unaffected.
type REST struct {
	Z       zitadel.API
	MiloSAR utils.SubjectAccessReviewer
}

var _ rest.Scoper = &REST{}
var _ rest.Lister = &REST{}
var _ rest.Getter = &REST{}
var _ rest.TableConvertor = &REST{}
var _ rest.Storage = &REST{}
var _ rest.SingularNameProvider = &REST{}

var passkeysGR = schema.GroupResource{Group: milov1alpha1.SchemeGroupVersion.Group, Resource: "passkeys"}

func (r *REST) NamespaceScoped() bool   { return false }
func (r *REST) New() runtime.Object     { return &milov1alpha1.Passkey{} }
func (r *REST) NewList() runtime.Object { return &milov1alpha1.PasskeyList{} }
func (r *REST) GetSingularName() string { return "passkey" }

// passkeyState maps the raw Zitadel AuthFactorState string onto the milo
// Active|Inactive status. Only AUTH_FACTOR_STATE_READY is Active; every
// other state — including any future addition — is Inactive.
func passkeyState(raw string) string {
	if raw == "AUTH_FACTOR_STATE_READY" {
		return "Active"
	}
	return "Inactive"
}

func toMiloPasskey(p zitadel.Passkey, uid string) *milov1alpha1.Passkey {
	return &milov1alpha1.Passkey{
		TypeMeta:   metav1.TypeMeta{Kind: "Passkey", APIVersion: milov1alpha1.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{Name: p.ID, CreationTimestamp: metav1.Now()},
		Status: milov1alpha1.PasskeyStatus{
			UserUID:     uid,
			DisplayName: p.Name,
			State:       milov1alpha1.PasskeyState(passkeyState(p.State)),
		},
	}
}

func (r *REST) List(ctx context.Context, options *metainternal.ListOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for List")
		return nil, apierrors.NewUnauthorized("no user in context")
	}

	// Default: list the caller's own passkeys. If the caller passes a
	// status.userUID field selector targeting a different user UID, ask
	// milo (via SAR) whether the caller can `get` that user; proceed iff
	// allowed.
	uid := u.GetUID()
	if options != nil && options.FieldSelector != nil {
		if targetUID, err := utils.ExtractUserUIDFromFieldSelector(options.FieldSelector); err == nil && targetUID != "" && targetUID != u.GetUID() {
			if r.MiloSAR == nil {
				klog.V(2).InfoS("Cross-user passkey lookup rejected: no milo SAR client configured",
					"requestor", u.GetUID(), "targetUID", targetUID)
				return nil, apierrors.NewForbidden(
					passkeysGR,
					"",
					fmt.Errorf("cross-user passkey lookup requires the apiserver to be configured with a milo kubeconfig"))
			}
			allowed, err := utils.CanGetUser(ctx, r.MiloSAR, u, targetUID)
			if err != nil {
				klog.ErrorS(err, "SubjectAccessReview against milo failed",
					"requestor", u.GetUID(), "targetUID", targetUID)
				return nil, apierrors.NewInternalError(err)
			}
			if !allowed {
				klog.V(2).InfoS("Unauthorized: caller cannot get target user in milo",
					"requestor", u.GetUID(), "targetUID", targetUID)
				return nil, apierrors.NewForbidden(
					passkeysGR,
					"",
					fmt.Errorf("not authorized to query passkeys for user %q (requires get on iam.miloapis.com/users)", targetUID))
			}
			klog.V(2).InfoS("Cross-user passkey lookup authorized by milo",
				"requestor", u.GetUID(), "targetUID", targetUID)
			uid = targetUID
		}
	}
	klog.V(2).InfoS("Listing passkeys", "uid", uid)

	zp, err := r.Z.ListPasskeys(ctx, uid)
	if err != nil {
		klog.ErrorS(err, "Failed to list passkeys", "uid", uid)
		return nil, translateErr(err, "")
	}

	out := &milov1alpha1.PasskeyList{TypeMeta: metav1.TypeMeta{Kind: "PasskeyList", APIVersion: milov1alpha1.SchemeGroupVersion.String()}}
	for _, p := range zp {
		out.Items = append(out.Items, *toMiloPasskey(p, uid))
	}
	klog.V(3).InfoS("Listed passkeys", "uid", uid, "count", len(out.Items))
	return out, nil
}

func (r *REST) Get(ctx context.Context, name string, _ *metav1.GetOptions) (runtime.Object, error) {
	u, ok := request.UserFrom(ctx)
	if !ok {
		klog.ErrorS(nil, "No user in context for Get", "name", name)
		return nil, apierrors.NewUnauthorized("no user in context")
	}
	uid := u.GetUID()
	klog.V(2).InfoS("Getting passkey", "name", name, "requestor", uid)

	zp, err := r.Z.ListPasskeys(ctx, uid)
	if err != nil {
		klog.ErrorS(err, "Failed to list passkeys", "uid", uid)
		return nil, translateErr(err, name)
	}
	for _, p := range zp {
		if p.ID == name {
			klog.V(3).InfoS("Found passkey", "name", name, "uid", uid)
			return toMiloPasskey(p, uid), nil
		}
	}
	klog.V(1).InfoS("Passkey not found", "name", name, "uid", uid)
	return nil, apierrors.NewNotFound(passkeysGR, name)
}

func translateErr(err error, name string) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return apierrors.NewNotFound(passkeysGR, name)
		case codes.PermissionDenied:
			return apierrors.NewForbidden(passkeysGR, name, nil)
		case codes.Unauthenticated:
			return apierrors.NewUnauthorized("unauthenticated")
		case codes.DeadlineExceeded, codes.Unavailable:
			return apierrors.NewServiceUnavailable("zitadel unavailable")
		default:
			return apierrors.NewInternalError(err)
		}
	}
	return err
}

// ConvertToTable enables kubectl table output using the default convertor.
func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return rest.NewDefaultTableConvertor(passkeysGR).ConvertToTable(ctx, obj, tableOptions)
}

// Destroy satisfies rest.Storage.
func (r *REST) Destroy() {}
