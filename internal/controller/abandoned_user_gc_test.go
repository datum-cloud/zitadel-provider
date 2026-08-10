package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A-GC. Abandoned unverified accounts.

var gcNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// reaper records the ORDER of operations, because the order is the invariant:
// deleting the milo User before the Zitadel user lets UserSweeper resurrect it.
type reaper struct {
	users     []zitadel.User
	listErr   error
	deleteErr error
	calls     *[]string
}

func (r *reaper) ListHumanUsers(context.Context, uint64, uint32) ([]zitadel.User, int, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	return r.users, len(r.users), nil
}

func (r *reaper) DeleteUser(_ context.Context, userID string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	*r.calls = append(*r.calls, "zitadel:"+userID)
	return nil
}

// orderingClient records milo deletes into the same slice as the reaper, so one
// ordered log covers both systems.
type orderingClient struct {
	client.Client
	calls *[]string
}

func (c *orderingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	*c.calls = append(*c.calls, "milo:"+obj.GetName())
	return c.Client.Delete(ctx, obj, opts...)
}

func newGC(t *testing.T, users []zitadel.User, dryRun bool) (*AbandonedUserGC, *[]string, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := iammiloapiscomv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	calls := &[]string{}
	objs := make([]client.Object, 0, len(users))
	for _, u := range users {
		objs = append(objs, &iammiloapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: u.ID}})
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	return &AbandonedUserGC{
		Client:    &orderingClient{Client: base, calls: calls},
		Zitadel:   &reaper{users: users, calls: calls},
		Interval:  time.Hour,
		Retention: 30 * 24 * time.Hour,
		DryRun:    dryRun,
		now:       func() time.Time { return gcNow },
	}, calls, base
}

func unverified(id string, ageDays int) zitadel.User {
	return zitadel.User{ID: id, Email: id + "@example.test", CreatedAt: gcNow.AddDate(0, 0, -ageDays)}
}

func miloUserExists(t *testing.T, c client.Client, name string) bool {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKey{Name: name}, &iammiloapiscomv1alpha1.User{})
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("get user %q: %v", name, err)
	}
	return true
}

func sweep(t *testing.T, g *AbandonedUserGC) {
	t.Helper()
	if err := g.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}
}

// THE invariant. Zitadel first, milo second — the reverse lets UserSweeper
// recreate the User on its next tick and the two controllers fight forever.
func TestAbandonedGC_DeletesZitadelBeforeMilo(t *testing.T) {
	g, calls, _ := newGC(t, []zitadel.User{unverified("u1", 60)}, false)

	sweep(t, g)

	got := *calls
	if len(got) != 2 || got[0] != "zitadel:u1" || got[1] != "milo:u1" {
		t.Fatalf("got %v, want [zitadel:u1 milo:u1] — the Zitadel user MUST be deleted first, or user_sweep.go resurrects the milo User", got)
	}
}

func TestAbandonedGC_VerifiedAccountsSurvive(t *testing.T) {
	verified := unverified("u1", 60)
	verified.IsEmailVerified = true
	g, calls, c := newGC(t, []zitadel.User{verified}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("a verified account must never be collected however old, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

func TestAbandonedGC_RecentAccountsSurvive(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 3)}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("an account inside the retention window must survive, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

// A zero CreatedAt means the API reported no creation date. Deleting on unknown
// age would collect accounts of unknown vintage.
func TestAbandonedGC_UnknownAgeIsSkipped(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{{ID: "u1", Email: "u1@example.test"}}, false)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("unknown creation date must be skipped, not treated as ancient, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive")
	}
}

// Merging must not be activating: dry-run is the flag default.
func TestAbandonedGC_DryRun_DeletesNothing(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 90)}, true)

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("dry run must observe without deleting, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive a dry run")
	}
}

// Non-positive settings disable the sweep. They must never read as
// "delete everything".
func TestAbandonedGC_NonPositiveSettingsDisable(t *testing.T) {
	for name, mutate := range map[string]func(*AbandonedUserGC){
		"zero retention":     func(g *AbandonedUserGC) { g.Retention = 0 },
		"negative retention": func(g *AbandonedUserGC) { g.Retention = -time.Hour },
		"zero interval":      func(g *AbandonedUserGC) { g.Interval = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			g, calls, c := newGC(t, []zitadel.User{unverified("u1", 90)}, false)
			mutate(g)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := g.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}

			if len(*calls) != 0 {
				t.Fatalf("a disabled sweep must delete nothing, got %v", *calls)
			}
			if !miloUserExists(t, c, "u1") {
				t.Fatal("milo User must survive")
			}
		})
	}
}

// If the Zitadel delete fails, the milo User must be left alone — deleting it
// would hand UserSweeper a User to recreate against a still-live Zitadel user.
func TestAbandonedGC_ZitadelDeleteFails_MiloUntouched(t *testing.T) {
	g, calls, c := newGC(t, []zitadel.User{unverified("u1", 60)}, false)
	g.Zitadel = &reaper{
		users:     []zitadel.User{unverified("u1", 60)},
		deleteErr: errors.New("zitadel unavailable"),
		calls:     calls,
	}

	sweep(t, g)

	if len(*calls) != 0 {
		t.Fatalf("no deletion should be recorded, got %v", *calls)
	}
	if !miloUserExists(t, c, "u1") {
		t.Fatal("milo User must survive a failed Zitadel delete")
	}
}

func TestAbandonedGC_ListError_IsReported(t *testing.T) {
	g, calls, _ := newGC(t, nil, false)
	g.Zitadel = &reaper{listErr: errors.New("boom"), calls: calls}

	if err := g.sweepOnce(context.Background()); err == nil {
		t.Fatal("a list failure must surface, not be swallowed")
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing should be deleted, got %v", *calls)
	}
}

// The GC guard checks CreatedAt.IsZero(), so the mapping must produce the ZERO
// time for a missing creation date — not the Unix epoch.
//
// This exists because the tests above build zitadel.User directly and so never
// exercise the proto mapping. protobuf's (*Timestamp)(nil).AsTime() returns
// 1970-01-01, which is not zero, reads as ancient, and would have deleted every
// account whose creation date the API did not report.
func TestAbandonedGC_EpochIsNotTreatedAsUnknown(t *testing.T) {
	epoch := zitadel.User{ID: "u1", Email: "u1@example.test", CreatedAt: time.Unix(0, 0).UTC()}
	g, _, _ := newGC(t, nil, false)

	if !g.isAbandoned(epoch, gcNow.Add(-30*24*time.Hour)) {
		t.Fatal("an epoch CreatedAt is a real timestamp and must be collectable")
	}

	var zero zitadel.User
	zero.ID = "u2"
	if g.isAbandoned(zero, gcNow.Add(-30*24*time.Hour)) {
		t.Fatal("a ZERO CreatedAt means unknown age and must be skipped — if the mapping ever produces epoch instead of zero, this is the account that gets wrongly deleted")
	}
}
