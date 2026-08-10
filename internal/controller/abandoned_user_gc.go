package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// DefaultAbandonedRetention is how long an unverified account is kept before
	// it becomes eligible for collection.
	DefaultAbandonedRetention = 30 * 24 * time.Hour
	// DefaultAbandonedGCInterval is how often the sweep runs.
	DefaultAbandonedGCInterval = 6 * time.Hour
)

var (
	abandonedScanned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_scanned_total",
		Help: "Zitadel human users examined by the abandoned-account sweep.",
	})
	abandonedEligible = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_eligible_total",
		Help: "Unverified accounts past the retention window. In dry-run this is the blast radius; read it before disabling dry-run.",
	})
	abandonedDeleted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_deleted_total",
		Help: "Abandoned accounts actually deleted.",
	})
	abandonedErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_abandoned_gc_errors_total",
		Help: "Errors encountered while collecting abandoned accounts.",
	})
)

func init() {
	metrics.Registry.MustRegister(abandonedScanned, abandonedEligible, abandonedDeleted, abandonedErrors)
}

// ZitadelUserReaper is the narrow surface the sweep needs.
type ZitadelUserReaper interface {
	ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]zitadel.User, int, error)
	DeleteUser(ctx context.Context, userID string) error
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;delete

// AbandonedUserGC deletes accounts abandoned before email verification.
//
// The population is narrow by construction. Wave 0 established that a user who
// never verifies never obtains a session and therefore never reaches onboarding
// billing, so such an account owns exactly: one Zitadel user, one milo User,
// and the User's owner-referenced children (two PolicyBindings and a
// UserPreference) which Kubernetes garbage-collects with it. There is no
// organization, membership or quota to unwind — this is not a subtree walk.
//
// ORDERING IS NOT OPTIONAL: the Zitadel user is deleted FIRST, then the milo
// User. UserSweeper recreates a User resource for every Zitadel human user
// "regardless of state" on every tick, so deleting the milo User first means
// the next sweep resurrects it and the two controllers fight indefinitely —
// silently, with zitadel_provider_user_sweep_created_total as the only symptom
// anyone would ever see.
type AbandonedUserGC struct {
	Client  client.Client
	Zitadel ZitadelUserReaper

	// Interval between sweeps. Non-positive disables the sweep entirely.
	Interval time.Duration
	// Retention is how long an unverified account is kept. Non-positive
	// disables the sweep: it must never be read as "delete everything".
	Retention time.Duration
	// DryRun reports what would be collected without deleting anything.
	//
	// Defaults true at the flag. This is one of exactly two Phase B items the
	// spec says must not merge dark, because it deletes user accounts — the
	// blast radius has to be read from the eligible counter before anyone
	// enables it.
	DryRun bool

	// now is overridable in tests.
	now func() time.Time
}

func (g *AbandonedUserGC) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("abandoned-user-gc")

	if g.Interval <= 0 || g.Retention <= 0 {
		log.Info("Abandoned-account GC disabled",
			"interval", g.Interval, "retention", g.Retention)
		return nil
	}
	log.Info("Starting abandoned-account GC",
		"interval", g.Interval, "retention", g.Retention, "dryRun", g.DryRun)

	ticker := time.NewTicker(g.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := g.sweepOnce(ctx); err != nil {
				log.Error(err, "Abandoned-account sweep failed")
			}
		}
	}
}

func (g *AbandonedUserGC) sweepOnce(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("abandoned-user-gc")
	cutoff := g.clock().Add(-g.Retention)

	var offset uint64
	var eligible, deleted int

	for {
		users, raw, err := g.Zitadel.ListHumanUsers(ctx, offset, sweepPageSize)
		if err != nil {
			abandonedErrors.Inc()
			return fmt.Errorf("list human users at offset %d: %w", offset, err)
		}

		for _, u := range users {
			abandonedScanned.Inc()
			if !g.isAbandoned(u, cutoff) {
				continue
			}
			eligible++
			abandonedEligible.Inc()

			if g.DryRun {
				log.Info("DRY RUN: would collect abandoned unverified account",
					"userID", u.ID, "createdAt", u.CreatedAt)
				continue
			}
			if err := g.collect(ctx, u.ID); err != nil {
				abandonedErrors.Inc()
				log.Error(err, "Failed to collect abandoned account", "userID", u.ID)
				continue
			}
			deleted++
			abandonedDeleted.Inc()
			log.Info("Collected abandoned unverified account", "userID", u.ID)
		}

		if raw < sweepPageSize {
			break
		}
		offset += uint64(raw)
	}

	log.Info("Abandoned-account sweep complete",
		"eligible", eligible, "deleted", deleted, "dryRun", g.DryRun)
	return nil
}

// isAbandoned reports whether an account is unverified and past the window.
func (g *AbandonedUserGC) isAbandoned(u zitadel.User, cutoff time.Time) bool {
	if u.IsEmailVerified {
		return false
	}
	// A zero CreatedAt means the API reported no creation date. Treat that as
	// unknown age and skip: guessing here deletes accounts of unknown vintage.
	if u.CreatedAt.IsZero() {
		return false
	}
	return u.CreatedAt.Before(cutoff)
}

// collect deletes the Zitadel user, then the milo User.
//
// The order is the whole point — see the type comment. Deleting milo first
// means UserSweeper recreates it on the next tick.
func (g *AbandonedUserGC) collect(ctx context.Context, userID string) error {
	if err := g.Zitadel.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("delete zitadel user %q: %w", userID, err)
	}

	user := &iammiloapiscomv1alpha1.User{}
	user.SetName(userID)
	if err := g.Client.Delete(ctx, user); err != nil && !apierrors.IsNotFound(err) {
		// The Zitadel user is already gone, so UserSweeper will not recreate
		// this User; the next sweep retries the milo side.
		return fmt.Errorf("delete milo user %q: %w", userID, err)
	}
	return nil
}

func (g *AbandonedUserGC) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}
