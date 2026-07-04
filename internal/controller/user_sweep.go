package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

const sweepPageSize = 100

var (
	sweepScanned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_scanned_total",
		Help: "Eligible Zitadel human users scanned by the invariant sweeper.",
	})
	sweepMissing = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_missing_total",
		Help: "Zitadel users found without a corresponding User resource.",
	})
	sweepCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_created_total",
		Help: "User resources created by the invariant sweeper.",
	})
	sweepErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "zitadel_provider_user_sweep_errors_total",
		Help: "Sweeps aborted by an error.",
	})
	sweepLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "zitadel_provider_user_sweep_last_success_timestamp_seconds",
		Help: "Unix time of the last fully successful sweep.",
	})
)

func init() {
	metrics.Registry.MustRegister(sweepScanned, sweepMissing, sweepCreated, sweepErrors, sweepLastSuccess)
}

// ZitadelUserLister is the narrow slice of the pkg/zitadel API the sweeper
// needs. Eligibility is decided server-side: every human user, regardless of
// state, must have a Milo counterpart; machine users are excluded.
type ZitadelUserLister interface {
	ListHumanUsers(ctx context.Context, offset uint64, limit uint32) ([]zitadel.User, error)
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;create

// UserSweeper periodically ensures every Zitadel human user has a User
// resource on the core control plane. Create-only: it never deletes or
// mutates existing resources — deletion authority stays with UserController's
// finalizer flow.
type UserSweeper struct {
	Client   client.Client
	Zitadel  ZitadelUserLister
	Interval time.Duration
}

func (s *UserSweeper) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("user-sweeper")
	if s.Interval <= 0 {
		log.Info("User sweep disabled (interval <= 0)")
		return nil
	}
	log.Info("Starting user sweeper", "interval", s.Interval)

	// The first sweep in an environment is the backfill — run immediately.
	if err := s.sweepOnce(ctx); err != nil {
		log.Error(err, "Sweep failed")
	}

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.sweepOnce(ctx); err != nil {
				log.Error(err, "Sweep failed")
			}
		}
	}
}

func (s *UserSweeper) sweepOnce(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("user-sweeper")

	// One List per sweep: the manager client serves it from the shared
	// informer cache, so diffing against this set avoids a per-user Get.
	// Users created between snapshot and Create are covered by EnsureUser
	// treating AlreadyExists as success.
	var userList iammiloapiscomv1alpha1.UserList
	if err := s.Client.List(ctx, &userList); err != nil {
		sweepErrors.Inc()
		return fmt.Errorf("list existing user resources: %w", err)
	}
	existing := make(map[string]struct{}, len(userList.Items))
	for i := range userList.Items {
		existing[userList.Items[i].Name] = struct{}{}
	}

	var offset uint64
	for {
		users, err := s.Zitadel.ListHumanUsers(ctx, offset, sweepPageSize)
		if err != nil {
			sweepErrors.Inc()
			return fmt.Errorf("list zitadel users (offset %d): %w", offset, err)
		}
		for i := range users {
			u := &users[i]
			sweepScanned.Inc()
			if _, ok := existing[u.ID]; ok {
				continue
			}
			sweepMissing.Inc()
			created, err := userprovision.EnsureUser(ctx, s.Client,
				userprovision.NewUser(u.ID, u.Email, u.GivenName, u.FamilyName))
			if err != nil {
				sweepErrors.Inc()
				return fmt.Errorf("create user %s: %w", u.ID, err)
			}
			if created {
				sweepCreated.Inc()
				log.Info("Provisioned missing User resource", "zitadelUserId", u.ID, "email", u.Email)
			}
		}
		if len(users) < sweepPageSize {
			break
		}
		offset += uint64(len(users))
	}
	sweepLastSuccess.SetToCurrentTime()
	return nil
}
