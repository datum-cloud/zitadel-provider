package controller

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"go.miloapis.com/auth-provider-zitadel/internal/userprovision"
	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
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

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;create

// UserSweeper periodically ensures every eligible Zitadel human user has a
// User resource on the core control plane. Create-only: it never deletes or
// mutates existing resources — deletion authority stays with UserController's
// finalizer flow.
type UserSweeper struct {
	Client   client.Client
	Zitadel  *zitadel.Client
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
	offset := 0
	for {
		resp, err := s.Zitadel.ListUsers(ctx, zitadel.ListUsersRequest{
			Query: &zitadel.SearchQuery{Offset: strconv.Itoa(offset), Limit: sweepPageSize, Asc: true},
			Queries: []zitadel.UserSearchQuery{
				{TypeQuery: &zitadel.TypeQuery{Type: zitadel.UserTypeHuman}},
			},
		})
		if err != nil {
			sweepErrors.Inc()
			return fmt.Errorf("list zitadel users (offset %d): %w", offset, err)
		}
		for i := range resp.Result {
			u := &resp.Result[i]
			if !eligibleForProvisioning(u) {
				continue
			}
			sweepScanned.Inc()
			if err := s.ensureUser(ctx, u, log); err != nil {
				sweepErrors.Inc()
				return err
			}
		}
		if len(resp.Result) < sweepPageSize {
			break
		}
		offset += len(resp.Result)
	}
	sweepLastSuccess.SetToCurrentTime()
	return nil
}

// eligibleForProvisioning is the security boundary deciding which Zitadel
// users MUST have a User resource (and therefore fraud screening).
func eligibleForProvisioning(u *zitadel.User) bool {
	return u.Human != nil && u.State == zitadel.UserStateActive
}

func (s *UserSweeper) ensureUser(ctx context.Context, u *zitadel.User, log logr.Logger) error {
	err := s.Client.Get(ctx, types.NamespacedName{Name: u.UserID}, &iammiloapiscomv1alpha1.User{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get user %s: %w", u.UserID, err)
	}
	sweepMissing.Inc()

	var email, given, family string
	if u.Human.Email != nil {
		email = u.Human.Email.Email
	}
	if u.Human.Profile != nil {
		given, family = u.Human.Profile.GivenName, u.Human.Profile.FamilyName
	}
	created, err := userprovision.EnsureUser(ctx, s.Client, userprovision.NewUser(u.UserID, email, given, family))
	if err != nil {
		return fmt.Errorf("create user %s: %w", u.UserID, err)
	}
	if created {
		sweepCreated.Inc()
		log.Info("Provisioned missing User resource", "zitadelUserId", u.UserID, "email", email)
	}
	return nil
}
