package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

// mockUserLister is a hand-written mock of the sweeper's Zitadel dependency
// (repo pattern: mockZitadelAPI in httpactionsserver/server_test.go).
type mockUserLister struct {
	pages [][]zitadel.User
	err   error
	calls int
}

func (m *mockUserLister) ListHumanUsers(_ context.Context, _ uint64, _ uint32) ([]zitadel.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	idx := m.calls
	m.calls++
	if idx >= len(m.pages) {
		return nil, nil
	}
	return m.pages[idx], nil
}

var _ = ginkgo.Describe("UserSweeper", func() {
	var (
		sctx   context.Context
		scheme *runtime.Scheme
	)

	ginkgo.BeforeEach(func() {
		sctx = context.TODO()
		scheme = runtime.NewScheme()
		gomega.Expect(iammiloapiscomv1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
	})

	human := func(id, email, given, family, state string) zitadel.User {
		return zitadel.User{ID: id, Email: email, GivenName: given, FamilyName: family, State: state}
	}

	ginkgo.It("provisions every human user regardless of state, skipping existing", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		gomega.Expect(k8sFake.Create(sctx, &iammiloapiscomv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: "u-existing"},
		})).To(gomega.Succeed())

		lister := &mockUserLister{pages: [][]zitadel.User{{
			human("u-existing", "a@example.com", "A", "B", "USER_STATE_ACTIVE"),
			human("u-missing", "c@example.com", "C", "D", "USER_STATE_ACTIVE"),
			human("u-inactive", "e@example.com", "E", "F", "USER_STATE_INACTIVE"),
			human("u-initial", "g@example.com", "G", "H", "USER_STATE_INITIAL"),
		}}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())

		var created iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-missing"}, &created)).To(gomega.Succeed())
		gomega.Expect(created.Spec.Email).To(gomega.Equal("c@example.com"))
		gomega.Expect(created.Spec.GivenName).To(gomega.Equal("C"))

		// Milo decides the state of the user: inactive and initial Zitadel
		// users MUST get their counterpart too.
		for _, name := range []string{"u-inactive", "u-initial"} {
			gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: name},
				&iammiloapiscomv1alpha1.User{})).To(gomega.Succeed(), name)
		}

		var list iammiloapiscomv1alpha1.UserList
		gomega.Expect(k8sFake.List(sctx, &list)).To(gomega.Succeed())
		gomega.Expect(list.Items).To(gomega.HaveLen(4))
	})

	ginkgo.It("diffs against a single List instead of per-user Gets", func() {
		getCalls, listCalls := 0, 0
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(&iammiloapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "u-existing"}}).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					getCalls++
					return c.Get(ctx, key, obj, opts...)
				},
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					listCalls++
					return c.List(ctx, list, opts...)
				},
			}).Build()

		lister := &mockUserLister{pages: [][]zitadel.User{{
			human("u-existing", "a@example.com", "A", "B", "USER_STATE_ACTIVE"),
			human("u-missing", "c@example.com", "C", "D", "USER_STATE_ACTIVE"),
		}}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())
		gomega.Expect(getCalls).To(gomega.BeZero(), "sweep must not issue per-user Gets")
		gomega.Expect(listCalls).To(gomega.Equal(1), "sweep must List existing users exactly once")
	})

	ginkgo.It("paginates until a short page", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		full := make([]zitadel.User, 0, sweepPageSize)
		for i := 0; i < sweepPageSize; i++ {
			full = append(full, human(fmt.Sprintf("u-%d", i),
				fmt.Sprintf("u%d@example.com", i), "G", "F", "USER_STATE_ACTIVE"))
		}
		short := []zitadel.User{human("u-last", "last@example.com", "L", "P", "USER_STATE_ACTIVE")}
		lister := &mockUserLister{pages: [][]zitadel.User{full, short}}
		s := &UserSweeper{Client: k8sFake, Zitadel: lister}

		gomega.Expect(s.sweepOnce(sctx)).To(gomega.Succeed())
		gomega.Expect(lister.calls).To(gomega.Equal(2))

		var last iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-last"}, &last)).To(gomega.Succeed())
		var list iammiloapiscomv1alpha1.UserList
		gomega.Expect(k8sFake.List(sctx, &list)).To(gomega.Succeed())
		gomega.Expect(list.Items).To(gomega.HaveLen(sweepPageSize + 1))
	})

	ginkgo.It("aborts the sweep on a Zitadel error", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := &UserSweeper{Client: k8sFake, Zitadel: &mockUserLister{err: errors.New("boom")}}
		gomega.Expect(s.sweepOnce(sctx)).ToNot(gomega.Succeed())
	})

	ginkgo.It("does nothing when interval is zero (disabled)", func() {
		k8sFake := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := &UserSweeper{Client: k8sFake, Zitadel: nil, Interval: 0}
		gomega.Expect(s.Start(sctx)).To(gomega.Succeed())
	})
})
