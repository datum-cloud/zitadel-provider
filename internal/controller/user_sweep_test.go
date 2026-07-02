package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
)

var _ = ginkgo.Describe("UserSweeper", func() {
	var (
		sctx    context.Context
		k8sFake client.Client
	)

	ginkgo.BeforeEach(func() {
		sctx = context.TODO()
		s := runtime.NewScheme()
		gomega.Expect(iammiloapiscomv1alpha1.AddToScheme(s)).To(gomega.Succeed())
		k8sFake = fake.NewClientBuilder().WithScheme(s).Build()
	})

	newSweeper := func(ts *httptest.Server) *UserSweeper {
		zc := zitadel.NewClientWithTokenSource(ts.URL,
			oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"}))
		return &UserSweeper{Client: k8sFake, Zitadel: zc}
	}

	stubPages := func(pages ...string) *httptest.Server {
		call := 0
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gomega.Expect(r.URL.Path).To(gomega.Equal("/v2/users"))
			w.Header().Set("Content-Type", "application/json")
			body := pages[call]
			if call < len(pages)-1 {
				call++
			}
			_, _ = w.Write([]byte(body))
		}))
	}

	ginkgo.It("creates missing CRs for active humans, skips existing/machine/inactive", func() {
		ts := stubPages(`{"details":{"totalResult":"4"},"result":[
			{"userId":"u-existing","state":"USER_STATE_ACTIVE","human":{"profile":{"givenName":"A","familyName":"B"},"email":{"email":"a@example.com"}}},
			{"userId":"u-missing","state":"USER_STATE_ACTIVE","human":{"profile":{"givenName":"C","familyName":"D"},"email":{"email":"c@example.com"}}},
			{"userId":"u-inactive","state":"USER_STATE_INACTIVE","human":{"profile":{"givenName":"E","familyName":"F"},"email":{"email":"e@example.com"}}},
			{"userId":"m-machine","state":"USER_STATE_ACTIVE","machine":{}}]}`)
		defer ts.Close()

		gomega.Expect(k8sFake.Create(sctx, &iammiloapiscomv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: "u-existing"},
		})).To(gomega.Succeed())

		gomega.Expect(newSweeper(ts).sweepOnce(sctx)).To(gomega.Succeed())

		var created iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-missing"}, &created)).To(gomega.Succeed())
		gomega.Expect(created.Spec.Email).To(gomega.Equal("c@example.com"))
		gomega.Expect(created.Spec.GivenName).To(gomega.Equal("C"))

		for _, name := range []string{"u-inactive", "m-machine"} {
			err := k8sFake.Get(sctx, types.NamespacedName{Name: name}, &iammiloapiscomv1alpha1.User{})
			gomega.Expect(apierrors.IsNotFound(err)).To(gomega.BeTrue(), name)
		}
	})

	ginkgo.It("paginates until a short page", func() {
		items := make([]string, 0, sweepPageSize)
		for i := 0; i < sweepPageSize; i++ {
			items = append(items, fmt.Sprintf(
				`{"userId":"u-%d","state":"USER_STATE_ACTIVE","human":{"profile":{"givenName":"G","familyName":"F"},"email":{"email":"u%d@example.com"}}}`, i, i))
		}
		page1 := `{"details":{"totalResult":"101"},"result":[` + strings.Join(items, ",") + `]}`
		page2 := `{"details":{"totalResult":"101"},"result":[{"userId":"u-last","state":"USER_STATE_ACTIVE","human":{"profile":{"givenName":"L","familyName":"P"},"email":{"email":"last@example.com"}}}]}`
		ts := stubPages(page1, page2)
		defer ts.Close()

		gomega.Expect(newSweeper(ts).sweepOnce(sctx)).To(gomega.Succeed())

		var last iammiloapiscomv1alpha1.User
		gomega.Expect(k8sFake.Get(sctx, types.NamespacedName{Name: "u-last"}, &last)).To(gomega.Succeed())
		var list iammiloapiscomv1alpha1.UserList
		gomega.Expect(k8sFake.List(sctx, &list)).To(gomega.Succeed())
		gomega.Expect(list.Items).To(gomega.HaveLen(sweepPageSize + 1))
	})

	ginkgo.It("aborts the sweep on a Zitadel error", func() {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		gomega.Expect(newSweeper(ts).sweepOnce(sctx)).ToNot(gomega.Succeed())
	})

	ginkgo.It("does nothing when interval is zero (disabled)", func() {
		s := &UserSweeper{Client: k8sFake, Zitadel: nil, Interval: 0}
		gomega.Expect(s.Start(sctx)).To(gomega.Succeed())
	})
})
