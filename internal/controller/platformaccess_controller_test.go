/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = ginkgo.Describe("PlatformAccessController", func() {
	var (
		scheme    *runtime.Scheme
		k8sClient client.Client
		ctx       context.Context
	)

	ginkgo.BeforeEach(func() {
		ctx = context.TODO()
		scheme = runtime.NewScheme()
		gomega.Expect(iammiloapiscomv1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
		k8sClient = fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&iammiloapiscomv1alpha1.PlatformAccess{}).
			Build()
	})

	ginkgo.Context("Reconcile", func() {
		ginkgo.It("should ignore requests for missing PlatformAccess resources", func() {
			r := &PlatformAccessController{
				Client: k8sClient,
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "missing"}}
			res, err := r.Reconcile(ctx, req)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(res.RequeueAfter).To(gomega.Equal(time.Duration(0)))
		})

		ginkgo.It("should fail if the corresponding User resource does not exist", func() {
			// Arrange: Create PlatformAccess but no User
			pa := &iammiloapiscomv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: "john"},
				Spec: iammiloapiscomv1alpha1.PlatformAccessSpec{
					UserRef: iammiloapiscomv1alpha1.UserReference{Name: "john"},
					State:   iammiloapiscomv1alpha1.PlatformAccessStateSuspended,
				},
			}
			gomega.Expect(k8sClient.Create(ctx, pa)).To(gomega.Succeed())

			r := &PlatformAccessController{
				Client: k8sClient,
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "john"}}
			_, err := r.Reconcile(ctx, req)
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("failed to get User resource"))
		})

		ginkgo.It("should deactivate user in Zitadel when state is Suspended", func() {
			var deactivateCalls int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v2/users/john/deactivate" {
					atomic.AddInt32(&deactivateCalls, 1)
					w.WriteHeader(http.StatusOK)
					return
				}
				ginkgo.GinkgoT().Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}))
			defer ts.Close()

			// Arrange: Create User and PlatformAccess
			user := &iammiloapiscomv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "john"},
			}
			gomega.Expect(k8sClient.Create(ctx, user)).To(gomega.Succeed())

			pa := &iammiloapiscomv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: "john"},
				Spec: iammiloapiscomv1alpha1.PlatformAccessSpec{
					UserRef: iammiloapiscomv1alpha1.UserReference{Name: "john"},
					State:   iammiloapiscomv1alpha1.PlatformAccessStateSuspended,
				},
			}
			gomega.Expect(k8sClient.Create(ctx, pa)).To(gomega.Succeed())

			zitadelClient := zitadel.NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}))
			r := &PlatformAccessController{
				Client:  k8sClient,
				Zitadel: zitadelClient,
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "john"}}
			_, err := r.Reconcile(ctx, req)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(deactivateCalls).To(gomega.Equal(int32(1)))

			// Verify status is updated with ZitadelReady condition
			updated := &iammiloapiscomv1alpha1.PlatformAccess{}
			gomega.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "john"}, updated)).To(gomega.Succeed())
			gomega.Expect(updated.Status.Conditions).To(gomega.HaveLen(1))
			gomega.Expect(updated.Status.Conditions[0].Type).To(gomega.Equal("ZitadelReady"))
			gomega.Expect(updated.Status.Conditions[0].Status).To(gomega.Equal(metav1.ConditionTrue))
			gomega.Expect(updated.Status.Conditions[0].Reason).To(gomega.Equal("Suspended"))
		})

		ginkgo.It("should reactivate user in Zitadel for other states like Approved", func() {
			var reactivateCalls int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v2/users/john/reactivate" {
					atomic.AddInt32(&reactivateCalls, 1)
					w.WriteHeader(http.StatusOK)
					return
				}
				ginkgo.GinkgoT().Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}))
			defer ts.Close()

			// Arrange: Create User and PlatformAccess
			user := &iammiloapiscomv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "john"},
			}
			gomega.Expect(k8sClient.Create(ctx, user)).To(gomega.Succeed())

			pa := &iammiloapiscomv1alpha1.PlatformAccess{
				ObjectMeta: metav1.ObjectMeta{Name: "john"},
				Spec: iammiloapiscomv1alpha1.PlatformAccessSpec{
					UserRef: iammiloapiscomv1alpha1.UserReference{Name: "john"},
					State:   iammiloapiscomv1alpha1.PlatformAccessStateApproved,
				},
			}
			gomega.Expect(k8sClient.Create(ctx, pa)).To(gomega.Succeed())

			zitadelClient := zitadel.NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}))
			r := &PlatformAccessController{
				Client:  k8sClient,
				Zitadel: zitadelClient,
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "john"}}
			_, err := r.Reconcile(ctx, req)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(reactivateCalls).To(gomega.Equal(int32(1)))
		})
	})
})
