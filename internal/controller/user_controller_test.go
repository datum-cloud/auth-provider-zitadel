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
	"sigs.k8s.io/controller-runtime/pkg/finalizer"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = ginkgo.Describe("UserController", func() {
	var (
		scheme    *runtime.Scheme
		k8sClient client.Client
		ctx       context.Context
	)

	ginkgo.BeforeEach(func() {
		ctx = context.TODO()
		scheme = runtime.NewScheme()
		gomega.Expect(iammiloapiscomv1alpha1.AddToScheme(scheme)).To(gomega.Succeed())
		k8sClient = fake.NewClientBuilder().WithScheme(scheme).Build()
	})

	ginkgo.Context("Reconcile", func() {
		ginkgo.It("should ignore requests for missing User resources", func() {
			r := &UserController{
				Client:     k8sClient,
				Finalizers: finalizer.NewFinalizers(),
			}

			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "ghost"}}
			res, err := r.Reconcile(ctx, req)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(res.RequeueAfter).To(gomega.Equal(time.Duration(0)))
		})
	})

	ginkgo.Context("userFinalizer", func() {
		ginkgo.It("should skip deletion when user not found in Zitadel", func() {
			var getCalls, deleteCalls int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					atomic.AddInt32(&getCalls, 1)
					http.NotFound(w, r)
					return
				}
				ginkgo.GinkgoT().Errorf("unexpected method %s", r.Method)
			}))
			defer ts.Close()

			client := zitadel.NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}))
			f := &userFinalizer{Zitadel: client}

			user := &iammiloapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "john"}}
			res, err := f.Finalize(ctx, user)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(res.Updated).To(gomega.BeFalse())
			gomega.Expect(getCalls).To(gomega.BeNumerically(">=", 1))
			gomega.Expect(deleteCalls).To(gomega.BeZero())
		})

		ginkgo.It("should delete user when present in Zitadel", func() {
			var deleteCalls int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"user": {"userId": "john"}, "details": {}}`))
					return
				}
				if r.Method == http.MethodDelete {
					atomic.AddInt32(&deleteCalls, 1)
					w.WriteHeader(http.StatusOK)
					return
				}
				ginkgo.GinkgoT().Errorf("unexpected method %s", r.Method)
			}))
			defer ts.Close()

			client := zitadel.NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}))
			f := &userFinalizer{Zitadel: client}
			user := &iammiloapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "john"}}

			res, err := f.Finalize(ctx, user)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			gomega.Expect(res.Updated).To(gomega.BeFalse())
			gomega.Expect(deleteCalls).To(gomega.Equal(int32(1)))
		})
	})

	ginkgo.Context("Finalizer registration", func() {
		ginkgo.It("should add the user finalizer on first reconcile", func() {
			// Arrange: create a User without finalizers in the fake cluster
			user := &iammiloapiscomv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
			}
			gomega.Expect(k8sClient.Create(ctx, user)).To(gomega.Succeed())

			// Setup controller with proper finalizer registration (no Zitadel interaction needed)
			finalizers := finalizer.NewFinalizers()
			gomega.Expect(finalizers.Register(userFinalizerKey, &userFinalizer{})).To(gomega.Succeed())

			r := &UserController{
				Client:     k8sClient,
				Finalizers: finalizers,
			}

			// Act: reconcile the user
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "alice"}})
			gomega.Expect(err).ToNot(gomega.HaveOccurred())

			// Assert: the user object now contains the finalizer key
			updated := &iammiloapiscomv1alpha1.User{}
			gomega.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "alice"}, updated)).To(gomega.Succeed())
			gomega.Expect(updated.GetFinalizers()).To(gomega.ContainElement(userFinalizerKey))
		})
	})
})
