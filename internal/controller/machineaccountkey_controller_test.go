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
	"fmt"
	"net/http"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

// mockZitadelAPI implements pkgzitadel.API for testing.
type mockZitadelAPI struct {
	addMachineKeyFn    func(ctx context.Context, userID string, publicKey []byte, expirationDate *time.Time) (string, error)
	removeMachineKeyFn func(ctx context.Context, userID, keyID string) error
}

func (m *mockZitadelAPI) AddMachineKey(ctx context.Context, userID string, pk []byte, exp *time.Time) (string, error) {
	if m.addMachineKeyFn != nil {
		return m.addMachineKeyFn(ctx, userID, pk, exp)
	}
	return "", nil
}

func (m *mockZitadelAPI) RemoveMachineKey(ctx context.Context, userID, keyID string) error {
	if m.removeMachineKeyFn != nil {
		return m.removeMachineKeyFn(ctx, userID, keyID)
	}
	return nil
}

func (m *mockZitadelAPI) ListSessions(_ context.Context, _ string) ([]pkgzitadel.Session, error) {
	return nil, nil
}

func (m *mockZitadelAPI) GetSession(_ context.Context, _ string) (*pkgzitadel.Session, error) {
	return nil, nil
}

func (m *mockZitadelAPI) DeleteSession(_ context.Context, _, _ string) error {
	return nil
}

func (m *mockZitadelAPI) ListIDPLinks(_ context.Context, _ string) ([]pkgzitadel.IDPLink, error) {
	return nil, nil
}

// fakeMcCluster wraps a fake.Client to satisfy cluster.Cluster.
// Only GetClient and GetScheme are called by the controller; the other methods return zero values.
type fakeMcCluster struct {
	cl     client.Client
	scheme *runtime.Scheme
}

func (f *fakeMcCluster) GetClient() client.Client                          { return f.cl }
func (f *fakeMcCluster) GetScheme() *runtime.Scheme                        { return f.scheme }
func (f *fakeMcCluster) GetCache() cache.Cache                             { return nil }
func (f *fakeMcCluster) GetConfig() *rest.Config                           { return nil }
func (f *fakeMcCluster) GetEventRecorderFor(_ string) record.EventRecorder { return nil }
func (f *fakeMcCluster) GetRESTMapper() apimeta.RESTMapper                 { return nil }
func (f *fakeMcCluster) GetAPIReader() client.Reader                       { return f.cl }
func (f *fakeMcCluster) GetFieldIndexer() client.FieldIndexer              { return nil }
func (f *fakeMcCluster) GetHTTPClient() *http.Client                       { return nil }
func (f *fakeMcCluster) Start(_ context.Context) error                     { return nil }

var _ cluster.Cluster = &fakeMcCluster{}

// fakeMcManager implements the clusterGetter interface used by MachineAccountKeyController.
type fakeMcManager struct {
	cl     client.Client
	scheme *runtime.Scheme
}

func (f *fakeMcManager) GetCluster(_ context.Context, _ string) (cluster.Cluster, error) {
	return &fakeMcCluster{cl: f.cl, scheme: f.scheme}, nil
}

var _ clusterGetter = &fakeMcManager{}

// newTestScheme returns a scheme with the IAM types registered.
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = iammiloapiscomv1alpha1.AddToScheme(s)
	return s
}

// newReconciler constructs a MachineAccountKeyController wired with the given mock and fake manager.
func newReconciler(mock pkgzitadel.API, cl client.Client, s *runtime.Scheme) *MachineAccountKeyController {
	r := &MachineAccountKeyController{
		Zitadel: mock,
		mgr:     &fakeMcManager{cl: cl, scheme: s},
	}
	r.Finalizers = finalizer.NewFinalizers()
	_ = r.Finalizers.Register(machineAccountKeyFinalizerKey, &machineAccountKeyFinalizer{Zitadel: mock})
	return r
}

// reconcileReq builds a mcreconcile.Request for the given namespace/name.
func reconcileReq(namespace, name string) mcreconcile.Request {
	return mcreconcile.Request{
		ClusterName: "test-cluster",
		Request: ctrl.Request{
			NamespacedName: types.NamespacedName{
				Namespace: namespace,
				Name:      name,
			},
		},
	}
}

var _ = ginkgo.Describe("MachineAccountKeyController", func() {
	var (
		ctx    context.Context
		s      *runtime.Scheme
		mock   *mockZitadelAPI
		cl     client.Client
		r      *MachineAccountKeyController
		ns     = "default"
		maName = "test-ma"
		maUID  = types.UID("test-uid-123")
	)

	ginkgo.BeforeEach(func() {
		ctx = context.TODO()
		s = newTestScheme()
		mock = &mockZitadelAPI{}
	})

	// TC-01: Resource not found — no-op
	ginkgo.It("TC-01: should return nil when MachineAccountKey not found", func() {
		cl = fake.NewClientBuilder().WithScheme(s).Build()
		r = newReconciler(mock, cl, s)

		addCalled := false
		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			addCalled = true
			return "", nil
		}

		res, err := r.Reconcile(ctx, reconcileReq(ns, "ghost"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(res).To(gomega.Equal(ctrl.Result{}))
		gomega.Expect(addCalled).To(gomega.BeFalse())
	})

	// TC-02: Happy path — new key registration.
	// The finalizer is pre-populated to simulate that a prior reconcile already registered it,
	// so this reconcile goes directly to the key-registration business logic.
	ginkgo.It("TC-02: should register a new key when authProviderKeyId is empty", func() {
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      maName,
				Namespace: ns,
				UID:       maUID,
			},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          "ssh-rsa AAAAB3NzaC1yc2E test",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		var addUserID string
		mock.addMachineKeyFn = func(_ context.Context, userID string, _ []byte, _ *time.Time) (string, error) {
			addUserID = userID
			return "key-123", nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		gomega.Expect(addUserID).To(gomega.Equal(string(maUID)))

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key"}, updated)).To(gomega.Succeed())
		gomega.Expect(updated.Status.AuthProviderKeyID).To(gomega.Equal("key-123"))
		gomega.Expect(updated.Annotations[machineAccountKeyPublicKeyHashAnnotation]).To(gomega.Equal(publicKeyHash(mak.Spec.PublicKey)))
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("Registered"))
	})

	// TC-03: Owner reference is set.
	ginkgo.It("TC-03: should set owner reference to parent MachineAccount", func() {
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      maName,
				Namespace: ns,
				UID:       maUID,
			},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key-ownerref",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          "ssh-rsa AAAA test",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)
		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			return "key-456", nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-ownerref"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-ownerref"}, updated)).To(gomega.Succeed())

		ownerRefs := updated.GetOwnerReferences()
		gomega.Expect(ownerRefs).ToNot(gomega.BeEmpty())
		gomega.Expect(ownerRefs[0].UID).To(gomega.Equal(maUID))
	})

	// TC-04: Idempotency — key unchanged.
	ginkgo.It("TC-04: should not call Zitadel when key is already registered and unchanged", func() {
		pubKey := "ssh-rsa AAAAB3NzaC1yc2E unchanged"
		hash := publicKeyHash(pubKey)
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test-key-idempotent",
				Namespace:   ns,
				Finalizers:  []string{machineAccountKeyFinalizerKey},
				Annotations: map[string]string{machineAccountKeyPublicKeyHashAnnotation: hash},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          pubKey,
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "key-123",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		addCalled := false
		removeCalled := false
		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			addCalled = true
			return "", nil
		}
		mock.removeMachineKeyFn = func(_ context.Context, _, _ string) error {
			removeCalled = true
			return nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-idempotent"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(addCalled).To(gomega.BeFalse())
		gomega.Expect(removeCalled).To(gomega.BeFalse())

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-idempotent"}, updated)).To(gomega.Succeed())
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("Reconciled"))
	})

	// TC-05: Key rotation — publicKey changed.
	ginkgo.It("TC-05: should rotate the key when publicKey changes", func() {
		oldPubKey := "ssh-rsa AAAA old"
		newPubKey := "ssh-rsa AAAA new"
		oldHash := publicKeyHash(oldPubKey)

		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key-rotate",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
				Annotations: map[string]string{
					machineAccountKeyPublicKeyHashAnnotation: oldHash,
				},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          newPubKey, // publicKey has changed
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "old-id",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		addCalled := 0
		var removedKeyID string
		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			addCalled++
			return "new-id", nil
		}
		mock.removeMachineKeyFn = func(_ context.Context, _, keyID string) error {
			removedKeyID = keyID
			return nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-rotate"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(addCalled).To(gomega.Equal(1))
		gomega.Expect(removedKeyID).To(gomega.Equal("old-id"))

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-rotate"}, updated)).To(gomega.Succeed())
		gomega.Expect(updated.Status.AuthProviderKeyID).To(gomega.Equal("new-id"))
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("Rotated"))
	})

	// TC-06: Rotation — old key revocation fails (non-fatal).
	ginkgo.It("TC-06: should not requeue when old key revocation fails during rotation", func() {
		oldPubKey := "ssh-rsa AAAA old2"
		newPubKey := "ssh-rsa AAAA new2"
		oldHash := publicKeyHash(oldPubKey)

		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key-rotate-fail",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
				Annotations: map[string]string{
					machineAccountKeyPublicKeyHashAnnotation: oldHash,
				},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          newPubKey,
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "old-id-2",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			return "new-id-2", nil
		}
		mock.removeMachineKeyFn = func(_ context.Context, _, _ string) error {
			return fmt.Errorf("revoke failed")
		}

		res, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-rotate-fail"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred()) // best-effort, no requeue
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(time.Duration(0)))

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-rotate-fail"}, updated)).To(gomega.Succeed())
		gomega.Expect(updated.Status.AuthProviderKeyID).To(gomega.Equal("new-id-2"))
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionTrue))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("Rotated"))
	})

	// TC-07: Deletion — finalizer revokes key.
	ginkgo.It("TC-07: should revoke key when MachineAccountKey is deleted", func() {
		now := metav1.Now()
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-key-delete",
				Namespace:         ns,
				Finalizers:        []string{machineAccountKeyFinalizerKey},
				DeletionTimestamp: &now,
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "key-abc",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		var removedUserID, removedKeyID string
		mock.removeMachineKeyFn = func(_ context.Context, userID, keyID string) error {
			removedUserID = userID
			removedKeyID = keyID
			return nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-delete"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(removedUserID).To(gomega.Equal(string(maUID)))
		gomega.Expect(removedKeyID).To(gomega.Equal("key-abc"))
	})

	// TC-08: Deletion — key already absent (NotFound treated as success at SDK layer).
	ginkgo.It("TC-08: should succeed without error when RemoveMachineKey returns nil", func() {
		now := metav1.Now()
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-key-absent",
				Namespace:         ns,
				Finalizers:        []string{machineAccountKeyFinalizerKey},
				DeletionTimestamp: &now,
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "key-gone",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		// SDKClient.RemoveMachineKey swallows NotFound — mock simulates the already-swallowed result
		mock.removeMachineKeyFn = func(_ context.Context, _, _ string) error {
			return nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-absent"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	})

	// TC-09: Deletion — parent MachineAccount not found.
	ginkgo.It("TC-09: should remove finalizer without Zitadel call when parent MA not found during deletion", func() {
		now := metav1.Now()
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-key-no-parent",
				Namespace:         ns,
				Finalizers:        []string{machineAccountKeyFinalizerKey},
				DeletionTimestamp: &now,
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: "gone-ma",
			},
			Status: iammiloapiscomv1alpha1.MachineAccountKeyStatus{
				AuthProviderKeyID: "key-abc",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		removeCalled := false
		mock.removeMachineKeyFn = func(_ context.Context, _, _ string) error {
			removeCalled = true
			return nil
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-no-parent"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(removeCalled).To(gomega.BeFalse())
	})

	// TC-10: Parent MachineAccount not found (create path) — requeue.
	// The finalizer is pre-populated; this tests the ParentNotFound requeue path.
	ginkgo.It("TC-10: should requeue after 10s when parent MachineAccount is not found", func() {
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key-orphan",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: "missing-ma",
				PublicKey:          "ssh-rsa AAAA test",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		addCalled := false
		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			addCalled = true
			return "", nil
		}

		res, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-orphan"))
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
		gomega.Expect(res.RequeueAfter).To(gomega.Equal(10 * time.Second))
		gomega.Expect(addCalled).To(gomega.BeFalse())

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-orphan"}, updated)).To(gomega.Succeed())
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("ParentNotFound"))
	})

	// TC-11: AddMachineKey returns error.
	ginkgo.It("TC-11: should return error and set ZitadelAPIError condition when AddMachineKey fails", func() {
		ma := &iammiloapiscomv1alpha1.MachineAccount{
			ObjectMeta: metav1.ObjectMeta{Name: maName, Namespace: ns, UID: maUID},
		}
		mak := &iammiloapiscomv1alpha1.MachineAccountKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-key-err",
				Namespace:  ns,
				Finalizers: []string{machineAccountKeyFinalizerKey},
			},
			Spec: iammiloapiscomv1alpha1.MachineAccountKeySpec{
				MachineAccountName: maName,
				PublicKey:          "ssh-rsa AAAA test",
			},
		}

		cl = fake.NewClientBuilder().WithScheme(s).
			WithObjects(ma, mak).
			WithStatusSubresource(mak).
			Build()
		r = newReconciler(mock, cl, s)

		mock.addMachineKeyFn = func(_ context.Context, _ string, _ []byte, _ *time.Time) (string, error) {
			return "", fmt.Errorf("zitadel unavailable")
		}

		_, err := r.Reconcile(ctx, reconcileReq(ns, "test-key-err"))
		gomega.Expect(err).To(gomega.HaveOccurred())

		updated := &iammiloapiscomv1alpha1.MachineAccountKey{}
		gomega.Expect(cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: "test-key-err"}, updated)).To(gomega.Succeed())
		gomega.Expect(updated.Status.AuthProviderKeyID).To(gomega.BeEmpty())
		gomega.Expect(conditionStatus(updated, "Ready")).To(gomega.Equal(metav1.ConditionFalse))
		gomega.Expect(conditionReason(updated, "Ready")).To(gomega.Equal("ZitadelAPIError"))
	})
})

// conditionStatus returns the Status of the named condition, or "" if not found.
func conditionStatus(mak *iammiloapiscomv1alpha1.MachineAccountKey, condType string) metav1.ConditionStatus {
	for _, c := range mak.Status.Conditions {
		if c.Type == condType {
			return c.Status
		}
	}
	return ""
}

// conditionReason returns the Reason of the named condition, or "" if not found.
func conditionReason(mak *iammiloapiscomv1alpha1.MachineAccountKey, condType string) string {
	for _, c := range mak.Status.Conditions {
		if c.Type == condType {
			return c.Reason
		}
	}
	return ""
}
