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
	"crypto/sha256"
	"fmt"
	"time"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	finalizer "sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

const (
	machineAccountKeyFinalizerKey = "iam.miloapis.com/machineaccountkey"

	// machineAccountKeyPublicKeyHashAnnotation stores the SHA-256 hex digest of
	// spec.publicKey. Used to detect key rotation without a Zitadel API call.
	machineAccountKeyPublicKeyHashAnnotation = "iam.miloapis.com/public-key-hash"
)

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccountkeys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccountkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccountkeys/finalizers,verbs=update
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccounts,verbs=get;list;watch

// clusterGetter is the minimal interface needed from the multicluster manager.
// Using a narrow interface makes the controller easier to test without
// implementing the full mcmanager.Manager.
type clusterGetter interface {
	GetCluster(ctx context.Context, clusterName string) (cluster.Cluster, error)
}

// MachineAccountKeyController reconciles MachineAccountKey objects across
// project control planes.
type MachineAccountKeyController struct {
	Finalizers finalizer.Finalizers
	Zitadel    pkgzitadel.API
	mgr        clusterGetter
}

type machineAccountKeyFinalizer struct {
	Zitadel pkgzitadel.API
}

// contextKeyClusterClient is the unexported context key for injecting the per-cluster client.
type contextKeyClusterClient struct{}

func withClusterClient(ctx context.Context, c client.Client) context.Context {
	return context.WithValue(ctx, contextKeyClusterClient{}, c)
}

func clusterClientFromContext(ctx context.Context) client.Client {
	c, _ := ctx.Value(contextKeyClusterClient{}).(client.Client)
	return c
}

// publicKeyHash returns the SHA-256 hex digest of the given public key string.
func publicKeyHash(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return fmt.Sprintf("%x", sum)
}

// setCondition sets a Ready condition on the MachineAccountKey status.
func setCondition(mak *iammiloapiscomv1alpha1.MachineAccountKey,
	conditionStatus metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&mak.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// setAnnotation sets a single annotation on the given object, initialising the map if needed.
func setAnnotation(obj metav1.Object, key, value string) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[key] = value
	obj.SetAnnotations(annotations)
}

// Reconcile moves the current state of a MachineAccountKey closer to the desired state.
func (r *MachineAccountKeyController) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("machineaccountkey-reconciler")
	log.Info("Starting reconciliation", "request", req)

	// 1. Resolve cluster.
	cluster, err := r.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		log.Error(err, "Failed to get cluster", "clusterName", req.ClusterName)
		return ctrl.Result{}, fmt.Errorf("get cluster %s: %w", req.ClusterName, err)
	}
	clusterClient := cluster.GetClient()

	// 2. Fetch MachineAccountKey.
	mak := &iammiloapiscomv1alpha1.MachineAccountKey{}
	if err = clusterClient.Get(ctx, req.NamespacedName, mak); err != nil {
		if errors.IsNotFound(err) {
			log.Info("MachineAccountKey resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get MachineAccountKey")
		return ctrl.Result{}, fmt.Errorf("get MachineAccountKey: %w", err)
	}

	// 3. Run finalizers (handles deletion path; inject cluster client via context).
	log.Info("Running finalizers", "machineAccountKeyName", mak.GetName())
	ctx = withClusterClient(ctx, clusterClient)
	finalizeResult, err := r.Finalizers.Finalize(ctx, mak)
	if err != nil {
		log.Error(err, "Failed to run finalizers")
		return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the object. Updating API server")
		updateErr := clusterClient.Update(ctx, mak)
		if updateErr != nil && !errors.IsNotFound(updateErr) {
			log.Error(updateErr, "Failed to update MachineAccountKey after finalizer update")
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}
	if mak.GetDeletionTimestamp() != nil {
		log.Info("MachineAccountKey is marked for deletion. Stopping reconciliation")
		return ctrl.Result{}, nil
	}

	log.Info("Resolving parent MachineAccount", "machineAccountName", mak.Spec.MachineAccountName)
	// 4. Resolve parent MachineAccount.
	ma := &iammiloapiscomv1alpha1.MachineAccount{}
	if err = clusterClient.Get(ctx, types.NamespacedName{
		Namespace: mak.Namespace, Name: mak.Spec.MachineAccountName,
	}, ma); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Parent MachineAccount not found. Requeueing", "machineAccountName", mak.Spec.MachineAccountName)
			setCondition(mak, metav1.ConditionFalse, "ParentNotFound",
				fmt.Sprintf("MachineAccount %q not found", mak.Spec.MachineAccountName))
			_ = clusterClient.Status().Update(ctx, mak)
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		log.Error(err, "Failed to get parent MachineAccount")
		return ctrl.Result{}, fmt.Errorf("get MachineAccount: %w", err)
	}

	// 5. Set owner reference (idempotent; GC cascades MachineAccount deletion to keys).
	if err = controllerutil.SetControllerReference(ma, mak, clusterClient.Scheme()); err != nil {
		log.Error(err, "Failed to set owner reference")
		return ctrl.Result{}, fmt.Errorf("set owner reference: %w", err)
	}
	if err = clusterClient.Update(ctx, mak); err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to update owner reference")
		return ctrl.Result{}, fmt.Errorf("update owner reference: %w", err)
	}

	// 6. Derive Zitadel user ID.
	zitadelUserID := string(ma.GetUID())

	// 7. Compute hash and detect rotation.
	currentHash := publicKeyHash(mak.Spec.PublicKey)
	storedHash := mak.Annotations[machineAccountKeyPublicKeyHashAnnotation]
	hasKey := mak.Status.AuthProviderKeyID != ""
	keyRotation := hasKey && storedHash != "" && storedHash != currentHash

	// --- CASE A: New key ---
	if !hasKey {
		log.Info("Registering new machine key in Zitadel")
		publicKeyBytes := []byte(mak.Spec.PublicKey)
		var expiration *time.Time
		if mak.Spec.ExpirationDate != nil {
			t := mak.Spec.ExpirationDate.Time
			expiration = &t
		}

		keyID, err := r.Zitadel.AddMachineKey(ctx, zitadelUserID, publicKeyBytes, expiration)
		if err != nil {
			log.Error(err, "Failed to register new key in Zitadel")
			setCondition(mak, metav1.ConditionFalse, "ZitadelAPIError",
				fmt.Sprintf("Failed to register key: %v", err))
			_ = clusterClient.Status().Update(ctx, mak)
			return ctrl.Result{}, fmt.Errorf("add machine key: %w", err)
		}
		
		log.Info("Successfully registered new machine key in Zitadel", "keyID", keyID)

		setAnnotation(mak, machineAccountKeyPublicKeyHashAnnotation, currentHash)
		if err = clusterClient.Update(ctx, mak); err != nil {
			log.Error(err, "Failed to update K8s annotations with key hash")
			return ctrl.Result{}, err
		}

		mak.Status.AuthProviderKeyID = keyID
		setCondition(mak, metav1.ConditionTrue, "Registered", "Key registered in Zitadel")
		if err = clusterClient.Status().Update(ctx, mak); err != nil {
			log.Error(err, "Failed to update K8s status with keyID")
			return ctrl.Result{}, err
		}
		
		log.Info("Reconciliation completed for new key")
		return ctrl.Result{}, nil
	}

	// --- CASE B: Rotation ---
	if keyRotation {
		oldKeyID := mak.Status.AuthProviderKeyID
		publicKeyBytes := []byte(mak.Spec.PublicKey)
		var expiration *time.Time
		if mak.Spec.ExpirationDate != nil {
			t := mak.Spec.ExpirationDate.Time
			expiration = &t
		}

		log.Info("Detected key rotation. Revoking old machine key in Zitadel", "oldKeyID", oldKeyID)
		// Security: Must revoke the old key BEFORE registering the new one or updating K8s.
		// If the controller crashes after registration but before updating the K8s object,
		// K8s loses track of the oldKeyID, and the old key remains permanently active.
		// Orphaned new keys (from retries) are harmless because they require the private key.
		if err := r.Zitadel.RemoveMachineKey(ctx, zitadelUserID, oldKeyID); err != nil {
			log.Error(err, "Failed to revoke old machine key", "oldKeyID", oldKeyID)
			return ctrl.Result{}, fmt.Errorf("remove old machine key: %w", err)
		}
		log.Info("Successfully revoked old machine key", "oldKeyID", oldKeyID)

		keyID, err := r.Zitadel.AddMachineKey(ctx, zitadelUserID, publicKeyBytes, expiration)
		if err != nil {
			log.Error(err, "Failed to register rotated key in Zitadel")
			setCondition(mak, metav1.ConditionFalse, "ZitadelAPIError",
				fmt.Sprintf("Failed to register rotated key: %v", err))
			_ = clusterClient.Status().Update(ctx, mak)
			return ctrl.Result{}, fmt.Errorf("add rotated machine key: %w", err)
		}
		log.Info("Successfully registered rotated machine key in Zitadel", "newKeyID", keyID)

		setAnnotation(mak, machineAccountKeyPublicKeyHashAnnotation, currentHash)
		if err = clusterClient.Update(ctx, mak); err != nil {
			log.Error(err, "Failed to update K8s annotations with new key hash")
			return ctrl.Result{}, err
		}

		mak.Status.AuthProviderKeyID = keyID
		setCondition(mak, metav1.ConditionTrue, "Rotated", "Key rotated in Zitadel")
		if err = clusterClient.Status().Update(ctx, mak); err != nil {
			log.Error(err, "Failed to update K8s status with new keyID")
			return ctrl.Result{}, err
		}

		log.Info("Reconciliation completed for rotated key")
		return ctrl.Result{}, nil
	}

	// --- CASE C: Steady state ---
	log.Info("Key is in steady state. No changes required")
	setCondition(mak, metav1.ConditionTrue, "Reconciled", "Key is registered in Zitadel")
	return ctrl.Result{}, clusterClient.Status().Update(ctx, mak)
}

// Finalize revokes the Zitadel key when a MachineAccountKey is deleted.
func (f *machineAccountKeyFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("machineaccountkey-finalizer")
	log.Info("Running machine account key finalizer")

	mak, ok := obj.(*iammiloapiscomv1alpha1.MachineAccountKey)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected MachineAccountKey", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, err
	}

	// Nothing registered — nothing to revoke.
	if mak.Status.AuthProviderKeyID == "" {
		log.Info("No key registered in Zitadel. Nothing to revoke.")
		return finalizer.Result{}, nil
	}

	// Resolve parent MachineAccount for the Zitadel user ID.
	log.Info("Resolving parent MachineAccount for Zitadel UserID")
	clusterClient := clusterClientFromContext(ctx)
	ma := &iammiloapiscomv1alpha1.MachineAccount{}
	if err := clusterClient.Get(ctx, types.NamespacedName{
		Namespace: mak.Namespace, Name: mak.Spec.MachineAccountName,
	}, ma); err != nil {
		if errors.IsNotFound(err) {
			// Parent gone → Zitadel user gone → key implicitly revoked.
			log.Info("Parent MachineAccount not found. Assuming Zitadel user is gone and key is implicitly revoked")
			return finalizer.Result{}, nil
		}
		log.Error(err, "Failed to get parent MachineAccount in finalizer")
		return finalizer.Result{}, fmt.Errorf("get parent MachineAccount: %w", err)
	}

	zitadelUserID := string(ma.GetUID())
	log.Info("Revoking key in Zitadel", "keyID", mak.Status.AuthProviderKeyID, "zitadelUserID", zitadelUserID)
	if err := f.Zitadel.RemoveMachineKey(ctx, zitadelUserID, mak.Status.AuthProviderKeyID); err != nil {
		log.Error(err, "Failed to revoke key in Zitadel during finalizer")
		return finalizer.Result{}, fmt.Errorf("revoke key: %w", err)
	}

	log.Info("Successfully finalized MachineAccountKey")
	return finalizer.Result{}, nil
}

// SetupWithManager registers the finalizer and sets up the controller with the Manager.
func (r *MachineAccountKeyController) SetupWithManager(mgr mcmanager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	r.mgr = mgr

	if err := r.Finalizers.Register(machineAccountKeyFinalizerKey, &machineAccountKeyFinalizer{
		Zitadel: r.Zitadel,
	}); err != nil {
		return fmt.Errorf("register finalizer: %w", err)
	}

	return mcbuilder.ControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.MachineAccountKey{}).
		Named("machineaccountkey").
		Complete(r)
}
