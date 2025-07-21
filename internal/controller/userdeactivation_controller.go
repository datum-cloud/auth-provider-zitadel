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

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	mcbuilder "sigs.k8s.io/multicluster-runtime/pkg/builder"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	mcreconcile "sigs.k8s.io/multicluster-runtime/pkg/reconcile"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
)

const (
	userDeactivationFinalizerKey   = "iam.miloapis.com/userdeactivation"
	userDeactivationReadyCondition = "Ready"
)

type UserDeactivationController struct {
	Client     client.Client
	Finalizers finalizer.Finalizers
	Zitadel    *zitadel.Client
}

type userDeactivationFinalizer struct {
	Client  client.Client
	Zitadel *zitadel.Client
}

func (f *userDeactivationFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("userdeactivation-finalizer")

	// Type assertion to get the user deactivation object.
	userDeactivation, ok := obj.(*iammiloapiscomv1alpha1.UserDeactivation)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected UserDeactivation", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, fmt.Errorf("type assertion failed: %w", err)
	}
	log.Info("Running finalizers", "userDeactivationName", obj.GetName(), "userDeactivationUID", obj.GetUID())

	// Get the user reference from this UserDeactivation
	userRef := userDeactivation.Spec.UserRef.Name

	log.Info("Checking for other UserDeactivation objects", "userRef", userRef)
	otherUserDeactivationsCount, err := f.countOtherUserDeactivations(ctx, userDeactivation, userRef)
	if err != nil {
		log.Error(err, "Failed to count other UserDeactivation objects")
		return finalizer.Result{}, fmt.Errorf("failed to count other UserDeactivation objects: %w", err)
	}

	// If there are no other UserDeactivation objects for this user, reactivate the user
	if otherUserDeactivationsCount == 0 {
		log.Info("No other UserDeactivation objects found, reactivating user in Zitadel", "userRef", userRef)
		err = f.Zitadel.ReactivateUser(ctx, userRef)
		if err != nil {
			log.Error(err, "Failed to reactivate user in Zitadel", "userRef", userRef)
			return finalizer.Result{}, fmt.Errorf("failed to reactivate user in Zitadel: %w", err)
		}
		log.Info("Successfully reactivated user in Zitadel", "userRef", userRef)

		// Update the User status to Active
		user := &iammiloapiscomv1alpha1.User{}
		err = f.Client.Get(ctx, client.ObjectKey{Name: userRef}, user)
		if err != nil {
			log.Error(err, "Failed to get User resource", "userRef", userRef)
			return finalizer.Result{}, fmt.Errorf("failed to get User resource: %w", err)
		}
		user.Status.State = "Active"
		err = f.Client.Status().Update(ctx, user)
		if err != nil {
			log.Error(err, "Failed to update User status", "userRef", userRef)
			return finalizer.Result{}, fmt.Errorf("failed to update User status: %w", err)
		}
		log.Info("Successfully updated User status to Active", "userRef", userRef)
	} else {
		log.Info("Other UserDeactivation objects exist for user, skipping reactivation", "userRef", userRef)
	}

	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=userdeactivations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=userdeactivations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=userdeactivations/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the UserDeactivation object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *UserDeactivationController) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("userdeactivation-reconciler")
	log.Info("Starting reconciliation", "request", req)

	// Get the UserDeactivation object
	userDeactivation := &iammiloapiscomv1alpha1.UserDeactivation{}
	err := r.Client.Get(ctx, req.NamespacedName, userDeactivation)
	if errors.IsNotFound(err) {
		log.Info("UserDeactivation resource not found")
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get UserDeactivation resource")
		return ctrl.Result{}, fmt.Errorf("failed to get UserDeactivation resource: %w", err)
	}

	// Run the finalizers
	log.Info("Running finalizers", "userDeactivationName", userDeactivation.GetName(), "userDeactivationUID", userDeactivation.GetUID())
	finalizeResult, err := r.Finalizers.Finalize(ctx, userDeactivation)
	if err != nil {
		log.Error(err, "Failed to run finalizers for UserDeactivation")
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for UserDeactivation: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the userDeactivation object, updating API server")
		if updateErr := r.Client.Update(ctx, userDeactivation); updateErr != nil {
			log.Error(updateErr, "Failed to update UserDeactivation after finalizer update")
			return ctrl.Result{}, fmt.Errorf("failed to update UserDeactivation after finalizer update: %w", updateErr)
		}
		return ctrl.Result{}, nil
	}

	// Get the User to deactivate based on UserRef
	user := &iammiloapiscomv1alpha1.User{}
	userObjectKey := client.ObjectKey{
		Name: userDeactivation.Spec.UserRef.Name,
	}
	err = r.Client.Get(ctx, userObjectKey, user)
	if err != nil {
		// The user must exists, otherwise the UserDeactivation object should not be created
		log.Error(err, "Failed to get User resource", "userRef", userDeactivation.Spec.UserRef)
		return ctrl.Result{}, fmt.Errorf("failed to get User resource: %w", err)
	}

	// Deactivate the user in Zitadel
	// The deactivation decision is based on the user's current state rather than other UserDeactivation objects
	// to ensure deactivation occurs even if the user was accidentally reactivated through manual intervention.
	deactivateUser := user.Status.State == "Active" || user.Status.State == ""
	if deactivateUser {
		log.Info("Deactivating User in Zitadel", "userRef", userDeactivation.Spec.UserRef)
		err = r.Zitadel.DeactivateUser(ctx, user.GetName())
		if err != nil {
			log.Error(err, "Failed to deactivate User in Zitadel", "userRef", userDeactivation.Spec.UserRef)
			return ctrl.Result{}, fmt.Errorf("failed to deactivate User in Zitadel: %w", err)
		}
		user.Status.State = "Inactive"
		err = r.Client.Status().Update(ctx, user)
		if err != nil {
			log.Error(err, "Failed to update User status", "userRef", userDeactivation.Spec.UserRef)
			return ctrl.Result{}, fmt.Errorf("failed to update User status: %w", err)
		}
	} else {
		log.Info("User is already deactivated", "userRef", userDeactivation.Spec.UserRef)
	}

	log.Info("Updating UserDeactivation status", "userDeactivationName", userDeactivation.GetName())
	userDeactivationCondition := metav1.Condition{
		Type:               userDeactivationReadyCondition,
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "UserDeactivation successfully reconciled",
		LastTransitionTime: metav1.Now(),
	}
	meta.SetStatusCondition(&user.Status.Conditions, userDeactivationCondition)
	if err := r.Client.Status().Update(ctx, userDeactivation); err != nil {
		log.Error(err, "Failed to update UserDeactivation status")
		return ctrl.Result{}, fmt.Errorf("failed to update UserDeactivation status: %w", err)
	}

	log.Info("Reconciliation completed", "userRef", userDeactivation.Spec.UserRef)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *UserDeactivationController) SetupWithManager(mgr mcmanager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(userDeactivationFinalizerKey, &userDeactivationFinalizer{
		Client:  r.Client,
		Zitadel: r.Zitadel,
	}); err != nil {
		return fmt.Errorf("failed to register group finalizer: %w", err)
	}

	return mcbuilder.ControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.UserDeactivation{}).
		Named("userdeactivation").
		Complete(r)
}

// countOtherUserDeactivations counts how many other UserDeactivation objects
// reference the same user, excluding the current UserDeactivation object
func (f *userDeactivationFinalizer) countOtherUserDeactivations(ctx context.Context, userDeactivation *iammiloapiscomv1alpha1.UserDeactivation, userRef string) (int, error) {
	log := logf.FromContext(ctx).WithName("count-other-deactivations")

	// List all UserDeactivation objects to see if any other ones reference the same user
	userDeactivationList := &iammiloapiscomv1alpha1.UserDeactivationList{}
	err := f.Client.List(ctx, userDeactivationList)
	if err != nil {
		log.Error(err, "Failed to list UserDeactivation objects")
		return 0, fmt.Errorf("failed to list UserDeactivation objects: %w", err)
	}

	// Count how many UserDeactivation objects reference the same user (excluding the current one)
	otherDeactivationsCount := 0
	for _, item := range userDeactivationList.Items {
		// Skip the current UserDeactivation object
		if item.GetUID() == userDeactivation.GetUID() {
			continue
		}
		// Check if this UserDeactivation references the same user
		if item.Spec.UserRef.Name == userRef {
			otherDeactivationsCount++
		}
	}

	log.Info("Other UserDeactivation objects found", "userRef", userRef, "count", otherDeactivationsCount)
	return otherDeactivationsCount, nil
}
