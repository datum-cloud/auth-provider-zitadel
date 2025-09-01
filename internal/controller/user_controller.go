package controller

import (
	"context"
	"fmt"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"go.miloapis.com/auth-provider-zitadel/internal/zitadel"
)

const (
	userFinalizerKey = "iam.miloapis.com/user"
)

// UserController reconciles User objects to handle deletions and Zitadel cleanup.
type UserController struct {
	Client     client.Client
	Finalizers finalizer.Finalizers
	Zitadel    *zitadel.Client
}

type userFinalizer struct {
	Zitadel *zitadel.Client
}

// Finalize implements finalizer.Finalizer for User resources.
func (f *userFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("user-finalizer")

	user, ok := obj.(*iammiloapiscomv1alpha1.User)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected User", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, err
	}

	log.Info("Finalizing User deletion", "userName", user.GetName(), "userUID", user.GetUID())

	// Delete the user in Zitadel if it exists.
	if err := f.Zitadel.DeleteUser(ctx, user.GetName()); err != nil {
		if errors.IsNotFound(err) {
			log.Info("User already deleted in Zitadel, skipping", "userName", user.GetName())
		} else {
			log.Error(err, "Failed to delete user in Zitadel", "userName", user.GetName())
			return finalizer.Result{}, fmt.Errorf("failed to delete user in Zitadel: %w", err)
		}
	}

	log.Info("Successfully deleted user", "userName", user.GetName())

	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;update;list;watch;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users/finalizers,verbs=update

// Reconcile executes the reconciliation loop for User resources.
func (r *UserController) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("user-reconciler")
	log.Info("Starting reconciliation", "request", req)

	user := &iammiloapiscomv1alpha1.User{}
	if err := r.Client.Get(ctx, req.NamespacedName, user); err != nil {
		if errors.IsNotFound(err) {
			log.Info("User resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get User resource")
		return ctrl.Result{}, fmt.Errorf("failed to get User resource: %w", err)
	}

	// Run finalizers.
	finalizeResult, err := r.Finalizers.Finalize(ctx, user)
	if err != nil {
		log.Error(err, "Failed to run finalizers for User")
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for User: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the User object, updating API server")
		if updateErr := r.Client.Update(ctx, user); updateErr != nil {
			log.Error(updateErr, "Failed to update User after finalizer update")
			return ctrl.Result{}, fmt.Errorf("failed to update User after finalizer update: %w", updateErr)
		}
		return ctrl.Result{}, nil
	}

	log.Info("Reconciliation complete")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the provided manager.
func (r *UserController) SetupWithManager(mgr manager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(userFinalizerKey, &userFinalizer{
		Zitadel: r.Zitadel,
	}); err != nil {
		return fmt.Errorf("failed to register user finalizer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.User{}).
		Named("user").
		Complete(r)
}
