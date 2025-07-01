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
	machineAccountFinalizerKey = "iam.miloapis.com/machineaccount"
)

// MachineAccountReconciler reconciles a MachineAccount object
type MachineAccountController struct {
	Client             client.Client
	Finalizers         finalizer.Finalizers
	Zitadel            *zitadel.Client
	EmailAddressSuffix string
}

type machineAccountFinalizer struct {
	Client  client.Client
	Zitadel *zitadel.Client
}

func (f *machineAccountFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("machineaccount-finalizer")
	log.Info("Starting finalization")

	// Type assertion to get the machine account object.
	machineAccount, ok := obj.(*iammiloapiscomv1alpha1.MachineAccount)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected MachineAccount", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, err
	}

	log.Info("Checking if machine account exists in Zitadel", "username", machineAccount.GetUID())
	_, err := f.Zitadel.GetUser(ctx, string(machineAccount.GetUID()))
	if errors.IsNotFound(err) {
		log.Info("Machine account not found in Zitadel, nothing to clean up", "uid", machineAccount.GetUID())
		return finalizer.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "userName", machineAccount.GetUID())
		return finalizer.Result{}, err
	}

	log.Info("Deleting machine account from Zitadel", "userName", machineAccount.GetUID())
	err = f.Zitadel.DeleteUser(ctx, string(machineAccount.GetUID()))
	if errors.IsNotFound(err) {
		log.Info("Machine account already deleted from Zitadel", "username", machineAccount.GetUID())
	} else if err != nil {
		log.Error(err, "Failed to delete user from Zitadel", "username", machineAccount.GetUID())
		return finalizer.Result{}, err
	}

	log.Info("Successfully finalized machine account", "username", machineAccount.GetUID())
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=machineaccounts/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the MachineAccount object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *MachineAccountController) Reconcile(ctx context.Context, req mcreconcile.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("machineaccount-reconciler")
	log.Info("Starting reconciliation", "request", req)

	machineAccount := &iammiloapiscomv1alpha1.MachineAccount{}
	err := r.Client.Get(ctx, req.NamespacedName, machineAccount)
	if errors.IsNotFound(err) {
		log.Info("MachineAccount resource not found")
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get MachineAccount resource")
		return ctrl.Result{}, err
	}

	// Funalizers must run before we update the MachineAccount Status,
	// we need to set the Status State to the desired state on the first complete reconciliation
	log.Info("Running finalizers", "machineAccountName", machineAccount.GetName(), "machineAccountUID", machineAccount.GetUID())
	finalizeResult, err := r.Finalizers.Finalize(ctx, machineAccount)
	if err != nil {
		log.Error(err, "Failed to run finalizers for MachineAccount")
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for MachineAccount: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the machineAccount object, updating API server")
		if updateErr := r.Client.Update(ctx, machineAccount); updateErr != nil {
			log.Error(updateErr, "Failed to update MachineAccount after finalizer update")
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	maComputedEmail := r.computeEmailAddress(machineAccount, req)
	log.Info("Checking if machine account exists in Zitadel", "username", machineAccount.GetUID())
	_, err = r.Zitadel.GetUser(ctx, string(machineAccount.GetUID()))
	if errors.IsNotFound(err) {
		log.Info("Machine account not found in Zitadel, creating it", "username", machineAccount.GetUID())
		// Create the machine account in Zitadel.
		// UID is used instead of Name as UID is never reused
		_, err := r.Zitadel.CreateMachineUser(ctx, zitadel.MachineUserRequest{
			UserName:        maComputedEmail,
			Name:            string(machineAccount.GetUID()),
			AccessTokenType: zitadel.AccessTokenTypeJWT,
			UserId:          string(machineAccount.GetUID()),
		})
		if err != nil {
			log.Error(err, "Failed to create machine user in Zitadel", "username", machineAccount.GetUID())
			return ctrl.Result{}, err
		}
		log.Info("Successfully created machine account in Zitadel", "username", machineAccount.GetUID())
	} else if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "username", machineAccount.GetUID())
		return ctrl.Result{}, err
	}

	// Update the machine account state in Zitadel if it is different from the desired state
	if machineAccount.Status.State != machineAccount.Spec.State {
		if err := r.updateMachineAccountState(ctx, machineAccount); err != nil {
			return ctrl.Result{}, err
		}
	}

	if machineAccount.GetDeletionTimestamp() != nil {
		log.Info("MachineAccount is marked for deletion, stopping reconciliation")
		return ctrl.Result{}, nil
	}

	log.Info("Updating MachineAccount status", "machineAccountName", machineAccount.GetName())
	machineAccount.Status.State = machineAccount.Spec.State
	machineAccount.Status.Email = maComputedEmail
	machineAccountCondition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "Group successfully reconciled",
		LastTransitionTime: metav1.Now(),
	}
	meta.SetStatusCondition(&machineAccount.Status.Conditions, machineAccountCondition)
	if err := r.Client.Status().Update(ctx, machineAccount); err != nil {
		log.Error(err, "Failed to update MachineAccount status")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled MachineAccount")
	return ctrl.Result{}, nil
}

// updateMachineAccountState updates the state of a machine account in Zitadel
func (r *MachineAccountController) updateMachineAccountState(ctx context.Context, machineAccount *iammiloapiscomv1alpha1.MachineAccount) error {
	log := logf.FromContext(ctx).WithName("machineaccount-reconciler")
	log.Info("el estatus es ", machineAccount.Spec.State)

	skipUpdate := false
	var updateFnc func(ctx context.Context, userID string) error
	switch machineAccount.Spec.State {
	case "Active":
		if machineAccount.Status.State == "" {
			log.Info("New Machine Account. Zitadel default state is Active")
			skipUpdate = true
		}
		log.Info("Reactivating machine account", "username", machineAccount.GetName())
		updateFnc = r.Zitadel.ReactivateUser

	case "Inactive":
		log.Info("Deactivating machine account", "username", machineAccount.GetName())
		updateFnc = r.Zitadel.DeactivateUser

	default:
		log.Error(fmt.Errorf("invalid state: %s", machineAccount.Spec.State), "Invalid state")
		return fmt.Errorf("invalid state: %s", machineAccount.Spec.State)
	}

	if !skipUpdate {
		log.Info("Updating machine account state", "username", machineAccount.GetName())
		err := updateFnc(ctx, string(machineAccount.GetUID()))
		if !errors.IsNotFound(err) {
			log.Error(err, "Failed to update machine account on Zitadel", "username", machineAccount.GetName())
			return err
		}

		log.Info("Successfully updated machine account", "username", machineAccount.GetName())
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineAccountController) SetupWithManager(mgr mcmanager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(machineAccountFinalizerKey, &machineAccountFinalizer{
		Client:  r.Client,
		Zitadel: r.Zitadel,
	}); err != nil {
		return fmt.Errorf("failed to register group finalizer: %w", err)
	}

	return mcbuilder.ControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.MachineAccount{}).
		Named("machineaccount").
		Complete(r)
}

// computeEmailAddress computes the email address for a machine account
// EmailAddress is {metadata.name}@{metadata.namespace}.{project.metadata.name}.{EmailAddressSuffix}
func (r *MachineAccountController) computeEmailAddress(machineAccount *iammiloapiscomv1alpha1.MachineAccount, req mcreconcile.Request) string {
	return string(machineAccount.GetUID()) + "@" + machineAccount.GetNamespace() + "." + req.ClusterName + "." + r.EmailAddressSuffix
}
