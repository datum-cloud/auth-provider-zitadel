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
	"strings"

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

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
)

const (
	machineAccountFinalizerKey  = "iam.miloapis.com/machineaccount"
	inactiveMachineAccountState = "Inactive"
	activeMachineAccountState   = "Active"
)

// MachineAccountController reconciles a MachineAccount object
type MachineAccountController struct {
	Finalizers         finalizer.Finalizers
	Zitadel            pkgzitadel.API
	EmailAddressSuffix string
	mgr                mcmanager.Manager
}

type machineAccountFinalizer struct {
	Zitadel pkgzitadel.API
}

func (f *machineAccountFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("machineaccount-finalizer")
	log.Info("Starting finalization")

	// Type assertion to get the machine account object.
	machineAccount, ok := obj.(*iammiloapiscomv1alpha1.MachineAccount)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected MachineAccount", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, fmt.Errorf("type assertion failed: %w", err)
	}

	userID := string(machineAccount.GetUID())
	log.Info("Checking if machine account exists in Zitadel", "userID", userID)

	user, err := f.Zitadel.GetUserByID(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "userID", userID)
		return finalizer.Result{}, fmt.Errorf("get user by id: %w", err)
	}

	if user == nil {
		log.Info("Machine account not found in Zitadel, nothing to clean up", "userID", userID)
		return finalizer.Result{}, nil
	}

	log.Info("Deleting machine account from Zitadel", "userID", userID)
	err = f.Zitadel.DeleteUser(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to delete user from Zitadel", "userID", userID)
		return finalizer.Result{}, fmt.Errorf("delete user: %w", err)
	}

	log.Info("Successfully finalized machine account", "userID", userID)
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

	cluster, err := r.mgr.GetCluster(ctx, req.ClusterName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get cluster %s from manager: %w", req.ClusterName, err)
	}

	machineAccount := &iammiloapiscomv1alpha1.MachineAccount{}
	err = cluster.GetClient().Get(ctx, req.NamespacedName, machineAccount)
	if errors.IsNotFound(err) {
		log.Info("MachineAccount resource not found")
		return ctrl.Result{}, nil
	} else if err != nil {
		log.Error(err, "Failed to get MachineAccount resource")
		return ctrl.Result{}, fmt.Errorf("failed to get MachineAccount resource: %w", err)
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
		if updateErr := cluster.GetClient().Update(ctx, machineAccount); updateErr != nil {
			log.Error(updateErr, "Failed to update MachineAccount after finalizer update")
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	// Resolve the Zitadel Organization ID for this machine account's project.
	// The cluster name is /{project-name}, so strip the leading / to get the project name.
	// The org ID is prefixed to avoid collisions with infrastructure-managed
	// Zitadel organizations that use the bare project name.
	projectName := strings.TrimPrefix(req.ClusterName, "/")
	orgID := pkgzitadel.OrgIDForProject(projectName)
	log.V(2).Info("Checking if Zitadel organization exists", "orgID", orgID)
	org, err := r.Zitadel.GetOrganization(ctx, orgID)
	if err != nil {
		log.Error(err, "Failed to check if Zitadel Organization exists", "orgID", orgID)
		return ctrl.Result{}, fmt.Errorf("get organization: %w", err)
	}

	if org == nil {
		log.Info("Zitadel Organization does not exist, creating it", "orgID", orgID, "displayName", projectName)
		if _, err := r.Zitadel.CreateOrganizationWithID(ctx, projectName, orgID); err != nil {
			log.Error(err, "Failed to create Zitadel Organization", "orgID", orgID)
			return ctrl.Result{}, fmt.Errorf("create organization: %w", err)
		}
		log.Info("Successfully created Zitadel Organization", "orgID", orgID, "displayName", projectName)
	}

	maComputedEmail := r.computeEmailAddress(machineAccount, req)
	userID := string(machineAccount.GetUID())
	log.Info("Checking if machine account exists in Zitadel", "userID", userID, "orgID", orgID)

	user, err := r.Zitadel.GetUserByID(ctx, userID)
	if err != nil {
		log.Error(err, "Failed to get user from Zitadel", "userID", userID)
		return ctrl.Result{}, fmt.Errorf("get user by id: %w", err)
	}

	if user == nil {
		log.Info("Machine account not found in Zitadel, creating it", "userID", userID, "orgID", orgID)
		// Create the machine account in the project's Zitadel Organization.
		// UID is used instead of Name as UID is never reused.
		_, err := r.Zitadel.AddMachineUserInOrganization(ctx, orgID, userID, maComputedEmail, machineAccount.GetName())
		if err != nil {
			log.Error(err, "Failed to create machine user in Zitadel", "userID", userID, "orgID", orgID)
			return ctrl.Result{}, fmt.Errorf("add machine user in organization: %w", err)
		}
		log.Info("Successfully created machine account in Zitadel", "userID", userID, "orgID", orgID)
	}

	// Update the machine account state in Zitadel if it is different from the desired state
	if machineAccount.Status.State != machineAccount.Spec.State {
		if err := r.updateMachineAccountState(ctx, orgID, machineAccount); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update machine account state: %w", err)
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
	if err := cluster.GetClient().Status().Update(ctx, machineAccount); err != nil {
		log.Error(err, "Failed to update MachineAccount status")
		return ctrl.Result{}, fmt.Errorf("failed to update MachineAccount status: %w", err)
	}

	log.Info("Successfully reconciled MachineAccount")
	return ctrl.Result{}, nil
}

// updateMachineAccountState updates the state of a machine account in Zitadel
func (r *MachineAccountController) updateMachineAccountState(ctx context.Context, orgID string, machineAccount *iammiloapiscomv1alpha1.MachineAccount) error {
	log := logf.FromContext(ctx).WithName("machineaccount-reconciler")

	userID := string(machineAccount.GetUID())
	skipUpdate := false
	var updateFnc func(ctx context.Context, orgID, userID string) error

	switch machineAccount.Spec.State {
	case activeMachineAccountState:
		if machineAccount.Status.State == "" {
			log.Info("New Machine Account. Zitadel default state is Active")
			skipUpdate = true
		}
		log.Info("Reactivating machine account", "userID", userID, "orgID", orgID)
		updateFnc = r.Zitadel.ReactivateUser

	case inactiveMachineAccountState:
		log.Info("Deactivating machine account", "userID", userID, "orgID", orgID)
		updateFnc = r.Zitadel.DeactivateUser

	default:
		log.Error(fmt.Errorf("invalid state: %s", machineAccount.Spec.State), "Invalid state")
		return fmt.Errorf("invalid state: %s", machineAccount.Spec.State)
	}

	if !skipUpdate {
		log.Info("Updating machine account state", "userID", userID, "orgID", orgID)
		err := updateFnc(ctx, orgID, userID)
		if err != nil {
			log.Error(err, "Failed to update machine account on Zitadel", "userID", userID, "orgID", orgID)
			return err
		}

		log.Info("Successfully updated machine account", "userID", userID, "orgID", orgID)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineAccountController) SetupWithManager(mgr mcmanager.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	r.mgr = mgr

	if err := r.Finalizers.Register(machineAccountFinalizerKey, &machineAccountFinalizer{
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
// EmailAddress is {metadata.name}@{project-name}.{EmailAddressSuffix}
func (r *MachineAccountController) computeEmailAddress(machineAccount *iammiloapiscomv1alpha1.MachineAccount, req mcreconcile.Request) string {
	projectName := strings.TrimPrefix(req.ClusterName, "/")
	return machineAccount.GetName() + "@" + projectName + "." + r.EmailAddressSuffix
}
