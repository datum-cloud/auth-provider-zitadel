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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pkgzitadel "go.miloapis.com/auth-provider-zitadel/pkg/zitadel"
	resourcemanagermiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

const (
	projectFinalizerKey   = "auth-provider-zitadel.miloapis.com/project"
	projectConditionReady = "ZitadelOrgReady"
)

// ProjectController reconciles Project resources in the main cluster.
// It watches Project resources and maintains a 1:1 mapping to Zitadel Organizations.
// On Project creation, a Zitadel Organization is created with the Project UID as the org ID and name.
// On Project deletion, the Zitadel Organization is deleted (handled by finalizer).
type ProjectController struct {
	Finalizers finalizer.Finalizers
	Zitadel    pkgzitadel.API
	Client     client.Client
}

type projectFinalizer struct {
	Zitadel pkgzitadel.API
}

// Finalize handles cleanup when a Project is deleted.
// It deletes the corresponding Zitadel Organization.
// NotFound errors are treated as success (idempotent).
func (f *projectFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx).WithName("project-finalizer")
	log.Info("Starting finalization for Project")

	project, ok := obj.(*resourcemanagermiloapiscomv1alpha1.Project)
	if !ok {
		err := fmt.Errorf("unexpected object type %T, expected Project", obj)
		log.Error(err, "Type assertion failed")
		return finalizer.Result{}, err
	}

	projectName := project.GetName()
	log.Info("Deleting Zitadel Organization", "projectName", projectName)

	err := f.Zitadel.DeleteOrganization(ctx, projectName)
	if err != nil {
		log.Error(err, "Failed to delete Zitadel Organization", "orgID", projectName)
		return finalizer.Result{}, fmt.Errorf("delete organization: %w", err)
	}

	log.Info("Successfully finalized Project", "projectName", projectName)
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/status,verbs=get;update
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/finalizers,verbs=update

// Reconcile moves the current state of a Project closer to the desired state.
// It watches Project resources and ensures a corresponding Zitadel Organization exists.
func (r *ProjectController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithName("project-reconciler")
	log.Info("Starting reconciliation", "request", req)

	// Fetch Project resource from the main cluster.
	project := &resourcemanagermiloapiscomv1alpha1.Project{}
	if err := r.Client.Get(ctx, req.NamespacedName, project); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Project not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Project")
		return ctrl.Result{}, fmt.Errorf("get project: %w", err)
	}

	// Run finalizers (handles deletion path).
	finalizeResult, err := r.Finalizers.Finalize(ctx, project)
	if err != nil {
		log.Error(err, "Failed to run finalizers")
		return ctrl.Result{}, fmt.Errorf("finalize: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Finalizer updated the object. Updating API server")
		if err := r.Client.Update(ctx, project); err != nil {
			log.Error(err, "Failed to update Project after finalizer")
			return ctrl.Result{}, fmt.Errorf("update project after finalizer: %w", err)
		}
	}

	// If object is marked for deletion, we're done.
	if project.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	projectName := project.GetName()

	// Skip reconciliation if the Zitadel Organization is already ready.
	// This avoids unnecessary GetOrganization API calls on every reconciliation.
	if condition := meta.FindStatusCondition(project.Status.Conditions, projectConditionReady); condition != nil && condition.Status == metav1.ConditionTrue {
		log.V(2).Info("Zitadel Organization is already ready. Skipping reconciliation", "projectName", projectName)
		return ctrl.Result{}, nil
	}

	// Check if Zitadel Organization already exists.
	// The organization ID matches the project name, which also matches the project control plane cluster name (/{project-name}).
	org, err := r.Zitadel.GetOrganization(ctx, projectName)
	if err != nil {
		log.Error(err, "Failed to check if Zitadel Organization exists", "projectName", projectName)
		return ctrl.Result{}, fmt.Errorf("get organization: %w", err)
	}

	// Create organization if it doesn't exist.
	if org == nil {
		log.Info("Zitadel Organization does not exist. Creating...", "projectName", projectName)
		orgID, err := r.Zitadel.CreateOrganizationWithID(ctx, projectName, projectName)
		if err != nil {
			log.Error(err, "Failed to create Zitadel Organization", "projectName", projectName)
			setProjectCondition(project, metav1.ConditionFalse, "OrgCreationFailed", err.Error())
			if statusErr := r.Client.Status().Update(ctx, project); statusErr != nil {
				log.Error(statusErr, "Failed to update Project status")
			}
			return ctrl.Result{}, fmt.Errorf("create organization: %w", err)
		}
		log.Info("Zitadel Organization created successfully", "orgID", orgID)
	}

	// Update Project status to indicate Zitadel Org is ready.
	setProjectCondition(project, metav1.ConditionTrue, projectConditionReady, "Zitadel Organization is ready")

	if err := r.Client.Status().Update(ctx, project); err != nil {
		log.Error(err, "Failed to update Project status")
		return ctrl.Result{}, fmt.Errorf("update project status: %w", err)
	}

	log.Info("Successfully reconciled Project", "projectName", projectName)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the given manager.
func (r *ProjectController) SetupWithManager(mgr ctrl.Manager) error {
	log := logf.Log.WithName("project-controller-setup")
	log.Info("Setting up Project controller")

	r.Finalizers = finalizer.NewFinalizers()
	projectFin := &projectFinalizer{
		Zitadel: r.Zitadel,
	}
	if err := r.Finalizers.Register(projectFinalizerKey, projectFin); err != nil {
		return fmt.Errorf("register project finalizer: %w", err)
	}
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&resourcemanagermiloapiscomv1alpha1.Project{}).
		Complete(r)
}

// setProjectCondition sets a condition on the Project's status.
// It updates the ZitadelOrgReady condition with the given status, reason, and message.
func setProjectCondition(project *resourcemanagermiloapiscomv1alpha1.Project, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&project.Status.Conditions, metav1.Condition{
		Type:               projectConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}
