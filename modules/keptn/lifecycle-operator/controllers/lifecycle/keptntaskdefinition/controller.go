/*
Copyright 2022.

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

package keptntaskdefinition

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	apilifecycle "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1"
	controllercommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/taskdefinition"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KeptnTaskDefinitionReconciler reconciles a KeptnTaskDefinition object
type KeptnTaskDefinitionReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	Log         logr.Logger
	EventSender eventsender.IEvent
}

// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntaskdefinitions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntaskdefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntaskdefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=create;get;update;list;watch

func (r *KeptnTaskDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	requestInfo := controllercommon.GetRequestInfo(req)
	r.Log.Info("Reconciling KeptnTaskDefinition", "requestInfo", requestInfo)

	definition := &apilifecycle.KeptnTaskDefinition{}

	if err := r.Client.Get(ctx, req.NamespacedName, definition); err != nil {
		if errors.IsNotFound(err) {
			// taking down all associated K8s resources is handled by K8s
			r.Log.Info("KeptnTaskDefinition resource not found. Ignoring since object must be deleted", "requestInfo", requestInfo)
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "Failed to get the KeptnTaskDefinition")
		return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
	}
	defSpec := taskdefinition.GetRuntimeSpec(definition)
	if definition.Spec.Container == nil && defSpec != nil { // if the spec is well-defined

		// get configmap reference either existing configmap name or inline generated one
		cmName := taskdefinition.GetCmName(definition.Name, defSpec)

		// get existing configmap either generated from inline or user defined
		cm, err := r.getConfigMap(ctx, cmName, req.Namespace)
		// if IsNotFound we need to create it
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		// generate the updated config map, this is either the existing config map or the inline one
		functionCm := cm
		if taskdefinition.IsInline(defSpec) {
			functionCm = r.generateConfigMap(defSpec, cmName, definition.Namespace)
		}
		// compare and handle updated and existing
		r.reconcileConfigMap(ctx, functionCm, cm)
		// / if neither exist remove from status
		r.updateTaskDefinitionStatus(functionCm, definition)
		// now we know that the reference to the config map is valid, so we update the definition
		err = r.Client.Status().Update(ctx, definition)
		if err != nil {
			r.Log.Error(err, "could not update configmap status reference for: "+definition.Name)
			return ctrl.Result{}, nil
		}
		r.Log.Info("updated configmap status reference for: "+definition.Name, "requestInfo", requestInfo)

	}

	r.Log.Info("Finished Reconciling KeptnTaskDefinition", "requestInfo", requestInfo)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeptnTaskDefinitionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apilifecycle.KeptnTaskDefinition{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}
