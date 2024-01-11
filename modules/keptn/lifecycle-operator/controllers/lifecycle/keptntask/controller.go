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

package keptntask

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	controllercommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"go.opentelemetry.io/otel/metric"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// KeptnTaskReconciler reconciles a KeptnTask object
type KeptnTaskReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	EventSender eventsender.IEvent
	Log         logr.Logger
	Meters      apicommon.KeptnMeters
}

// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntasks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntasks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptntasks/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;get;update;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs/status,verbs=get;list

func (r *KeptnTaskReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	requestInfo := controllercommon.GetRequestInfo(req)
	r.Log.Info("Reconciling KeptnTask", "requestInfo", requestInfo)
	task := &klcv1beta1.KeptnTask{}

	if err := r.Client.Get(ctx, req.NamespacedName, task); err != nil {
		if errors.IsNotFound(err) {
			// taking down all associated K8s resources is handled by K8s
			r.Log.Info("KeptnTask resource not found. Ignoring since object must be deleted", "requestInfo", requestInfo)
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "Failed to get the KeptnTask")
		return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
	}

	task.SetStartTime()

	defer func() {
		err := r.Client.Status().Update(ctx, task)
		if err != nil {
			r.Log.Error(err, "could not update KeptnTask status reference for: "+task.Name)
		}
	}()

	job, err := r.getJob(ctx, task.Status.JobName, req.Namespace)
	if err != nil && !errors.IsNotFound(err) {
		r.Log.Error(err, "Could not check if job is running")
		return ctrl.Result{Requeue: true, RequeueAfter: 30 * time.Second}, nil
	}

	if job == nil {
		err = r.createJob(ctx, req, task)
		if err != nil {
			r.Log.Error(err, "could not create Job")
		} else {
			task.Status.Status = apicommon.StateProgressing
		}
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	if !task.Status.Status.IsCompleted() {
		r.updateTaskStatus(job, task)
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	r.Log.Info("Finished Reconciling KeptnTask", "requestInfo", requestInfo)

	// Task is completed at this place
	task.SetEndTime()

	attrs := task.GetMetricsAttributes()

	r.Log.Info("Increasing task count", "requestInfo", requestInfo)

	// metrics: increment task counter
	r.Meters.TaskCount.Add(ctx, 1, metric.WithAttributes(attrs...))

	// metrics: add task duration
	duration := task.Status.EndTime.Time.Sub(task.Status.StartTime.Time)
	r.Meters.TaskDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeptnTaskReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// predicate disabling the auto reconciliation after updating the object status
		For(&klcv1beta1.KeptnTask{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
