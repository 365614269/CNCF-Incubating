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

package keptnevaluation

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apilifecycle "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	controllercommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/providers/keptnmetric"
	"go.opentelemetry.io/otel/metric"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// KeptnEvaluationReconciler reconciles a KeptnEvaluation object
type KeptnEvaluationReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	EventSender eventsender.IEvent
	Log         logr.Logger
	Meters      apicommon.KeptnMeters
}

// clusterrole
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnevaluations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnevaluations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnevaluations/finalizers,verbs=update
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnevaluationdefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=metrics.keptn.sh,resources=keptnmetrics,verbs=get;list;watch

// role
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *KeptnEvaluationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	requestInfo := controllercommon.GetRequestInfo(req)
	r.Log.Info("Reconciling KeptnEvaluation", "requestInfo", requestInfo)
	evaluation := &apilifecycle.KeptnEvaluation{}

	if err := r.Client.Get(ctx, req.NamespacedName, evaluation); err != nil {
		if errors.IsNotFound(err) {
			// taking down all associated K8s resources is handled by K8s
			r.Log.Info("KeptnEvaluation resource not found. Ignoring since object must be deleted", "requestInfo", requestInfo)
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "Failed to get the KeptnEvaluation")
		return ctrl.Result{}, nil
	}

	evaluation.SetStartTime()

	if evaluation.Status.RetryCount >= evaluation.Spec.Retries {
		r.handleEvaluationExceededRetries(ctx, evaluation)
		return ctrl.Result{}, nil
	}

	if !evaluation.Status.OverallStatus.IsSucceeded() {
		evaluationDefinition, err := controllercommon.GetEvaluationDefinition(r.Client, r.Log, ctx, evaluation.Spec.EvaluationDefinition, req.NamespacedName.Namespace)
		if err != nil {
			if errors.IsNotFound(err) {
				r.Log.Info("KeptnEvaluation not found", "requestInfo", requestInfo, "evaluationDefinition", evaluation.Spec.EvaluationDefinition)
				return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
			}
			r.Log.Error(err, "Failed to retrieve a resource")
			return ctrl.Result{}, nil
		}

		evaluation = r.performEvaluation(ctx, evaluation, evaluationDefinition)

	}

	if !evaluation.Status.OverallStatus.IsSucceeded() {
		if err := r.handleEvaluationIncomplete(ctx, evaluation); err != nil {
			return ctrl.Result{Requeue: true}, err
		}
		return ctrl.Result{Requeue: true, RequeueAfter: evaluation.Spec.RetryInterval.Duration}, nil
	}

	r.Log.Info("Finished Reconciling KeptnEvaluation", "requestInfo", requestInfo)

	err := r.updateFinishedEvaluationMetrics(ctx, evaluation)

	return ctrl.Result{}, err

}

func (r *KeptnEvaluationReconciler) handleEvaluationIncomplete(ctx context.Context, evaluation *apilifecycle.KeptnEvaluation) error {
	// Evaluation is uncompleted, update status anyway this avoids updating twice in case of completion
	err := r.Client.Status().Update(ctx, evaluation)
	if err != nil {
		r.EventSender.Emit(apicommon.PhaseReconcileEvaluation, "Warning", evaluation, apicommon.PhaseStateReconcileError, "could not update status", "")
		return err
	}

	return nil

}

func (r *KeptnEvaluationReconciler) handleEvaluationExceededRetries(ctx context.Context, evaluation *apilifecycle.KeptnEvaluation) {
	r.EventSender.Emit(apicommon.PhaseReconcileEvaluation, "Warning", evaluation, apicommon.PhaseStateReconcileTimeout, "retryCount exceeded", "")
	evaluation.Status.OverallStatus = apicommon.StateFailed
	err := r.updateFinishedEvaluationMetrics(ctx, evaluation)
	if err != nil {
		r.Log.Error(err, "failed to update finished evaluation metrics")
	}
}

func (r *KeptnEvaluationReconciler) performEvaluation(ctx context.Context, evaluation *apilifecycle.KeptnEvaluation, evaluationDefinition *apilifecycle.KeptnEvaluationDefinition) *apilifecycle.KeptnEvaluation {
	statusSummary := apicommon.StatusSummary{Total: len(evaluationDefinition.Spec.Objectives)}
	newStatus := make(map[string]apilifecycle.EvaluationStatusItem)

	if evaluation.Status.EvaluationStatus == nil {
		evaluation.Status.EvaluationStatus = make(map[string]apilifecycle.EvaluationStatusItem)
	}

	provider := &keptnmetric.KeptnMetricProvider{
		Log:       r.Log,
		K8sClient: r.Client,
	}

	for _, query := range evaluationDefinition.Spec.Objectives {
		newStatus, statusSummary = r.evaluateObjective(ctx, evaluation, statusSummary, newStatus, query, provider)
	}

	evaluation.Status.RetryCount++
	evaluation.Status.EvaluationStatus = newStatus
	if apicommon.GetOverallState(statusSummary) == apicommon.StateSucceeded {
		evaluation.Status.OverallStatus = apicommon.StateSucceeded
	} else {
		evaluation.Status.OverallStatus = apicommon.StateProgressing
	}

	return evaluation
}

func (r *KeptnEvaluationReconciler) evaluateObjective(ctx context.Context, evaluation *apilifecycle.KeptnEvaluation, statusSummary apicommon.StatusSummary, newStatus map[string]apilifecycle.EvaluationStatusItem, objective apilifecycle.Objective, provider *keptnmetric.KeptnMetricProvider) (map[string]apilifecycle.EvaluationStatusItem, apicommon.StatusSummary) {
	if _, ok := evaluation.Status.EvaluationStatus[objective.KeptnMetricRef.Name]; !ok {
		evaluation.AddEvaluationStatus(objective)
	}
	if evaluation.Status.EvaluationStatus[objective.KeptnMetricRef.Name].Status.IsSucceeded() {
		statusSummary = apicommon.UpdateStatusSummary(apicommon.StateSucceeded, statusSummary)
		newStatus[objective.KeptnMetricRef.Name] = evaluation.Status.EvaluationStatus[objective.KeptnMetricRef.Name]
		return newStatus, statusSummary
	}
	// resolving the SLI value
	statusItem := &apilifecycle.EvaluationStatusItem{
		Status: apicommon.StateFailed,
	}

	value, _, err := provider.FetchData(ctx, objective, evaluation.Namespace)
	if err != nil {
		statusItem.Message = err.Error()
		r.Log.Error(err, "Could not fetch data")
		return updateStatusSummary(statusSummary, statusItem, newStatus, objective)
	}

	statusItem.Value = value
	// Evaluating SLO
	check, err := checkValue(objective, statusItem)
	if err != nil {
		statusItem.Message = err.Error()
		r.Log.Error(err, "Could not check objective result")
		return updateStatusSummary(statusSummary, statusItem, newStatus, objective)
	}
	// if there is no error, we set the message depending on if the value passed the objective, or not
	if check {
		statusItem.Status = apicommon.StateSucceeded
		statusItem.Message = fmt.Sprintf("value '%s' met objective '%s'", value, objective.EvaluationTarget)
	} else {
		statusItem.Message = fmt.Sprintf("value '%s' did not meet objective '%s'", value, objective.EvaluationTarget)
	}
	return updateStatusSummary(statusSummary, statusItem, newStatus, objective)
}

func updateStatusSummary(statusSummary apicommon.StatusSummary, statusItem *apilifecycle.EvaluationStatusItem, newStatus map[string]apilifecycle.EvaluationStatusItem, objective apilifecycle.Objective) (map[string]apilifecycle.EvaluationStatusItem, apicommon.StatusSummary) {
	statusSummary = apicommon.UpdateStatusSummary(statusItem.Status, statusSummary)
	newStatus[objective.KeptnMetricRef.Name] = *statusItem
	return newStatus, statusSummary
}

func (r *KeptnEvaluationReconciler) updateFinishedEvaluationMetrics(ctx context.Context, evaluation *apilifecycle.KeptnEvaluation) error {
	evaluation.SetEndTime()

	err := r.Client.Status().Update(ctx, evaluation)
	if err != nil {
		r.EventSender.Emit(apicommon.PhaseReconcileEvaluation, "Warning", evaluation, apicommon.PhaseStateReconcileError, "could not update status", "")
		return err
	}

	attrs := evaluation.GetMetricsAttributes()

	r.Log.Info("Increasing evaluation count")

	// metrics: increment evaluation counter
	r.Meters.EvaluationCount.Add(ctx, 1, metric.WithAttributes(attrs...))

	// metrics: add evaluation duration
	duration := evaluation.Status.EndTime.Time.Sub(evaluation.Status.StartTime.Time)
	r.Meters.EvaluationDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeptnEvaluationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apilifecycle.KeptnEvaluation{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
