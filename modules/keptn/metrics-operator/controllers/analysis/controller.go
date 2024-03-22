/*
Copyright 2023.

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

package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	ctrlcommon "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common"
	common "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis"
	evalType "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis/types"
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// AnalysisReconciler reconciles an Analysis object
type AnalysisReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Log        logr.Logger
	MaxWorkers int //maybe 2 or 4 as def
	NewWorkersPoolFactory
	common.IAnalysisEvaluator
	analysisResults chan evalType.AnalysisCompletion
}

//+kubebuilder:rbac:groups=metrics.keptn.sh,resources=analyses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=metrics.keptn.sh,resources=analyses/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=metrics.keptn.sh,resources=analyses/finalizers,verbs=update
// +kubebuilder:rbac:groups=metrics.keptn.sh,resources=keptnmetricsproviders,verbs=get;list;watch;
//+kubebuilder:rbac:groups=metrics.keptn.sh,resources=analysisdefinitions,verbs=get;list;watch;
//+kubebuilder:rbac:groups=metrics.keptn.sh,resources=analysisvaluetemplates,verbs=get;list;watch;

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its AnalysisResult here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (a *AnalysisReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	requestInfo := ctrlcommon.GetRequestInfo(req)
	a.Log.Info("Reconciling Analysis", "requestInfo", requestInfo)
	analysis := &metricsapi.Analysis{}

	//retrieve analysis
	if err := a.Client.Get(ctx, req.NamespacedName, analysis); err != nil {
		if errors.IsNotFound(err) {
			// taking down all associated K8s resources is handled by K8s
			a.Log.Info("Analysis resource not found. Ignoring since object must be deleted", "requestInfo", requestInfo)
			return ctrl.Result{}, nil
		}
		a.Log.Error(err, "Failed to get the Analysis", "requestInfo", requestInfo)
		return ctrl.Result{}, err
	}

	if analysis.Status.State.IsCompleted() {
		return ctrl.Result{}, nil
	}

	analysis.EnsureTimeframeIsSet()

	//find AnalysisDefinition to have the collection of Objectives
	analysisDef, err := a.retrieveAnalysisDefinition(ctx, analysis)
	if err != nil {
		// do not return error, as here we should always try to fetch the definition again
		// in the next reconcile loop
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, a.updateStatus(ctx, analysis)
	}

	if analysis.Status.State.IsPending() {
		analysis.Status.State = metricsapi.StateProgressing
	}

	var done map[string]metricsapi.ProviderResult
	todo := analysisDef.Spec.Objectives
	if analysis.Status.StoredValues != nil {
		todo, done = extractMissingObjectives(analysisDef.Spec.Objectives, analysis.Status.StoredValues)
	}

	//create multiple workers handling the Objectives
	childCtx, wp := a.NewWorkersPoolFactory(ctx, analysis, todo, a.MaxWorkers, a.Client, a.Log, analysisDef.Namespace)

	res, err := wp.DispatchAndCollect(childCtx)
	if err != nil {
		a.Log.Error(err, "Failed to collect all values required for the Analysis, caching collected values", "requestInfo", requestInfo)
		analysis.Status.StoredValues = res
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, a.updateStatus(ctx, analysis)
	}

	maps.Copy(res, done)
	a.evaluateObjectives(res, analysisDef, analysis)
	if err := a.updateStatus(ctx, analysis); err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, err
	}

	return ctrl.Result{}, nil
}

func (a *AnalysisReconciler) evaluateObjectives(res map[string]metricsapi.ProviderResult, analysisDef *metricsapi.AnalysisDefinition, analysis *metricsapi.Analysis) {
	eval := a.Evaluate(res, analysisDef)
	analysisResultJSON, err := json.Marshal(eval)
	if err != nil {
		a.Log.Error(err, "Could not marshal status")
	} else {
		analysis.Status.Raw = string(analysisResultJSON)
	}
	analysis.Status.Warning = eval.Warning
	analysis.Status.Pass = eval.Pass
	analysis.Status.State = metricsapi.StateCompleted
	// if evaluation was successful remove the stored values
	analysis.Status.StoredValues = nil
	go a.reportAnalysisResult(eval, *analysis)
}

func (a *AnalysisReconciler) reportAnalysisResult(eval evalType.AnalysisResult, analysis metricsapi.Analysis) {
	if a.analysisResults == nil {
		return
	}

	a.analysisResults <- evalType.AnalysisCompletion{
		Result:   eval,
		Analysis: analysis,
	}
}

func (a *AnalysisReconciler) SetAnalysisResultsChannel(c chan evalType.AnalysisCompletion) {
	a.analysisResults = c
}

func (a *AnalysisReconciler) updateStatus(ctx context.Context, analysis *metricsapi.Analysis) error {
	if err := a.Client.Status().Update(ctx, analysis); err != nil {
		a.Log.Error(err, "Failed to update the Analysis status")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (a *AnalysisReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&metricsapi.Analysis{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(a)
}

func (a *AnalysisReconciler) retrieveAnalysisDefinition(ctx context.Context, analysis *metricsapi.Analysis) (*metricsapi.AnalysisDefinition, error) {
	analysisDefNamespace := analysis.Spec.AnalysisDefinition.GetNamespace(analysis.Namespace)
	analysisDef := &metricsapi.AnalysisDefinition{}
	err := a.Client.Get(ctx,
		types.NamespacedName{
			Name:      analysis.Spec.AnalysisDefinition.Name,
			Namespace: analysisDefNamespace},
		analysisDef,
	)

	if err != nil {
		if errors.IsNotFound(err) {
			a.Log.Info(
				fmt.Sprintf("AnalysisDefinition '%s' in namespace '%s' not found, requeueing",
					analysis.Spec.AnalysisDefinition.Name,
					analysis.Spec.AnalysisDefinition.Name),
			)
			return nil, err
		}
		a.Log.Error(err, "Failed to retrieve the AnalysisDefinition")
		return nil, err
	}

	return analysisDef, nil
}

func extractMissingObjectives(objectives []metricsapi.Objective, status map[string]metricsapi.ProviderResult) ([]metricsapi.Objective, map[string]metricsapi.ProviderResult) {
	var todo []metricsapi.Objective
	done := make(map[string]metricsapi.ProviderResult, len(status))
	for _, obj := range objectives {
		key := common.ComputeKey(obj.AnalysisValueTemplateRef)
		if value, ok := status[key]; ok {
			if value.ErrMsg != "" {
				todo = append(todo, obj)
			} else {
				done[key] = status[key]
			}
		} else {
			todo = append(todo, obj)
		}
	}
	return todo, done
}
