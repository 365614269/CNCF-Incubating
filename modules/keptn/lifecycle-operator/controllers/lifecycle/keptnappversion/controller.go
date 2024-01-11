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

package keptnappversion

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	controllercommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/evaluation"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/phase"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry"
	controllererrors "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const traceComponentName = "keptn/lifecycle-operator/appversion"

// KeptnAppVersionReconciler reconciles a KeptnAppVersion object
type KeptnAppVersionReconciler struct {
	Scheme *runtime.Scheme
	client.Client
	Log               logr.Logger
	EventSender       eventsender.IEvent
	TracerFactory     telemetry.TracerFactory
	Meters            apicommon.KeptnMeters
	SpanHandler       telemetry.ISpanHandler
	EvaluationHandler evaluation.IEvaluationHandler
	PhaseHandler      phase.IHandler
}

// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnappversions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnappversions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnappversions/finalizers,verbs=update
// +kubebuilder:rbac:groups=lifecycle.keptn.sh,resources=keptnworkloadversions/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KeptnAppVersion object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
//
//nolint:gocyclo
func (r *KeptnAppVersionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	requestInfo := controllercommon.GetRequestInfo(req)
	r.Log.Info("Searching for Keptn App Version", "requestInfo", requestInfo)

	appVersion := &klcv1beta1.KeptnAppVersion{}
	err := r.Get(ctx, req.NamespacedName, appVersion)
	if errors.IsNotFound(err) {
		return reconcile.Result{}, nil
	}
	if err != nil {
		r.Log.Error(err, "App Version not found")
		return reconcile.Result{}, fmt.Errorf(controllererrors.ErrCannotFetchAppVersionMsg, err)
	}

	ctxAppTrace, completionFunc := r.setupSpansContexts(ctx, appVersion)
	defer completionFunc()

	currentPhase := apicommon.PhaseAppPreDeployment

	ctxAppTrace, spanAppTrace, err := r.SpanHandler.GetSpan(ctxAppTrace, r.getTracer(), appVersion, "")
	if err != nil {
		r.Log.Error(err, "could not get span")
	}

	if appVersion.Status.CurrentPhase == "" {
		appVersion.SetSpanAttributes(spanAppTrace)
		spanAppTrace.AddEvent("App Version Pre-Deployment Tasks started", trace.WithTimestamp(time.Now()))
	}

	if !appVersion.IsPreDeploymentSucceeded() {
		reconcilePreDep := func(phaseCtx context.Context) (apicommon.KeptnState, error) {
			return r.reconcilePrePostDeployment(ctx, phaseCtx, appVersion, apicommon.PreDeploymentCheckType)
		}
		result, err := r.PhaseHandler.HandlePhase(ctx, ctxAppTrace, r.getTracer(), appVersion, currentPhase, reconcilePreDep)
		if !result.Continue {
			return result.Result, err
		}
	}

	currentPhase = apicommon.PhaseAppPreEvaluation
	if !appVersion.IsPreDeploymentEvaluationSucceeded() {
		reconcilePreEval := func(phaseCtx context.Context) (apicommon.KeptnState, error) {
			return r.reconcilePrePostEvaluation(ctx, phaseCtx, appVersion, apicommon.PreDeploymentEvaluationCheckType)
		}
		result, err := r.PhaseHandler.HandlePhase(ctx, ctxAppTrace, r.getTracer(), appVersion, currentPhase, reconcilePreEval)
		if !result.Continue {
			return result.Result, err
		}
	}

	currentPhase = apicommon.PhaseAppDeployment
	if !appVersion.AreWorkloadsSucceeded() {
		reconcileAppDep := func(phaseCtx context.Context) (apicommon.KeptnState, error) {
			return r.reconcileWorkloads(ctx, appVersion)
		}
		result, err := r.PhaseHandler.HandlePhase(ctx, ctxAppTrace, r.getTracer(), appVersion, currentPhase, reconcileAppDep)
		if !result.Continue {
			return result.Result, err
		}
	}

	currentPhase = apicommon.PhaseAppPostDeployment
	if !appVersion.IsPostDeploymentSucceeded() {
		reconcilePostDep := func(phaseCtx context.Context) (apicommon.KeptnState, error) {
			return r.reconcilePrePostDeployment(ctx, phaseCtx, appVersion, apicommon.PostDeploymentCheckType)
		}
		result, err := r.PhaseHandler.HandlePhase(ctx, ctxAppTrace, r.getTracer(), appVersion, currentPhase, reconcilePostDep)
		if !result.Continue {
			return result.Result, err
		}
	}

	currentPhase = apicommon.PhaseAppPostEvaluation
	if !appVersion.IsPostDeploymentEvaluationCompleted() {
		reconcilePostEval := func(phaseCtx context.Context) (apicommon.KeptnState, error) {
			return r.reconcilePrePostEvaluation(ctx, phaseCtx, appVersion, apicommon.PostDeploymentEvaluationCheckType)
		}
		result, err := r.PhaseHandler.HandlePhase(ctx, ctxAppTrace, r.getTracer(), appVersion, currentPhase, reconcilePostEval)
		if !result.Continue {
			return result.Result, err
		}
	}

	// AppVersion is completed at this place
	return r.finishKeptnAppVersionReconcile(ctx, appVersion, spanAppTrace)
}

func (r *KeptnAppVersionReconciler) finishKeptnAppVersionReconcile(ctx context.Context, appVersion *klcv1beta1.KeptnAppVersion, spanAppTrace trace.Span) (ctrl.Result, error) {

	if !appVersion.IsEndTimeSet() {
		appVersion.Status.CurrentPhase = apicommon.PhaseCompleted.ShortName
		appVersion.Status.Status = apicommon.StateSucceeded
		appVersion.SetEndTime()
	}

	err := r.Client.Status().Update(ctx, appVersion)
	if err != nil {
		return ctrl.Result{Requeue: true}, err
	}

	r.EventSender.Emit(apicommon.PhaseAppCompleted, "Normal", appVersion, apicommon.PhaseStateFinished, "has finished", appVersion.GetVersion())

	attrs := appVersion.GetMetricsAttributes()

	// metrics: add app duration
	duration := appVersion.Status.EndTime.Time.Sub(appVersion.Status.StartTime.Time)
	r.Meters.AppDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))

	spanAppTrace.AddEvent(appVersion.Name + " has finished")
	spanAppTrace.SetStatus(codes.Ok, "Finished")
	spanAppTrace.End()
	if err := r.SpanHandler.UnbindSpan(appVersion, ""); err != nil {
		r.Log.Error(err, controllererrors.ErrCouldNotUnbindSpan, appVersion.Name)
	}

	return ctrl.Result{}, nil
}

func (r *KeptnAppVersionReconciler) setupSpansContexts(ctx context.Context, appVersion *klcv1beta1.KeptnAppVersion) (context.Context, func()) {
	appVersion.SetStartTime()

	appTraceContextCarrier := propagation.MapCarrier(appVersion.Spec.TraceId)
	ctxAppTrace := otel.GetTextMapPropagator().Extract(context.TODO(), appTraceContextCarrier)

	endFunc := func() {
		if appVersion.IsEndTimeSet() {
			r.Log.Info("Increasing app count")
			attrs := appVersion.GetMetricsAttributes()
			r.Meters.AppCount.Add(ctx, 1, metric.WithAttributes(attrs...))
		}
	}

	return ctxAppTrace, endFunc
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeptnAppVersionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&klcv1beta1.KeptnAppVersion{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

func (r *KeptnAppVersionReconciler) getTracer() telemetry.ITracer {
	return r.TracerFactory.GetTracer(traceComponentName)
}
