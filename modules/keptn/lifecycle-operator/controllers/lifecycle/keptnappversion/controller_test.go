package keptnappversion

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	lfcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	keptncontext "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/context"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/evaluation"
	evalfake "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/evaluation/fake"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/phase"
	phasefake "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/phase/fake"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry"
	telemetryfake "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry/fake"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/testcommon"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type contextID string

const CONTEXTID contextID = "start"

// this test checks if the chain of reconcile events is correct
func TestKeptnAppVersionReconciler_reconcile(t *testing.T) {

	pendingStatus := lfcv1beta1.KeptnAppVersionStatus{
		CurrentPhase:                   "",
		Status:                         apicommon.StatePending,
		PreDeploymentStatus:            apicommon.StatePending,
		PreDeploymentEvaluationStatus:  apicommon.StatePending,
		WorkloadOverallStatus:          apicommon.StatePending,
		PostDeploymentStatus:           apicommon.StatePending,
		PostDeploymentEvaluationStatus: apicommon.StatePending,
	}

	app := testcommon.ReturnAppVersion("default", "myappversion", "1.0.0", nil, pendingStatus)

	r, eventChannel, _ := setupReconciler(app)

	r.PhaseHandler = &phasefake.MockHandler{HandlePhaseFunc: func(ctx context.Context, ctxTrace context.Context, tracer telemetry.ITracer, reconcileObject client.Object, phaseMoqParam apicommon.KeptnPhaseType, reconcilePhase func(phaseCtx context.Context) (apicommon.KeptnState, error)) (phase.PhaseResult, error) {
		return phase.PhaseResult{Continue: true, Result: ctrl.Result{Requeue: false}}, nil
	}}

	tests := []struct {
		name    string
		req     ctrl.Request
		wantErr error
		events  []string // check correct events are generated
	}{
		{
			name: "new appVersion with no workload nor evaluation should finish",
			req: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      "myappversion-1.0.0",
				},
			},
			wantErr: nil,
			events: []string{
				`AppCompletedFinished`,
			},
		},
		{
			name: "notfound should not return error nor event",
			req: ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      "mynotthereapp",
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := r.Reconcile(context.WithValue(context.TODO(), CONTEXTID, tt.req.Name), tt.req)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.events != nil {
				for _, e := range tt.events {
					event := <-eventChannel
					require.Equal(t, strings.Contains(event, tt.req.Name), true, "wrong appversion")
					require.Equal(t, strings.Contains(event, tt.req.Namespace), true, "wrong namespace")
					require.Equal(t, strings.Contains(event, e), true, fmt.Sprintf("no %s found in %s", e, event))
				}

			}
		})

	}

}

func TestKeptnAppVersionReconciler_ReconcileFailed(t *testing.T) {

	status := lfcv1beta1.KeptnAppVersionStatus{
		CurrentPhase:        apicommon.PhaseAppPreDeployment.ShortName,
		Status:              apicommon.StateProgressing,
		PreDeploymentStatus: apicommon.StateProgressing,
		PreDeploymentTaskStatus: []lfcv1beta1.ItemStatus{
			{
				Name:           "pre-task",
				DefinitionName: "task",
				Status:         apicommon.StateFailed,
			},
		},
		PreDeploymentEvaluationStatus:  apicommon.StatePending,
		WorkloadOverallStatus:          apicommon.StatePending,
		PostDeploymentStatus:           apicommon.StatePending,
		PostDeploymentEvaluationStatus: apicommon.StatePending,
	}

	appVersionName := fmt.Sprintf("%s-%s", "myapp", "1.0.0")
	app := &lfcv1beta1.KeptnAppVersion{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:       appVersionName,
			Namespace:  "default",
			Generation: 1,
		},
		Spec: lfcv1beta1.KeptnAppVersionSpec{
			KeptnAppSpec: lfcv1beta1.KeptnAppSpec{
				Version: "1.0.0",
			},
			KeptnAppContextSpec: lfcv1beta1.KeptnAppContextSpec{
				DeploymentTaskSpec: lfcv1beta1.DeploymentTaskSpec{
					PreDeploymentTasks: []string{
						"task",
					},
				},
			},
			AppName: "myapp",
			TraceId: map[string]string{
				"traceparent": "parent-trace",
			},
		},
		Status: status,
	}
	r, _, _ := setupReconciler(app)
	r.PhaseHandler = &phasefake.MockHandler{HandlePhaseFunc: func(ctx context.Context, ctxTrace context.Context, tracer telemetry.ITracer, reconcileObject client.Object, phaseMoqParam apicommon.KeptnPhaseType, reconcilePhase func(phaseCtx context.Context) (apicommon.KeptnState, error)) (phase.PhaseResult, error) {
		return phase.PhaseResult{Continue: false, Result: ctrl.Result{}}, nil
	}}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "myapp-1.0.0",
		},
	}

	result, err := r.Reconcile(context.WithValue(context.TODO(), CONTEXTID, req.Name), req)
	require.Nil(t, err)

	// do not requeue since we reached completion
	require.False(t, result.Requeue)
}

func TestKeptnAppVersionReconciler_ReconcileReachCompletion(t *testing.T) {

	app := testcommon.ReturnAppVersion("default", "myfinishedapp", "1.0.0", nil, createFinishedAppVersionStatus())
	r, eventChannel, _ := setupReconciler(app)
	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "myfinishedapp-1.0.0",
		},
	}

	result, err := r.Reconcile(context.WithValue(context.TODO(), CONTEXTID, req.Name), req)
	require.Nil(t, err)

	expectedEvents := []string{
		"CompletedFinished",
	}

	for _, e := range expectedEvents {
		event := <-eventChannel
		require.Equal(t, strings.Contains(event, req.Name), true, "wrong appversion")
		require.Equal(t, strings.Contains(event, req.Namespace), true, "wrong namespace")
		require.Equal(t, strings.Contains(event, e), true, fmt.Sprintf("no %s found in %s", e, event))
	}

	require.Nil(t, err)

	spanHandlerMock := r.SpanHandler.(*telemetryfake.ISpanHandlerMock)

	require.Len(t, spanHandlerMock.GetSpanCalls(), 1)
	require.Len(t, spanHandlerMock.UnbindSpanCalls(), 1)

	// verify the propagation of the metadata
	metadata, b := keptncontext.GetAppMetadataFromContext(spanHandlerMock.GetSpanCalls()[0].Ctx)

	require.True(t, b)
	require.Equal(t, "test", metadata["testy"])

	// do not requeue since we reached completion
	require.False(t, result.Requeue)
}

func createFinishedAppVersionStatus() lfcv1beta1.KeptnAppVersionStatus {
	return lfcv1beta1.KeptnAppVersionStatus{
		CurrentPhase:                       apicommon.PhaseCompleted.ShortName,
		PreDeploymentStatus:                apicommon.StateSucceeded,
		PostDeploymentStatus:               apicommon.StateSucceeded,
		PreDeploymentEvaluationStatus:      apicommon.StateSucceeded,
		PostDeploymentEvaluationStatus:     apicommon.StateSucceeded,
		PreDeploymentTaskStatus:            []lfcv1beta1.ItemStatus{{Status: apicommon.StateSucceeded}},
		PostDeploymentTaskStatus:           []lfcv1beta1.ItemStatus{{Status: apicommon.StateSucceeded}},
		PreDeploymentEvaluationTaskStatus:  []lfcv1beta1.ItemStatus{{Status: apicommon.StateSucceeded}},
		PostDeploymentEvaluationTaskStatus: []lfcv1beta1.ItemStatus{{Status: apicommon.StateSucceeded}},
		WorkloadOverallStatus:              apicommon.StateSucceeded,
		WorkloadStatus:                     []lfcv1beta1.WorkloadStatus{{Status: apicommon.StateSucceeded}},
		Status:                             apicommon.StateSucceeded,
	}
}

func setupReconcilerWithMeters() *KeptnAppVersionReconciler {
	// setup logger
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// fake a tracer
	tr := &telemetryfake.ITracerMock{StartFunc: func(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
		return ctx, trace.SpanFromContext(ctx)
	}}

	tf := &telemetryfake.TracerFactoryMock{GetTracerFunc: func(name string) telemetry.ITracer {
		return tr
	}}

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	r := &KeptnAppVersionReconciler{
		Log:           ctrl.Log.WithName("test-appVersionController"),
		TracerFactory: tf,
		Meters:        testcommon.InitAppMeters(),
	}
	return r
}

func setupReconciler(objs ...client.Object) (*KeptnAppVersionReconciler, chan string, *telemetryfake.ISpanHandlerMock) {
	// setup logger
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// fake a tracer
	tr := &telemetryfake.ITracerMock{StartFunc: func(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
		return ctx, trace.SpanFromContext(ctx)
	}}

	tf := &telemetryfake.TracerFactoryMock{GetTracerFunc: func(name string) telemetry.ITracer {
		return tr
	}}

	// fake span handler

	spanRecorder := &telemetryfake.ISpanHandlerMock{
		GetSpanFunc: func(ctx context.Context, tracer telemetry.ITracer, reconcileObject client.Object, phase string, links ...trace.Link) (context.Context, trace.Span, error) {
			return ctx, trace.SpanFromContext(ctx), nil
		},
		UnbindSpanFunc: func(reconcileObject client.Object, phase string) error { return nil },
	}

	workloadVersionIndexer := func(obj client.Object) []string {
		workloadVersion, _ := obj.(*lfcv1beta1.KeptnWorkloadVersion)
		return []string{workloadVersion.Spec.AppName}
	}

	testcommon.SetupSchemes()
	fakeClient := fake.NewClientBuilder().WithObjects(objs...).WithStatusSubresource(objs...).WithScheme(scheme.Scheme).WithObjects().WithIndex(&lfcv1beta1.KeptnWorkloadVersion{}, "spec.app", workloadVersionIndexer).Build()

	recorder := record.NewFakeRecorder(100)
	r := &KeptnAppVersionReconciler{
		Client:        fakeClient,
		Scheme:        scheme.Scheme,
		EventSender:   eventsender.NewK8sSender(recorder),
		Log:           ctrl.Log.WithName("test-appVersionController"),
		TracerFactory: tf,
		SpanHandler:   spanRecorder,
		Meters:        testcommon.InitAppMeters(),
		EvaluationHandler: &evalfake.MockEvaluationHandler{
			ReconcileEvaluationsFunc: func(ctx context.Context, phaseCtx context.Context, reconcileObject client.Object, evaluationCreateAttributes evaluation.CreateEvaluationAttributes) ([]lfcv1beta1.ItemStatus, apicommon.StatusSummary, error) {
				return []lfcv1beta1.ItemStatus{}, apicommon.StatusSummary{}, nil
			},
		},
	}
	return r, recorder.Events, spanRecorder
}

func TestKeptnApVersionReconciler_setupSpansContexts(t *testing.T) {

	r := setupReconcilerWithMeters()
	type args struct {
		ctx        context.Context
		appVersion *lfcv1beta1.KeptnAppVersion
	}
	tests := []struct {
		name    string
		args    args
		baseCtx context.Context
	}{
		{
			name: "Current trace ctx should be != than app trace context",
			args: args{
				ctx: context.WithValue(context.TODO(), CONTEXTID, 1),
				appVersion: &lfcv1beta1.KeptnAppVersion{
					Spec: lfcv1beta1.KeptnAppVersionSpec{TraceId: map[string]string{
						"traceparent": "00-52527d549a7b33653017ce960be09dfc-a38a5a8d179a88b5-01",
					}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, endFunc := r.setupSpansContexts(tt.args.ctx, tt.args.appVersion)
			require.NotNil(t, ctx)
			require.NotNil(t, endFunc)

		})
	}
}

func TestKeptnAppVersionReconciler_getLinkedSpans(t *testing.T) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	type fields struct {
		Log logr.Logger
	}
	type args struct {
		version *lfcv1beta1.KeptnAppVersion
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []trace.Link
	}{
		{
			name: "get linked trace",
			fields: fields{
				Log: ctrl.Log.WithName("test-appVersionController"),
			},
			args: args{
				version: &lfcv1beta1.KeptnAppVersion{
					Spec: lfcv1beta1.KeptnAppVersionSpec{
						KeptnAppContextSpec: lfcv1beta1.KeptnAppContextSpec{
							SpanLinks: []string{"00-c088f5c586bab8649159ccc39a9862f7-f862289833f1fba3-01"},
						},
					},
				},
			},
			want: []trace.Link{
				{
					SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
						SpanID:     trace.SpanID([8]byte{0xf8, 0x62, 0x28, 0x98, 0x33, 0xf1, 0xfb, 0xa3}),
						TraceID:    trace.TraceID([16]byte{0xc0, 0x88, 0xf5, 0xc5, 0x86, 0xba, 0xb8, 0x64, 0x91, 0x59, 0xcc, 0xc3, 0x9a, 0x98, 0x62, 0xf7}),
						TraceFlags: trace.TraceFlags(1),
						Remote:     true,
					}),
					Attributes: []attribute.KeyValue{
						{
							Key:   "opentracing.ref_type",
							Value: attribute.StringValue("follows-from"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &KeptnAppVersionReconciler{
				Log: tt.fields.Log,
			}
			got := r.getLinkedSpans(tt.args.version)
			require.Equal(t, tt.want, got)
		})
	}
}
