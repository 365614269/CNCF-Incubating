package task

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/config"
	keptncontext "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/context"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry"
	telemetryfake "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry/fake"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/testcommon"
	controllererrors "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/errors"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

//nolint:dupl
func TestTaskHandler(t *testing.T) {
	tests := []struct {
		name            string
		object          client.Object
		createAttr      CreateTaskAttributes
		wantStatus      []v1beta1.ItemStatus
		wantSummary     apicommon.StatusSummary
		taskObj         v1beta1.KeptnTask
		taskDef         *v1beta1.KeptnTaskDefinition
		wantErr         error
		getSpanCalls    int
		unbindSpanCalls int
	}{
		{
			name:            "cannot unwrap object",
			object:          &v1beta1.KeptnTask{},
			taskObj:         v1beta1.KeptnTask{},
			createAttr:      CreateTaskAttributes{},
			wantStatus:      nil,
			wantSummary:     apicommon.StatusSummary{},
			wantErr:         controllererrors.ErrCannotWrapToPhaseItem,
			getSpanCalls:    0,
			unbindSpanCalls: 0,
		},
		{
			name:    "no tasks",
			object:  &v1beta1.KeptnAppVersion{},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName:   "",
				Definition: v1beta1.KeptnTaskDefinition{},
				CheckType:  apicommon.PreDeploymentCheckType,
			},
			wantStatus:      []v1beta1.ItemStatus(nil),
			wantSummary:     apicommon.StatusSummary{},
			wantErr:         nil,
			getSpanCalls:    0,
			unbindSpanCalls: 0,
		},
		{
			name: "task not started - could not find taskDefinition",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
			},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus:      nil,
			wantSummary:     apicommon.StatusSummary{Total: 1, Pending: 0},
			wantErr:         nil,
			getSpanCalls:    0,
			unbindSpanCalls: 0,
		},
		{
			name: "tasks not started - could not find taskDefinition of one task",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def", "other-task-def"},
						},
					},
				},
			},
			taskDef: &v1beta1.KeptnTaskDefinition{
				ObjectMeta: v1.ObjectMeta{
					Namespace: testcommon.KeptnNamespace,
					Name:      "task-def",
				},
			},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StatePending,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 2, Pending: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 0,
		},
		{
			name: "task not started - taskDefinition in default Keptn namespace",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
			},
			taskDef: &v1beta1.KeptnTaskDefinition{
				ObjectMeta: v1.ObjectMeta{
					Namespace: testcommon.KeptnNamespace,
					Name:      "task-def",
				},
			},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StatePending,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Pending: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 0,
		},
		{
			name: "task not started",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
			},
			taskDef: &v1beta1.KeptnTaskDefinition{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "task-def",
				},
			},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StatePending,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Pending: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 0,
		},
		{
			name: "already done task",
			object: &v1beta1.KeptnAppVersion{
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PreDeploymentStatus: apicommon.StateSucceeded,
					PreDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "task-def",
							Status:         apicommon.StateSucceeded,
							Name:           "pre-task-def-",
						},
					},
				},
			},
			taskObj: v1beta1.KeptnTask{},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StateSucceeded,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Succeeded: 1},
			wantErr:         nil,
			getSpanCalls:    0,
			unbindSpanCalls: 0,
		},
		{
			name: "failed task",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PreDeploymentStatus: apicommon.StateSucceeded,
					PreDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "task-def",
							Status:         apicommon.StateProgressing,
							Name:           "pre-task-def-",
						},
					},
				},
			},
			taskObj: v1beta1.KeptnTask{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "pre-task-def-",
				},
				Status: v1beta1.KeptnTaskStatus{
					Status: apicommon.StateFailed,
				},
			},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StateFailed,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Failed: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 1,
		},
		{
			name: "succeeded task",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PreDeploymentStatus: apicommon.StateSucceeded,
					PreDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "task-def",
							Status:         apicommon.StateProgressing,
							Name:           "pre-task-def-",
						},
					},
				},
			},
			taskObj: v1beta1.KeptnTask{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "pre-task-def-",
				},
				Status: v1beta1.KeptnTaskStatus{
					Status: apicommon.StateSucceeded,
				},
			},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PreDeploymentCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StateSucceeded,
					Name:           "pre-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Succeeded: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 1,
		},
		{
			name: "succeeded promotion task",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PromotionTasks: []string{"task-def"},
						},
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PromotionStatus: apicommon.StateSucceeded,
					PromotionTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "task-def",
							Status:         apicommon.StateProgressing,
							Name:           "prom-task-def-",
						},
					},
				},
			},
			taskObj: v1beta1.KeptnTask{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
					Name:      "prom-task-def-",
				},
				Status: v1beta1.KeptnTaskStatus{
					Status: apicommon.StateSucceeded,
				},
			},
			createAttr: CreateTaskAttributes{
				SpanName: "",
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
				CheckType: apicommon.PromotionCheckType,
			},
			wantStatus: []v1beta1.ItemStatus{
				{
					DefinitionName: "task-def",
					Status:         apicommon.StateSucceeded,
					Name:           "prom-task-def-",
				},
			},
			wantSummary:     apicommon.StatusSummary{Total: 1, Succeeded: 1},
			wantErr:         nil,
			getSpanCalls:    1,
			unbindSpanCalls: 1,
		},
	}
	config.Instance().SetDefaultNamespace(testcommon.KeptnNamespace)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v1beta1.AddToScheme(scheme.Scheme)
			require.Nil(t, err)
			spanHandlerMock := telemetryfake.ISpanHandlerMock{
				GetSpanFunc: func(ctx context.Context, tracer telemetry.ITracer, reconcileObject client.Object, phase string, links ...trace.Link) (context.Context, trace.Span, error) {
					return context.TODO(), trace.SpanFromContext(context.TODO()), nil
				},
				UnbindSpanFunc: func(reconcileObject client.Object, phase string) error {
					return nil
				},
			}
			initObjs := []client.Object{&tt.taskObj}
			if tt.taskDef != nil {
				initObjs = append(initObjs, tt.taskDef)
			}
			handler := Handler{
				SpanHandler: &spanHandlerMock,
				Log:         ctrl.Log.WithName("controller"),
				EventSender: eventsender.NewK8sSender(record.NewFakeRecorder(100)),
				Client:      fake.NewClientBuilder().WithObjects(initObjs...).Build(),
				Tracer:      noop.NewTracerProvider().Tracer("tracer"),
				Scheme:      scheme.Scheme,
			}
			status, summary, err := handler.ReconcileTasks(context.TODO(), context.TODO(), tt.object, tt.createAttr)
			if len(tt.wantStatus) == len(status) {
				for j, item := range status {
					require.Equal(t, tt.wantStatus[j].DefinitionName, item.DefinitionName)
					require.True(t, strings.Contains(item.Name, tt.wantStatus[j].Name))
					require.Equal(t, tt.wantStatus[j].Status, item.Status)
				}
			} else {
				t.Errorf("unexpected result, want %+v, got %+v", tt.wantStatus, status)
			}
			require.Equal(t, tt.wantSummary, summary)
			require.Equal(t, tt.wantErr, err)
			require.Equal(t, tt.getSpanCalls, len(spanHandlerMock.GetSpanCalls()))
			require.Equal(t, tt.unbindSpanCalls, len(spanHandlerMock.UnbindSpanCalls()))
		})
	}
}

func TestTaskHandler_createTask(t *testing.T) {
	tests := []struct {
		name       string
		object     client.Object
		createAttr CreateTaskAttributes
		wantName   string
		wantErr    error
	}{
		{
			name:       "cannot unwrap object",
			object:     &v1beta1.KeptnEvaluation{},
			createAttr: CreateTaskAttributes{},
			wantName:   "",
			wantErr:    controllererrors.ErrCannotWrapToPhaseItem,
		},
		{
			name: "created task",
			object: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "namespace",
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppContextSpec: v1beta1.KeptnAppContextSpec{
						DeploymentTaskSpec: v1beta1.DeploymentTaskSpec{
							PreDeploymentTasks: []string{"task-def"},
						},
					},
				},
			},
			createAttr: CreateTaskAttributes{
				SpanName:  "",
				CheckType: apicommon.PreDeploymentCheckType,
				Definition: v1beta1.KeptnTaskDefinition{
					ObjectMeta: v1.ObjectMeta{
						Name: "task-def",
					},
				},
			},
			wantName: "pre-task-def-",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v1beta1.AddToScheme(scheme.Scheme)
			require.Nil(t, err)

			handler := Handler{
				SpanHandler: &telemetryfake.ISpanHandlerMock{},
				Log:         ctrl.Log.WithName("controller"),
				EventSender: eventsender.NewK8sSender(record.NewFakeRecorder(100)),
				Client:      fake.NewClientBuilder().Build(),
				Tracer:      noop.NewTracerProvider().Tracer("tracer"),
				Scheme:      scheme.Scheme,
			}

			// create a context with a traceParent and metadata attributes

			name, err := handler.CreateKeptnTask(context.TODO(), context.TODO(), "namespace", tt.object, tt.createAttr)

			require.True(t, strings.Contains(name, tt.wantName))
			require.Equal(t, tt.wantErr, err)
		})
	}
}

func Test_injectKeptnContext(t *testing.T) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	tp := sdktrace.NewTracerProvider()

	tracer := tp.Tracer("keptn")

	ctx := keptncontext.WithAppMetadata(context.TODO(), map[string]string{
		"foo": "bar",
	})
	ctx, span := tracer.Start(ctx, "my-span")
	defer span.End()

	task := &v1beta1.KeptnTask{}
	injectKeptnContext(ctx, task)

	require.Equal(
		t, map[string]string{
			"foo": "bar",
			"traceparent": fmt.Sprintf(
				"00-%s-%s-01",
				span.SpanContext().TraceID().String(),
				span.SpanContext().SpanID().String(),
			),
		},
		task.Spec.Context.Metadata,
	)

}
