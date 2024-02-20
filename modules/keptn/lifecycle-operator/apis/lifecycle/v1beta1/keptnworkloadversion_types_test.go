package v1beta1

import (
	"testing"
	"time"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKeptnWorkloadVersion(t *testing.T) {
	workload := &KeptnWorkloadVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workload",
			Namespace: "namespace",
		},
		Status: KeptnWorkloadVersionStatus{
			PreDeploymentStatus:            common.StateFailed,
			PreDeploymentEvaluationStatus:  common.StateFailed,
			PostDeploymentStatus:           common.StateFailed,
			PostDeploymentEvaluationStatus: common.StateFailed,
			DeploymentStatus:               common.StateFailed,
			Status:                         common.StateFailed,
			PreDeploymentTaskStatus: []ItemStatus{
				{
					DefinitionName: "defname",
					Status:         common.StateFailed,
					Name:           "taskname",
				},
			},
			PostDeploymentTaskStatus: []ItemStatus{
				{
					DefinitionName: "defname2",
					Status:         common.StateFailed,
					Name:           "taskname2",
				},
			},
			PreDeploymentEvaluationTaskStatus: []ItemStatus{
				{
					DefinitionName: "defname3",
					Status:         common.StateFailed,
					Name:           "taskname3",
				},
			},
			PostDeploymentEvaluationTaskStatus: []ItemStatus{
				{
					DefinitionName: "defname4",
					Status:         common.StateFailed,
					Name:           "taskname4",
				},
			},
			CurrentPhase: common.PhaseAppDeployment.ShortName,
		},
		Spec: KeptnWorkloadVersionSpec{
			KeptnWorkloadSpec: KeptnWorkloadSpec{
				PreDeploymentTasks:        []string{"task1", "task2"},
				PostDeploymentTasks:       []string{"task3", "task4"},
				PreDeploymentEvaluations:  []string{"task5", "task6"},
				PostDeploymentEvaluations: []string{"task7", "task8"},
				Version:                   "version",
				AppName:                   "appname",
			},
			PreviousVersion: "prev",
			WorkloadName:    "workloadname",
			TraceId:         map[string]string{"traceparent": "trace1"},
		},
	}

	require.True(t, workload.IsPreDeploymentCompleted())
	require.False(t, workload.IsPreDeploymentSucceeded())
	require.True(t, workload.IsPreDeploymentFailed())

	require.True(t, workload.IsPreDeploymentEvaluationCompleted())
	require.False(t, workload.IsPreDeploymentEvaluationSucceeded())
	require.True(t, workload.IsPreDeploymentEvaluationFailed())

	require.True(t, workload.IsPostDeploymentCompleted())
	require.False(t, workload.IsPostDeploymentSucceeded())
	require.True(t, workload.IsPostDeploymentFailed())

	require.True(t, workload.IsPostDeploymentEvaluationCompleted())
	require.False(t, workload.IsPostDeploymentEvaluationSucceeded())
	require.True(t, workload.IsPostDeploymentEvaluationFailed())

	require.True(t, workload.IsDeploymentCompleted())
	require.False(t, workload.IsDeploymentSucceeded())
	require.True(t, workload.IsDeploymentFailed())

	require.False(t, workload.IsEndTimeSet())
	require.False(t, workload.IsStartTimeSet())

	workload.SetStartTime()
	workload.SetEndTime()

	require.True(t, workload.IsEndTimeSet())
	require.True(t, workload.IsStartTimeSet())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("appname"),
		common.WorkloadName.String("workloadname"),
		common.WorkloadVersion.String("version"),
		common.WorkloadNamespace.String("namespace"),
	}, workload.GetActiveMetricsAttributes())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("appname"),
		common.WorkloadName.String("workloadname"),
		common.WorkloadVersion.String("version"),
		common.WorkloadNamespace.String("namespace"),
		common.WorkloadStatus.String(string(common.StateFailed)),
	}, workload.GetMetricsAttributes())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("appname"),
		common.WorkloadName.String("workloadname"),
		common.WorkloadVersion.String("version"),
		common.WorkloadPreviousVersion.String("prev"),
	}, workload.GetDurationMetricsAttributes())

	require.Equal(t, common.StateFailed, workload.GetState())

	require.Equal(t, []string{"task1", "task2"}, workload.GetPreDeploymentTasks())
	require.Equal(t, []string{"task3", "task4"}, workload.GetPostDeploymentTasks())
	require.Equal(t, []string{"task5", "task6"}, workload.GetPreDeploymentEvaluations())
	require.Equal(t, []string{"task7", "task8"}, workload.GetPostDeploymentEvaluations())

	require.Equal(t, []ItemStatus{
		{
			DefinitionName: "defname",
			Status:         common.StateFailed,
			Name:           "taskname",
		},
	}, workload.GetPreDeploymentTaskStatus())

	require.Equal(t, []ItemStatus{
		{
			DefinitionName: "defname2",
			Status:         common.StateFailed,
			Name:           "taskname2",
		},
	}, workload.GetPostDeploymentTaskStatus())

	require.Equal(t, []ItemStatus{
		{
			DefinitionName: "defname3",
			Status:         common.StateFailed,
			Name:           "taskname3",
		},
	}, workload.GetPreDeploymentEvaluationTaskStatus())

	require.Equal(t, []ItemStatus{
		{
			DefinitionName: "defname4",
			Status:         common.StateFailed,
			Name:           "taskname4",
		},
	}, workload.GetPostDeploymentEvaluationTaskStatus())

	require.Equal(t, "appname", workload.GetAppName())
	require.Equal(t, "prev", workload.GetPreviousVersion())
	require.Equal(t, "workloadname", workload.GetParentName())
	require.Equal(t, "namespace", workload.GetNamespace())

	workload.SetState(common.StatePending)
	require.Equal(t, common.StatePending, workload.GetState())

	require.True(t, !workload.GetStartTime().IsZero())
	require.True(t, !workload.GetEndTime().IsZero())

	workload.SetCurrentPhase(common.PhaseAppDeployment.LongName)
	require.Equal(t, common.PhaseAppDeployment.LongName, workload.GetCurrentPhase())

	workload.Status.EndTime = v1.Time{Time: time.Time{}}
	workload.Complete()
	require.True(t, !workload.GetEndTime().IsZero())

	require.Equal(t, "version", workload.GetVersion())

	require.Equal(t, "trace1.workloadname.namespace.version.phase", workload.GetSpanKey("phase"))

	retries := int32(5)
	task := workload.GenerateTask(KeptnTaskDefinition{
		ObjectMeta: v1.ObjectMeta{
			Name: "task-def",
			Labels: map[string]string{
				"label1": "label2",
			},
			Annotations: map[string]string{
				"annotation1": "annotation2",
			},
		},
		Spec: KeptnTaskDefinitionSpec{
			Timeout: v1.Duration{
				Duration: 5 * time.Second,
			},
			Retries: &retries,
		},
	}, common.PostDeploymentCheckType)
	require.Equal(t, KeptnTaskSpec{
		Context: TaskContext{
			AppName:         workload.GetAppName(),
			WorkloadVersion: workload.GetVersion(),
			WorkloadName:    workload.GetParentName(),
			TaskType:        string(common.PostDeploymentCheckType),
			ObjectType:      "Workload",
		},
		TaskDefinition:   "task-def",
		Parameters:       TaskParameters{},
		SecureParameters: SecureParameters{},
		Type:             common.PostDeploymentCheckType,
		Timeout: v1.Duration{
			Duration: 5 * time.Second,
		},
		Retries: &retries,
	}, task.Spec)

	require.Equal(t, map[string]string{
		"label1": "label2",
	}, task.Labels)

	require.Equal(t, map[string]string{
		"annotation1": "annotation2",
	}, task.Annotations)

	evaluation := workload.GenerateEvaluation(KeptnEvaluationDefinition{
		ObjectMeta: v1.ObjectMeta{
			Name: "eval-def",
		},
	}, common.PostDeploymentCheckType)
	require.Equal(t, KeptnEvaluationSpec{
		AppName:              workload.GetAppName(),
		WorkloadVersion:      workload.GetVersion(),
		Workload:             workload.GetParentName(),
		EvaluationDefinition: "eval-def",
		Type:                 common.PostDeploymentCheckType,
		RetryInterval: metav1.Duration{
			Duration: 5 * time.Second,
		},
	}, evaluation.Spec)

	require.Equal(t, "workload", workload.GetSpanName(""))

	require.Equal(t, "workloadname/phase", workload.GetSpanName("phase"))

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("appname"),
		common.WorkloadName.String("workloadname"),
		common.WorkloadVersion.String("version"),
		common.WorkloadNamespace.String("namespace"),
	}, workload.GetSpanAttributes())

	require.Equal(t, map[string]string{
		"appName":             "appname",
		"workloadName":        "workloadname",
		"workloadVersion":     "version",
		"workloadVersionName": "workload",
	}, workload.GetEventAnnotations())

	require.Equal(t,
		[]string{},
		workload.GetPromotionTasks(),
	)

	require.Equal(t,
		[]ItemStatus{},
		workload.GetPromotionTaskStatus(),
	)
}

//nolint:dupl
func TestKeptnWorkloadVersion_DeprecateRemainingPhases(t *testing.T) {
	workloadVersion := KeptnWorkloadVersion{
		Status: KeptnWorkloadVersionStatus{
			PreDeploymentStatus:            common.StatePending,
			PreDeploymentEvaluationStatus:  common.StatePending,
			PostDeploymentStatus:           common.StatePending,
			PostDeploymentEvaluationStatus: common.StatePending,
			DeploymentStatus:               common.StatePending,
			Status:                         common.StatePending,
		},
	}

	tests := []struct {
		workloadVersion KeptnWorkloadVersion
		phase           common.KeptnPhaseType
		want            KeptnWorkloadVersion
	}{
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseWorkloadPostEvaluation,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StatePending,
					PostDeploymentStatus:           common.StatePending,
					PostDeploymentEvaluationStatus: common.StatePending,
					DeploymentStatus:               common.StatePending,
					Status:                         common.StatePending,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseWorkloadPostDeployment,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StatePending,
					PostDeploymentStatus:           common.StatePending,
					PostDeploymentEvaluationStatus: common.StateDeprecated,
					DeploymentStatus:               common.StatePending,
					Status:                         common.StateFailed,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseWorkloadDeployment,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StatePending,
					PostDeploymentStatus:           common.StateDeprecated,
					PostDeploymentEvaluationStatus: common.StateDeprecated,
					DeploymentStatus:               common.StatePending,
					Status:                         common.StateFailed,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseWorkloadPreEvaluation,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StatePending,
					PostDeploymentStatus:           common.StateDeprecated,
					PostDeploymentEvaluationStatus: common.StateDeprecated,
					DeploymentStatus:               common.StateDeprecated,
					Status:                         common.StateFailed,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseWorkloadPreDeployment,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StateDeprecated,
					PostDeploymentStatus:           common.StateDeprecated,
					PostDeploymentEvaluationStatus: common.StateDeprecated,
					DeploymentStatus:               common.StateDeprecated,
					Status:                         common.StateFailed,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseDeprecated,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StateDeprecated,
					PreDeploymentEvaluationStatus:  common.StateDeprecated,
					PostDeploymentStatus:           common.StateDeprecated,
					PostDeploymentEvaluationStatus: common.StateDeprecated,
					DeploymentStatus:               common.StateDeprecated,
					Status:                         common.StateDeprecated,
				},
			},
		},
		{
			workloadVersion: workloadVersion,
			phase:           common.PhaseAppPreDeployment,
			want: KeptnWorkloadVersion{
				Status: KeptnWorkloadVersionStatus{
					PreDeploymentStatus:            common.StatePending,
					PreDeploymentEvaluationStatus:  common.StatePending,
					PostDeploymentStatus:           common.StatePending,
					PostDeploymentEvaluationStatus: common.StatePending,
					DeploymentStatus:               common.StatePending,
					Status:                         common.StateFailed,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			tt.workloadVersion.DeprecateRemainingPhases(tt.phase)
			require.Equal(t, tt.want, tt.workloadVersion)
		})
	}
}

func TestKeptnWorkloadVersion_SetPhaseTraceID(t *testing.T) {
	app := KeptnWorkloadVersion{
		Status: KeptnWorkloadVersionStatus{},
	}

	app.SetPhaseTraceID(common.PhaseAppDeployment.ShortName, propagation.MapCarrier{
		"name3": "trace3",
	})

	require.Equal(t, KeptnWorkloadVersion{
		Status: KeptnWorkloadVersionStatus{
			PhaseTraceIDs: common.PhaseTraceID{
				common.PhaseAppDeployment.ShortName: propagation.MapCarrier{
					"name3": "trace3",
				},
			},
		},
	}, app)

	app.SetPhaseTraceID(common.PhaseWorkloadDeployment.LongName, propagation.MapCarrier{
		"name2": "trace2",
	})

	require.Equal(t, KeptnWorkloadVersion{
		Status: KeptnWorkloadVersionStatus{
			PhaseTraceIDs: common.PhaseTraceID{
				common.PhaseAppDeployment.ShortName: propagation.MapCarrier{
					"name3": "trace3",
				},
				common.PhaseWorkloadDeployment.ShortName: propagation.MapCarrier{
					"name2": "trace2",
				},
			},
		},
	}, app)
}

func TestKeptnWorkloadVersionList(t *testing.T) {
	list := KeptnWorkloadVersionList{
		Items: []KeptnWorkloadVersion{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "obj1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "obj2",
				},
			},
		},
	}

	got := list.GetItems()
	require.Len(t, got, 2)
	require.Equal(t, "obj1", got[0].GetName())
	require.Equal(t, "obj2", got[1].GetName())
}
