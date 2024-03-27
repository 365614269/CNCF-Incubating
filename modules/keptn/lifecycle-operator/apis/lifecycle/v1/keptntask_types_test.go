package v1

import (
	"testing"
	"time"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKeptnTask(t *testing.T) {
	task := &KeptnTask{
		ObjectMeta: metav1.ObjectMeta{
			Name: "task",
			Labels: map[string]string{
				"label1": "label2",
			},
			Annotations: map[string]string{
				"annotation1": "annotation2",
			},
		},
		Spec: KeptnTaskSpec{
			Context: TaskContext{
				AppName:    "app",
				AppVersion: "appversion",
			},
			Type:           common.PostDeploymentCheckType,
			TaskDefinition: "def",
			Timeout: metav1.Duration{
				Duration: time.Duration(5 * time.Minute),
			},
		},
		Status: KeptnTaskStatus{
			Status: common.StateFailed,
		},
	}

	task.SetPhaseTraceID("", nil)
	require.Equal(t, KeptnTask{
		ObjectMeta: metav1.ObjectMeta{
			Name: "task",
			Labels: map[string]string{
				"label1": "label2",
			},
			Annotations: map[string]string{
				"annotation1": "annotation2",
			},
		},
		Spec: KeptnTaskSpec{
			Context: TaskContext{
				AppName:    "app",
				AppVersion: "appversion",
			},
			Type:           common.PostDeploymentCheckType,
			TaskDefinition: "def",
			Timeout: metav1.Duration{
				Duration: time.Duration(5 * time.Minute),
			},
		},
		Status: KeptnTaskStatus{
			Status: common.StateFailed,
		},
	}, *task)

	require.Equal(t, "task", task.GetSpanKey(""))
	require.Equal(t, "task", task.GetSpanName(""))

	require.False(t, task.IsEndTimeSet())
	require.False(t, task.IsStartTimeSet())

	task.SetStartTime()
	task.SetEndTime()

	require.True(t, task.IsEndTimeSet())
	require.True(t, task.IsStartTimeSet())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("app"),
		common.AppVersion.String("appversion"),
		common.WorkloadName.String(""),
		common.WorkloadVersion.String(""),
		common.TaskName.String("task"),
		common.TaskType.String(string(common.PostDeploymentCheckType)),
	}, task.GetActiveMetricsAttributes())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("app"),
		common.AppVersion.String("appversion"),
		common.WorkloadName.String(""),
		common.WorkloadVersion.String(""),
		common.TaskName.String("task"),
		common.TaskType.String(string(common.PostDeploymentCheckType)),
		common.TaskStatus.String(string(common.StateFailed)),
	}, task.GetMetricsAttributes())

	require.Equal(t, map[string]string{
		"keptn.sh/app":       "app",
		"keptn.sh/task-name": "task",
		"keptn.sh/version":   "appversion",
		"annotation1":        "annotation2",
	}, task.CreateKeptnAnnotations())

	task.Spec.Context.WorkloadName = "workload"
	task.Spec.Context.WorkloadVersion = "workloadversion"

	require.Equal(t, map[string]string{
		"keptn.sh/app":       "app",
		"keptn.sh/workload":  "workload",
		"keptn.sh/task-name": "task",
		"keptn.sh/version":   "workloadversion",
		"annotation1":        "annotation2",
	}, task.CreateKeptnAnnotations())

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("app"),
		common.AppVersion.String("appversion"),
		common.WorkloadName.String("workload"),
		common.WorkloadVersion.String("workloadversion"),
		common.TaskName.String("task"),
		common.TaskType.String(string(common.PostDeploymentCheckType)),
	}, task.GetSpanAttributes())

	require.Equal(t, map[string]string{
		"appName":            "app",
		"appVersion":         "appversion",
		"workloadName":       "workload",
		"workloadVersion":    "workloadversion",
		"taskName":           "task",
		"taskDefinitionName": "def",
	}, task.GetEventAnnotations())

	require.Equal(t, int64(300), *task.GetActiveDeadlineSeconds())

}

func TestKeptnTaskList(t *testing.T) {
	list := KeptnTaskList{
		Items: []KeptnTask{
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
}
