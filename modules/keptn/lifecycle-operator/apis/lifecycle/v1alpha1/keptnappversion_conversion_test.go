//nolint:dupl
package v1alpha1

import (
	"testing"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1alpha1/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	v1beta1common "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v2 "sigs.k8s.io/controller-runtime/pkg/webhook/conversion/testdata/api/v2"
)

func TestKeptnAppVersion_ConvertFrom(t *testing.T) {
	tests := []struct {
		name    string
		srcObj  *v1beta1.KeptnAppVersion
		wantErr bool
		wantObj *KeptnAppVersion
	}{
		{
			name: "Test that conversion from v1beta1 to v1alpha1 works",
			srcObj: &v1beta1.KeptnAppVersion{
				TypeMeta: v1.TypeMeta{
					Kind:       "KeptnAppVersion",
					APIVersion: "lifecycle.keptn.sh/v1beta1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "some-keptn-app-name",
					Namespace: "",
					Labels: map[string]string{
						"some-label": "some-label-value",
					},
					Annotations: map[string]string{
						"some-annotation": "some-annotation-value",
					},
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppSpec: v1beta1.KeptnAppSpec{
						Version:  "1.2.3",
						Revision: 1,
						Workloads: []v1beta1.KeptnWorkloadRef{
							{
								Name:    "workload-1",
								Version: "1.2.3",
							},
							{
								Name:    "workload-2",
								Version: "4.5.6",
							},
						},
						PreDeploymentTasks: []string{
							"some-pre-deployment-task1",
						},
						PostDeploymentTasks: []string{
							"some-post-deployment-task2",
						},
						PreDeploymentEvaluations: []string{
							"some-pre-evaluation-task1",
						},
						PostDeploymentEvaluations: []string{
							"some-pre-evaluation-task2",
						},
					},
					AppName:         "app",
					PreviousVersion: "1.0",
					TraceId: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PreDeploymentStatus:            v1beta1common.StateFailed,
					PostDeploymentStatus:           v1beta1common.StateFailed,
					PreDeploymentEvaluationStatus:  v1beta1common.StateFailed,
					PostDeploymentEvaluationStatus: v1beta1common.StateFailed,
					WorkloadOverallStatus:          v1beta1common.StateFailed,
					WorkloadStatus: []v1beta1.WorkloadStatus{
						{
							Workload: v1beta1.KeptnWorkloadRef{
								Name:    "name1",
								Version: "1",
							},
							Status: v1beta1common.StateFailed,
						},
						{
							Workload: v1beta1.KeptnWorkloadRef{
								Name:    "name2",
								Version: "2",
							},
							Status: v1beta1common.StateFailed,
						},
					},
					CurrentPhase: "phase",
					PreDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def1",
							Name:           "name1",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def12",
							Name:           "name12",
							Status:         v1beta1common.StateFailed,
						},
					},
					PostDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def2",
							Name:           "name2",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def22",
							Name:           "name22",
							Status:         v1beta1common.StateFailed,
						},
					},
					PreDeploymentEvaluationTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def3",
							Name:           "name3",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def32",
							Name:           "name32",
							Status:         v1beta1common.StateFailed,
						},
					},
					PostDeploymentEvaluationTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def4",
							Name:           "name4",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def42",
							Name:           "name42",
							Status:         v1beta1common.StateFailed,
						},
					},
					PhaseTraceIDs: v1beta1common.PhaseTraceID{
						"key": propagation.MapCarrier{
							"key1": "value1",
							"key2": "value2",
						},
						"key22": propagation.MapCarrier{
							"key122": "value122",
							"key222": "value222",
						},
					},
					Status: v1beta1common.StateFailed,
				},
			},
			wantErr: false,
			wantObj: &KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Name:      "some-keptn-app-name",
					Namespace: "",
					Labels: map[string]string{
						"some-label": "some-label-value",
					},
					Annotations: map[string]string{
						"some-annotation": "some-annotation-value",
					},
				},
				Spec: KeptnAppVersionSpec{
					KeptnAppSpec: KeptnAppSpec{
						Version: "1.2.3",
						Workloads: []KeptnWorkloadRef{
							{
								Name:    "workload-1",
								Version: "1.2.3",
							},
							{
								Name:    "workload-2",
								Version: "4.5.6",
							},
						},
						PreDeploymentTasks: []string{
							"some-pre-deployment-task1",
						},
						PostDeploymentTasks: []string{
							"some-post-deployment-task2",
						},
						PreDeploymentEvaluations: []string{
							"some-pre-evaluation-task1",
						},
						PostDeploymentEvaluations: []string{
							"some-pre-evaluation-task2",
						},
					},
					AppName:         "app",
					PreviousVersion: "1.0",
					TraceId: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
				Status: KeptnAppVersionStatus{
					PreDeploymentStatus:            common.StateFailed,
					PostDeploymentStatus:           common.StateFailed,
					PreDeploymentEvaluationStatus:  common.StateFailed,
					PostDeploymentEvaluationStatus: common.StateFailed,
					WorkloadOverallStatus:          common.StateFailed,
					WorkloadStatus: []WorkloadStatus{
						{
							Workload: KeptnWorkloadRef{
								Name:    "name1",
								Version: "1",
							},
							Status: common.StateFailed,
						},
						{
							Workload: KeptnWorkloadRef{
								Name:    "name2",
								Version: "2",
							},
							Status: common.StateFailed,
						},
					},
					CurrentPhase: "phase",
					PreDeploymentTaskStatus: []TaskStatus{
						{
							TaskDefinitionName: "def1",
							TaskName:           "name1",
							Status:             common.StateFailed,
						},
						{
							TaskDefinitionName: "def12",
							TaskName:           "name12",
							Status:             common.StateFailed,
						},
					},
					PostDeploymentTaskStatus: []TaskStatus{
						{
							TaskDefinitionName: "def2",
							TaskName:           "name2",
							Status:             common.StateFailed,
						},
						{
							TaskDefinitionName: "def22",
							TaskName:           "name22",
							Status:             common.StateFailed,
						},
					},
					PreDeploymentEvaluationTaskStatus: []EvaluationStatus{
						{
							EvaluationDefinitionName: "def3",
							EvaluationName:           "name3",
							Status:                   common.StateFailed,
						},
						{
							EvaluationDefinitionName: "def32",
							EvaluationName:           "name32",
							Status:                   common.StateFailed,
						},
					},
					PostDeploymentEvaluationTaskStatus: []EvaluationStatus{
						{
							EvaluationDefinitionName: "def4",
							EvaluationName:           "name4",
							Status:                   common.StateFailed,
						},
						{
							EvaluationDefinitionName: "def42",
							EvaluationName:           "name42",
							Status:                   common.StateFailed,
						},
					},
					PhaseTraceIDs: common.PhaseTraceID{
						"key": propagation.MapCarrier{
							"key1": "value1",
							"key2": "value2",
						},
						"key22": propagation.MapCarrier{
							"key122": "value122",
							"key222": "value222",
						},
					},
					Status: common.StateFailed,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := &KeptnAppVersion{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Spec:       KeptnAppVersionSpec{},
				Status:     KeptnAppVersionStatus{},
			}
			if err := dst.ConvertFrom(tt.srcObj); (err != nil) != tt.wantErr {
				t.Errorf("ConvertFrom() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantObj != nil {
				require.Equal(t, tt.wantObj, dst, "Object was not converted correctly")
			}
		})
	}
}

func TestKeptnAppVersion_ConvertTo(t *testing.T) {
	tests := []struct {
		name    string
		src     *KeptnAppVersion
		wantErr bool
		wantObj *v1beta1.KeptnAppVersion
	}{
		{
			name: "Test that conversion from v1alpha1 to v1beta1 works",
			src: &KeptnAppVersion{
				TypeMeta: v1.TypeMeta{
					Kind:       "KeptnAppVersion",
					APIVersion: "lifecycle.keptn.sh/v1alpha1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "some-keptn-app-name",
					Namespace: "",
					Labels: map[string]string{
						"some-label": "some-label-value",
					},
					Annotations: map[string]string{
						"some-annotation": "some-annotation-value",
					},
				},
				Spec: KeptnAppVersionSpec{
					KeptnAppSpec: KeptnAppSpec{
						Version: "1.2.3",
						Workloads: []KeptnWorkloadRef{
							{
								Name:    "workload-1",
								Version: "1.2.3",
							},
							{
								Name:    "workload-2",
								Version: "4.5.6",
							},
						},
						PreDeploymentTasks: []string{
							"some-pre-deployment-task1",
						},
						PostDeploymentTasks: []string{
							"some-post-deployment-task2",
						},
						PreDeploymentEvaluations: []string{
							"some-pre-evaluation-task1",
						},
						PostDeploymentEvaluations: []string{
							"some-pre-evaluation-task2",
						},
					},
					AppName:         "app",
					PreviousVersion: "1.0",
					TraceId: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
				Status: KeptnAppVersionStatus{
					PreDeploymentStatus:            common.StateFailed,
					PostDeploymentStatus:           common.StateFailed,
					PreDeploymentEvaluationStatus:  common.StateFailed,
					PostDeploymentEvaluationStatus: common.StateFailed,
					WorkloadOverallStatus:          common.StateFailed,
					WorkloadStatus: []WorkloadStatus{
						{
							Workload: KeptnWorkloadRef{
								Name:    "name1",
								Version: "1",
							},
							Status: common.StateFailed,
						},
						{
							Workload: KeptnWorkloadRef{
								Name:    "name2",
								Version: "2",
							},
							Status: common.StateFailed,
						},
					},
					CurrentPhase: "phase",
					PreDeploymentTaskStatus: []TaskStatus{
						{
							TaskDefinitionName: "def1",
							TaskName:           "name1",
							Status:             common.StateFailed,
						},
						{
							TaskDefinitionName: "def12",
							TaskName:           "name12",
							Status:             common.StateFailed,
						},
					},
					PostDeploymentTaskStatus: []TaskStatus{
						{
							TaskDefinitionName: "def2",
							TaskName:           "name2",
							Status:             common.StateFailed,
						},
						{
							TaskDefinitionName: "def22",
							TaskName:           "name22",
							Status:             common.StateFailed,
						},
					},
					PreDeploymentEvaluationTaskStatus: []EvaluationStatus{
						{
							EvaluationDefinitionName: "def3",
							EvaluationName:           "name3",
							Status:                   common.StateFailed,
						},
						{
							EvaluationDefinitionName: "def32",
							EvaluationName:           "name32",
							Status:                   common.StateFailed,
						},
					},
					PostDeploymentEvaluationTaskStatus: []EvaluationStatus{
						{
							EvaluationDefinitionName: "def4",
							EvaluationName:           "name4",
							Status:                   common.StateFailed,
						},
						{
							EvaluationDefinitionName: "def42",
							EvaluationName:           "name42",
							Status:                   common.StateFailed,
						},
					},
					PhaseTraceIDs: common.PhaseTraceID{
						"key": propagation.MapCarrier{
							"key1": "value1",
							"key2": "value2",
						},
						"key22": propagation.MapCarrier{
							"key122": "value122",
							"key222": "value222",
						},
					},
					Status: common.StateFailed,
				},
			},
			wantErr: false,
			wantObj: &v1beta1.KeptnAppVersion{
				ObjectMeta: v1.ObjectMeta{
					Name:      "some-keptn-app-name",
					Namespace: "",
					Labels: map[string]string{
						"some-label": "some-label-value",
					},
					Annotations: map[string]string{
						"some-annotation": "some-annotation-value",
					},
				},
				Spec: v1beta1.KeptnAppVersionSpec{
					KeptnAppSpec: v1beta1.KeptnAppSpec{
						Version:  "1.2.3",
						Revision: 1,
						Workloads: []v1beta1.KeptnWorkloadRef{
							{
								Name:    "workload-1",
								Version: "1.2.3",
							},
							{
								Name:    "workload-2",
								Version: "4.5.6",
							},
						},
						PreDeploymentTasks: []string{
							"some-pre-deployment-task1",
						},
						PostDeploymentTasks: []string{
							"some-post-deployment-task2",
						},
						PreDeploymentEvaluations: []string{
							"some-pre-evaluation-task1",
						},
						PostDeploymentEvaluations: []string{
							"some-pre-evaluation-task2",
						},
					},
					AppName:         "app",
					PreviousVersion: "1.0",
					TraceId: map[string]string{
						"key1": "value1",
						"key2": "value2",
					},
				},
				Status: v1beta1.KeptnAppVersionStatus{
					PreDeploymentStatus:            v1beta1common.StateFailed,
					PostDeploymentStatus:           v1beta1common.StateFailed,
					PreDeploymentEvaluationStatus:  v1beta1common.StateFailed,
					PostDeploymentEvaluationStatus: v1beta1common.StateFailed,
					WorkloadOverallStatus:          v1beta1common.StateFailed,
					WorkloadStatus: []v1beta1.WorkloadStatus{
						{
							Workload: v1beta1.KeptnWorkloadRef{
								Name:    "name1",
								Version: "1",
							},
							Status: v1beta1common.StateFailed,
						},
						{
							Workload: v1beta1.KeptnWorkloadRef{
								Name:    "name2",
								Version: "2",
							},
							Status: v1beta1common.StateFailed,
						},
					},
					CurrentPhase: "phase",
					PreDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def1",
							Name:           "name1",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def12",
							Name:           "name12",
							Status:         v1beta1common.StateFailed,
						},
					},
					PostDeploymentTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def2",
							Name:           "name2",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def22",
							Name:           "name22",
							Status:         v1beta1common.StateFailed,
						},
					},
					PreDeploymentEvaluationTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def3",
							Name:           "name3",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def32",
							Name:           "name32",
							Status:         v1beta1common.StateFailed,
						},
					},
					PostDeploymentEvaluationTaskStatus: []v1beta1.ItemStatus{
						{
							DefinitionName: "def4",
							Name:           "name4",
							Status:         v1beta1common.StateFailed,
						},
						{
							DefinitionName: "def42",
							Name:           "name42",
							Status:         v1beta1common.StateFailed,
						},
					},
					PhaseTraceIDs: v1beta1common.PhaseTraceID{
						"key": propagation.MapCarrier{
							"key1": "value1",
							"key2": "value2",
						},
						"key22": propagation.MapCarrier{
							"key122": "value122",
							"key222": "value222",
						},
					},
					Status: v1beta1common.StateFailed,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := v1beta1.KeptnAppVersion{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Spec:       v1beta1.KeptnAppVersionSpec{},
				Status:     v1beta1.KeptnAppVersionStatus{},
			}
			if err := tt.src.ConvertTo(&dst); (err != nil) != tt.wantErr {
				t.Errorf("ConvertTo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantObj != nil {
				require.Equal(t, tt.wantObj, &dst, "Object was not converted correctly")
			}
		})
	}
}

func TestKeptnAppVersion_ConvertFrom_Errorcase(t *testing.T) {
	// A random different object is used here to simulate a different API version
	testObj := v2.ExternalJob{}

	dst := &KeptnAppVersion{
		TypeMeta:   v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{},
		Spec:       KeptnAppVersionSpec{},
		Status:     KeptnAppVersionStatus{},
	}

	if err := dst.ConvertFrom(&testObj); err == nil {
		t.Errorf("ConvertFrom() error = %v", err)
	} else {
		require.ErrorIs(t, err, common.ErrCannotCastKeptnAppVersion)
	}
}

func TestKeptnAppVersion_ConvertTo_Errorcase(t *testing.T) {
	testObj := KeptnAppVersion{}

	// A random different object is used here to simulate a different API version
	dst := v2.ExternalJob{}

	if err := testObj.ConvertTo(&dst); err == nil {
		t.Errorf("ConvertTo() error = %v", err)
	} else {
		require.ErrorIs(t, err, common.ErrCannotCastKeptnAppVersion)
	}
}
