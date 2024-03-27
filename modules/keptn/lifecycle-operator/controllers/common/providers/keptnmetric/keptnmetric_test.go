package keptnmetric

import (
	"context"
	"testing"

	apilifecycle "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/config"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/testcommon"
	metricsapi "github.com/keptn/lifecycle-toolkit/lifecycle-operator/test/api/metrics/v1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func Test_keptnmetric(t *testing.T) {
	tests := []struct {
		name      string
		metric    *metricsapi.KeptnMetric
		out       string
		outraw    []byte
		wantError bool
	}{
		{
			name:      "no KeptnMetric",
			metric:    &metricsapi.KeptnMetric{},
			out:       "",
			outraw:    []byte(nil),
			wantError: true,
		},
		{
			name: "KeptnMetric without results",
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "default",
				},
			},
			out:       "",
			outraw:    []byte(nil),
			wantError: true,
		},
		{
			name: "KeptnMetric without rawValue",
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "default",
				},
				Status: metricsapi.KeptnMetricStatus{
					Value: "1",
				},
			},
			out:       "",
			outraw:    []byte(nil),
			wantError: true,
		},
		{
			name: "KeptnMetric with results",
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "default",
				},
				Status: metricsapi.KeptnMetricStatus{
					Value:    "1",
					RawValue: []byte("1"),
				},
			},
			out:       "1",
			outraw:    []byte("1"),
			wantError: false,
		},
	}
	config.Instance().SetDefaultNamespace(testcommon.KeptnNamespace)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := metricsapi.AddToScheme(scheme.Scheme)
			require.Nil(t, err)
			client := fake.NewClientBuilder().WithObjects(tt.metric).Build()

			kmp := KeptnMetricProvider{
				Log:       ctrl.Log.WithName("testytest"),
				K8sClient: client,
			}

			obj := apilifecycle.Objective{
				KeptnMetricRef: apilifecycle.KeptnMetricReference{
					Name:      "metric",
					Namespace: "default",
				},
			}

			r, _, e := kmp.FetchData(context.TODO(), obj, "default")
			require.Equal(t, tt.out, r)
			// require.Equal(t, tt.outraw, raw)
			if tt.wantError != (e != nil) {
				t.Errorf("want error: %t, got: %v", tt.wantError, e)
			}

		})

	}
}

func Test_Getkeptnmetric(t *testing.T) {
	tests := []struct {
		name      string
		objective apilifecycle.Objective
		metric    *metricsapi.KeptnMetric
		namespace string
		out       *metricsapi.KeptnMetric
		wantError bool
	}{
		{
			name: "objective with namespace and existing keptnmetric",
			objective: apilifecycle.Objective{
				KeptnMetricRef: apilifecycle.KeptnMetricReference{
					Name:      "metric",
					Namespace: "my-namespace",
				},
			},
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "my-namespace",
				},
			},
			namespace: "my-other-namespace",
			out: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "my-namespace",
				},
			},
			wantError: false,
		},
		{
			name: "objective with namespace and non-existing keptnmetric",
			objective: apilifecycle.Objective{
				KeptnMetricRef: apilifecycle.KeptnMetricReference{
					Name:      "metric",
					Namespace: "my-namespace",
				},
			},
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "my-other-namespace",
				},
			},
			namespace: "my-other-namespace",
			out:       nil,
			wantError: true,
		},
		{
			name: "objective without namespace and existing keptnmetric",
			objective: apilifecycle.Objective{
				KeptnMetricRef: apilifecycle.KeptnMetricReference{
					Name: "metric",
				},
			},
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "my-other-namespace",
				},
			},
			namespace: "my-other-namespace",
			out: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: "my-other-namespace",
				},
			},
			wantError: false,
		},
		{
			name: "objective without namespace and existing keptnmetric in default Keptn namespace",
			objective: apilifecycle.Objective{
				KeptnMetricRef: apilifecycle.KeptnMetricReference{
					Name: "metric",
				},
			},
			metric: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: testcommon.KeptnNamespace,
				},
			},
			namespace: "my-other-namespace",
			out: &metricsapi.KeptnMetric{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "metric",
					Namespace: testcommon.KeptnNamespace,
				},
			},
			wantError: false,
		},
	}

	err := metricsapi.AddToScheme(scheme.Scheme)
	require.Nil(t, err)

	config.Instance().SetDefaultNamespace(testcommon.KeptnNamespace)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithObjects(tt.metric).Build()
			kmp := KeptnMetricProvider{
				Log:       ctrl.Log.WithName("testytest"),
				K8sClient: client,
			}

			m, err := kmp.GetKeptnMetric(context.TODO(), tt.objective, tt.namespace)
			if tt.out != nil && m != nil {
				require.Equal(t, tt.out.Name, getStringValue(m, "name"))
				require.Equal(t, tt.out.Namespace, getStringValue(m, "namespace"))
			}
			if tt.wantError != (err != nil) {
				t.Errorf("want error: %t, got: %v", tt.wantError, err)
			}

		})
	}
}

func getStringValue(obj *unstructured.Unstructured, key string) string {
	val, _, _ := unstructured.NestedString(obj.UnstructuredContent(), "metadata", key)
	return val
}
