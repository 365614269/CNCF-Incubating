package prometheus

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/fake"
	fakeprom "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/providers/prometheus/fake"
	promapi "github.com/prometheus/client_golang/api"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const promWarnPayloadWithNoRange = "{\"status\":\"success\",\"warnings\":[\"awarning\"],\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"value\":[1669714193.275,\"1\"]}]}}"
const promPayloadWithNoRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"value\":[1669714193.275,\"1\"]}]}}"
const promEmptyDataPayloadWithNoRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[]}}"
const promMatrixPayloadWithNoRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[]}}"
const promMultiPointPayloadWithNoRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"value\":[1669714193.275,\"1\"]},{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kube-proxy\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kube-proxy-dlq7m\",\"pod_ip\":\"172.18.0.2\",\"priority_class\":\"system-node-critical\",\"uid\":\"31240e57-5286-4bc6-ad69-80b68bf806d0\"},\"value\":[1669714193.275,\"1\"]},{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"node-exporter\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"monitoring\",\"node\":\"kind-control-plane\",\"pod\":\"node-exporter-dv6nr\",\"pod_ip\":\"172.18.0.2\",\"priority_class\":\"system-cluster-critical\",\"uid\":\"cf7baf10-ac9a-4b7d-9510-a6502d7ed271\"},\"value\":[1669714193.275,\"1\"]}]}}"

const promWarnPayloadWithRange = "{\"status\":\"success\",\"warnings\":[\"awarning\"],\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"]]}]}}"
const promPayloadWithRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"]]}]}}"
const promEmptyDataPayloadWithRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[[]]}}"
const promVectorPayloadWithRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[[]]}}"
const promMultiPointPayloadWithRange = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"]]},{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"]]}]}}"

const promWarnPayloadWithRangeAndStep = "{\"status\":\"success\",\"warnings\":[\"awarning\"],\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"]]}]}}"
const promPayloadWithRangeAndStep = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"]]}]}}"
const promEmptyDataPayloadWithRangeAndStep = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[[]]}}"
const promVectorPayloadWithRangeAndStep = "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[[]]}}"
const promMultiPointPayloadWithRangeAndStep = "{\"status\":\"success\",\"data\":{\"resultType\":\"matrix\",\"result\":[{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"]]},{\"metric\":{\"__name__\":\"kube_pod_info\",\"container\":\"kube-rbac-proxy-main\",\"created_by_kind\":\"DaemonSet\",\"created_by_name\":\"kindnet\",\"host_ip\":\"172.18.0.2\",\"host_network\":\"true\",\"instance\":\"10.244.0.24:8443\",\"job\":\"kube-state-metrics\",\"namespace\":\"kube-system\",\"node\":\"kind-control-plane\",\"pod\":\"kindnet-llt85\",\"pod_ip\":\"172.18.0.2\",\"uid\":\"0bb9d9db-2658-439f-aed9-ab3e8502397d\"},\"values\":[[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"],[1669714193.275,\"1\"]]}]}}"

func Test_prometheus(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		out        string
		outForStep []string
		outraw     []byte
		wantError  bool
		hasRange   bool
		hasStep    bool
	}{
		{
			name:      "wrong data with no range",
			in:        "garbage",
			out:       "",
			wantError: true,
		},
		{
			name:      "warnings with no range",
			in:        promWarnPayloadWithNoRange,
			out:       "1",
			outraw:    []byte("\"1\""),
			wantError: false,
			hasRange:  false,
		},
		{
			name:      "multiple datapoint with no range",
			in:        promMultiPointPayloadWithNoRange,
			out:       "",
			wantError: true,
			hasRange:  false,
		},
		{
			name:      "empty datapoint with no range",
			in:        promEmptyDataPayloadWithNoRange,
			out:       "",
			wantError: true,
			hasRange:  false,
		},
		{
			name:      "unsupported answer type with no range",
			in:        promMatrixPayloadWithNoRange,
			out:       "",
			wantError: true,
			hasRange:  false,
		},
		{
			name:      "happy path with no range",
			in:        promPayloadWithNoRange,
			out:       "1",
			outraw:    []byte("\"1\""),
			wantError: false,
			hasRange:  false,
		},
		{
			name:      "warnings with range",
			in:        promWarnPayloadWithRange,
			out:       "1",
			outraw:    []byte("\"1\""),
			wantError: false,
			hasRange:  true,
			hasStep:   false,
		},
		{
			name:      "multiple datapoint with range",
			in:        promMultiPointPayloadWithRange,
			out:       "",
			wantError: true,
			hasRange:  true,
			hasStep:   false,
		},
		{
			name:      "empty datapoint with range",
			in:        promEmptyDataPayloadWithRange,
			out:       "",
			wantError: true,
			hasRange:  true,
			hasStep:   false,
		},
		{
			name:      "unsupported answer type with range",
			in:        promVectorPayloadWithRange,
			out:       "",
			wantError: true,
			hasRange:  false,
			hasStep:   false,
		},
		{
			name:      "happy path with range",
			in:        promPayloadWithRange,
			out:       "1",
			outraw:    []byte("\"1\""),
			wantError: false,
			hasRange:  true,
			hasStep:   false,
		},
		{
			name:       "warnings with range and step",
			in:         promWarnPayloadWithRangeAndStep,
			outForStep: []string{"1", "1", "1", "1", "1"},
			outraw:     []byte("[\"1\",\"1\",\"1\",\"1\",\"1\"]"),
			wantError:  false,
			hasRange:   true,
			hasStep:    true,
		},
		{
			name:       "multiple datapoint with range and step",
			in:         promMultiPointPayloadWithRangeAndStep,
			outForStep: nil,
			wantError:  true,
			hasRange:   true,
			hasStep:    true,
		},
		{
			name:       "empty datapoint with range and step",
			in:         promEmptyDataPayloadWithRangeAndStep,
			outForStep: nil,
			wantError:  true,
			hasRange:   true,
			hasStep:    true,
		},
		{
			name:       "unsupported answer type with range and step",
			in:         promVectorPayloadWithRangeAndStep,
			outForStep: nil,
			wantError:  true,
			hasRange:   true,
			hasStep:    true,
		},
		{
			name:       "happy path with range and step",
			in:         promPayloadWithRangeAndStep,
			outForStep: []string{"1", "1", "1", "1", "1"},
			outraw:     []byte("[\"1\",\"1\",\"1\",\"1\",\"1\"]"),
			wantError:  false,
			hasRange:   true,
			hasStep:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(tt.in))
				require.Nil(t, err)
			}))
			defer svr.Close()

			fclient := fake.NewClient()
			kpp := KeptnPrometheusProvider{
				K8sClient: fclient,
				Log:       ctrl.Log.WithName("testytest"),
				Getter:    RoundTripperRetriever{},
			}
			p := metricsapi.KeptnMetricsProvider{
				Spec: metricsapi.KeptnMetricsProviderSpec{
					TargetServer: svr.URL,
				},
			}
			switch tt.hasRange {
			case false:
				obj := metricsapi.KeptnMetric{
					Spec: metricsapi.KeptnMetricSpec{
						Query: "my-query",
					},
				}
				r, raw, e := kpp.EvaluateQuery(context.TODO(), obj, p)
				require.Equal(t, tt.out, r)
				require.Equal(t, tt.outraw, raw)
				if tt.wantError != (e != nil) {
					t.Errorf("want error: %t, got: %v", tt.wantError, e)
				}
			case true:
				if tt.hasStep {
					obj := metricsapi.KeptnMetric{
						Spec: metricsapi.KeptnMetricSpec{
							Query: "my-query",
							Range: &metricsapi.RangeSpec{
								Interval:    "5m",
								Step:        "1m",
								Aggregation: "max",
							},
						},
					}
					r, raw, e := kpp.EvaluateQueryForStep(context.TODO(), obj, p)
					require.Equal(t, tt.outForStep, r)
					require.Equal(t, tt.outraw, raw)
					if tt.wantError != (e != nil) {
						t.Errorf("want error: %t, got: %v", tt.wantError, e)
					}
				} else {
					obj := metricsapi.KeptnMetric{
						Spec: metricsapi.KeptnMetricSpec{
							Query: "my-query",
							Range: &metricsapi.RangeSpec{Interval: "5m"},
						},
					}
					r, raw, e := kpp.EvaluateQuery(context.TODO(), obj, p)
					require.Equal(t, tt.out, r)
					require.Equal(t, tt.outraw, raw)
					if tt.wantError != (e != nil) {
						t.Errorf("want error: %t, got: %v", tt.wantError, e)
					}
				}
			}
		})
	}
}

func Test_resultsForMatrix(t *testing.T) {
	tests := []struct {
		name             string
		result           model.Value
		wantResultSlice  []string
		wantResultString string
		wantRaw          []byte
		wantErr          bool
		hasStep          bool
	}{
		// this is to cover the scenario where we get an empty result matrix from the prometheus API
		// right now, the prometheus client returns an error in the QueryRange function if that is the case,
		// but we should do a check for an empty matrix here as well in case the behavior of the QueryRange function
		// changes
		{
			name:            "empty matrix with step - return err",
			result:          model.Matrix{},
			wantResultSlice: nil,
			wantRaw:         nil,
			wantErr:         true,
			hasStep:         true,
		},
		{
			name:             "empty matrix without step- return err",
			result:           model.Matrix{},
			wantResultString: "",
			wantRaw:          nil,
			wantErr:          true,
			hasStep:          false,
		},
		{
			name:             "unsupported matrix with step- return err",
			result:           model.Vector{},
			wantResultString: "",
			wantRaw:          nil,
			wantErr:          true,
			hasStep:          true,
		},
		{
			name:             "unsupported matrix without step- return err",
			result:           model.Vector{},
			wantResultString: "",
			wantRaw:          nil,
			wantErr:          true,
			hasStep:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.hasStep {
			case true:
				resultSlice, raw, err := getResultForStepMatrix(tt.result)
				if (err != nil) != tt.wantErr {
					t.Errorf("getResultForStepMatrix() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				require.Equal(t, tt.wantResultSlice, resultSlice)
				require.Equal(t, tt.wantRaw, raw)
			case false:
				resultString, raw, err := getResultForMatrix(tt.result)
				if (err != nil) != tt.wantErr {
					t.Errorf("getResultForMatrix() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				require.Equal(t, tt.wantResultString, resultString)
				require.Equal(t, tt.wantRaw, raw)
			}
		})
	}
}

func TestFetchAnalysisValueWithAuth(t *testing.T) {

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		// prometheus encodes basic user password in header
		t.Log(header)
		encoded := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))
		if strings.Contains(header, encoded) {
			_, err := w.Write([]byte(promPayloadWithRangeAndStep))
			require.Nil(t, err)
		} else {
			_, err := w.Write([]byte("Unauthorized"))
			require.Nil(t, err)
		}
	}))
	defer svr.Close()

	// Create a mock KeptnMetricsProvider
	mockProvider := &metricsapi.KeptnMetricsProvider{
		Spec: metricsapi.KeptnMetricsProviderSpec{
			SecretKeyRef: v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "myapitoken",
				},
				Key: "defaultuser",
			},
			TargetServer: svr.URL,
		},
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "myapitoken",
			Namespace: "",
		},
		Data: map[string][]byte{
			secretKeyUserName: []byte(secretKeyUserName),
			secretKeyPassword: []byte(secretKeyPassword),
		},
	}
	fclient := fake.NewClient(&secret)
	// Create your KeptnPrometheusProvider instance
	provider := KeptnPrometheusProvider{
		K8sClient: fclient,
		Log:       ctrl.Log.WithName("testytest"),
		Getter:    RoundTripperRetriever{},
	}

	// Prepare the analysis spec
	now := time.Now()
	analysis := metricsapi.Analysis{
		Spec: metricsapi.AnalysisSpec{
			Timeframe: metricsapi.Timeframe{
				From: metav1.Time{
					Time: now.Add(-time.Hour),
				},
				To: metav1.Time{
					Time: now,
				}},
		},
	}

	// Prepare the expected result
	expectedResult := "1"

	// Call the function
	result, err := provider.FetchAnalysisValue(context.Background(), "your_query_string_here", analysis, mockProvider)

	// Assertions
	require.NoError(t, err)
	require.Equal(t, expectedResult, result)
}

func TestKeptnPrometheusProvider_setupApi(t *testing.T) {
	var b byte = 0x7f
	tests := []struct {
		name          string
		getter        IRoundTripper
		provider      metricsapi.KeptnMetricsProvider
		expectedError string
	}{
		{
			name: "Successful setup",
			getter: &fakeprom.IRoundTripperMock{
				GetRoundTripperFunc: func(ctx context.Context, provider metricsapi.KeptnMetricsProvider, k8sClient client.Client) (http.RoundTripper, error) {
					return promapi.DefaultRoundTripper, nil
				},
			},
			provider: metricsapi.KeptnMetricsProvider{
				Spec: metricsapi.KeptnMetricsProviderSpec{
					TargetServer: "http://example.com",
				},
			},
			expectedError: "",
		},
		{
			name: "Error in getter",
			getter: &fakeprom.IRoundTripperMock{
				GetRoundTripperFunc: func(ctx context.Context, provider metricsapi.KeptnMetricsProvider, k8sClient client.Client) (http.RoundTripper, error) {
					return nil, errors.New("bad")
				},
			},

			provider: metricsapi.KeptnMetricsProvider{
				Spec: metricsapi.KeptnMetricsProviderSpec{
					TargetServer: "http://example.com",
				},
			},
			expectedError: "bad",
		},
		{
			name: "Error in NewClient",
			getter: &fakeprom.IRoundTripperMock{
				GetRoundTripperFunc: func(ctx context.Context, provider metricsapi.KeptnMetricsProvider, k8sClient client.Client) (http.RoundTripper, error) {
					return promapi.DefaultRoundTripper, nil
				},
			},
			provider: metricsapi.KeptnMetricsProvider{
				Spec: metricsapi.KeptnMetricsProviderSpec{
					TargetServer: string(b),
				},
			},
			expectedError: "parse",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &KeptnPrometheusProvider{
				K8sClient: fake.NewClient(), // Initialize with your K8s client
				Getter:    tc.getter,
			}
			_, err := r.setupApi(context.Background(), tc.provider)
			if tc.expectedError == "" {
				require.Nil(t, err)
			} else {
				require.Contains(t, err.Error(), tc.expectedError)
			}
		})
	}
}
