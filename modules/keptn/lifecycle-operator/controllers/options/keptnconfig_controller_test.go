package options

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	optionsv1alpha1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/options/v1alpha1"
	fakeconfig "github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/config/fake"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/testcommon"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestKeptnConfigReconciler_Reconcile(t *testing.T) {
	// set up logger
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	type args struct {
		ctx context.Context
		req ctrl.Request
	}
	tests := []struct {
		name                             string
		args                             args
		lastAppliedConfig                *optionsv1alpha1.KeptnConfigSpec
		reconcileConfig                  *optionsv1alpha1.KeptnConfig
		want                             ctrl.Result
		wantErr                          bool
		wantCreationRequestTimeoutConfig time.Duration
		wantCloudEventsEndpointConfig    string
		wantBlockDeployment              bool
		blockDeploymentCalls             int
		wantObservabilityTimeout         metav1.Duration
		observabilityTimeoutCalls        int
	}{
		{
			name: "test 1",
			args: args{
				ctx: context.TODO(),
				req: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "keptn-system",
						Name:      "empty-config",
					},
				},
			},
			reconcileConfig: &optionsv1alpha1.KeptnConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-config",
					Namespace: "keptn-system",
				},
				Spec: optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl: "",
					BlockDeployment:  true,
					ObservabilityTimeout: metav1.Duration{
						Duration: time.Duration(5 * time.Minute),
					},
				},
			},
			lastAppliedConfig:         &optionsv1alpha1.KeptnConfigSpec{},
			want:                      ctrl.Result{},
			wantErr:                   false,
			wantBlockDeployment:       true,
			blockDeploymentCalls:      1,
			observabilityTimeoutCalls: 1,
			wantObservabilityTimeout: metav1.Duration{
				Duration: time.Duration(5 * time.Minute),
			},
		},
		{
			name: "test 2",
			args: args{
				ctx: context.TODO(),
				req: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "keptn-system",
						Name:      "empty-config",
					},
				},
			},
			reconcileConfig: &optionsv1alpha1.KeptnConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-config",
					Namespace: "keptn-system",
				},
				Spec: optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl: "",
					BlockDeployment:  true,
					ObservabilityTimeout: metav1.Duration{
						Duration: time.Duration(5 * time.Minute),
					},
				},
			},
			want:                      ctrl.Result{},
			wantErr:                   false,
			wantBlockDeployment:       true,
			blockDeploymentCalls:      1,
			observabilityTimeoutCalls: 1,
			wantObservabilityTimeout: metav1.Duration{
				Duration: time.Duration(5 * time.Minute),
			},
		},
		{
			name: "test 3",
			args: args{
				ctx: context.TODO(),
				req: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "keptn-system",
						Name:      "not-found-config",
					},
				},
			},
			reconcileConfig: &optionsv1alpha1.KeptnConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-config",
					Namespace: "keptn-system",
				},
			},
			want:                      ctrl.Result{},
			wantErr:                   false,
			blockDeploymentCalls:      0,
			observabilityTimeoutCalls: 0,
		},
		{
			name: "test 4",
			args: args{
				ctx: context.TODO(),
				req: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "keptn-system",
						Name:      "config1",
					},
				},
			},
			lastAppliedConfig: &optionsv1alpha1.KeptnConfigSpec{
				OTelCollectorUrl: "some-url",
				BlockDeployment:  true,
			},
			reconcileConfig: &optionsv1alpha1.KeptnConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "config1",
					Namespace: "keptn-system",
				},
				Spec: optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl:                      "url1",
					KeptnAppCreationRequestTimeoutSeconds: 10,
					CloudEventsEndpoint:                   "ce-endpoint",
					BlockDeployment:                       false,
					ObservabilityTimeout: metav1.Duration{
						Duration: time.Duration(5 * time.Minute),
					},
				},
			},
			want:                             ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second},
			wantCloudEventsEndpointConfig:    "ce-endpoint",
			wantCreationRequestTimeoutConfig: 10 * time.Second,
			wantErr:                          true,
			wantBlockDeployment:              false,
			blockDeploymentCalls:             1,
			observabilityTimeoutCalls:        1,
			wantObservabilityTimeout: metav1.Duration{
				Duration: time.Duration(5 * time.Minute),
			},
		},
		{
			name: "test 5",
			args: args{
				ctx: context.TODO(),
				req: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "keptn-system",
						Name:      "config1",
					},
				},
			},
			lastAppliedConfig: &optionsv1alpha1.KeptnConfigSpec{
				OTelCollectorUrl: "some-url",
			},
			reconcileConfig: &optionsv1alpha1.KeptnConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "config1",
					Namespace: "keptn-system",
				},
				Spec: optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl:                      "url1",
					KeptnAppCreationRequestTimeoutSeconds: 10,
					CloudEventsEndpoint:                   "ce-endpoint",
					BlockDeployment:                       false,
					ObservabilityTimeout: metav1.Duration{
						Duration: time.Duration(10 * time.Minute),
					},
				},
			},
			want:                             ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second},
			wantCloudEventsEndpointConfig:    "ce-endpoint",
			wantCreationRequestTimeoutConfig: 10 * time.Second,
			wantErr:                          true,
			wantBlockDeployment:              false,
			blockDeploymentCalls:             1,
			observabilityTimeoutCalls:        1,
			wantObservabilityTimeout: metav1.Duration{
				Duration: time.Duration(10 * time.Minute),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler := setupReconciler(tt.reconcileConfig)
			reconciler.LastAppliedSpec = tt.lastAppliedConfig
			got, err := reconciler.Reconcile(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Reconcile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Reconcile() got = %v, want %v", got, tt.want)
			}

			mockConfig := reconciler.config.(*fakeconfig.MockConfig)

			if tt.wantCreationRequestTimeoutConfig > 0 {
				require.Len(t, mockConfig.SetCreationRequestTimeoutCalls(), 1)
				require.Equal(t, tt.wantCreationRequestTimeoutConfig, mockConfig.SetCreationRequestTimeoutCalls()[0].Value)
			}
			if tt.wantCloudEventsEndpointConfig != "" {
				require.Len(t, mockConfig.SetCloudEventsEndpointCalls(), 1)
				require.Equal(t, tt.wantCloudEventsEndpointConfig, mockConfig.SetCloudEventsEndpointCalls()[0].Endpoint)
			}
			require.Len(t, mockConfig.SetBlockDeploymentCalls(), tt.blockDeploymentCalls)
			if tt.blockDeploymentCalls > 0 {
				require.Equal(t, tt.wantBlockDeployment, mockConfig.SetBlockDeploymentCalls()[0].Value)
			}
			require.Len(t, mockConfig.SetObservabilityTimeoutCalls(), tt.observabilityTimeoutCalls)
			if tt.observabilityTimeoutCalls > 0 {
				require.Equal(t, tt.wantObservabilityTimeout, mockConfig.SetObservabilityTimeoutCalls()[0].Timeout)
			}
		})
	}
}

func TestKeptnConfigReconciler_initConfig(t *testing.T) {
	type fields struct {
		Client          client.Client
		Scheme          *runtime.Scheme
		Log             logr.Logger
		LastAppliedSpec *optionsv1alpha1.KeptnConfigSpec
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Test basic initialization",
			fields: fields{
				LastAppliedSpec: &optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl: "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &KeptnConfigReconciler{
				Client:          tt.fields.Client,
				Scheme:          tt.fields.Scheme,
				Log:             tt.fields.Log,
				LastAppliedSpec: tt.fields.LastAppliedSpec,
			}
			r.initConfig()
		})
	}
}

func TestKeptnConfigReconciler_reconcileOtelCollectorUrl(t *testing.T) {
	// set up logger
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	type fields struct {
		Client          client.Client
		Scheme          *runtime.Scheme
		Log             logr.Logger
		LastAppliedSpec *optionsv1alpha1.KeptnConfigSpec
	}
	type args struct {
		config *optionsv1alpha1.KeptnConfig
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    ctrl.Result
		wantErr bool
	}{
		{
			name: "Test garbage URL",
			fields: fields{
				Client: nil,
				Scheme: nil,
				Log:    ctrl.Log.WithName("test-keptn-config-controller"),
				LastAppliedSpec: &optionsv1alpha1.KeptnConfigSpec{
					OTelCollectorUrl: "",
				},
			},
			args: args{
				config: &optionsv1alpha1.KeptnConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-config",
					},
					Spec: optionsv1alpha1.KeptnConfigSpec{
						OTelCollectorUrl: "some-url",
					},
				},
			},
			want:    ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second},
			wantErr: true,
		},
		{
			name: "Test with no URL",
			fields: fields{
				Client: nil,
				Scheme: nil,
				Log:    ctrl.Log.WithName("test-keptn-config-controller"),
			},
			args: args{
				config: &optionsv1alpha1.KeptnConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-config",
					},
					Spec: optionsv1alpha1.KeptnConfigSpec{
						OTelCollectorUrl: "",
					},
				},
			},
			want:    ctrl.Result{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &KeptnConfigReconciler{
				Client:          tt.fields.Client,
				Scheme:          tt.fields.Scheme,
				Log:             tt.fields.Log,
				LastAppliedSpec: tt.fields.LastAppliedSpec,
			}
			got, err := r.reconcileOtelCollectorUrl(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("reconcileOtelCollectorUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reconcileOtelCollectorUrl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func setupReconciler(withConfig *optionsv1alpha1.KeptnConfig) *KeptnConfigReconciler {
	// setup logger
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	fakeClient := testcommon.NewTestClient(withConfig)

	r := NewReconciler(
		fakeClient,
		fakeClient.Scheme(),
		ctrl.Log.WithName("test-keptnconfig-controller"),
	)
	r.config = &fakeconfig.MockConfig{
		SetCloudEventsEndpointFunc:    func(endpoint string) {},
		SetCreationRequestTimeoutFunc: func(value time.Duration) {},
		SetBlockDeploymentFunc:        func(value bool) {},
		SetObservabilityTimeoutFunc:   func(timeout metav1.Duration) {},
	}
	return r
}
