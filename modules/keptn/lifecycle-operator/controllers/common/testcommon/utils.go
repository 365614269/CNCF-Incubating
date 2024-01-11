package testcommon

import (
	"fmt"

	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	optionsv1alpha1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/options/v1alpha1"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	corev1 "k8s.io/api/core/v1"
	apiv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const KeptnNamespace = "keptn"

// NewTestClient returns a new controller-runtime fake Client configured with the Operator's scheme, and initialized with objs.
func NewTestClient(objs ...client.Object) client.Client {
	SetupSchemes()
	return fake.NewClientBuilder().WithScheme(scheme.Scheme).WithStatusSubresource(objs...).WithObjects(objs...).Build()
}

func SetupSchemes() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme.Scheme))
	utilruntime.Must(corev1.AddToScheme(scheme.Scheme))
	utilruntime.Must(apiv1.AddToScheme(scheme.Scheme))
	utilruntime.Must(klcv1beta1.AddToScheme(scheme.Scheme))
	utilruntime.Must(optionsv1alpha1.AddToScheme(scheme.Scheme))
}

func GetApp(name string) *klcv1beta1.KeptnApp {
	app := &klcv1beta1.KeptnApp{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Generation: 1,
		},
		Spec: klcv1beta1.KeptnAppSpec{
			Version: "1.0.0",
		},
		Status: klcv1beta1.KeptnAppStatus{},
	}
	return app
}

func ReturnAppVersion(namespace string, appName string, version string, workloads []klcv1beta1.KeptnWorkloadRef, status klcv1beta1.KeptnAppVersionStatus) *klcv1beta1.KeptnAppVersion {
	appVersionName := fmt.Sprintf("%s-%s", appName, version)
	app := &klcv1beta1.KeptnAppVersion{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:       appVersionName,
			Namespace:  namespace,
			Generation: 1,
		},
		Spec: klcv1beta1.KeptnAppVersionSpec{
			KeptnAppSpec: klcv1beta1.KeptnAppSpec{
				Version:   version,
				Workloads: workloads,
			},
			AppName: appName,
			TraceId: map[string]string{
				"traceparent": "parent-trace",
			},
		},
		Status: status,
	}
	return app
}

func InitAppMeters() apicommon.KeptnMeters {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("keptn/task")
	appCount, _ := meter.Int64Counter("keptn.app.count", metric.WithDescription("a simple counter for Keptn Apps"))
	appDuration, _ := meter.Float64Histogram("keptn.app.duration", metric.WithDescription("a histogram of duration for Keptn Apps"), metric.WithUnit("s"))
	deploymentCount, _ := meter.Int64Counter("keptn.deployment.count", metric.WithDescription("a simple counter for Keptn Deployments"))
	deploymentDuration, _ := meter.Float64Histogram("keptn.deployment.duration", metric.WithDescription("a histogram of duration for Keptn Deployments"), metric.WithUnit("s"))

	meters := apicommon.KeptnMeters{
		AppCount:           appCount,
		AppDuration:        appDuration,
		DeploymentCount:    deploymentCount,
		DeploymentDuration: deploymentDuration,
	}
	return meters
}
