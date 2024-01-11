package common

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry"
	metricsapi "github.com/keptn/lifecycle-toolkit/lifecycle-operator/test/api/metrics/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	ginkgotypes "github.com/onsi/ginkgo/v2/types"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	otelsdk "go.opentelemetry.io/otel/sdk/trace"
	sdktest "go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func InitKeptnMeters() apicommon.KeptnMeters {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("keptn/task")
	deploymentCount, _ := meter.Int64Counter("keptn.deployment.count", metric.WithDescription("a simple counter for Keptn Deployments"))
	deploymentDuration, _ := meter.Float64Histogram("keptn.deployment.duration", metric.WithDescription("a histogram of duration for Keptn Deployments"), metric.WithUnit("s"))
	taskCount, _ := meter.Int64Counter("keptn.task.count", metric.WithDescription("a simple counter for Keptn Tasks"))
	taskDuration, _ := meter.Float64Histogram("keptn.task.duration", metric.WithDescription("a histogram of duration for Keptn Tasks"), metric.WithUnit("s"))
	appCount, _ := meter.Int64Counter("keptn.app.count", metric.WithDescription("a simple counter for Keptn Apps"))
	appDuration, _ := meter.Float64Histogram("keptn.app.duration", metric.WithDescription("a histogram of duration for Keptn Apps"), metric.WithUnit("s"))
	evaluationCount, _ := meter.Int64Counter("keptn.evaluation.count", metric.WithDescription("a simple counter for Keptn Evaluations"))
	evaluationDuration, _ := meter.Float64Histogram("keptn.evaluation.duration", metric.WithDescription("a histogram of duration for Keptn Evaluations"), metric.WithUnit("s"))

	meters := apicommon.KeptnMeters{
		TaskCount:          taskCount,
		TaskDuration:       taskDuration,
		DeploymentCount:    deploymentCount,
		DeploymentDuration: deploymentDuration,
		AppCount:           appCount,
		AppDuration:        appDuration,
		EvaluationCount:    evaluationCount,
		EvaluationDuration: evaluationDuration,
	}
	return meters
}

type TracerFactory struct {
	Tracer trace.TracerProvider
}

func (f *TracerFactory) GetTracer(name string) telemetry.ITracer {
	return f.Tracer.Tracer(name)
}

func IgnoreAlreadyExists(err error) error {
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func LogErrorIfPresent(err error) {
	if err != nil {
		GinkgoLogr.Error(err, "Something went wrong while cleaning up the test environment")
	}
}

func ResetSpanRecords(tp *otelsdk.TracerProvider, spanRecorder *sdktest.SpanRecorder) {
	GinkgoLogr.Info("Removing ", fmt.Sprint(len(spanRecorder.Ended())), " spans")
	tp.UnregisterSpanProcessor(spanRecorder)
	spanRecorder = sdktest.NewSpanRecorder()
	tp.RegisterSpanProcessor(spanRecorder)
}

func MakeKeptnDefaultNamespace(k8sClient client.Client, name string) *v1.Namespace {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	_ = k8sClient.Create(context.TODO(), ns)

	return ns
}

func DeleteAppInCluster(ctx context.Context, k8sClient client.Client, instance *klcv1beta1.KeptnApp) {
	By("Cleaning Up KeptnApp CRD ")
	err := k8sClient.Delete(ctx, instance)
	LogErrorIfPresent(err)
}

func AssertResourceUpdated(ctx context.Context, k8sClient client.Client, instance *klcv1beta1.KeptnApp) *klcv1beta1.KeptnAppVersion {

	appVersion := GetAppVersion(ctx, k8sClient, instance)

	By("Comparing expected app version")
	Expect(appVersion.Spec.AppName).To(Equal(instance.Name))
	Expect(appVersion.Spec.Version).To(Equal(instance.Spec.Version))
	Expect(appVersion.Spec.Workloads).To(Equal(instance.Spec.Workloads))

	return appVersion
}

func GetAppVersion(ctx context.Context, k8sClient client.Client, instance *klcv1beta1.KeptnApp) *klcv1beta1.KeptnAppVersion {
	appvName := types.NamespacedName{
		Namespace: instance.Namespace,
		Name:      instance.GetAppVersionName(),
	}

	appVersion := &klcv1beta1.KeptnAppVersion{}
	By("Retrieving Created app version")
	Eventually(func() error {
		return k8sClient.Get(ctx, appvName, appVersion)
	}, "20s").Should(Succeed())

	return appVersion
}

func InitSuite() (context.Context, ctrl.Manager, *otelsdk.TracerProvider, *sdktest.SpanRecorder, client.Client, chan struct{}) {
	var (
		cfg          *rest.Config
		k8sClient    client.Client
		testEnv      *envtest.Environment
		ctx          context.Context
		k8sManager   ctrl.Manager
		spanRecorder *sdktest.SpanRecorder
		tracer       *otelsdk.TracerProvider
	)

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx = context.TODO()
	By("bootstrapping test environment")

	if os.Getenv("USE_EXISTING_CLUSTER") == "true" {
		t := true
		testEnv = &envtest.Environment{
			UseExistingCluster: &t,
		}
	} else {
		GinkgoLogr.Info("Setting up fake test env")
		testEnv = &envtest.Environment{
			CRDDirectoryPaths: []string{
				filepath.Join("..", "..", "..", "config", "crd", "bases"),
				filepath.Join("..", "..", "..", "..", "metrics-operator", "config", "crd", "bases"),
			},
			ErrorIfCRDPathMissing: true,
		}
	}
	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// +kubebuilder:scaffold:scheme
	err = klcv1beta1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = metricsapi.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	readyToStart := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		<-readyToStart
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		gexec.KillAndWait(4 * time.Second)

		// Teardown the test environment once controller is finished.
		// Otherwise, from Kubernetes 1.21+, teardown timeouts waiting on
		// kube-apiserver to return
		err := testEnv.Stop()
		Expect(err).ToNot(HaveOccurred())
	}()

	By("Creating the Controller")

	spanRecorder = sdktest.NewSpanRecorder()
	tracer = otelsdk.NewTracerProvider(otelsdk.WithSpanProcessor(spanRecorder))

	return ctx, k8sManager, tracer, spanRecorder, k8sClient, readyToStart
}

func WriteReport(specReport ginkgotypes.SpecReport, f *os.File) {
	path := strings.Split(specReport.FileName(), "/")
	testFile := path[len(path)-1]
	if specReport.ContainerHierarchyTexts != nil {
		testFile = specReport.ContainerHierarchyTexts[0]
	}
	fmt.Fprintf(f, "%s %s ", testFile, specReport.LeafNodeText)
	switch specReport.State {
	case ginkgotypes.SpecStatePassed:
		fmt.Fprintf(f, "%s\n", "✓")
	case ginkgotypes.SpecStateFailed:
		fmt.Fprintf(f, "%s\n", "✕")
	default:
		fmt.Fprintf(f, "%s\n", specReport.State)
	}
}
