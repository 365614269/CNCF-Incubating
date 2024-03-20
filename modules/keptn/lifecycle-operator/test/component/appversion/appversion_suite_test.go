package appversion_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/config"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/eventsender"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/phase"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/telemetry"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/lifecycle/keptnappversion"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/test/component/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	otelsdk "go.opentelemetry.io/otel/sdk/trace"
	sdktest "go.opentelemetry.io/otel/sdk/trace/tracetest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestAppversion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Appversion Suite")
}

var (
	k8sManager   ctrl.Manager
	tracer       *otelsdk.TracerProvider
	k8sClient    client.Client
	ctx          context.Context
	spanRecorder *sdktest.SpanRecorder
)

const (
	KeptnNamespace     = "keptnlifecycle"
	traceComponentName = "keptn/lifecycle-operator/appversion"
)

var _ = BeforeSuite(func() {
	var readyToStart chan struct{}
	ctx, k8sManager, tracer, spanRecorder, k8sClient, readyToStart = common.InitSuite()

	tracerFactory := &common.TracerFactory{Tracer: tracer}

	phaseHandler := phase.NewHandler(
		k8sManager.GetClient(),
		eventsender.NewK8sSender(k8sManager.GetEventRecorderFor("test-appversion-controller")),
		GinkgoLogr,
		&telemetry.Handler{},
	)

	config.Instance().SetDefaultNamespace(KeptnNamespace)

	// //setup controllers here
	controller := &keptnappversion.KeptnAppVersionReconciler{
		Client:        k8sManager.GetClient(),
		Scheme:        k8sManager.GetScheme(),
		EventSender:   eventsender.NewK8sSender(k8sManager.GetEventRecorderFor("test-appversion-controller")),
		Log:           GinkgoLogr,
		Meters:        common.InitKeptnMeters(),
		SpanHandler:   &telemetry.Handler{},
		TracerFactory: tracerFactory,
		PhaseHandler:  phaseHandler,
		Config:        config.Instance(),
	}
	Eventually(controller.SetupWithManager(k8sManager)).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
	close(readyToStart)
})

var _ = ReportAfterSuite("custom report", func(report Report) {
	f, err := os.Create("report.appversion-lifecycle-operator")
	Expect(err).ToNot(HaveOccurred(), "failed to generate report")
	for _, specReport := range report.SpecReports {
		common.WriteReport(specReport, f)
	}
	f.Close()
})
