/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/keptn/lifecycle-toolkit/keptn-cert-manager/pkg/certificates"
	certCommon "github.com/keptn/lifecycle-toolkit/keptn-cert-manager/pkg/common"
	certwebhook "github.com/keptn/lifecycle-toolkit/keptn-cert-manager/pkg/webhook"
	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/cmd/metrics/adapter"
	analysiscontroller "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/analysis"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis"
	analysistypes "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis/types"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/providers"
	metricscontroller "github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/metrics"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/converter"
	keptnserver "github.com/keptn/lifecycle-toolkit/metrics-operator/pkg/metrics"
	analysismetrics "github.com/keptn/lifecycle-toolkit/metrics-operator/pkg/metrics/analysis"
	"github.com/open-feature/go-sdk/openfeature"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	scheme                     = runtime.NewScheme()
	setupLog                   = ctrl.Log.WithName("setup")
	metricServerTickerInterval = 10 * time.Second
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(metricsapi.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

type envConfig struct {
	PodNamespace                  string `envconfig:"POD_NAMESPACE" default:""`
	PodName                       string `envconfig:"POD_NAME" default:""`
	KeptnMetricControllerLogLevel int    `envconfig:"METRICS_CONTROLLER_LOG_LEVEL" default:"0"`
	AnalysisControllerLogLevel    int    `envconfig:"ANALYSIS_CONTROLLER_LOG_LEVEL" default:"0"`
	ExposeKeptnMetrics            bool   `envconfig:"EXPOSE_KEPTN_METRICS" default:"true"`
	EnableCustomMetricsAPIService bool   `envconfig:"ENABLE_CUSTOM_METRICS_API_SERVICE" default:"true"`
	CertManagerEnabled            bool   `envconfig:"CERT_MANAGER_ENABLED" default:"true"`
}

//nolint:gocyclo,funlen
func main() {
	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Fatalf("Failed to process env var: %s", err)
	}
	var metricsAddr string
	var SLIFilePath string
	var provider string
	var namespace string
	var SLOFilePath string
	var analysisDefinition string
	var enableLeaderElection bool
	var disableWebhook bool
	var probeAddr string
	flag.StringVar(&SLIFilePath, "convert-sli", "", "The path the the SLI file to be converted")
	flag.StringVar(&provider, "keptn-provider-name", "", "The name of KeptnMetricsProvider referenced in KeptnValueTemplates")
	flag.StringVar(&namespace, "keptn-provider-namespace", "", "The namespace of the referenced KeptnMetricsProvider")
	flag.StringVar(&SLOFilePath, "convert-slo", "", "The path the the SLO file to be converted")
	flag.StringVar(&analysisDefinition, "analysis-definition-name", "", "The name of AnalysisDefinition to be created")
	flag.StringVar(&namespace, "analysis-value-template-namespace", "", "The namespace of the referenced AnalysisValueTemplate")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&disableWebhook, "disable-webhook", false, "Disable the registration of webhooks.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if SLIFilePath != "" {
		// convert
		content, err := convertSLI(SLIFilePath, provider, namespace)
		if err != nil {
			log.Fatalf(err.Error())
			return
		}
		// write out converted result
		fmt.Print(content)
		return
	}

	if SLOFilePath != "" {
		// convert
		content, err := convertSLO(SLOFilePath, analysisDefinition, namespace)
		if err != nil {
			log.Fatalf(err.Error())
			return
		}
		// write out converted result
		fmt.Print(content)
		return
	}

	if env.EnableCustomMetricsAPIService {
		// Start the custom metrics adapter
		go startCustomMetricsAdapter(env.PodNamespace)
	}
	disableCacheFor := []ctrlclient.Object{&corev1.Secret{}}

	opt := ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		Client: ctrlclient.Options{
			Cache: &ctrlclient.CacheOptions{
				DisableFor: disableCacheFor,
			},
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "3f8532ca.keptn.sh",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}

	var webhookBuilder certwebhook.Builder
	if !disableWebhook {
		webhookBuilder = certwebhook.NewWebhookServerBuilder().
			LoadCertOptionsFromFlag().
			SetPort(9443).
			SetNamespace(env.PodNamespace).
			SetPodName(env.PodName)
		opt.WebhookServer = webhookBuilder.GetWebhookServer()
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), opt)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keptnserver.StartServerManager(ctx, mgr.GetClient(), openfeature.NewClient("keptn"), env.ExposeKeptnMetrics, metricServerTickerInterval)

	metricsLogger := ctrl.Log.WithName("KeptnMetric Controller")
	if err = (&metricscontroller.KeptnMetricReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Log:             metricsLogger.V(env.KeptnMetricControllerLogLevel),
		ProviderFactory: providers.NewProvider,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeptnMetric")
		os.Exit(1)
	}

	analysisLogger := ctrl.Log.WithName("KeptnAnalysis Controller")
	targetEval := analysis.NewTargetEvaluator(&analysis.OperatorEvaluator{})
	objEval := analysis.NewObjectiveEvaluator(&targetEval)
	analysisEval := analysis.NewAnalysisEvaluator(&objEval)

	ac := &analysiscontroller.AnalysisReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		Log:                   analysisLogger.V(env.AnalysisControllerLogLevel),
		MaxWorkers:            2,
		NewWorkersPoolFactory: analysiscontroller.NewWorkersPool,
		IAnalysisEvaluator:    &analysisEval,
	}
	if err = ac.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeptnMetric")
		os.Exit(1)
	}

	res := make(chan analysistypes.AnalysisCompletion)

	ac.SetAnalysisResultsChannel(res)

	_ = analysismetrics.GetResultsReporter(ctx, res)

	// +kubebuilder:scaffold:builder

	setupValidationWebhooks(mgr)
	setupProbes(mgr)

	if !disableWebhook {
		var certificateWatcher certificates.ICertificateWatcher

		// Check if cert manager is enabled
		if env.CertManagerEnabled {
			certificateWatcher = certificates.NewCertificateWatcher(
				mgr.GetAPIReader(),
				webhookBuilder.GetOptions().CertDir,
				env.PodNamespace,
				certCommon.SecretName,
				setupLog,
			)
		} else {
			// Use the NoOpCertificateWatcher when cert manager is disabled
			certificateWatcher = certificates.NewNoOpCertificateWatcher()
		}

		webhookBuilder = webhookBuilder.SetCertificateWatcher(certificateWatcher)
		webhookBuilder.Register(mgr, nil)
		setupLog.Info("starting webhook")
	}
	setupLog.Info("starting manager")
	setupLog.Info("Keptn metrics-operator is alive")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func setupValidationWebhooks(mgr manager.Manager) {
	if err := (&metricsapi.KeptnMetric{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "KeptnMetric")
		os.Exit(1)
	}
	if err := (&metricsapi.AnalysisDefinition{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "AnalysisDefinition")
		os.Exit(1)
	}
	if err := (&metricsapi.Analysis{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Analysis")
		os.Exit(1)
	}
}

func setupProbes(mgr manager.Manager) {

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
}

func startCustomMetricsAdapter(namespace string) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	metricsAdapter := adapter.MetricsAdapter{KeptnNamespace: namespace}
	metricsAdapter.RunAdapter(ctx)
}

func convertSLI(SLIFilePath, provider, namespace string) (string, error) {
	//read file content
	fileContent, err := os.ReadFile(SLIFilePath)
	if err != nil {
		return "", fmt.Errorf("error reading file content: %s", err.Error())
	}

	// convert
	c := converter.NewSLIConverter()
	content, err := c.Convert(fileContent, provider, namespace)
	if err != nil {
		return "", err
	}

	return content, nil
}

func convertSLO(SLOFilePath, analysisDefinition, namespace string) (string, error) {
	//read file content
	fileContent, err := os.ReadFile(SLOFilePath)
	if err != nil {
		return "", fmt.Errorf("error reading file content: %s", err.Error())
	}

	// convert
	c := converter.NewSLOConverter()
	content, err := c.Convert(fileContent, analysisDefinition, namespace)
	if err != nil {
		return "", err
	}

	return content, nil
}
