package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/controller/operators/validatingroundtripper"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/metadata"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/operator-framework/operator-lifecycle-manager/pkg/api/client/clientset/versioned"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/controller/operators/olm"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/controller/operators/openshift"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/feature"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/lib/operatorclient"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/lib/operatorstatus"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/lib/queueinformer"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/lib/server"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/lib/signals"
	"github.com/operator-framework/operator-lifecycle-manager/pkg/metrics"
	olmversion "github.com/operator-framework/operator-lifecycle-manager/pkg/version"
)

const (
	defaultWakeupInterval          = 5 * time.Minute
	defaultOperatorName            = ""
	defaultPackageServerStatusName = ""
)

// config flags defined globally so that they appear on the test binary as well
var (
	wakeupInterval = pflag.Duration(
		"interval", defaultWakeupInterval, "wake up interval")

	watchedNamespaces = pflag.String(
		"watchedNamespaces", "", "comma separated list of namespaces for olm operator to watch. "+
			"If not set, or set to the empty string (e.g. `-watchedNamespaces=\"\"`), "+
			"olm operator will watch all namespaces in the cluster.")

	writeStatusName = pflag.String(
		"writeStatusName", defaultOperatorName, "ClusterOperator name in which to write status, set to \"\" to disable.")

	writePackageServerStatusName = pflag.String(
		"writePackageServerStatusName", defaultPackageServerStatusName, "ClusterOperator name in which to write status for package API server, set to \"\" to disable.")

	debug = pflag.Bool(
		"debug", false, "use debug log level")

	version = pflag.Bool("version", false, "displays olm version")

	tlsKeyPath = pflag.String(
		"tls-key", "", "Path to use for private key (requires tls-cert)")

	protectedCopiedCSVNamespaces = pflag.String("protectedCopiedCSVNamespaces",
		"", "A comma-delimited set of namespaces where global Copied CSVs will always appear, even if Copied CSVs are disabled")

	tlsCertPath = pflag.String(
		"tls-cert", "", "Path to use for certificate key (requires tls-key)")

	_ = pflag.Bool("profiling", false, "deprecated")

	clientCAPath = pflag.String("client-ca", "", "path to watch for client ca bundle")

	namespace = pflag.String(
		"namespace", "", "namespace where cleanup runs")
)

func init() {
	metrics.RegisterOLM()

	// Add feature gates before parsing
	feature.AddFlag(pflag.CommandLine)
}

// main function - entrypoint to OLM operator
func main() {
	// Get exit signal context
	ctx, cancel := context.WithCancel(signals.Context())
	defer cancel()

	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)

	pflag.Parse()

	// Parse the command-line flags.

	// Check if version flag was set
	if *version {
		fmt.Print(olmversion.String())

		// Exit early
		os.Exit(0)
	}

	// `namespaces` will always contain at least one entry: if `*watchedNamespaces` is
	// the empty string, the resulting array will be `[]string{""}`.
	namespaces := strings.Split(*watchedNamespaces, ",")
	for _, ns := range namespaces {
		if ns == corev1.NamespaceAll {
			namespaces = []string{corev1.NamespaceAll}
			break
		}
	}

	// Set log level to debug if `debug` flag set
	logger := logrus.New()
	if *debug {
		logger.SetLevel(logrus.DebugLevel)
		klogVerbosity := klogFlags.Lookup("v")
		klogVerbosity.Value.Set("99")
	}
	logger.Infof("log level %s", logger.Level)

	listenAndServe, err := server.GetListenAndServeFunc(server.WithLogger(logger), server.WithTLS(tlsCertPath, tlsKeyPath, clientCAPath), server.WithDebug(*debug))
	if err != nil {
		logger.Fatalf("Error setting up health/metric/pprof service: %v", err)
	}

	go func() {
		if err := listenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(err)
		}
	}()

	mgr, err := Manager(ctx, *debug)
	if err != nil {
		logger.WithError(err).Fatal("error configuring controller manager")
	}
	config := mgr.GetConfig()

	// create a config that validates we're creating objects with labels
	validatingConfig := validatingroundtripper.Wrap(config, mgr.GetScheme())

	versionedConfigClient, err := configclientset.NewForConfig(config)
	if err != nil {
		logger.WithError(err).Fatal("error configuring openshift proxy client")
	}
	configClient, err := configv1client.NewForConfig(config)
	if err != nil {
		logger.WithError(err).Fatal("error configuring config client")
	}
	opClient, err := operatorclient.NewClientFromRestConfig(validatingConfig)
	if err != nil {
		logger.WithError(err).Fatal("error configuring operator client")
	}
	crClient, err := versioned.NewForConfig(config)
	if err != nil {
		logger.WithError(err).Fatal("error configuring custom resource client")
	}
	metadataClient, err := metadata.NewForConfig(config)
	if err != nil {
		logger.WithError(err).Fatal("error configuring metadata client")
	}

	// Create a new instance of the operator.
	op, err := olm.NewOperator(
		ctx,
		olm.WithLogger(logger),
		olm.WithWatchedNamespaces(namespaces...),
		olm.WithResyncPeriod(queueinformer.ResyncWithJitter(*wakeupInterval, 0.2)),
		olm.WithExternalClient(crClient),
		olm.WithMetadataClient(metadataClient),
		olm.WithOperatorClient(opClient),
		olm.WithRestConfig(validatingConfig),
		olm.WithConfigClient(versionedConfigClient),
		olm.WithProtectedCopiedCSVNamespaces(*protectedCopiedCSVNamespaces),
	)
	if err != nil {
		logger.WithError(err).Fatal("error configuring operator")
		return
	}

	op.Run(ctx)
	<-op.Ready()

	// Emit CSV metric
	if err = op.EnsureCSVMetric(); err != nil {
		logger.WithError(err).Fatal("error emitting metrics for existing CSV")
	}

	if *writeStatusName != "" {
		reconciler, err := openshift.NewClusterOperatorReconciler(
			openshift.WithClient(mgr.GetClient()),
			openshift.WithScheme(mgr.GetScheme()),
			openshift.WithLog(ctrl.Log.WithName("controllers").WithName("clusteroperator")),
			openshift.WithName(*writeStatusName),
			openshift.WithNamespace(*namespace),
			openshift.WithSyncChannel(op.AtLevel()),
			openshift.WithOLMOperator(),
		)
		if err != nil {
			logger.WithError(err).Fatal("error configuring openshift integration")
			return
		}

		if err := reconciler.SetupWithManager(mgr); err != nil {
			logger.WithError(err).Fatal("error configuring openshift integration")
			return
		}
	}

	if *writePackageServerStatusName != "" {
		logger.Info("Initializing cluster operator monitor for package server")

		names := *writePackageServerStatusName
		discovery := opClient.KubernetesInterface().Discovery()
		monitor, sender := operatorstatus.NewMonitor(logger, discovery, configClient, names)

		handler := operatorstatus.NewCSVWatchNotificationHandler(logger, op.GetCSVSetGenerator(), op.GetReplaceFinder(), sender)
		op.RegisterCSVWatchNotification(handler)

		go monitor.Run(op.Done())
	}

	// Start the controller manager
	if err := mgr.Start(ctx); err != nil {
		logger.WithError(err).Fatal("controller manager stopped")
	}

	<-op.Done()
}
