// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"log/slog"
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/util/workqueue"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	_ "github.com/cilium/cilium/pkg/hubble/metrics/dns"               // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/drop"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/flow"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/flows-to-world"    // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/http"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/icmp"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/kafka"             // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/policy"            // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/port-distribution" // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/tcp"               // invoke init
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/time"
)

type CiliumEndpointDeletionHandler struct {
	gracefulPeriod time.Duration
	queue          workqueue.TypedDelayingInterface[*types.CiliumEndpoint]
}

var (
	EnabledMetrics          []api.NamedHandler
	Registry                = prometheus.NewPedanticRegistry()
	endpointDeletionHandler *CiliumEndpointDeletionHandler
)

// Additional metrics - they're not counting flows, so are not served via
// Hubble metrics API, but belong to the same Prometheus namespace.
var (
	labelSource = "source"
	LostEvents  = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "lost_events_total",
		Help:      "Number of lost events",
	}, []string{labelSource})
)

// Metrics related to Hubble metrics HTTP requests handling
var (
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "metrics_http_handler_requests_total",
		Help:      "A counter for requests to Hubble metrics handler.",
	}, []string{"code"})
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "metrics_http_handler_request_duration_seconds",
		Help:      "A histogram of latencies of Hubble metrics handler.",
	}, []string{"code"})
)

func ProcessCiliumEndpointDeletion(pod *types.CiliumEndpoint) error {
	if endpointDeletionHandler != nil && EnabledMetrics != nil {
		endpointDeletionHandler.queue.AddAfter(pod, endpointDeletionHandler.gracefulPeriod)
	}
	return nil
}

func initEndpointDeletionHandler() {
	endpointDeletionHandler = &CiliumEndpointDeletionHandler{
		gracefulPeriod: time.Minute,
		queue:          workqueue.NewTypedDelayingQueue[*types.CiliumEndpoint](),
	}

	go func() {
		for {
			endpoint, quit := endpointDeletionHandler.queue.Get()
			if quit {
				return
			}
			api.ProcessCiliumEndpointDeletion(endpoint, EnabledMetrics)
			endpointDeletionHandler.queue.Done(endpoint)
		}
	}()
}

// InitMetrics initializes the metrics system
func InitMetrics(logger *slog.Logger, reg *prometheus.Registry, enabled *api.Config, grpcMetrics *grpc_prometheus.ServerMetrics) error {
	e, err := InitMetricHandlers(logger, reg, enabled)
	if err != nil {
		return err
	}
	EnabledMetrics = *e

	reg.MustRegister(grpcMetrics)
	reg.MustRegister(LostEvents)
	reg.MustRegister(RequestsTotal)
	reg.MustRegister(RequestDuration)

	initEndpointDeletionHandler()

	return nil
}

func InitHubbleInternalMetrics(reg *prometheus.Registry, grpcMetrics *grpc_prometheus.ServerMetrics) error {
	reg.MustRegister(grpcMetrics)
	reg.MustRegister(LostEvents)
	reg.MustRegister(RequestsTotal)
	reg.MustRegister(RequestDuration)

	initEndpointDeletionHandler()

	return nil
}

func InitMetricHandlers(logger *slog.Logger, reg *prometheus.Registry, enabled *api.Config) (*[]api.NamedHandler, error) {
	return api.DefaultRegistry().ConfigureHandlers(logger, reg, enabled)
}

func ServerHandler(reg *prometheus.Registry, enableOpenMetrics bool) http.Handler {
	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: enableOpenMetrics,
	})
	handler = promhttp.InstrumentHandlerCounter(RequestsTotal, handler)
	handler = promhttp.InstrumentHandlerDuration(RequestDuration, handler)
	mux.Handle("/metrics", handler)

	return mux
}

// FlowProcessor is an abstraction over the static and dynamic flow processors.
type FlowProcessor interface {
	// ProcessFlow processes a flow event and perform metrics accounting.
	ProcessFlow(ctx context.Context, flow *pb.Flow) error
}
