// Copyright (c) The Thanos Authors.
// Licensed under the Apache License 2.0.

package main

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	extflag "github.com/efficientgo/tools/extkingpin"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/oklog/run"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/client"
	objstoretracing "github.com/thanos-io/objstore/tracing/opentracing"

	"github.com/thanos-io/thanos/pkg/block/metadata"
	"github.com/thanos-io/thanos/pkg/clientconfig"
	"github.com/thanos-io/thanos/pkg/component"
	"github.com/thanos-io/thanos/pkg/exemplars"
	"github.com/thanos-io/thanos/pkg/extkingpin"
	"github.com/thanos-io/thanos/pkg/extprom"
	"github.com/thanos-io/thanos/pkg/info"
	"github.com/thanos-io/thanos/pkg/info/infopb"
	"github.com/thanos-io/thanos/pkg/logging"
	meta "github.com/thanos-io/thanos/pkg/metadata"
	thanosmodel "github.com/thanos-io/thanos/pkg/model"
	"github.com/thanos-io/thanos/pkg/prober"
	"github.com/thanos-io/thanos/pkg/promclient"
	"github.com/thanos-io/thanos/pkg/reloader"
	"github.com/thanos-io/thanos/pkg/rules"
	"github.com/thanos-io/thanos/pkg/runutil"
	grpcserver "github.com/thanos-io/thanos/pkg/server/grpc"
	httpserver "github.com/thanos-io/thanos/pkg/server/http"
	"github.com/thanos-io/thanos/pkg/shipper"
	"github.com/thanos-io/thanos/pkg/store"
	"github.com/thanos-io/thanos/pkg/store/labelpb"
	"github.com/thanos-io/thanos/pkg/targets"
	"github.com/thanos-io/thanos/pkg/tls"
)

func registerSidecar(app *extkingpin.App) {
	cmd := app.Command(component.Sidecar.String(), "Sidecar for Prometheus server.")
	conf := &sidecarConfig{}
	conf.registerFlag(cmd)
	cmd.Setup(func(g *run.Group, logger log.Logger, reg *prometheus.Registry, tracer opentracing.Tracer, _ <-chan struct{}, _ bool) error {

		grpcLogOpts, logFilterMethods, err := logging.ParsegRPCOptions(conf.reqLogConfig)

		if err != nil {
			return errors.Wrap(err, "error while parsing config for request logging")
		}

		httpConfContentYaml, err := conf.prometheus.httpClient.Content()
		if err != nil {
			return errors.Wrap(err, "getting http client config")
		}
		httpClientConfig, err := clientconfig.NewHTTPClientConfigFromYAML(httpConfContentYaml)
		if err != nil {
			return errors.Wrap(err, "parsing http config YAML")
		}

		httpClient, err := clientconfig.NewHTTPClient(*httpClientConfig, "thanos-sidecar")
		if err != nil {
			return errors.Wrap(err, "Improper http client config")
		}

		opts := reloader.Options{
			HTTPClient:    *httpClient,
			CfgFile:       conf.reloader.confFile,
			CfgOutputFile: conf.reloader.envVarConfFile,
			WatchedDirs:   conf.reloader.ruleDirectories,
			WatchInterval: conf.reloader.watchInterval,
			RetryInterval: conf.reloader.retryInterval,
		}

		switch conf.reloader.method {
		case HTTPReloadMethod:
			opts.ReloadURL = reloader.ReloadURLFromBase(conf.prometheus.url)
		case SignalReloadMethod:
			opts.ProcessName = conf.reloader.processName
			opts.RuntimeInfoURL = reloader.RuntimeInfoURLFromBase(conf.prometheus.url)
		default:
			return fmt.Errorf("invalid reload method: %s", conf.reloader.method)
		}

		rl := reloader.New(log.With(logger, "component", "reloader"),
			extprom.WrapRegistererWithPrefix("thanos_sidecar_", reg),
			&opts)

		return runSidecar(g, logger, reg, tracer, rl, component.Sidecar, *conf, httpClient, grpcLogOpts, logFilterMethods)
	})
}

func runSidecar(
	g *run.Group,
	logger log.Logger,
	reg *prometheus.Registry,
	tracer opentracing.Tracer,
	reloader *reloader.Reloader,
	comp component.Component,
	conf sidecarConfig,
	httpClient *http.Client,
	grpcLogOpts []grpc_logging.Option,
	logFilterMethods []string,
) error {

	var m = &promMetadata{
		promURL: conf.prometheus.url,
		// Start out with the full time range. The shipper will constrain it later.
		// TODO(fabxc): minimum timestamp is never adjusted if shipping is disabled.
		mint: conf.limitMinTime.PrometheusTimestamp(),
		maxt: math.MaxInt64,

		limitMinTime: conf.limitMinTime,
		client:       promclient.NewWithTracingClient(logger, httpClient, "thanos-sidecar"),
	}

	confContentYaml, err := conf.objStore.Content()
	if err != nil {
		return errors.Wrap(err, "getting object store config")
	}

	var uploads = len(confContentYaml) != 0
	if !uploads {
		level.Info(logger).Log("msg", "no supported bucket was configured, uploads will be disabled")
	}

	grpcProbe := prober.NewGRPC()
	httpProbe := prober.NewHTTP()
	statusProber := prober.Combine(
		httpProbe,
		grpcProbe,
		prober.NewInstrumentation(comp, logger, extprom.WrapRegistererWithPrefix("thanos_", reg)),
	)

	// Setup the HTTP server.
	{
		srv := httpserver.New(logger, reg, comp, httpProbe,
			httpserver.WithListen(conf.http.bindAddress),
			httpserver.WithGracePeriod(time.Duration(conf.http.gracePeriod)),
			httpserver.WithTLSConfig(conf.http.tlsConfig),
		)

		g.Add(func() error {
			statusProber.Healthy()
			return srv.ListenAndServe()
		}, func(err error) {

			statusProber.NotReady(err)
			defer statusProber.NotHealthy(err)

			srv.Shutdown(err)
		})
	}

	// Once we have loaded external labels from prometheus we can use this to signal the servers
	// that they can start now.
	readyToStartGRPC := make(chan struct{})

	// Setup Prometheus Heartbeats.
	{
		promUp := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "thanos_sidecar_prometheus_up",
			Help: "Boolean indicator whether the sidecar can reach its Prometheus peer.",
		})

		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			// Only check Prometheus's flags when upload is enabled.
			if uploads {
				// Check prometheus's flags to ensure same sidecar flags.
				// We retry infinitely until we validated prometheus flags
				err := runutil.Retry(conf.prometheus.getConfigInterval, ctx.Done(), func() error {
					iterCtx, iterCancel := context.WithTimeout(context.Background(), conf.prometheus.getConfigTimeout)
					defer iterCancel()

					if err := validatePrometheus(iterCtx, m.client, logger, conf.shipper.ignoreBlockSize, m); err != nil {
						level.Warn(logger).Log(
							"msg", "failed to validate prometheus flags. Is Prometheus running? Retrying",
							"err", err,
						)
						return err
					}

					level.Info(logger).Log(
						"msg", "successfully validated prometheus flags",
					)
					return nil
				})
				if err != nil {
					return errors.Wrap(err, "failed to validate prometheus flags")
				}
			}

			// We retry infinitely until we reach and fetch BuildVersion from our Prometheus.
			err := runutil.Retry(conf.prometheus.getConfigInterval, ctx.Done(), func() error {
				iterCtx, iterCancel := context.WithTimeout(context.Background(), conf.prometheus.getConfigTimeout)
				defer iterCancel()

				if err := m.BuildVersion(iterCtx); err != nil {
					level.Warn(logger).Log(
						"msg", "failed to fetch prometheus version. Is Prometheus running? Retrying",
						"err", err,
					)
					return err
				}

				level.Info(logger).Log(
					"msg", "successfully loaded prometheus version",
				)
				return nil
			})
			if err != nil {
				return errors.Wrap(err, "failed to get prometheus version")
			}

			// Blocking query of external labels before joining as a Source Peer into gossip.
			// We retry infinitely until we reach and fetch labels from our Prometheus.
			err = runutil.Retry(conf.prometheus.getConfigInterval, ctx.Done(), func() error {
				iterCtx, iterCancel := context.WithTimeout(context.Background(), conf.prometheus.getConfigTimeout)
				defer iterCancel()

				if err := m.UpdateTimestamps(iterCtx); err != nil {
					level.Warn(logger).Log(
						"msg", "failed to fetch timestamps. Is Prometheus running? Retrying",
						"err", err,
					)
					return err
				}

				if err := m.UpdateLabels(iterCtx); err != nil {
					level.Warn(logger).Log(
						"msg", "failed to fetch initial external labels. Is Prometheus running? Retrying",
						"err", err,
					)
					return err
				}

				level.Info(logger).Log(
					"msg", "successfully loaded prometheus external labels",
					"external_labels", m.Labels().String(),
				)
				return nil
			})
			if err != nil {
				return errors.Wrap(err, "initial external labels query")
			}

			if m.Labels().Len() == 0 {
				return errors.New("no external labels configured on Prometheus server, uniquely identifying external labels must be configured; see https://thanos.io/tip/thanos/storage.md#external-labels for details.")
			}
			promUp.Set(1)
			statusProber.Ready()

			close(readyToStartGRPC)

			// Periodically query the Prometheus config. We use this as a heartbeat as well as for updating
			// the external labels we apply.
			return runutil.Repeat(conf.prometheus.getConfigInterval, ctx.Done(), func() error {
				iterCtx, iterCancel := context.WithTimeout(context.Background(), conf.prometheus.getConfigTimeout)
				defer iterCancel()
				if err := m.UpdateTimestamps(iterCtx); err != nil {
					level.Warn(logger).Log("msg", "updating timestamps failed", "err", err)
					promUp.Set(0)
					statusProber.NotReady(err)
					return nil
				}

				if err := m.UpdateLabels(iterCtx); err != nil {
					level.Warn(logger).Log("msg", "updating labels failed", "err", err)
					promUp.Set(0)
					statusProber.NotReady(err)
					return nil
				}
				promUp.Set(1)
				statusProber.Ready()
				return nil
			})
		}, func(error) {
			cancel()
		})
	}

	// Setup the Reloader.
	{
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			return reloader.Watch(ctx)
		}, func(error) {
			cancel()
		})
	}

	// Setup the gRPC server.
	{
		c := promclient.NewWithTracingClient(logger, httpClient, clientconfig.ThanosUserAgent)

		promStore, err := store.NewPrometheusStore(logger, reg, c, conf.prometheus.url, component.Sidecar, m.Labels, m.Timestamps, m.Version)
		if err != nil {
			return errors.Wrap(err, "create Prometheus store")
		}

		tlsCfg, err := tls.NewServerConfig(log.With(logger, "protocol", "gRPC"),
			conf.grpc.tlsSrvCert, conf.grpc.tlsSrvKey, conf.grpc.tlsSrvClientCA, conf.grpc.tlsMinVersion)
		if err != nil {
			return errors.Wrap(err, "setup gRPC server")
		}

		exemplarSrv := exemplars.NewPrometheus(conf.prometheus.url, c, m.Labels)

		infoSrv := info.NewInfoServer(
			component.Sidecar.String(),
			info.WithLabelSetFunc(func() []labelpb.ZLabelSet {
				return promStore.LabelSet()
			}),
			info.WithStoreInfoFunc(func() (*infopb.StoreInfo, error) {
				if httpProbe.IsReady() {
					mint, maxt := m.Timestamps()
					return &infopb.StoreInfo{
						MinTime:                      mint,
						MaxTime:                      maxt,
						SupportsSharding:             true,
						SupportsWithoutReplicaLabels: true,
						TsdbInfos:                    promStore.TSDBInfos(),
					}, nil
				}
				return nil, errors.New("Not ready")
			}),
			info.WithExemplarsInfoFunc(),
			info.WithRulesInfoFunc(),
			info.WithTargetsInfoFunc(),
			info.WithMetricMetadataInfoFunc(),
		)

		storeServer := store.NewLimitedStoreServer(store.NewInstrumentedStoreServer(reg, promStore), reg, conf.storeRateLimits)
		s := grpcserver.New(logger, reg, tracer, grpcLogOpts, logFilterMethods, comp, grpcProbe,
			grpcserver.WithServer(store.RegisterStoreServer(storeServer, logger)),
			grpcserver.WithServer(rules.RegisterRulesServer(rules.NewPrometheus(conf.prometheus.url, c, m.Labels))),
			grpcserver.WithServer(targets.RegisterTargetsServer(targets.NewPrometheus(conf.prometheus.url, c, m.Labels))),
			grpcserver.WithServer(meta.RegisterMetadataServer(meta.NewPrometheus(conf.prometheus.url, c))),
			grpcserver.WithServer(exemplars.RegisterExemplarsServer(exemplarSrv)),
			grpcserver.WithServer(info.RegisterInfoServer(infoSrv)),
			grpcserver.WithListen(conf.grpc.bindAddress),
			grpcserver.WithGracePeriod(conf.grpc.gracePeriod),
			grpcserver.WithMaxConnAge(conf.grpc.maxConnectionAge),
			grpcserver.WithTLSConfig(tlsCfg),
		)

		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-readyToStartGRPC:
			}

			statusProber.Ready()
			return s.ListenAndServe()
		}, func(err error) {
			cancel()
			statusProber.NotReady(err)
			s.Shutdown(err)
		})
	}
	if uploads {
		// The background shipper continuously scans the data directory and uploads
		// new blocks to Google Cloud Storage or an S3-compatible storage service.
		bkt, err := client.NewBucket(logger, confContentYaml, component.Sidecar.String(), nil)
		if err != nil {
			return err
		}
		bkt = objstoretracing.WrapWithTraces(objstore.WrapWithMetrics(bkt, extprom.WrapRegistererWithPrefix("thanos_", reg), bkt.Name()))

		// Ensure we close up everything properly.
		defer func() {
			if err != nil {
				runutil.CloseWithLogOnErr(logger, bkt, "bucket client")
			}
		}()

		if err := promclient.IsWALDirAccessible(conf.tsdb.path); err != nil {
			level.Error(logger).Log("err", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			defer runutil.CloseWithLogOnErr(logger, bkt, "bucket client")

			promReadyTimeout := conf.prometheus.readyTimeout
			extLabelsCtx, cancel := context.WithTimeout(ctx, promReadyTimeout)
			defer cancel()

			if err := runutil.Retry(2*time.Second, extLabelsCtx.Done(), func() error {
				if m.Labels().Len() == 0 {
					return errors.New("not uploading as no external labels are configured yet - is Prometheus healthy/reachable?")
				}
				return nil
			}); err != nil {
				return errors.Wrapf(err, "aborting as no external labels found after waiting %s", promReadyTimeout)
			}

			s := shipper.New(
				bkt,
				conf.tsdb.path,
				shipper.WithLogger(logger),
				shipper.WithRegisterer(reg),
				shipper.WithSource(metadata.SidecarSource),
				shipper.WithHashFunc(metadata.HashFunc(conf.shipper.hashFunc)),
				shipper.WithMetaFileName(conf.shipper.metaFileName),
				shipper.WithLabels(m.Labels),
				shipper.WithUploadCompacted(conf.shipper.uploadCompacted),
				shipper.WithAllowOutOfOrderUploads(conf.shipper.allowOutOfOrderUpload),
				shipper.WithSkipCorruptedBlocks(conf.shipper.skipCorruptedBlocks),
			)

			return runutil.Repeat(30*time.Second, ctx.Done(), func() error {
				if uploaded, err := s.Sync(ctx); err != nil {
					level.Warn(logger).Log("err", err, "uploaded", uploaded)
				}
				return nil
			})
		}, func(error) {
			cancel()
		})
	}

	level.Info(logger).Log("msg", "starting sidecar")
	return nil
}

func validatePrometheus(ctx context.Context, client *promclient.Client, logger log.Logger, ignoreBlockSize bool, m *promMetadata) error {
	var (
		flagErr error
		flags   promclient.Flags
	)

	if err := runutil.Retry(2*time.Second, ctx.Done(), func() error {
		if flags, flagErr = client.ConfiguredFlags(ctx, m.promURL); flagErr != nil && flagErr != promclient.ErrFlagEndpointNotFound {
			level.Warn(logger).Log("msg", "failed to get Prometheus flags. Is Prometheus running? Retrying", "err", flagErr)
			return errors.Wrapf(flagErr, "fetch Prometheus flags")
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "fetch Prometheus flags")
	}

	if flagErr != nil {
		level.Warn(logger).Log("msg", "failed to check Prometheus flags, due to potentially older Prometheus. No extra validation is done.", "err", flagErr)
		return nil
	}

	// Check if compaction is disabled.
	if flags.TSDBMinTime != flags.TSDBMaxTime {
		if !ignoreBlockSize {
			return errors.Errorf("found that TSDB Max time is %s and Min time is %s. "+
				"Compaction needs to be disabled (storage.tsdb.min-block-duration = storage.tsdb.max-block-duration)", flags.TSDBMaxTime, flags.TSDBMinTime)
		}
		level.Warn(logger).Log("msg", "flag to ignore Prometheus min/max block duration flags differing is being used. If the upload of a 2h block fails and a Prometheus compaction happens that block may be missing from your Thanos bucket storage.")
	}
	// Check if block time is 2h.
	if flags.TSDBMinTime != model.Duration(2*time.Hour) {
		level.Warn(logger).Log("msg", "found that TSDB block time is not 2h. Only 2h block time is recommended.", "block-time", flags.TSDBMinTime)
	}

	return nil
}

type promMetadata struct {
	promURL *url.URL

	mtx          sync.Mutex
	mint         int64
	maxt         int64
	labels       labels.Labels
	promVersion  string
	limitMinTime thanosmodel.TimeOrDurationValue

	client *promclient.Client
}

func (s *promMetadata) UpdateLabels(ctx context.Context) error {
	elset, err := s.client.ExternalLabels(ctx, s.promURL)
	if err != nil {
		return err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.labels = elset
	return nil
}

func (s *promMetadata) UpdateTimestamps(ctx context.Context) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	mint, err := s.client.LowestTimestamp(ctx, s.promURL)
	if err != nil {
		return err
	}

	s.mint = max(s.limitMinTime.PrometheusTimestamp(), mint)
	s.maxt = math.MaxInt64

	return nil
}

func (s *promMetadata) Labels() labels.Labels {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.labels
}

func (s *promMetadata) Timestamps() (mint, maxt int64) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.mint, s.maxt
}

func (s *promMetadata) BuildVersion(ctx context.Context) error {
	ver, err := s.client.BuildVersion(ctx, s.promURL)
	if err != nil {
		return err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.promVersion = ver
	return nil
}

func (s *promMetadata) Version() string {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.promVersion
}

type sidecarConfig struct {
	http            httpConfig
	grpc            grpcConfig
	prometheus      prometheusConfig
	tsdb            tsdbConfig
	reloader        reloaderConfig
	reqLogConfig    *extflag.PathOrContent
	objStore        extflag.PathOrContent
	shipper         shipperConfig
	limitMinTime    thanosmodel.TimeOrDurationValue
	storeRateLimits store.SeriesSelectLimits
}

func (sc *sidecarConfig) registerFlag(cmd extkingpin.FlagClause) {
	sc.http.registerFlag(cmd)
	sc.grpc.registerFlag(cmd)
	sc.prometheus.registerFlag(cmd)
	sc.tsdb.registerFlag(cmd)
	sc.reloader.registerFlag(cmd)
	sc.reqLogConfig = extkingpin.RegisterRequestLoggingFlags(cmd)
	sc.objStore = *extkingpin.RegisterCommonObjStoreFlags(cmd, "", false)
	sc.shipper.registerFlag(cmd)
	sc.storeRateLimits.RegisterFlags(cmd)
	cmd.Flag("min-time", "Start of time range limit to serve. Thanos sidecar will serve only metrics, which happened later than this value. Option can be a constant time in RFC3339 format or time duration relative to current time, such as -1d or 2h45m. Valid duration units are ms, s, m, h, d, w, y.").
		Default("0000-01-01T00:00:00Z").SetValue(&sc.limitMinTime)
}
