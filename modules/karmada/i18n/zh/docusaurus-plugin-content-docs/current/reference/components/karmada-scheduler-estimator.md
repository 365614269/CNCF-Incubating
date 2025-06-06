---
title: karmada-scheduler-estimator
---



### Synopsis

The karmada-scheduler-estimator runs an accurate scheduler estimator of a cluster. It 
provides the scheduler with more accurate cluster resource information.

```
karmada-scheduler-estimator [flags]
```

### Options

```
      --add_dir_header                     If true, adds the file directory to the header of the log messages
      --alsologtostderr                    log to standard error as well as files (no effect when -logtostderr=true)
      --cluster-name string                Name of member cluster that the estimator serves for.
      --enable-pprof                       Enable profiling via web interface host:port/debug/pprof/.
      --feature-gates mapStringBool        A set of key=value pairs that describe feature gates for alpha/experimental features. Options are:
                                           AllAlpha=true|false (ALPHA - default=false)
                                           AllBeta=true|false (BETA - default=false)
                                           CustomizedClusterResourceModeling=true|false (BETA - default=true)
                                           Failover=true|false (BETA - default=false)
                                           FederatedQuotaEnforcement=true|false (ALPHA - default=false)
                                           GracefulEviction=true|false (BETA - default=true)
                                           MultiClusterService=true|false (ALPHA - default=false)
                                           PriorityBasedScheduling=true|false (ALPHA - default=false)
                                           PropagateDeps=true|false (BETA - default=true)
                                           PropagationPolicyPreemption=true|false (ALPHA - default=false)
                                           ResourceQuotaEstimate=true|false (ALPHA - default=false)
                                           StatefulFailoverInjection=true|false (ALPHA - default=false)
      --grpc-auth-cert-file string         SSL certification file used for grpc SSL/TLS connections.
      --grpc-auth-key-file string          SSL key file used for grpc SSL/TLS connections.
      --grpc-client-ca-file string         SSL Certificate Authority file used to verify grpc client certificates on incoming requests.
      --health-probe-bind-address string   The TCP address that the server should bind to for serving health probes(e.g. 127.0.0.1:10351, :10351). It can be set to "0" to disable serving the health probe. Defaults to 0.0.0.0:10351. (default ":10351")
  -h, --help                               help for karmada-scheduler-estimator
      --insecure-skip-grpc-client-verify   If set to true, the estimator will not verify the grpc client's certificate chain and host name. When the relevant certificates are not configured, it will not take effect.
      --kube-api-burst int                 Burst to use while talking with apiserver. (default 30)
      --kube-api-qps float32               QPS to use while talking with apiserver. (default 20)
      --kubeconfig string                  Path to member cluster's kubeconfig file.
      --log_backtrace_at traceLocation     when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                     If non-empty, write log files in this directory (no effect when -logtostderr=true)
      --log_file string                    If non-empty, use this log file (no effect when -logtostderr=true)
      --log_file_max_size uint             Defines the maximum size a log file can grow to (no effect when -logtostderr=true). Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                        log to standard error instead of files (default true)
      --master string                      The address of the member Kubernetes API server. Overrides any value in KubeConfig. Only required if out-of-cluster.
      --metrics-bind-address string        The TCP address that the server should bind to for serving prometheus metrics(e.g. 127.0.0.1:8080, :8080). It can be set to "0" to disable the metrics serving. Defaults to 0.0.0.0:8080. (default ":8080")
      --one_output                         If true, only write logs to their native severity level (vs also writing to each lower severity level; no effect when -logtostderr=true)
      --parallelism int                    Parallelism defines the amount of parallelism in algorithms for estimating. Must be greater than 0. Defaults to 16.
      --profiling-bind-address string      The TCP address for serving profiling(e.g. 127.0.0.1:6060, :6060). This is only applicable if profiling is enabled. (default ":6060")
      --server-port int                    The secure port on which to serve gRPC. (default 10352)
      --skip_headers                       If true, avoid header prefixes in the log messages
      --skip_log_headers                   If true, avoid headers when opening log files (no effect when -logtostderr=true)
      --stderrthreshold severity           logs at or above this threshold go to stderr when writing to files and stderr (no effect when -logtostderr=true or -alsologtostderr=true) (default 2)
  -v, --v Level                            number for the log level verbosity
      --vmodule moduleSpec                 comma-separated list of pattern=N settings for file-filtered logging
```

###### Auto generated by [spf13/cobra script in Karmada](https://github.com/karmada-io/karmada/tree/master/hack/tools/gencomponentdocs)