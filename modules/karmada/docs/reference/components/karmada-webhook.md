---
title: karmada-webhook
---



### Synopsis

The karmada-webhook starts a webhook server and manages policies about how to mutate and validate
Karmada resources including 'PropagationPolicy', 'OverridePolicy' and so on.

```
karmada-webhook [flags]
```

### Options

```
      --add_dir_header                     If true, adds the file directory to the header of the log messages
      --allow-no-execute-taint-policy      Allows configuring taints with NoExecute effect in ClusterTaintPolicy. Given the impact of NoExecute, applying such a taint to a cluster may trigger the eviction of workloads that do not explicitly tolerate it, potentially causing unexpected service disruptions. 
                                           This parameter is designed to remain disabled by default and requires careful evaluation by administrators before being enabled.
      --alsologtostderr                    log to standard error as well as files (no effect when -logtostderr=true)
      --bind-address string                The IP address on which to listen for the --secure-port port. (default "0.0.0.0")
      --cert-dir string                    The directory that contains the server key and certificate. (default "/tmp/k8s-webhook-server/serving-certs")
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
      --health-probe-bind-address string   The TCP address that the controller should bind to for serving health probes(e.g. 127.0.0.1:8000, :8000) (default ":8000")
  -h, --help                               help for karmada-webhook
      --kube-api-burst int                 Burst to use while talking with karmada-apiserver. (default 60)
      --kube-api-qps float32               QPS to use while talking with karmada-apiserver. (default 40)
      --kubeconfig string                  Path to karmada control plane kubeconfig file.
      --log_backtrace_at traceLocation     when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                     If non-empty, write log files in this directory (no effect when -logtostderr=true)
      --log_file string                    If non-empty, use this log file (no effect when -logtostderr=true)
      --log_file_max_size uint             Defines the maximum size a log file can grow to (no effect when -logtostderr=true). Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
      --logtostderr                        log to standard error instead of files (default true)
      --metrics-bind-address string        The TCP address that the controller should bind to for serving prometheus metrics(e.g. 127.0.0.1:8080, :8080). It can be set to "0" to disable the metrics serving. (default ":8080")
      --one_output                         If true, only write logs to their native severity level (vs also writing to each lower severity level; no effect when -logtostderr=true)
      --profiling-bind-address string      The TCP address for serving profiling(e.g. 127.0.0.1:6060, :6060). This is only applicable if profiling is enabled. (default ":6060")
      --secure-port int                    The secure port on which to serve HTTPS. (default 8443)
      --skip_headers                       If true, avoid header prefixes in the log messages
      --skip_log_headers                   If true, avoid headers when opening log files (no effect when -logtostderr=true)
      --stderrthreshold severity           logs at or above this threshold go to stderr when writing to files and stderr (no effect when -logtostderr=true or -alsologtostderr=true) (default 2)
      --tls-cert-file-name string          The name of server certificate. (default "tls.crt")
      --tls-min-version string             Minimum TLS version supported. Possible values: 1.0, 1.1, 1.2, 1.3. (default "1.3")
      --tls-private-key-file-name string   The name of server key. (default "tls.key")
  -v, --v Level                            number for the log level verbosity
      --vmodule moduleSpec                 comma-separated list of pattern=N settings for file-filtered logging
```

###### Auto generated by [spf13/cobra script in Karmada](https://github.com/karmada-io/karmada/tree/master/hack/tools/gencomponentdocs)