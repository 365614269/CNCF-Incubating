---
comments: true
---

# Keptn Metrics

The Keptn metrics component
allows you to define any type of metric
from multiple instances
of any type of data source in your Kubernetes cluster.
You may have deployment tools like Argo, Flux, KEDA, HPA, or Keptn
that need observability data to make automated decisions
such as whether a rollout is good, or whether to scale up or down.

Your observability data may come
from multiple observability solutions --
Prometheus, Dynatrace, Datadog and others --
or may be data that comes directly
from your cloud provider such as AWS, Google, or Azure.
The Keptn Metrics Server unifies and standardizes access to all this data.
Minimal configuration is required
because Keptn hooks directly into Kubernetes primitives.

The
[Kubernetes metric server](https://github.com/kubernetes-sigs/metrics-server)
requires that you maintain point-to-point integrations
from Argo Rollouts, Flux, KEDA, and HPA.
Each has plugins but it is difficult to maintain them,
especially if you are using multiple tools,
and multiple observability platforms,
and multiple instances of some tools or observability platforms.
The Keptn metrics feature unites all these metrics
integrates metrics from all these sources into a single set of metrics.

## Using this exercise

This exercise is based on the
[simplenode-dev](https://github.com/keptn-sandbox/klt-on-k3s-with-argocd)
example.
You can clone that repo to access it locally
or just look at it for examples
as you implement the functionality "from scratch"
on your local Kubernetes deployment cluster.

The steps to implement metrics in an existing cluster are:

1. [Install Keptn](../installation/index.md)
1. Configure the metrics you want to use:
   - [Define metrics providers](#define-metrics-providers)
   - [Define KeptnMetric information](#define-keptnmetric-information)

If you want to create your own cluster to run this exercise,
follow the instructions in [Installation](../installation/index.md).

## Define metrics to use

You need to define the external observability platforms
from which you want to pull data
and then the specific data you want to pull.
This data is pulled and fetched continuously
at an interval you specify for each specific bit of data.
Data is available through the resource and through the data provider itself,
as well as the Kubernetes CLI.

### Define metrics providers

Populate a
[KeptnMetricsProvider](../reference/crd-reference/metricsprovider.md)
resource for each external observability platform you want to use.

For our example, we define two observability platforms:

- `dev-prometheus`
- `dev-dynatrace`

You can specify a virtually unlimited number of providers,
including multiple instances of each observability platform.
Each one must be assigned a unique name,
identified by the type of platform it is
and the URL of the target server.
If the target server is protected by a Secret,
provide information about the token and key.

The [keptn-metrics-provider.yaml](../reference/crd-reference/metricsprovider.md#examples)
file for our example looks like:

```yaml
{% include "./assets/metric-providers.yaml" %}
```

### Define KeptnMetric information

The [KeptnMetric](../reference/crd-reference/metric.md) resource
defines the information you want to gather,
specified as a query for the particular observability platform
you are using.
You can define any type of metric from any data source.

In our example, we define two bits of information to retrieve:

- Number of CPUs, derived from the `dev-prometheus` data platform
- `availability` SLO, derived from the `dev-dynatrace` data platform

Each of these are configured to fetch data every 10 seconds
but you could configure a different `fetchIntervalSeconds` value
for each metric.

The
[keptn-metric.yaml](https://github.com/keptn-sandbox/klt-on-k3s-with-argocd/blob/main/simplenode-dev/keptn-metric.yaml)
file for our example looks like:

```yaml
{% include "./assets/metric.yaml" %}
```

Note the following:

- Populate one YAML file per metric
  then apply all of them.
- Each metric is assigned a unique `name`.
- The value of the `spec.provider.name` field
  must correspond to the name assigned in
  the `metadata.name` field of a `KeptnMetricsProvider` resource.
- Information is fetched in on a continuous basis
  at a rate specified
  by the value of the `spec.fetchIntervalSeconds` field.

### View available metrics

Use the following command to view
the metrics that are configured in your cluster.
This example displays the two metrics we configured above:

```shell
kubectl get KeptnMetrics -A
```

```shell
NAMESPACE       NAME              PROVIDER       QUERY
simplenode-dev  availability-slo  dev-dynatrace  func:slo.availability_simplenodeservice
simplenode-dev  available-cpus    dev-prometheus sum(kube_node_status_capacity{resource=`cpu`})
```

## Run the metrics

As soon as you define your `KeptnMetricsProvider` and `KeptnMetric` resources,
Keptn begins collecting the metrics you defined.
You do not need to do anything else.

## Observing the metrics

The metrics can be retrieved
through CRs and through the Kubernetes Metric API.

The syntax to retrieve metrics from the CR is:

```shell
kubectl get keptnmetrics.metrics.keptn.sh -n <namespace> <metric-name>
```

For example, the output for the `available-cpus` metric looks like:

```shell
$ kubectl get keptnmetrics.metrics.keptn.sh -n simplenode-dev available-cpus

NAME             PROVIDER     QUERY                                           VALUE
cpu-throttling   my-provider  sum(kube_node_status_capacity{resource=`cpu`})   6.000
```

The syntax to retrieve metrics through the Kubernetes API  is:

```yaml
kubectl get --raw "/apis/custom.metrics.k8s.io/v1beta2/namespaces/<namespace>/keptnmetrics.metrics.sh/<metric-name>/<metric-name>"
```

For example, the output for the `available-cpus` looks like:

```yaml
$ kubectl get --raw "/apis/custom.metrics.k8s.io/v1beta2/namespaces/simplenode-dev/keptnmetrics.metrics.sh/available-cpus/available-cpus"

{
  "kind": "MetricValueList",
  "apiVersion": "custom.metrics.k8s.io/v1beta2",
  "metadata": {},
  "items": [
    {
      "describedObject": {
        "kind": "KeptnMetric",
        "namespace": "simplenode-dev",
        "name": "available-cpus",
        "apiVersion": "metrics.keptn.sh/v1beta1"
      },
      "metric": {
        "name": "available-cpus",
        "selector": {}
      },
      "timestamp": "2023-05-11T08:05:36Z",
      "value": "6"
    }
  ]
}
```

You can also display the metrics graphically using a dashboard such as Grafana.

## Implementing autoscaling with HPA

The Kubernetes HorizontalPodAutoscaler (HPA)
uses metrics to provide autoscaling for the cluster.
HPA can retrieve KeptnMetrics and use those metrics to implement HPA.
See
Using the [HorizontalPodAutoscaler](../use-cases/hpa.md)
for detailed information.

## Learn more

To learn more about the Keptn Metrics Server, see:

- Architecture:
  [Keptn Metrics Operator](../components/metrics-operator.md)
- More information about implementing Keptn Metrics:
  [Keptn Metrics](../guides/evaluatemetrics.md)
