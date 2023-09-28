---
title: Define SLOs/SLIs with Analyses
description: Understand Analyses in Keptn and how to use them
weight: 91
---

The Keptn Metrics Operator implements an SLO/SLI feature set inspired by Keptn v1 under the name of Analysis.
With an Analysis Definition you can specify multiple Service Level Objectives (SLOs) that will be evaluated in your Analysis.
At the end of the Analysis the status returns whether your objective failed or passed.

The Analysis result is exposed as an OpenTelemetry metric and can be displayed on dashboard tools, such as Grafana.

Keptn v1 users may use converters for
[SLOs](https://github.com/keptn/lifecycle-toolkit/blob/main/metrics-operator/converter/slo_converter.md#slo-converter)
and [SLIs](https://github.com/keptn/lifecycle-toolkit/blob/main/metrics-operator/converter/sli_converter.md#sli-converter)
to migrate towards Keptn Analysis.

## Keptn Analysis basics

A Keptn Analysis is implemented with three resources:

* [Analysis](../../crd-ref/metrics/v1alpha3/#analysis) --
  define the specific configurations and the Analysis to report
* [AnalysisDefinition](../../crd-ref/metrics/v1alpha3/#analysisdefinition) --
  define the list of SLOs for an Analysis
* [AnalysisValueTemplate](../../crd-ref/metrics/v1alpha3/#analysisvaluetemplate) --
  define the SLI: the KeptnMetricsProvider and the query to perform for each SLI

### Define Analysis, Analysis Definition and AnalysisValueTemplate

An Analysis customizes the templates defined inside an AnalysisDefinition by adding configuration such as:

* a timeframe that specifies the range for the corresponding query in the AnalysisValueTemplate
* a map of key/value pairs that can be used to substitute placeholders in the AnalysisValueTemplate

An AnalysisDefinition contains a list of objectives to satisfy.
Each of these objectives:

* specifies failure or warning target criteria
* specifies whether the objective is a key objective (its failure would fail the Analysis)
* indicates the weight of the objective on the overall Analysis
* refers to an AnalysisValueTemplate that contains the SLIs, defining the data provider from which to gather the data
  and how to compute the Analysis

In each AnalysisValueTemplate we store the query for the Analysis of the SLI.
You must define a
[KeptnMetricsProvider](../../yaml-crd-ref/metricsprovider.md) resource
for each instance of each data provider you are using.
The template refers to that provider and queries it.

Let's consider the following Analysis:

{{< embed path="/metrics-operator/config/samples/metrics_v1alpha3_analysis.yaml" >}}

This CR sets up the timeframe we are interested in
as between 5 am and 10 am on the 5th of May 2023,
and adds a few specific key-value pairs that will be substituted in the query.
For instance, the query could contain a `{{.nodename}}` and this value will be substituted with `test`

The definition of this Analysis is referenced by its name and namespace and can be seen here:

{{< embed path="/metrics-operator/config/samples/metrics_v1alpha3_analysisdefinition.yaml" >}}

This simple definition contains a single objective, `response-time-p95`.
For this objective, there are both
failure and warning criteria:

* the objective will fail if the percentile 95 is less than 600
* there will be a warning in case the value is between 300 and 500

The total score shows that this Analysis should have an overall score of 90% to pass or 75% to get a warning.
Since the objective is only one, this means that we either will pass with 100% (response time is less than 600) or fail
with 0% (slower response time).

The objective points to the corresponding AnalysisValueTemplate:
{{< embed path="/metrics-operator/config/samples/metrics_v1alpha3_analysisvaluetemplate.yaml" >}}

This template tells us that we will query a provider called `prometheus` using this query:

```shell
 sum(kube_pod_container_resource_limits{node='{{.nodename}}'}) - sum(kube_node_status_capacity{node='{{.nodename}}'})
```

At runtime, the metrics operator will try to substitute everything in`{{.variableName}}`
format with a key-value pair in the Analysis resource,
so in this case the query would become:

```shell
 sum(kube_pod_container_resource_limits{node='test'}) - sum(kube_node_status_capacity{node='test'})
```

The other key-value pairs such as 'project' and 'stage' are just examples of how one could pass to the provider
information similar to Keptn v1 objectives.
For a working example you can
check [here](https://github.com/keptn/lifecycle-toolkit/tree/main/test/testanalysis/analysis-controller-multiple-providers).

## Accessing Analysis

### Retrieve KeptnMetric values with kubectl

Use the `kubectl get` command to retrieve all the `Analyses` in your cluster:

```shell
kubectl get analyses.metrics.keptn.sh -A

```

This will return something like

```shell
NAMESPACE   NAME              ANALYSISDEFINITION    STATE   WARNING   PASS
default     analysis-sample   ed-my-proj-dev-svc1
```

You can then describe the Analysis with:

```shell
kubectl describe analyses.metrics.keptn.sh analysis-sample -n=default
```
