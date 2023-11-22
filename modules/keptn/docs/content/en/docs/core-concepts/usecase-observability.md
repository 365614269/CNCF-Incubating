---
title: Standardize observability
description: How Keptn standardizes access to observability data for Kubernetes deployments
weight: 10
---

Keptn makes any Kubernetes deployment observable.
In other words, it creates a distributed, end-to-end trace
of everything Kubernetes does in the context of a Deployment.
It provides this information
for all applications running in your cluster,
and includes information about
everything Kubernetes does in the context of a deployment.
To do this,
Keptn introduces the concept of an `application`,
which is an abstraction that connects multiple
workloads that logically belong together,
even if they use different deployment strategies.

This means that:

- You can readily see why a deployment takes so long
  or why it fails, even when using multiple deployment strategies.
- Keptn can capture DORA metrics and expose them as OpenTelemetry metrics

The observability data is an amalgamation of the following:

- DORA metrics are collected out of the box when Keptn is enabled
- OpenTelemetry runs traces that show
  everything that happens in the Kubernetes cluster
- Custom Keptn metrics that you can use to monitor
  information from all the data providers configured in your cluster

All this information can be displayed with dashboard tools
such as Grafana.

## Using this exercise

This exercise shows how to standardize access
to the observability data for your cluster.
It is based on the
[simplenode-dev](https://github.com/keptn-sandbox/klt-on-k3s-with-argocd)
example.

This is the second of three exercises in the
[Introducing Keptn](_index.md)
series:

- In the
  [Getting started with Keptn metrics](../getting-started/metrics.md)
  exercise, you learn how to define and use Keptn metrics.
  You may want to complete that exercise before doing this exercise
  although that is not required.
- In
  [Manage release lifecycle](usecase-orchestrate.md),
  you learn how to implement
  pre- and post-deployment tasks and evaluations
  to orchestrate the flow of all the [workloads](https://kubernetes.io/docs/concepts/workloads/)
  that are part of your `application`.

This exercise shows how to standardize access
to the observability data for your cluster.

If you are installing Keptn on an existing cluster
or on a local cluster you are creating for this exercise,
you need to do the following:

1. Follow the instructions in
   [Install and update](../installation)
   to install and enable Keptn on your cluster.
1. Follow the instructions in
   [Basic annotations](../guides/integrate.md#basic-annotations)
   to integrate Keptn into your Kubernetes cluster
   by applying basic annotations
   to your [workload](https://kubernetes.io/docs/concepts/workloads/) resources.
   and to create appropriate
   [KeptnApp](../reference/crd-reference/app.md)
   resources that aggregate
   all the [workloads](https://kubernetes.io/docs/concepts/workloads/) for a logical deployment into a single resource.

## DORA metrics

DORA metrics are an industry-standard set of measurements
about your deployments.

Keptn starts collecting these metrics
as soon as you annotate the `Deployment` resource.
See
[DORA metrics](../guides/dora.md)
for more details.

## Using OpenTelemetry

Keptn extends the Kubernetes
primitives to create OpenTelemetry data
that connects all your deployment and observability tools
without worrying about where it is stored and where it is managed.
OpenTelemetry traces collect data as Kubernetes is deploying the changes,
which allows you to trace everything done in the context of that deployment.

- You must have an OpenTelemetry collector installed on your cluster.
  See
  [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
  for more information.
- Follow the instructions in
  [OpenTelemetry observability](../guides/otel.md)
  to configure where your OpenTelemetry data is sent.
  This requires you to define a [KeptnConfig](../reference/crd-reference/config.md) resource
  that defines the URL and port of the OpenTelemetry collector.
  For our example, this is in the
  [keptnconfig.yaml](https://github.com/keptn-sandbox/klt-on-k3s-with-argocd/blob/main/setup/keptn/keptnconfig.yaml)
  file.

## Keptn metrics

You can supplement the DORA Metrics and OpenTelemetry information
with information you explicitly define using Keptn metrics.
The
[Getting started with Keptn metrics](../getting-started/metrics.md)
exercise discusses how to define Keptn metrics.

## View the results

To start feeding observability data for your deployments
onto a dashboard of your choice:

1. Modify either your `Deployment` or `KeptnApp` resource yaml file
   to increment the version number
1. Commit that change to your repository.

Note that, from the `KeptnApp` YAML file,
you can either increment the version number of the application
(which causes all [workloads](https://kubernetes.io/docs/concepts/workloads/) to be rerun and produce observability data)
or you can increment the version number of a single [workload](https://kubernetes.io/docs/concepts/workloads/),
(which causes just that [workload](https://kubernetes.io/docs/concepts/workloads/)
to be rerun and produce observability data).

The videos that go with this exercise show how the
DORA, OpenTelemetry, and Keptn metrics information
appears on a Grafana dashboard with
[Jaeger](https://grafana.com/docs/grafana-cloud/data-configuration/metrics/prometheus-config-examples/the-jaeger-authors-jaeger/).

If you also have the Jaeger extension for Grafana installed on your cluster,
you can view the full end-to-end trace for everything
that happens in your deployment.
For more information, see
[Monitoring Jaeger](https://www.jaegertracing.io/docs/1.45/monitoring/).
