---
comments: true
---

# KeptnConfig

`KeptnConfig` defines Keptn configuration values.

## Yaml Synopsis

```yaml
apiVersion: options.keptn.sh/v1alpha1
kind: KeptnConfig
metadata:
  name: <configuration-name>
spec:
  OTelCollectorUrl: '<otelurl:port>'
  keptnAppCreationRequestTimeoutSeconds: <#-seconds>
  cloudEventsEndpoint: <endpoint>
```

## Fields
<!-- markdownlint-disable MD007 -->

* **apiVersion** -- API version being used.
* **kind** -- Resource type.
   Must be set to `KeptnConfig`.

* **metadata**
     * **name** -- Unique name of this set of configurations.
       Names must comply with the
       [Kubernetes Object Names and IDs](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names)
       specification.

* **spec**
     * **OTelCollectorUrl** -- The URL and port of the OpenTelemetry collector
       This field must be populated
       in order to export traces to the OpenTelemetry Collector.
     * **keptnAppCreationRequestTimeoutSeconds** --
       Interval in which automatic app discovery searches for [workloads](https://kubernetes.io/docs/concepts/workloads/)
       to put into the same auto-generated [KeptnApp](app.md).
       The default value is 30 (seconds).
     * **cloudEventsEndpoint** --
       Endpoint where the lifecycle operator posts Cloud Events.
<!-- markdownlint-enable MD007 -->

## Usage

Each cluster should have a single `KeptnConfig` CRD
that describes all configurations for that cluster.

## Example

### OTel example

This example specifies the URL of the OpenTelemetry collector
and that the automatic app discovery should be run every 40 seconds:

```yaml
apiVersion: options.keptn.sh/v1alpha2
kind: KeptnConfig
metadata:
  name: keptn-config
spec:
  OTelCollectorUrl: 'otel-collector:4317'
  keptnAppCreationRequestTimeoutSeconds: 40
  cloudEventsEndpoint: 'http://endpoint.com'
```

## Files

API Reference:

* [KeptnTaskDefinition](../api-reference/lifecycle/v1beta1/index.md#keptntaskdefinition)

## Differences between versions

## See also

* [KeptnApp](./app.md)
* [OpenTelemetry observability](../../guides/otel.md)
* [Keptn automatic app discovery](../../guides/auto-app-discovery.md)
