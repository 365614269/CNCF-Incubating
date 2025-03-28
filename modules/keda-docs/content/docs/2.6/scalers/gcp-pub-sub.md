+++
title = "Google Cloud Platform Pub/Sub"
availability = "v1.0+"
maintainer = "Community"
description = "Scale applications based on Google Cloud Platform Pub/Sub."
go_file = "gcp_pub_sub_scaler"
+++

### Trigger Specification

This specification describes the `gcp-pubsub` trigger for Google Cloud Platform Pub/Sub.

```yaml
triggers:
- type: gcp-pubsub
  authenticationRef: gcp-pubsub-credentials # Required
  metadata:
    subscriptionSize: "5" # Deprecated, use mode and value fields instead
    mode: "SubscriptionSize" # Optional - Default is SubscriptionSize - SubscriptionSize or OldestUnackedMessageAge
    value: "5" # Optional - Default is 5 for SubscriptionSize | Default is 10 for OldestUnackedMessageAge
    subscriptionName: "mysubscription" # Required
```

The Google Cloud Platform (GCP) Pub/Sub trigger allows you to scale based on the number of messages or oldest unacked message age in your Pub/Sub subscription.

`authenticationRef` defines how KEDA connect to Google Cloud Platform, to collect the required stack driver metrics in order to read the number of messages in the Pub/Sub subscription.

`subscriptionName` defines the subscription that should be monitored. You can use different formulas:

- Just the subscription name, in which case you will reference a subscription from the current project or the one specified in the credentials file used.
- Use the full link provided by Google, so that you can reference a subscription that is hosted in another project Eg: `projects/myproject/subscriptions/mysubscription`.

You can use either `subscriptionSize` to define the target average which the deployment will be scaled on or `mode` and `value` fields. `subscriptionSize` field is deprecated, it is recommended to use `mode` and `value` fields instead. Scaler will not work if you define both `subscriptionSize` and at least one of `mode` or `value`.
The mode chooses whether to scale using number of messages `SubscriptionSize` or using oldest unacked message age `OldestUnackedMessageAge`.
The `value` determines the target average which the deployment will be scaled on. The default value is 5 for `SubscriptionSize` and 10 for `OldestUnackedMessageAge`.

Here's an [example](https://github.com/kedacore/sample-go-gcppubsub).

### Authentication Parameters
You can configure authorization for a `ScaledObject` either directly using credentials in `credentialsFromEnv` or using an `authenticationRef` referencing a `TriggerAuthentication` CRD which configures authorization.

**Pod identity based authentication:**
- `podIdentity.provider` - Needs to be set to `gcp` on the `TriggerAuthentication` and the pod's [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) or node's (default) service account must be configured correctly.

**Credential based authentication via TriggerAuthentication:**
- `secretTargetRef` - Needs to be set on the `TriggerAuthentication`, with `parameter=GoogleApplicationCredentials` and `name` must reference a Secret in which `key` is the key containing the JSON ServiceAccount value.

**Credential based authentication via ScaledObject:**
- `credentialsFromEnv` - Needs to be set on the `ScaledObject`.

### Examples
To use the GCP default authentication, you need to create a `TriggerAuthentication` as this example, and reference it in the `ScaledObject`.

```yaml
apiVersion: keda.sh/v1alpha1
kind: TriggerAuthentication
metadata:
  name: gcp-pubsub-credentials
spec:
  podIdentity:
    provider: gcp # Required
---
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: pubsub-scaledobject
spec:
  scaleTargetRef:
    name: keda-pubsub-go
  triggers:
  - type: gcp-pubsub
    metadata:
      subscriptionName: "input" # Required
    authenticationRef:
      name: gcp-pubsub-credentials
```

Alternatively, you can configure the credentials in a secret, via the `TriggerAuthentication`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pubsub-secret
data:
  GOOGLE_APPLICATION_CREDENTIALS_JSON: <json-credential-value>
---
apiVersion: keda.sh/v1alpha1
kind: TriggerAuthentication
metadata:
  name: gcp-pubsub-credentials
spec:
  secretTargetRef:
  - parameter: GoogleApplicationCredentials
    name: pubsub-secret  # Required. Refers to the name of the secret
    key: GOOGLE_APPLICATION_CREDENTIALS_JSON # Required
---
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: pubsub-scaledobject
spec:
  scaleTargetRef:
    name: keda-pubsub-go
  triggers:
  - type: gcp-pubsub
    metadata:
      subscriptionName: "input" # Required
    authenticationRef:
      name: gcp-pubsub-credentials # Required
```

The `credentialsFromEnv` property maps to the name of an environment variable in the scale target (`scaleTargetRef`) that contains the service account credentials (JSON).

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: pubsub-scaledobject
  namespace: keda-pubsub-test
spec:
  scaleTargetRef:
    name: keda-pubsub-go
  triggers:
  - type: gcp-pubsub
    metadata:
      subscriptionSize: "5"
      subscriptionName: "mysubscription" # Required
      credentialsFromEnv: GOOGLE_APPLICATION_CREDENTIALS_JSON # Required
```

## Example using ClusterTriggerAuthentication with GCP Identity

```yaml
apiVersion: keda.sh/v1alpha1
kind: ClusterTriggerAuthentication
metadata:
  name: keda-clustertrigger-auth-gcp-credentials
spec:
  podIdentity:
    provider: gcp
---
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: pubsub-scaledobject
spec:
  scaleTargetRef:
    name: keda-pubsub-go
  triggers:
  - type: gcp-pubsub
    authenticationRef:
      name: keda-clustertrigger-auth-gcp-credentials
      kind: ClusterTriggerAuthentication
    metadata:
      subscriptionName: "input" # Required
```
