+++
title = "Google Cloud Platform‎ Pub/Sub"
availability = "v1.0+"
maintainer = "Community"
description = "Scale applications based on Google Cloud Platform‎ Pub/Sub."
go_file = "gcp_pub_sub_scaler"
+++

### Trigger Specification

This specification describes the `gcp-pubsub` trigger for Google Cloud Platform‎ Pub/Sub.

```yaml
triggers:
- type: gcp-pubsub
  metadata:
    subscriptionSize: "5" # Optional - Default is 5
    subscriptionName: "mysubscription" # Required
    credentials: GOOGLE_APPLICATION_CREDENTIALS_JSON # Required
```

The Google Cloud Platform‎ (GCP) Pub/Sub trigger allows you to scale based on the number of messages in your Pub/Sub subscription.

The `credentials` property maps to the name of an environment variable in the scale target (`scaleTargetRef`) that contains the service account credentials (JSON). KEDA will use those to connect to Google Cloud Platform and collect the required stack driver metrics in order to read the number of messages in the Pub/Sub subscription.

`subscriptionName` defines the subscription that should be monitored. The `subscriptionSize` determines the target average which the deployment will be scaled on. The default `subscriptionSize` is 5.

### Authentication Parameters

Not supported yet.

### Example

```yaml
apiVersion: keda.k8s.io/v1alpha1
kind: ScaledObject
metadata:
  name: pubsub-scaledobject
  namespace: keda-pubsub-test
spec:
  scaleTargetRef:
    deploymentName: keda-pubsub-go
  triggers:
  - type: gcp-pubsub
    metadata:
      subscriptionSize: "5"
      subscriptionName: "mysubscription" # Required
      credentials: GOOGLE_APPLICATION_CREDENTIALS_JSON # Required
```
