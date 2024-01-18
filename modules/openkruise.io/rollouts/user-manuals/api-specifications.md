# API Specifications

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

A basic example for Kruise Rollouts resource YAML:

**Note: v1beta1 available from Kruise Rollout v0.5.0.**

<Tabs>
  <TabItem value="v1beta1" label="v1beta1" default>

```yaml
apiVersion: rollouts.kruise.io/v1beta1
kind: Rollout
metadata:
  name: rollouts-demo
  # The rollout resource needs to be in the same namespace as the corresponding workload
  namespace: default
spec:
  # rollout of published workloads, currently only supports Deployment, CloneSet, StatefulSet, Advanced StatefulSet
  workloadRef:
    apiVersion: apps/v1
    kind: Deployment
    name: echoserver
  strategy:
    canary:
      steps:
      ### the 1-st batch ###
      # routing 5% traffics to the new version
      - traffic: 5%
        # Need Manual confirmation before enter to next batch
        pause: {}
        # optional, The first step of released replicas. If not set, the default is to use 'weight', as shown above is 5%.
        replicas: 1
      ### the 2-nd batch ###
      - traffic: 50%
        replicas: 50%
        # Automatically enter the next batch after waiting 2 hours
        pause:
          duration: 7200
      ### the 3-rd batch ###
      - traffic: 100%
        replicas: 100%
      trafficRoutings:
      # service name that is related with the workload
      - service: echoserver
        # ingress name that is related with the service
        ingress:
          name: echoserver
```

  </TabItem>
  <TabItem value="v1alpha1" label="v1alpha1">

```yaml
apiVersion: rollouts.kruise.io/v1alpha1
kind: Rollout
metadata:
  name: rollouts-demo
  # The rollout resource needs to be in the same namespace as the corresponding workload
  namespace: default
  # This annotation can help us upgrade the Deployment using partition, just like StatefulSet/CloneSet.
  annotations:
    rollouts.kruise.io/rolling-style: partition
spec:
  objectRef:
    # rollout of published workloads, currently only supports Deployment, CloneSet, StatefulSet, Advanced StatefulSet
    workloadRef:
      apiVersion: apps/v1
      kind: Deployment
      name: echoserver
  strategy:
    canary:
      steps:
      ### the 1-st batch ###
      # routing 5% traffics to the new version
      - weight: 5
        # Need Manual confirmation before enter to next batch
        pause: {}
        # optional, The first step of released replicas. If not set, the default is to use 'weight', as shown above is 5%.
        replicas: 1
      ### the 2-nd batch ###
      - replicas: 50%
        # Automatically enter the next batch after waiting 2 hours
        pause:
          duration: 7200
      ### the 3-rd batch ###
      - replicas: 100%
      trafficRoutings:
      # service name that is related with the workload
      - service: echoserver
        # ingress name that is related with the service
        ingress:
          name: echoserver
```

  </TabItem>
</Tabs>

There are 3 major parts of api specifications you should pay attention to:
- Binding your workload: Tell Rollout which workload it should work on;
- Binding your traffic configuration: Tell Rollout which traffic configuration it should focus on.
- Config your deployment strategy before releasing: Tell Rollout how to roll your workload and traffic.

## API Details
### Workload Binding API (Mandatory)
Tell Kruise Rollout which workload should be bounded:

<Tabs>
  <TabItem value="v1beta1" label="v1beta1" default>

```yaml
apiVersion: rollouts.kruise.io/v1beta1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  workloadRef:
    apiVersion: apps/v1
    kind: StatefulSet
    name: <your-workload-name>
```

  </TabItem>
  <TabItem value="v1alpha1" label="v1alpha1">

```yaml
apiVersion: rollouts.kruise.io/v1alpha1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  objectRef:
    workloadRef:
      apiVersion: apps/v1
      kind: StatefulSet
      name: <your-workload-name>
```

  </TabItem>
</Tabs>

| Fields       | Type   | Defaults | Explanation         |
|--------------|--------|----------|---------------------|
| `apiVersion` | string | ""       | Workload APIVersion |
| `kind`       | string | ""       | Workload Kind       |
| `name`       | string | ""       | Workload Name       |

Currently, Kruise Rollout supports Deployment, CloneSet, StatefulSet, and Advanced StatefulSet.

**Note: The workload should be at the same namespace as the Rollout.**

### Traffic Binding API (Optional)
Different from "Workload Binding", Traffic Binding is not necessary. If you do not set the following specifications, the traffic configuration will keep their native behavior, for example, keeping load balance for all versioned Pods.

If you need do something special for traffic routings, just tell Kruise Rollout which traffic configurations should be bound:

<Tabs>
  <TabItem value="v1beta1" label="v1beta1" default>

```yaml
apiVersion: rollouts.kruise.io/v1beta1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  strategy:
    canary:
      trafficRoutings:
      - service: <service-name-that-is-related-your-workload>
        ingress: # alternative： ingress,gateway,customNetworkRefs
          classType: <traffic-type> # example: nginx | higress, defaults to "nginx"
          name: <ingress-name-that-is-related-the-service>
      - service: <service-name-that-is-related-your-workload>
        gateway:
          httpRouteName: <gateway-api-httpRoute-name>
      - service: <service-name-that-is-related-your-workload>
        customNetworkRefs:
        - apiVersion: <your-resource-apiVersion>
          kind: <your-resource-kind>
          name: <your-resource-name>
```

  </TabItem>
  <TabItem value="v1alpha1" label="v1alpha1">

```yaml
apiVersion: rollouts.kruise.io/v1alpha1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  strategy:
    canary:
      trafficRoutings:
      - service: <service-name-that-is-related-your-workload>
        ingress: # alternative： ingress,gateway,customNetworkRefs
          classType: <traffic-type> # example: nginx | higress, defaults to "nginx"
          name: <ingress-name-that-is-related-the-service>
      - service: <service-name-that-is-related-your-workload>
        gateway: 
          httpRouteName: <gateway-api-httpRoute-name>
      - service: <service-name-that-is-related-your-workload>
        customNetworkRefs:
        - apiVersion: <your-resource-apiVersion>
          kind: <your-resource-kind>
          name: <your-resource-name>
```

  </TabItem>
</Tabs>

| Fields                  | Type   | Defaults | Explanation                                                                                                   |
|-------------------------|--------|----------|---------------------------------------------------------------------------------------------------------------|
| `service`               | string | ""       | Name of service that select the pods of bounded workload                                                      |
| `ingress`               | object | nil      | (optional) Description of the Ingress object you want to bind                                                 |
| `gateway`               | object | nil      | (optional) Description of the [Gateway API](https://gateway-api.sigs.k8s.io/) resources you want to bind      |
| `ingress.classType`     | string | "nginx"  | Ingress type, such as "nginx", "higress", or others                                                           |
| `ingress.name`          | string | ""       | Name of ingress resource that bounded the service                                                             |
| `gateway.httpRouteName` | string | ""       | Name of [HTTPRoute](https://gateway-api.sigs.k8s.io/concepts/api-overview/#httproute) resource of Gateway API |
| `customNetworkRefs    ` | object | ""       | Definitions of [customize API Gateway resources](https://openkruise.io/rollouts/developer-manuals/custom-network-provider) | 

**Note: `ingress`,`gateway`,`customNetworkRefs` can not be nil at the same time if you decide to use `trafficRoutings`.**

### Strategy API (Mandatory)
Describe your strategy of rollout:

<Tabs>
  <TabItem value="v1beta1" label="v1beta1" default>

```yaml
apiVersion: rollouts.kruise.io/v1beta1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  strategy:
    canary:
      steps:
      # the first step
      - traffic: 5%
        replicas: 1 or 10%
        pause:
          duration: {}
        matches:
        - headers:
          - type: Exact # or "RegularExpression"
            name: <matched-header-name>
            value: <matched-header-value, or reg-expression>
      # the second step
      - traffic: 10%
        ... ....
```

| Fields                    | Type                | Defaults  | Explanation                                                                                                    |
|---------------------------|---------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| `steps[x].traffic`         | *string            | nil       | (optional) Percent weight of canary traffic for new-version Pods.                                              |
| `steps[x].replicas`       | *integer or *string | nil       | Absolute number or Percent of new-version Pods.                                                                 |
| `steps[x].pause`          | object              | {}        | (optional) Manual confirmation or auto confirmation before enter the next step.                                |
| `steps[x].pause.duration` | *integer            | nil       | (optional) Duration time before auto confirmation. if nil, means need manual confirmation.                     |
| `steps[x].matches`        | []object            | []        | (optional) The HTTP header match rules you want to traffic to new-version Pods.                                |
| `headers[x].type`         | string              | "Exact"   | "Exact" or "RegularExpression" rule to match key and value                                                     |
| `headers[x].name`         | string              | ""        | Matched HTTP header name. (And-Relationship between headers[i] and headers[j])                                  |
| `headers[x].value`        | string              | ""        | Matched HTTP header value.                                                                                     |

  </TabItem>
  <TabItem value="v1alpha1" label="v1alpha1">

```yaml
apiVersion: rollouts.kruise.io/v1alpha1
kind: Rollout
metadata:
  namespace: <your-workload-ns>
spec:
  strategy:
    canary:
      steps:
      # the first step
      - weight: 5
        replicas: 1 or 10%
        pause:
          duration: {}
        matches:
        - headers:
          - type: Exact # or "RegularExpression"
            name: <matched-header-name>
            value: <matched-header-value, or reg-expression>
      # the second step
      - weight: 10
        ... ....
```

| Fields                    | Type                | Defaults  | Explanation                                                                                                    |
|---------------------------|---------------------|-----------|----------------------------------------------------------------------------------------------------------------|
| `steps[x].weight`         | *integer            | nil       | (optional) Percent weight of canary traffic for new-version Pods.                                              |
| `steps[x].replicas`       | *integer or *string | nil       | (optional) Absolute number or Percent of new-version Pods. If nil, the default is to use 'weight' as replicas. |
| `steps[x].pause`          | object              | {}        | (optional) Manual confirmation or auto confirmation before enter the next step.                                |
| `steps[x].pause.duration` | *integer            | nil       | (optional) Duration time before auto confirmation. if nil, means need manual confirmation.                     |
| `steps[x].matches`        | []object            | []        | (optional) The HTTP header match rules you want to traffic to new-version Pods.                                |
| `headers[x].type`         | string              | "Exact"   | "Exact" or "RegularExpression" rule to match key and value                                                     |
| `headers[x].name`         | string              | ""        | Matched HTTP header name. (And-Relationship between headers[i] and headers[j])                                  |
| `headers[x].value`        | string              | ""        | Matched HTTP header value.                                                                                     |

  </TabItem>
</Tabs>

Note:
- `steps[x].replicas` can not be nil.
- `steps[x].matches[i] and steps[x].matches[j]` have **Or**-relationship.
- `steps[x].matches[y].headers[i] and steps[x].matches[y].header[j]` have **And**-relationship.

### Special Annotations of Rollout (Optional)

<Tabs>
  <TabItem value="v1beta1" label="v1beta1" default>

```
apiVersion: rollouts.kruise.io/v1beta1
kind: Rollout
spec:
  strategy:
    canary:
      // Default is false.
      enableExtraWorkloadForCanary: true
      steps:
      ...
```

**Note:** "true" means using canary update strategy for Deployment; "false" means using multi-batch update strategy for Deployment;

  </TabItem>
  <TabItem value="v1alpha1" label="v1alpha1">

```
apiVersion: rollouts.kruise.io/v1alpha1
kind: Rollout
metadata:
  annotations:
    # Default is "canary"
    rollouts.kruise.io/rolling-type: "canary" or "partition"
```

**Note:** "canary" means using canary update strategy for Deployment; "partition" means using multi-batch update strategy for Deployment;

  </TabItem>
</Tabs>

### Special Annotations of Workload (Optional)
There are some special annotations in Bounded Workload to enable specific abilities.

| Annotations                     | Value      | Defaults | Explanation                                                                                                                                                                       |
|---------------------------------|------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `rollouts.kruise.io/rollout-id` | any string | ""       | The concept is similar to the release order number. To solve the problem that users should know whether the current changes of workload is observed by Kruise Rollout controller. |

### Rollout Status You Should Know
```yaml
kind: Rollout
status:
  phase: Healthy
  observedGeneration: 2
  canaryStatus:
    canaryReplicas: 10
    canaryReadyReplicas: 10
    canaryRevision: 76fd76f75b
    currentStepIndex: 3
    currentStepState: Completed
    observedRolloutID: "20230313093823"
    observedWorkloadGeneration: 20
    podTemplateHash: 76fd76f75b
    stableRevision: b76b6f48f
```
| Fields                             | Type    | Mode        | Explanation                                                                                                                                     |
|------------------------------------|---------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `phase`                            | string  | ready-only  | "Initial" means no bounded workload; "Healthy" means bounded workload is promoted; "Progressing" means rollout is working.                      |
| `observedGeneration`               | integer | ready-only  | Observed rollout spec generation.                                                                                                               |
| `canaryStatus`                     | *object | ready-only  | Information about rollout progressing.                                                                                                          |
| `canaryStatus.canaryReplicas`      | integer | ready-only  | workload updated replicas                                                                                                                       |
| `canaryStatus.canaryReadyReplicas` | integer | ready-only  | workload updated ready replicas.                                                                                                                |
| `canaryStatus.podTemplateHash`     | string  | ready-only  | workload update(new) revision hash.                                                                                                             |
| `canaryStatus.canaryRevision`      | string  | ready-only  | workload update(new) revision hash calculated by Kruise Rollout controller.                                                                     |
| `canaryStatus.stableRevision`      | string  | ready-only  | workload stable(old) revision hash recorded before progressing.                                                                                 |
| `canaryStatus.observedRolloutID`   | string  | ready-only  | corresponding to workload `rollouts.kruise.io/rollout-id` annotations. if they are equal, it means rollout controller watched workload changes. |
| `canaryStatus.currentStepIndex`    | integer | ready-only  | rollout current step index. Start from 1.                                                                                                       |
| `canaryStatus.currentStepState`    | string  | ready&write | rollout current step state. Both "StepReady" and "Complete" mean current step is ready.                                                         |
