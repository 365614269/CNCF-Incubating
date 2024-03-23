---
title: Installation
---

Since v1.0.0 (alpha/beta), OpenKruise requires **Kubernetes version >= 1.16**.

## Install with helm

Kruise can be simply installed by helm v3.5+, which is a simple command-line tool and you can get it from [here](https://github.com/helm/helm/releases).

```bash
# Firstly add openkruise charts repository if you haven't do this.
$ helm repo add openkruise https://openkruise.github.io/charts/

# [Optional]
$ helm repo update

# Install the latest version.
$ helm install kruise openkruise/kruise --version 1.5.3
```
**Note:** [Changelog](https://github.com/openkruise/kruise/blob/master/CHANGELOG.md).

## Upgrade with helm

```bash
# Firstly add openkruise charts repository if you haven't do this.
$ helm repo add openkruise https://openkruise.github.io/charts/

# [Optional]
$ helm repo update

# Upgrade to the latest version.
$ helm upgrade kruise openkruise/kruise --version 1.5.3 [--force]
```

Note that:

1. Before upgrade, you **must** firstly read the [Change Log](https://github.com/openkruise/kruise/blob/master/CHANGELOG.md)
   to make sure that you have understand the breaking changes in the new version.
2. If you want to drop the chart parameters you configured for the old release or set some new parameters,
   it is recommended to add `--reset-values` flag in `helm upgrade` command.
   Otherwise you should use `--reuse-values` flag to reuse the last release's values.
3. If you are **upgrading Kruise from 0.x to 1.x**, you must add `--force` for upgrade command. Otherwise it is an optional flag.

## Optional: download charts manually

If you have problem with connecting to `https://openkruise.github.io/charts/` in production, you might need to download the chart from [here](https://github.com/openkruise/charts/releases) manually and install or upgrade with it.

```bash
$ helm install/upgrade kruise /PATH/TO/CHART
```

## Options

Note that installing this chart directly means it will use the default template values for Kruise.

You may have to set your specific configurations if it is deployed into a production cluster, or you want to configure feature-gates.

### Optional: chart parameters

The following table lists the configurable parameters of the chart and their default values.

| Parameter                                 | Description                                                  | Default                       |
| ----------------------------------------- | ------------------------------------------------------------ | ----------------------------- |
| `featureGates`                            | Feature gates for Kruise, empty string means all by default  | ` `                           |
| `installation.namespace`                  | namespace for kruise installation                            | `kruise-system`               |
| `installation.createNamespace`            | Whether to create the installation.namespace                 | `true`                        |
| `manager.log.level`                       | Log level that kruise-manager printed                        | `4`                           |
| `manager.replicas`                        | Replicas of kruise-controller-manager deployment             | `2`                           |
| `manager.image.repository`                | Repository for kruise-manager image                          | `openkruise/kruise-manager`   |
| `manager.image.tag`                       | Tag for kruise-manager image                                 | `v1.5.3`                      |
| `manager.resources.limits.cpu`            | CPU resource limit of kruise-manager container               | `200m`                        |
| `manager.resources.limits.memory`         | Memory resource limit of kruise-manager container            | `512Mi`                       |
| `manager.resources.requests.cpu`          | CPU resource request of kruise-manager container             | `100m`                        |
| `manager.resources.requests.memory`       | Memory resource request of kruise-manager container          | `256Mi`                       |
| `manager.metrics.port`                    | Port of metrics served                                       | `8080`                        |
| `manager.webhook.port`                    | Port of webhook served                                       | `9443`                        |
| `manager.nodeAffinity`                    | Node affinity policy for kruise-manager pod                  | `{}`                          |
| `manager.nodeSelector`                    | Node labels for kruise-manager pod                           | `{}`                          |
| `manager.tolerations`                     | Tolerations for kruise-manager pod                           | `[]`                          |
| `daemon.log.level`                        | Log level that kruise-daemon printed                         | `4`                           |
| `daemon.port`                             | Port of metrics and healthz that kruise-daemon served        | `10221`                       |
| `daemon.resources.limits.cpu`             | CPU resource limit of kruise-daemon container                | `50m`                         |
| `daemon.resources.limits.memory`          | Memory resource limit of kruise-daemon container             | `128Mi`                       |
| `daemon.resources.requests.cpu`           | CPU resource request of kruise-daemon container              | `0`                           |
| `daemon.resources.requests.memory`        | Memory resource request of kruise-daemon container           | `0`                           |
| `daemon.affinity`                         | Affinity policy for kruise-daemon pod                        | `{}`                          |
| `daemon.socketLocation`                   | Location of the container manager control socket             | `/var/run`                    |
| `daemon.socketFile`                       | Specify the socket file name in `socketLocation` (if you are not using containerd/docker/pouch/cri-o) | ` ` |
| `webhookConfiguration.failurePolicy.pods` | The failurePolicy for pods in mutating webhook configuration | `Ignore`                      |
| `webhookConfiguration.timeoutSeconds`     | The timeoutSeconds for all webhook configuration             | `30`                          |
| `crds.managed`                            | Kruise will not install CRDs with chart if this is false     | `true`                        |
| `manager.resyncPeriod`                    | Resync period of informer kruise-manager, defaults no resync | `0`                           |
| `manager.hostNetwork`                     | Whether kruise-manager pod should run with hostnetwork       | `false`                       |
| `imagePullSecrets`                        | The list of image pull secrets for kruise image              | `false`                       |
| `enableKubeCacheMutationDetector`         | Whether to enable KUBE_CACHE_MUTATION_DETECTOR               | `false`                       |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` or `helm upgrade`.

### Optional: feature-gate

Feature-gate controls some influential features in Kruise:

| Name                   | Description                                                  | Default | Effect (if closed)                   |
| ---------------------- | ------------------------------------------------------------ | ------- | --------------------------------------
| `PodWebhook`           | Whether to open a webhook for Pod **create**                 | `true`  | SidecarSet/KruisePodReadinessGate disabled    |
| `KruiseDaemon`         | Whether to deploy `kruise-daemon` DaemonSet                  | `true`  | ImagePulling/ContainerRecreateRequest disabled |
| `DaemonWatchingPod`    | Should each `kruise-daemon` watch pods on the same node      | `true`  | For in-place update with same imageID or env from labels/annotations |
| `CloneSetShortHash`    | Enables CloneSet controller only set revision hash name to pod label | `false` | CloneSet name can not be longer than 54 characters |
| `KruisePodReadinessGate` | Enables Kruise webhook to inject 'KruisePodReady' readiness-gate to all Pods during creation | `false` | The readiness-gate will only be injected to Pods created by Kruise workloads |
| `PreDownloadImageForInPlaceUpdate` | Enables CloneSet controller to create ImagePullJobs to pre-download images for in-place update | `false` | No image pre-download for in-place update |
| `CloneSetPartitionRollback` | Enables CloneSet controller to rollback Pods to currentRevision when number of updateRevision pods is bigger than (replicas - partition) | `false` | CloneSet will only update Pods to updateRevision |
| `ResourcesDeletionProtection` | Enables protection for resources deletion              | `true` | No protection for resources deletion |
| `TemplateNoDefaults` | Whether to disable defaults injection for pod/pvc template in workloads | `false` | Should not close this feature if it has open |
| `PodUnavailableBudgetDeleteGate` | Enables PodUnavailableBudget for pod deletion, eviction           | `true` | No protection for pod deletion, eviction |
| `PodUnavailableBudgetUpdateGate` | Enables PodUnavailableBudget for pod.Spec update                  | `false` | No protection for in-place update |
| `WorkloadSpread`                 | Enables WorkloadSpread to manage multi-domain and elastic deploy  | `true` | WorkloadSpread disabled |
| `InPlaceUpdateEnvFromMetadata`   | Enables Kruise to in-place update a container in Pod when its env from labels/annotations changed and pod is in-place updating | `true` | Only container image can be in-place update |
| `StatefulSetAutoDeletePVC`       | Enables policies controlling deletion of PVCs created by a StatefulSet  | `true` | No deletion of PVCs by StatefulSet |
| `PreDownloadImageForDaemonSetUpdate`       | Enables DaemonSet controller to create ImagePullJobs to pre-download images for in-place update  | `false` | No image pre-download for in-place update |
| `PodProbeMarkerGate`   | Whether to turn on PodProbeMarker ability  | `true` | PodProbeMarker disabled |
| `SidecarSetPatchPodMetadataDefaultsAllowed`   | Allow SidecarSet patch any annotations to Pod Object | `false` | Annotations are not allowed to patch randomly and need to be configured via SidecarSet_PatchPodMetadata_WhiteList |
| `SidecarTerminator`   | SidecarTerminator enables SidecarTerminator to stop sidecar containers when all main containers exited | `false` | SidecarTerminator disabled |
| `CloneSetEventHandlerOptimization`   | CloneSetEventHandlerOptimization enable optimization for cloneset-controller to reduce the queuing frequency cased by pod update | `false` | optimization for cloneset-controller to reduce the queuing frequency cased by pod update disabled |
| `ImagePullJobGate`                 | Enables ImagePullJob to pre-download images  | `false` | ImagePullJob disabled |
| `ResourceDistributionGate`         | Enables ResourceDistribution to distribute configmaps or secret resources  | `false` | ResourceDistribution disabled |
| `DeletionProtectionForCRDCascadingGate`         | Enables DeletionProtection for crd cascading deletion  | `false` | DeletionProtection for crd cascading deletion disabled |

If you want to configure the feature-gate, just set the parameter when install or upgrade. Such as:

```bash
$ helm install kruise https://... --set featureGates="ResourcesDeletionProtection=true\,PreDownloadImageForInPlaceUpdate=true"
```

If you want to enable all feature-gates, set the parameter as `featureGates=AllAlpha=true`.

### Optional: the local image for China

If you are in China and have problem to pull image from official DockerHub, you can use the registry hosted on Alibaba Cloud:

```bash
$ helm install kruise https://... --set  manager.image.repository=openkruise-registry.cn-shanghai.cr.aliyuncs.com/openkruise/kruise-manager
```

## Best Practices

### Installation parameters for K3s

Usually K3s has the different runtime path from the default `/var/run`. So you have to set `daemon.socketLocation` to the real runtime socket path on your K3s node (e.g. `/run/k3s` or `/var/run/k3s/`).

### Installation parameters for AWS EKS

When using a custom CNI (such as Weave or Calico) on EKS, the webhook cannot be reached by default. This happens because the control plane cannot be configured to run on a custom CNI on EKS, so the CNIs differ between control plane and worker nodes.

To address this, the webhook can be run in the host network so it can be reached, by setting `--set manager.hostNetwork=true` when use helm install or upgrade.

## Uninstall

Note that this will lead to all resources created by Kruise, including webhook configurations, services, namespace, CRDs, CR instances and Pods managed by Kruise controller, to be deleted!

Please do this ONLY when you fully understand the consequence.

To uninstall kruise if it is installed with helm charts:

```bash
$ helm uninstall kruise
release "kruise" uninstalled
```

## Kruise State Metrics

[kruise-state-metrics](https://github.com/openkruise/kruise-state-metrics) is a simple service that listens to the Kubernetes API server and generates metrics about the state of the objects.
It is not focused on the health of the individual OpenKruise components, but rather on the health of the various objects inside, such as clonesets, advanced statefulsets and sidecarsets.

```bash
# Firstly add openkruise charts repository if you haven't do this.
$ helm repo add openkruise https://openkruise.github.io/charts/

# [Optional]
$ helm repo update

# Install the latest version.
$ helm install kruise openkruise/kruise-state-metrics --version 0.1.0
```
