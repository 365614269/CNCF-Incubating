# Deploying NATS with Helm

The NATS Helm charts can be used to deploy a StatefulSet of NATS servers using Helm templates which are easy to extend. Using Helm3 you can add the NATS Helm repo as follows:

```shell
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm install my-nats nats/nats
```

The [ArtifactHub NATS Helm package](https://artifacthub.io/packages/helm/nats/nats) contains a complete list of configuration options.  Some common scenarios are outlined below.

## Configuration

### Server Image

```yaml
nats:
  image: nats:2.7.4-alpine
  pullPolicy: IfNotPresent
```

### Limits

```yaml
nats:
  # The number of connect attempts against discovered routes.
  connectRetries: 30

  # How many seconds should pass before sending a PING
  # to a client that has no activity.
  pingInterval:

  # Server settings.
  limits:
    maxConnections:
    maxSubscriptions:
    maxControlLine:
    maxPayload:

    writeDeadline:
    maxPending:
    maxPings:
    lameDuckDuration:

  # Number of seconds to wait for client connections to end after the pod termination is requested
  terminationGracePeriodSeconds: 60
```

### Logging

_Note_: It is not recommended to enable trace or debug in production since enabling it will significantly degrade performance.

```yaml
nats:
  logging:
    debug:
    trace:
    logtime:
    connectErrorReports:
    reconnectErrorReports:
```

### TLS setup for client connections

You can find more on how to set up and troubleshoot TLS connections at: [running-a-nats-service/configuration/securing_nats/tls](/running-a-nats-service/configuration/securing_nats/tls.md)

```yaml
nats:
  tls:
    secret:
      name: nats-client-tls
    ca: "ca.crt"
    cert: "tls.crt"
    key: "tls.key"
```

Example of creating the _nats-client-tls_ k8s secret with three named values matching the above setup:
```text
kubectl create secret generic nats-client-tls --from-file=tls.crt=./broker.crt --from-file=tls.key=./broker.key --from-file=ca.crt=./ca.pem
```
## Clustering

If clustering is enabled, then a 3-node cluster will be set up. More info at: [running-a-nats-server/configuration/clustering#nats-server-clustering](/running-a-nats-service/configuration/clustering/#nats-server-clustering)

```yaml
cluster:
  enabled: true
  replicas: 3

  tls:
    secret:
      name: nats-server-tls
    ca: "ca.crt"
    cert: "tls.crt"
    key: "tls.key"
```

Example:

```bash
helm install nats nats/nats --set cluster.enabled=true
```

## Leafnodes

Leafnode connections to extend a cluster. More info at: [running-a-nats-server/configuration/leafnodes](/running-a-nats-service/configuration/leafnodes/)

```yaml
leafnodes:
  enabled: true
  remotes:
    - url: "tls://connect.ngs.global:7422"
      # credentials:
      #   secret:
      #     name: leafnode-creds
      #     key: TA.creds
      # tls:
      #   secret:
      #     name: nats-leafnode-tls
      #   ca: "ca.crt"
      #   cert: "tls.crt"
      #   key: "tls.key"

  #######################
  #                     #
  #  TLS Configuration  #
  #                     #
  #######################
  # 
  #  # You can find more on how to setup and trouble shoot TLS connnections at:
  # 
  #  # https://docs.nats.io/running-a-nats-server/configuration/securing_nats/tls
  # 
  tls:
    secret:
      name: nats-client-tls
    ca: "ca.crt"
    cert: "tls.crt"
    key: "tls.key"
```

## Websocket Configuration

```yaml
websocket:
  enabled: true
  port: 443

  tls:
    secret:
      name: nats-tls
    cert: "fullchain.pem"
    key: "privkey.pem"
```

## Setting up External Access

### Using HostPorts

In case of both external access and advertisements being enabled, an initializer container will be used to gather the public IPs. This container will be required to have enough RBAC policy to be able to make a look up of the public IP of the node where it is running.

For example, to set up external access for a cluster and advertise the public IP to clients:

```yaml
nats:
  # Toggle whether to enable external access.
  # This binds a host port for clients, gateways and leafnodes.
  externalAccess: true

  # Toggle to disable client advertisements (connect_urls),
  # in case of running behind a load balancer (which is not recommended)
  # it might be required to disable advertisements.
  advertise: true

  # In case both external access and advertise are enabled
  # then a service account would be required to be able to
  # gather the public IP from a node.
  serviceAccount: "nats-server"
```

Where the service account named `nats-server` has the following RBAC policy for example:

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nats-server
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nats-server
rules:
- apiGroups: [""]
  resources:
  - nodes
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nats-server-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nats-server
subjects:
- kind: ServiceAccount
  name: nats-server
  namespace: default
```

The container image of the initializer can be customized via:

```yaml
bootconfig:
  image: natsio/nats-boot-config:latest
  pullPolicy: IfNotPresent
```

### Using LoadBalancers

When using a load balancer for external access, it is recommended to disable advertisement so that internal IPs from the NATS Servers are not advertised to the clients connecting through the load balancer.

```yaml
nats:
  image: nats:alpine

cluster:
  enabled: true
  noAdvertise: true

leafnodes:
  enabled: true
  noAdvertise: true

natsbox:
  enabled: true
```

You could then use an L4 enabled load balancer to connect to NATS, for example:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nats-lb
spec:
  type: LoadBalancer
  selector:
    app.kubernetes.io/name: nats
  ports:
    - protocol: TCP
      port: 4222
      targetPort: 4222
      name: nats
    - protocol: TCP
      port: 7422
      targetPort: 7422
      name: leafnodes
    - protocol: TCP
      port: 7522
      targetPort: 7522
      name: gateways
```

## Gateways

A supercluster can be formed by pointing to remote gateways. You can find more about gateways in the NATS documentation: [running-a-nats-server/configuration/gateways](/running-a-nats-service/configuration/gateways/).

```yaml
gateway:
  enabled: false
  name: 'default'

  #############################
  #                           #
  #  List of remote gateways  #
  #                           #
  #############################
  # gateways:
  #   - name: other
  #     url: nats://my-gateway-url:7522

  #######################
  #                     #
  #  TLS Configuration  #
  #                     #
  #######################
  # 
  #  # You can find more on how to setup and trouble shoot TLS connnections at:
  # 
  #  # https://docs.nats.io/running-a-nats-server/configuration/securing_nats/tls
  #
  # tls:
  #   secret:
  #     name: nats-client-tls
  #   ca: "ca.crt"
  #   cert: "tls.crt"
  #   key: "tls.key"
```

## Auth setup

### Auth with a Memory Resolver

```yaml
auth:
  enabled: true

  # Reference to the Operator JWT.
  operatorjwt:
    configMap:
      name: operator-jwt
      key: KO.jwt

  # Public key of the System Account
  systemAccount:

  resolver:
    ############################
    #                          #
    # Memory resolver settings #
    #                          #
    ##############################
    type: memory

    # 
    # Use a configmap reference which will be mounted
    # into the container.
    # 
    configMap:
      name: nats-accounts
      key: resolver.conf
```

### Auth using an Account Server Resolver

```yaml
auth:
  enabled: true

  # Reference to the Operator JWT.
  operatorjwt:
    configMap:
      name: operator-jwt
      key: KO.jwt

  # Public key of the System Account
  systemAccount:

  resolver:
    ##########################
    #                        #
    #  URL resolver settings #
    #                        #
    ##########################
    type: URL
    url: "http://nats-account-server:9090/jwt/v1/accounts/"
```

## JetStream

### Setting up Memory and File Storage

File Storage is **always** recommended, since JetStream's RAFT Meta Group will be persisted to file storage.  The Storage Class used should be block storage.  NFS is not recommended.

```yaml
nats:
  image: nats:alpine

  jetstream:
    enabled: true

    memStorage:
      enabled: true
      size: 2Gi

    fileStorage:
      enabled: true
      size: 10Gi
      # storageClassName: gp2 # NOTE: AWS setup but customize as needed for your infra.
```

### Using with an existing PersistentVolumeClaim

For example, given the following `PersistentVolumeClaim`:

```yaml
---
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: nats-js-disk
  annotations:
    volume.beta.kubernetes.io/storage-class: "default"
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 3Gi
```

You can start JetStream so that one pod is bound to it:

```yaml
nats:
  image: nats:alpine

  jetstream:
    enabled: true

    fileStorage:
      enabled: true
      storageDirectory: /data/
      existingClaim: nats-js-disk
      claimStorageSize: 3Gi
```

### Clustering example

```yaml
nats:
  image: nats:alpine

  jetstream:
    enabled: true

    memStorage:
      enabled: true
      size: "2Gi"

    fileStorage:
      enabled: true
      size: "1Gi"
      storageDirectory: /data/
      storageClassName: default

cluster:
  enabled: true
  # Cluster name is required, by default will be release name.
  # name: "nats"
  replicas: 3
```

## Misc

### NATS Box

A lightweight container with NATS and NATS Streaming utilities deployed along the cluster to confirm the setup. You can find the image at: [https://github.com/nats-io/nats-box](https://github.com/nats-io/nats-box)

```yaml
natsbox:
  enabled: true
  image: nats:alpine
  pullPolicy: IfNotPresent

  # credentials:
  #   secret:
  #     name: nats-sys-creds
  #     key: sys.creds
```

### Configuration Reload sidecar

The NATS config reloader image to use:

```yaml
reloader:
  enabled: true
  image: natsio/nats-server-config-reloader:latest
  pullPolicy: IfNotPresent
```

### Prometheus Exporter sidecar

You can toggle whether to start the sidecar to be used to feed metrics to Prometheus:

```yaml
exporter:
  enabled: true
  image: natsio/prometheus-nats-exporter:latest
  pullPolicy: IfNotPresent
```

### Prometheus operator ServiceMonitor support

You can enable Prometheus operator ServiceMonitor:

```yaml
exporter:
  # You have to enable exporter first
  enabled: true
  serviceMonitor:
    enabled: true
    ## Specify the namespace where Prometheus Operator is running
    # namespace: monitoring
    # ...
```

### Pod Customizations

#### Security Context

```yaml
 # Toggle whether to use setup a Pod Security Context
 # ## ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
securityContext:
  fsGroup: 1000
  runAsUser: 1000
  runAsNonRoot: true
```

#### Affinity

[https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#affinity-and-anti-affinity)

`matchExpressions` must be configured according to your setup

```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node.kubernetes.io/purpose
              operator: In
              values:
                - nats
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app
              operator: In
              values:
                - nats
                - stan
        topologyKey: "kubernetes.io/hostname"
```

#### Service topology

[Service topology](https://kubernetes.io/docs/concepts/services-networking/service-topology/) is disabled by default but can be enabled by setting `topologyKeys`. For example:

```yaml
topologyKeys:
  - "kubernetes.io/hostname"
  - "topology.kubernetes.io/zone"
  - "topology.kubernetes.io/region"
```

#### CPU/Memory Resource Requests/Limits

Sets the pods CPU/memory requests/limits

```yaml
nats:
  resources:
    requests:
      cpu: 2
      memory: 4Gi
    limits:
      cpu: 4
      memory: 6Gi
```

No resources are set by default.

#### Annotations

[https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations)

```yaml
podAnnotations:
  key1 : "value1",
  key2 : "value2"
```

### Name Overrides

Can change the name of the resources as needed with:

```yaml
nameOverride: "my-nats"
```

### Image Pull Secrets

```yaml
imagePullSecrets:
- name: myRegistry
```

Adds this to the StatefulSet:

```yaml
spec:
  imagePullSecrets:
    - name: myRegistry
```
