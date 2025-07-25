---
type: docs
title: "init CLI command reference"
linkTitle: "init"
description: "Detailed information on the init CLI command"
---

### Description

Install Dapr on supported hosting platforms.

### Supported platforms

- [Self-Hosted]({{< ref self-hosted >}})
- [Kubernetes]({{< ref kubernetes >}})

### Usage

```bash
dapr init [flags]
```

### Flags

| Name                  | Environment Variable | Default       | Description                                                                          |
| --------------------- | -------------------- | ------------- | ------------------------------------------------------------------------------------ |
| `--dashboard-version` |                      | `latest`       | The version of the Dapr dashboard to install, for example: `1.0.0`                                                   |
| `--enable-ha`         |                      | `false`       | Enable high availability (HA) mode                                                   |
| `--enable-mtls`       |                      | `true`        | Enable mTLS in your cluster                                                          |
| `--from-dir`          |                      |               | Path to a local directory containing a downloaded "Dapr Installer Bundle" release which is used to `init` the airgap environment      |
| `--help`, `-h`        |                      |               | Print this help message                                                              |
| `--image-registry`    |                      |               | Pulls container images required by Dapr from the given image registry                    |
| `--kubernetes`, `-k`  |                      | `false`       | Deploy Dapr to a Kubernetes cluster                                                  |
| `--namespace`, `-n`   |                      | `dapr-system` | The Kubernetes namespace to install Dapr in                                          |
| `--network`           |                      |               | The Docker network on which to install and deploy the Dapr runtime                                          |
| `--runtime-version`   |                      | `latest`      | The version of the Dapr runtime to install, for example: `1.0.0`                     |
| `--image-variant`   |                      |                 | The image variant to use for the Dapr runtime, for example: `mariner`               |
| `--set`               |                      |               | Configure options on the command line to be passed to the Dapr Helm chart and the Kubernetes cluster upon install. Can specify multiple values in a comma-separated list, for example: `key1=val1,key2=val2`                     |
| `--slim`, `-s`        |                      | `false`       | Exclude placement service, scheduler service, and the Redis and Zipkin containers from self-hosted installation |
| `--timeout`           |                      | `300`         | The wait timeout for the Kubernetes installation                                     |
| `--wait`              |                      | `false`       | Wait for Kubernetes initialization to complete                                       |
|        N/A            |DAPR_DEFAULT_IMAGE_REGISTRY|          | It is used to specify the default container registry to pull images from. When its value is set to `GHCR` or `ghcr` it pulls the required images from Github container registry. To default to Docker hub, unset the environment variable or leave it blank|
|        N/A            |DAPR_HELM_REPO_URL|          | Specifies a private Dapr Helm chart url|
|        N/A            | DAPR_HELM_REPO_USERNAME | A username for a private Helm chart | The username required to access the private Dapr Helm chart. If it can be accessed publicly, this env variable does not need to be set|
|        N/A            | DAPR_HELM_REPO_PASSWORD | A password for a private Helm chart  |The password required to access the private Dapr Helm chart. If it can be accessed publicly, this env variable does not need to be set| |
|  `--container-runtime`  |              |    `docker`      | Used to pass in a different container runtime other than Docker. Supported container runtimes are: `docker`, `podman` |
|  `--dev`  |              |          | Creates Redis and Zipkin deployments when run in Kubernetes. |
|  `--scheduler-volume`  |              |          | Self-hosted only. Optionally, you can specify a volume for the scheduler service data directory. By default, without this flag, scheduler data is not persisted and not resilient to restarts. |
|  `--scheduler-override-broadcast-host-port`  |  |  localhost:50006 (6060 for Windows)  | Self-hosted only. Specify the scheduler broadcast host and port, for example: 192.168.42.42:50006. |


### Examples

{{< tabs "Self-hosted" "Kubernetes" >}}

{{% codetab %}}

**Install**

Install Dapr by pulling container images for Placement, Scheduler, Redis, and Zipkin. By default, these images are pulled from Docker Hub.

> By default, a `dapr_scheduler` local volume is created for Scheduler service to be used as the database directory. The host file location for this volume is likely located at `/var/lib/docker/volumes/dapr_scheduler/_data` or `~/.local/share/containers/storage/volumes/dapr_scheduler/_data`, depending on your container runtime.

```bash
dapr init
```

Dapr can also run [Slim self-hosted mode]({{< ref self-hosted-no-docker.md >}}), without Docker.

```bash
dapr init -s
```

> To switch to Dapr Github container registry as the default registry, set the `DAPR_DEFAULT_IMAGE_REGISTRY` environment variable value to be `GHCR`. To switch back to Docker Hub as default registry, unset this environment variable.

**Specify a runtime version**

You can also specify a specific runtime version. By default, the latest version is used.

```bash
dapr init --runtime-version 1.13.4
```

**Install with image variant**

You can also install Dapr with a particular image variant, for example: [mariner]({{< ref "kubernetes-deploy.md#using-mariner-based-images" >}}).

```bash
dapr init --image-variant mariner
```

**Use Dapr Installer Bundle**

In an offline or airgap environment, you can [download a Dapr Installer Bundle](https://github.com/dapr/installer-bundle/releases) and use this to install Dapr instead of pulling images from the network.

```bash
dapr init --from-dir <path-to-installer-bundle-directory>
```

Dapr can also run in slim self-hosted mode without Docker in an airgap environment.

```bash
dapr init -s --from-dir <path-to-installer-bundle-directory>
```

**Specify private registry**

You can also specify a private registry to pull container images from. These images need to be published to private registries as shown below to enable Dapr CLI to pull them successfully via the `dapr init` command:

1. Dapr runtime container image(dapr) (Used to run Placement) - dapr/dapr:<version>
2. Redis container image(rejson)   - dapr/3rdparty/rejson
3. Zipkin container image(zipkin)  - dapr/3rdparty/zipkin

All the required images used by Dapr needs to be under the `dapr` path. The 3rd party images have to be published under `dapr/3rdparty` path.

`image-registry` uri follows the `docker.io/<username>` format.

```bash
dapr init --image-registry docker.io/username
```

This command resolves the complete image URI as shown below -
1. Placement container image(dapr) - docker.io/username/dapr/dapr:<version>
2. Redis container image(rejson)   - docker.io/username/dapr/3rdparty/rejson
3. zipkin container image(zipkin)  - docker.io/username/dapr/3rdparty/zipkin

You can specify a different container runtime while setting up Dapr. If you omit the `--container-runtime` flag, the default container runtime is Docker.

```bash
dapr init --container-runtime podman
```

**Use Docker network**

You can deploy local containers into Docker networks, which is useful for deploying into separate networks or when using Docker Compose for local development to deploy applications.

Create the Docker network.

```bash
docker network create mynet
```

Initialize Dapr and specify the created Docker network.

```bash
dapr init --network mynet
```

Verify all containers are running in the specified network.

```bash
docker ps
```

Uninstall Dapr from that Docker network.

```bash
dapr uninstall --all --network mynet
```

**Specify scheduler broadcast host and port**

You can specify the scheduler broadcast host and port, for example: 192.168.42.42:50006.

This is necessary when you have to connect to the scheduler using a different host and port, as the scheduler only allows connections matching this host and port.

By default, the scheduler will use localhost:50006 (6060 for Windows).

```bash
dapr init --scheduler-override-broadcast-host-port 192.168.42.42:50006
```

{{% /codetab %}}

{{% codetab %}}

```bash
dapr init -k
```

Using the `--dev` flag initializes Dapr in dev mode, which includes Zipkin and Redis.
```bash
dapr init -k --dev
```


You can wait for the installation to complete its deployment with the `--wait` flag.
The default timeout is 300s (5 min), but can be customized with the `--timeout` flag.

```bash
dapr init -k --wait --timeout 600
```

You can also specify a specific runtime version.

```bash
dapr init -k --runtime-version 1.4.0
```

Use the `--set` flag to configure a set of [Helm Chart values](https://github.com/dapr/dapr/tree/master/charts/dapr#configuration) during Dapr installation to help set up a Kubernetes cluster.

```bash
dapr init -k --set global.tag=1.0.0 --set dapr_operator.logLevel=error
```

You can also specify a private registry to pull container images from. As of now `dapr init -k` does not use specific images for sentry, operator, placement, scheduler, and sidecar. It relies on only Dapr runtime container image `dapr` for all these images.

Scenario 1 : dapr image hosted directly under root folder in private registry -
```bash
dapr init -k --image-registry docker.io/username
```
Scenario 2 : dapr image hosted under a new/different directory in private registry -
```bash
dapr init -k --image-registry docker.io/username/<directory-name>
```

{{% /codetab %}}

{{< /tabs >}}
