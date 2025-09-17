---
type: docs
title: "How to: Use the Multi-App Run template file"
linkTitle: "How to: Use the Multi-App Run template"
weight: 2000
description: Unpack the Multi-App Run template file and its properties
---

{{% alert title="Note" color="primary" %}}
 Multi-App Run for **Kubernetes** is currently a preview feature.
{{% /alert %}}

The Multi-App Run template file is a YAML file that you can use to run multiple applications at once. In this guide, you'll learn how to:
- Use the multi-app template
- View started applications
- Stop the multi-app template
- Structure the multi-app template file

## Use the multi-app template

You can use the multi-app template file in one of the following two ways:

### Execute by providing a directory path

When you provide a directory path, the CLI will try to locate the Multi-App Run template file, named `dapr.yaml` by default in the directory. If the file is not found, the CLI will return an error.

Execute the following CLI command to read the Multi-App Run template file, named `dapr.yaml` by default:

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

```cmd
# the template file needs to be called `dapr.yaml` by default if a directory path is given

dapr run -f <dir_path>
```
{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

```cmd
dapr run -f <dir_path> -k 
```
{{% /tab %}}

{{< /tabpane >}}

### Execute by providing a file path

If the Multi-App Run template file is named something other than `dapr.yaml`, then you can provide the relative or absolute file path to the command:

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

```cmd
dapr run -f ./path/to/<your-preferred-file-name>.yaml
```

{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

```cmd
dapr run -f ./path/to/<your-preferred-file-name>.yaml -k 
```
{{% /tab %}}

{{< /tabpane >}}

## View the started applications

Once the multi-app template is running, you can view the started applications with the following command:

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

```cmd
dapr list
```

{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

```cmd
dapr list -k 
```
{{% /tab %}}

{{< /tabpane >}}

## Stop the multi-app template

Stop the multi-app run template anytime with either of the following commands:

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

```cmd
# the template file needs to be called `dapr.yaml` by default if a directory path is given

dapr stop -f <dir_path>
```
or:

```cmd
dapr stop -f ./path/to/<your-preferred-file-name>.yaml
```

{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

```cmd
# the template file needs to be called `dapr.yaml` by default if a directory path is given

dapr stop -f <dir_path> -k
```
or:

```cmd
dapr stop -f ./path/to/<your-preferred-file-name>.yaml -k 
```

{{% /tab %}}

{{< /tabpane >}}


## Template file structure

The Multi-App Run template file can include the following properties. Below is an example template showing two applications that are configured with some of the properties.

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

```yaml
version: 1
common: # optional section for variables shared across apps
  resourcesPath: ./app/components # any dapr resources to be shared across apps
  env:  # any environment variable shared across apps
    DEBUG: true
apps:
  - appID: webapp # optional
    appDirPath: .dapr/webapp/ # REQUIRED
    resourcesPath: .dapr/resources # deprecated
    resourcesPaths: .dapr/resources # comma separated resources paths. (optional) can be left to default value by convention.
    appChannelAddress: 127.0.0.1 # network address where the app listens on. (optional) can be left to default value by convention.
    configFilePath: .dapr/config.yaml # (optional) can be default by convention too, ignore if file is not found.
    appProtocol: http
    appPort: 8080
    appHealthCheckPath: "/healthz"
    command: ["python3", "app.py"]
    appLogDestination: file # (optional), can be file, console or fileAndConsole. default is fileAndConsole.
    daprdLogDestination: file # (optional), can be file, console or fileAndConsole. default is file.
  - appID: backend # optional
    appDirPath: .dapr/backend/ # REQUIRED
    appProtocol: grpc
    appPort: 3000
    unixDomainSocket: "/tmp/test-socket"
    env:
      DEBUG: false
    command: ["./backend"]
```

The following rules apply for all the paths present in the template file:
 - If the path is absolute, it is used as is.
 - All relative paths under common section should be provided relative to the template file path.
 - `appDirPath` under apps section should be provided relative to the template file path.
 - All other relative paths under apps section should be provided relative to the `appDirPath`.

{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

```yaml
version: 1
common: # optional section for variables shared across apps
  env:  # any environment variable shared across apps
    DEBUG: true
apps:
  - appID: webapp # optional
    appDirPath: .dapr/webapp/ # REQUIRED
    appChannelAddress: 127.0.0.1 # network address where the app listens on. (optional) can be left to default value by convention.
    appProtocol: http
    appPort: 8080
    appHealthCheckPath: "/healthz"
    appLogDestination: file # (optional), can be file, console or fileAndConsole. default is fileAndConsole.
    daprdLogDestination: file # (optional), can be file, console or fileAndConsole. default is file.
    containerImage: ghcr.io/dapr/samples/hello-k8s-node:latest # (optional) URI of the container image to be used when deploying to Kubernetes dev/test environment.
    containerImagePullPolicy: IfNotPresent # (optional), the container image is downloaded if one is not present locally, otherwise the local one is used.
    createService: true # (optional) Create a Kubernetes service for the application when deploying to dev/test environment.
  - appID: backend # optional
    appDirPath: .dapr/backend/ # REQUIRED
    appProtocol: grpc
    appPort: 3000
    unixDomainSocket: "/tmp/test-socket"
    env:
      DEBUG: false
```

The following rules apply for all the paths present in the template file:
 - If the path is absolute, it is used as is.
 - `appDirPath` under apps section should be provided relative to the template file path.
 - All relative paths under app section should be provided relative to the `appDirPath`.

{{% /tab %}}

{{< /tabpane >}}

## Template properties

{{< tabpane text=true >}}

{{% tab "Self-hosted" %}}
<!--selfhosted-->

The properties for the Multi-App Run template align with the `dapr run` CLI flags, [listed in the CLI reference documentation]({{% ref "dapr-run.md#flags" %}}).

{{% table "table table-white table-striped table-bordered" %}}

| Properties               | Required | Details | Example |
|--------------------------|:--------:|--------|---------|
| `appDirPath`             | Y        | Path to the your application code | `./webapp/`, `./backend/` |
| `appID`                  | N        | Application's app ID. If not provided, will be derived from `appDirPath` | `webapp`, `backend` |
| `resourcesPath`          | N        | **Deprecated**. Path to your Dapr resources. Can be default value  by convention| `./app/components`, `./webapp/components` |
| `resourcesPaths`         | N        | Comma separated paths to your Dapr resources. Can be default value by convention | `./app/components`, `./webapp/components` |
| `appChannelAddress`      | N        | The network address the application listens on. Can be left to the default value by convention. | `127.0.0.1` | `localhost` |
| `configFilePath`         | N        | Path to your application's configuration file | `./webapp/config.yaml` |
| `appProtocol`            | N        | The protocol Dapr uses to talk to the application. | `http`, `grpc` |
| `appPort`                | N        | The port your application is listening on | `8080`, `3000` |
| `daprHTTPPort`           | N        | Dapr HTTP port |  |
| `daprGRPCPort`           | N        | Dapr GRPC port |  |
| `daprInternalGRPCPort`   | N        | gRPC port for the Dapr Internal API to listen on; used when parsing the value from a local DNS component |  |
| `metricsPort`            | N        | The port that Dapr sends its metrics information to |  |
| `unixDomainSocket`       | N        | Path to a unix domain socket dir mount. If specified, communication with the Dapr sidecar uses unix domain sockets for lower latency and greater throughput when compared to using TCP ports. Not available on Windows. | `/tmp/test-socket` |
| `profilePort`            | N        | The port for the profile server to listen on |  |
| `enableProfiling`        | N        | Enable profiling via an HTTP endpoint |  |
| `apiListenAddresses`     | N        | Dapr API listen addresses |  |
| `logLevel`               | N        | The log verbosity. |  |
| `appMaxConcurrency`      | N        | The concurrency level of the application; default is unlimited |  |
| `placementHostAddress`   | N        | Comma separated list of addresses for Dapr placement servers | `127.0.0.1:50057,127.0.0.1:50058` |
| `schedulerHostAddress`   | N        | Dapr Scheduler Service host address | `localhost:50006` |
| `appSSL`                 | N        | Enable https when Dapr invokes the application |  |
| `maxBodySize`            | N        | Max size of the request body in MB. Set the value using size units (e.g., `16Mi` for 16MB). The default is `4Mi` |  |
| `readBufferSize`         | N        | Max size of the HTTP read buffer in KB. This also limits the maximum size of HTTP headers. Set the value using size units, for example `32Ki` will support headers up to 32KB . Default is `4Ki` for 4KB |  |
| `enableAppHealthCheck`   | N        | Enable the app health check on the application | `true`, `false` |
| `appHealthCheckPath`     | N        | Path to the health check file | `/healthz` |
| `appHealthProbeInterval` | N        | Interval to probe for the health of the app in seconds |  |
| `appHealthProbeTimeout`  | N        | Timeout for app health probes in milliseconds |  |
| `appHealthThreshold`     | N        | Number of consecutive failures for the app to be considered unhealthy |  |
| `enableApiLogging`       | N        | Enable the logging of all API calls from application to Dapr |  |
| `runtimePath`            | N        | Dapr runtime install path |  |
| `env`                    | N        | Map to environment variable; environment variables applied per application will overwrite environment variables shared across applications | `DEBUG`, `DAPR_HOST_ADD` |
| `appLogDestination`                    | N        | Log destination for outputting app logs; Its value can be file, console or fileAndConsole. Default is fileAndConsole | `file`, `console`, `fileAndConsole` |
| `daprdLogDestination`                    | N        | Log destination for outputting daprd logs; Its value can be file, console or fileAndConsole. Default is file | `file`, `console`, `fileAndConsole` |

{{% /table %}}

## Next steps

Watch [this video for an overview on Multi-App Run](https://youtu.be/s1p9MNl4VGo?t=2456):

{{< youtube id=s1p9MNl4VGo start=2456 >}}

{{% /tab %}}

{{% tab "Kubernetes" %}}
<!--kubernetes-->

The properties for the Multi-App Run template align with the `dapr run -k` CLI flags, [listed in the CLI reference documentation]({{% ref "dapr-run.md#flags" %}}).

{{% table "table table-white table-striped table-bordered" %}}

| Properties                 | Required | Details                                                                                                                                                                                                                 | Example                                        |
|----------------------------|:--------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------|
| `appDirPath`               |    Y     | Path to the your application code                                                                                                                                                                                       | `./webapp/`, `./backend/`                      |
| `appID`                    |    N     | Application's app ID. If not provided, will be derived from `appDirPath`                                                                                                                                                | `webapp`, `backend`                            |
| `appChannelAddress`        |    N     | The network address the application listens on. Can be left to the default value by convention.                                                                                                                         | `127.0.0`, `localhost`                         |
| `appProtocol`              |    N     | The protocol Dapr uses to talk to the application.                                                                                                                                                                      | `http`, `grpc`                                 |
| `appPort`                  |    N     | The port your application is listening on                                                                                                                                                                               | `8080`, `3000`                                 |
| `daprHTTPPort`             |    N     | Dapr HTTP port                                                                                                                                                                                                          |                                                |
| `daprGRPCPort`             |    N     | Dapr GRPC port                                                                                                                                                                                                          |                                                |
| `daprInternalGRPCPort`     |    N     | gRPC port for the Dapr Internal API to listen on; used when parsing the value from a local DNS component                                                                                                                |                                                |
| `metricsPort`              |    N     | The port that Dapr sends its metrics information to                                                                                                                                                                     |                                                |
| `unixDomainSocket`         |    N     | Path to a unix domain socket dir mount. If specified, communication with the Dapr sidecar uses unix domain sockets for lower latency and greater throughput when compared to using TCP ports. Not available on Windows. | `/tmp/test-socket`                             |
| `profilePort`              |    N     | The port for the profile server to listen on                                                                                                                                                                            |                                                |
| `enableProfiling`          |    N     | Enable profiling via an HTTP endpoint                                                                                                                                                                                   |                                                |
| `apiListenAddresses`       |    N     | Dapr API listen addresses                                                                                                                                                                                               |                                                |
| `logLevel`                 |    N     | The log verbosity.                                                                                                                                                                                                      |                                                |
| `appMaxConcurrency`        |    N     | The concurrency level of the application; default is unlimited                                                                                                                                                          |                                                |
| `placementHostAddress`     |    N     | Comma separated list of addresses for Dapr placement servers                                                                                                                                                            | `127.0.0.1:50057,127.0.0.1:50058`              |
| `schedulerHostAddress`     |    N     | Dapr Scheduler Service host address                                                                                                                                                                                     | `127.0.0.1:50006`                              |
| `appSSL`                   |    N     | Enable HTTPS when Dapr invokes the application                                                                                                                                                                          |                                                |
| `maxBodySize`              |    N     | Max size of the request body in MB. Set the value using size units (e.g., `16Mi` for 16MB). The default is `4Mi`                                                                                                        | `16Mi`                                         |
| `readBufferSize`           |    N     | Max size of the HTTP read buffer in KB. This also limits the maximum size of HTTP headers. Set the value using size units, for example `32Ki` will support headers up to 32KB . Default is `4Ki` for 4KB                | `32Ki`                                         |
| `enableAppHealthCheck`     |    N     | Enable the app health check on the application                                                                                                                                                                          | `true`, `false`                                |
| `appHealthCheckPath`       |    N     | Path to the health check file                                                                                                                                                                                           | `/healthz`                                     |
| `appHealthProbeInterval`   |    N     | Interval to probe for the health of the app in seconds                                                                                                                                                                  |                                                |
| `appHealthProbeTimeout`    |    N     | Timeout for app health probes in milliseconds                                                                                                                                                                           |                                                |
| `appHealthThreshold`       |    N     | Number of consecutive failures for the app to be considered unhealthy                                                                                                                                                   |                                                |
| `enableApiLogging`         |    N     | Enable the logging of all API calls from application to Dapr                                                                                                                                                            |                                                |
| `env`                      |    N     | Map to environment variable; environment variables applied per application will overwrite environment variables shared across applications                                                                              | `DEBUG`, `DAPR_HOST_ADD`                       |
| `appLogDestination`        |    N     | Log destination for outputting app logs; Its value can be file, console or fileAndConsole. Default is fileAndConsole                                                                                                    | `file`, `console`, `fileAndConsole`            |
| `daprdLogDestination`      |    N     | Log destination for outputting daprd logs; Its value can be file, console or fileAndConsole. Default is file                                                                                                            | `file`, `console`, `fileAndConsole`            |
| `containerImage`           |    N     | URI of the container image to be used when deploying to Kubernetes dev/test environment.                                                                                                                                | `ghcr.io/dapr/samples/hello-k8s-python:latest` |
| `containerImagePullPolicy` |    N     | The container image pull policy (default to `Always`).                                                                                                                                                                  | `Always`, `IfNotPresent`, `Never`              |
| `createService`            |    N     | Create a Kubernetes service for the application when deploying to dev/test environment.                                                                                                                                 | `true`, `false`                                |

{{% /table %}}

## Next steps

Watch [this video for an overview on Multi-App Run in Kubernetes](https://youtu.be/nWatANwaAik?si=O8XR-TUaiY0gclgO&t=1024):

{{< youtube id=nWatANwaAik start=1024 >}}

{{% /tab %}}

{{< /tabpane >}}