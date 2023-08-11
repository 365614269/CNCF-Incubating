---
id: cri-o
title: CRI-O
slug: /setup/runtime/cri-o
---

Use dfget daemon as registry mirror for CRI-O

## Step 1: Validate Dragonfly Configuration {#step-1-validate-dragonfly-configuration}

To use dfget daemon as registry mirror,
first you need to ensure configuration in `/etc/dragonfly/dfget.yaml`:

```yaml
proxy:
  security:
    insecure: true
  tcpListen:
    listen: 0.0.0.0
    port: 65001
  registryMirror:
    url: https://index.docker.io
  proxies:
    - regx: blobs/sha256.*
```

This will proxy all requests for image layers with dfget.

## Step 2: Validate CRI-O Configuration {#step-2-validate-cri-o-configuration}

Then, enable mirrors in CRI-O registries configuration in
`/etc/containers/registries.conf`:

```toml
[[registry]]
location = "docker.io"
  [[registry.mirror]]
  location = "127.0.0.1:65001"
  insecure = true
```

## Step 3: Restart CRI-O Daemon {#step-3-restart-cri-o-daemon}

```shell
systemctl restart crio
```

If encounter error like these:
`mixing sysregistry v1/v2 is not supported` or
`registry must be in v2 format but is in v1`,
please convert your registries configuration to v2.

## Step 4: Pull Image {#step-4-pull-image}

You can pull image like this:

```shell
crictl pull docker.io/library/busybox
```

## Step 5: Validate Dragonfly {#step-5-validate-dragonfly}

You can execute the following command to
check if the busybox image is distributed via Dragonfly.

```shell
grep 'register peer task result' /var/log/dragonfly/daemon/*.log
```

If the output of command above has content like

```shell
{
    "level": "info",
    "ts": "2021-02-23 20:03:20.306",
    "caller": "client/client.go:83",
    "msg": "register peer task result:true[200] for taskId:adf62a86f001e17037eedeaaba3393f3519b80ce,peerIp:10.15.233.91,securityDomain:,idc:,scheduler:127.0.0.1:8002",
    "peerId": "10.15.233.91-65000-43096-1614081800301788000",
    "errMsg": null
}
```
