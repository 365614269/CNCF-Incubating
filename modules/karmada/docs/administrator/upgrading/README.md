---
title: Upgrading Instruction
---

## Overview
Karmada uses the [semver versioning](https://semver.org/) and each version in the format of v`MAJOR`.`MINOR`.`PATCH`:
- The `PATCH` release does not introduce breaking changes.
- The `MINOR` release might introduce minor breaking changes with a workaround.
- The `Major` release might introduce backward-incompatible behavior changes.

## Regular Upgrading Process
### Upgrading APIs
For releases that introduce API changes, the Karmada API(CRD) that Karmada components rely on must upgrade to keep consistent.

Karmada CRD is composed of two parts:
- bases: The CRD definition generated via API structs.
- patches: conversion settings for the CRD.

In order to support multiple versions of custom resources, the `patches` should be injected into `bases`.
To achieve this we introduced a `kustomization.yaml` configuration then use `kubectl kustomize` to build the final CRD.

The `bases`,`patches`and `kustomization.yaml` now located at `charts/_crds` directory of the repo.

#### Manual Upgrade API

**Step 1: Get the Webhook CA certificate**

The CA certificate will be injected into `patches` before building the final CRD.
We can retrieve it from the `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration` configurations, e.g:
```bash
kubectl get mutatingwebhookconfigurations.admissionregistration.k8s.io mutating-config
```
Copy the `ca_string` from the yaml path `webhooks.name[x].clientConfig.caBundle`, then replace the `{{caBundle}}` from
the yaml files in `patches`. e.g:
```bash
sed -i'' -e "s/{{caBundle}}/${ca_string}/g" ./"charts/karmada/_crds/patches/webhook_in_resourcebindings.yaml"
sed -i'' -e "s/{{caBundle}}/${ca_string}/g" ./"charts/karmada/_crds/patches/webhook_in_clusterresourcebindings.yaml"
```

**Step2: Build final CRD**

Generate the final CRD by `kubectl kustomize` command, e.g:
```bash
kubectl kustomize ./charts/karmada/_crds 
```
Or, you can apply to `karmada-apiserver` by:
```bash
kubectl kustomize ./charts/karmada/_crds | kubectl apply -f -
```

### Upgrading Components
Components upgrading is composed of image version update and possible command args changes.

> For the argument changes please refer to `Details Upgrading Instruction` below.

## Details Upgrading Instruction

The following instructions are for minor version upgrades. Cross-version upgrades are not recommended.
And it is recommended to use the latest patch version when upgrading, for example, if you are upgrading from 
v1.1.x to v1.2.x and the available patch versions are v1.2.0, v1.2.1 and v1.2.2, then select v1.2.2.

### [v0.8 to v0.9](./v0.8-v0.9.md)
### [v0.9 to v0.10](./v0.9-v0.10.md)
### [v0.10 to v1.0](./v0.10-v1.0.md)
### [v1.0 to v1.1](./v1.0-v1.1.md)
### [v1.1 to v1.2](./v1.1-v1.2.md)
### [v1.2 to v1.3](./v1.2-v1.3.md)
### [v1.3 to v1.4](./v1.3-v1.4.md)
### [v1.4 to v1.5](./v1.4-v1.5.md)
### [v1.5 to v1.6](./v1.5-v1.6.md)
### [v1.6 to v1.7](./v1.6-v1.7.md)
### [v1.7 to v1.8](./v1.7-v1.8.md)
### [v1.8 to v1.9](./v1.8-v1.9.md)
### [v1.9 to v1.10](./v1.9-v1.10.md)
### [v1.10 to v1.11](./v1.10-v1.11.md)
### [v1.11 to v1.12](./v1.11-v1.12.md)
### [v1.12 to v1.13](./v1.12-v1.13.md)
### [v1.13 to v1.14](./v1.13-v1.14.md)
