---
title: Installing approver-policy
description: 'Installation guide for the approver-policy policy plugin for cert-manager'
---

## Installation Steps

### 1. Install cert-manager

[cert-manager must be installed](../../../installation/README.md), and
the [the default approver in cert-manager must be disabled](../../../usage/certificaterequest.md#approver-controller).

> ⚠️ If the default approver is not disabled in cert-manager, approver-policy will
> race with cert-manager and policy will be ineffective.

If you install cert-manager using `helm install` or `helm upgrade`,
you can disable the default approver by [Customizing the Chart Before Installing](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing) using the `--set` or `--values` command line flags:

```
# Example --set value
--set extraArgs={--controllers='*\,-certificaterequests-approver'} # ⚠ Disable cert-manager's built-in approver
```

```yaml
# Example --values file content
extraArgs:
 - "--controllers=*,-certificaterequests-approver" # ⚠ Disable cert-manager's built-in approver
```

Here's a full example which will install cert-manager or reconfigure it if it is already installed:

```terminal
helm upgrade cert-manager jetstack/cert-manager \
  --install \
  --create-namespace \
  --namespace cert-manager \
  --version [[VAR::cert_manager_latest_version]] \
  --set installCRDs=true \
  --set extraArgs={--controllers='*\,-certificaterequests-approver'} # ⚠ Disable cert-manager's built-in approver
```

> ℹ️ The `--set installCRDs=true` setting is a convenient way to install the
> cert-manager CRDS, but it is optional and has some drawbacks.
> Read [Helm: Installing Custom Resource Definitions](https://deploy-preview-1216--cert-manager-website.netlify.app/docs/installation/helm/#3-install-customresourcedefinitions) to learn more.
>
> ℹ️ Be sure to customize the cert-manager controller `extraArgs`,
> which are at the top level of the values file.
> *Do not* change the `webhook.extraArgs`, `startupAPICheck.extraArgs` or `cainjector.extraArgs` settings.
>
> ⚠️ If you are reconfiguring an already installed cert-manager,
> check whether the original installation already customized the `extraArgs` value
> by running `helm get values cert-manager --namespace cert-manager`.
> If there are already `extraArgs` values, merge those with the extra `--controllers` value.
> Otherwise your original `extraArgs` values will be overwritten.

### 2. Install approver-policy

To install approver-policy:

```terminal
helm repo add jetstack https://charts.jetstack.io --force-update
helm upgrade -i -n cert-manager cert-manager-approver-policy jetstack/cert-manager-approver-policy --wait
```

If you are using approver-policy with [external
issuers](../../../configuration/issuers.md), you _must_
include their signer names so that approver-policy has permissions to approve
and deny CertificateRequests that
[reference them](../../../usage/certificaterequest.md#rbac-syntax).
For example, if using approver-policy for the internal issuer types, along with
[google-cas-issuer](https://github.com/jetstack/google-cas-issuer), and
[aws-privateca-issuer](https://github.com/cert-manager/aws-privateca-issuer),
set the following values when installing:

```terminal
$ helm upgrade -i -n cert-manager cert-manager-approver-policy jetstack/cert-manager-approver-policy --wait \
  --set app.approveSignerNames="{\
issuers.cert-manager.io/*,clusterissuers.cert-manager.io/*,\
googlecasclusterissuers.cas-issuer.jetstack.io/*,googlecasissuers.cas-issuer.jetstack.io/*,\
awspcaclusterissuers.awspca.cert-manager.io/*,awspcaissuers.awspca.cert-manager.io/*\
}"
```

## Usage

> 📖 Read the [approver-policy docs](./README.md).
