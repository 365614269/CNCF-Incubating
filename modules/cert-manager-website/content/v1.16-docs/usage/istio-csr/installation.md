---
title: Installing istio-csr
description: "Installation guide for cert-manager's Istio integration: istio-csr"
---

## Installation steps

This guide will run through installing and using istio-csr from scratch. We'll use [kind](https://kind.sigs.k8s.io/) to create a new cluster locally in Docker, but this guide should work on any cluster as long as the relevant Istio [Platform Setup](https://istio.io/latest/docs/setup/platform-setup/) has been performed.

Note that if you're following the Platform Setup guide for OpenShift, do not run the `istioctl install` command listed in that guide; we'll run our own command later.

### 0. Background

#### Supported Istio Versions

istio-csr is only tested against a subset of Istio versions, and older Istio versions are generally dropped from tests as they reach end-of-life upstream.

That said, most Istio versions work well with most istio-csr versions, and istio-csr is regularly tested against supported Istio versions for compatibility,
as well as always being tested against the latest Istio release (including Istio pre-releases).

Also note that:

- For Istio Ambient support, istio-csr `v0.12.0` or higher is required
- For Istio version 1.24 and newer, istio-csr `v0.13.0` or higher is required

#### Issuer Configuration

istio-csr uses cert-manager to issue Istio certificates, and needs to be able to reference an issuer resource to do this.

You can choose to configure an issuer when installing with the Helm chart and / or to configure a ConfigMap to watch which can then be used to configure an issuer at runtime.

Configuring a ConfigMap for the issuer details is called "runtime configuration", and it's required if no issuer is specified in the Helm chart.

If you configure an issuer in the chart, you'll be able to start issuing as soon as the istio-csr pods come online but you'll need to have already installed cert-manager and created the issuer.

If you don't set an issuer in the chart, istio-csr will not become ready until an issuer is specified via runtime configuration, but you'll be able to install cert-manager and istio-csr concurrently.

Note that the chart contains a default issuer name and so using runtime configuration requires an explicit opt-in. The guide below assumes you'll install istio-csr after an issuer is configured without runtime configuration; there are notes for runtime configuration at the bottom.

#### Istio Ambient

As of `v0.12.0` istio-csr supports Istio Ambient mode, which allows for pods to be included in the Istio mesh without a side-car container.

To enable Istio Ambient mode support, pass the `app.server.caTrustedNodeAccounts` Helm value, which is a comma-separated list of `namespace/service-accounts` values indicating which service accounts are permitted to use node authentication.

An example would be `--set app.server.caTrustedNodeAccounts=istio-system/ztunnel`

### 1. Initial Setup

You'll need the following tools installed on your machine:

- [istioctl](https://github.com/istio/istio/releases/latest)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) and [docker](https://docs.docker.com/get-docker/) (if you're using kind)
- [helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- [jq](https://stedolan.github.io/jq/download/)

In addition, Istio must not already be installed in your cluster. Installing istio-csr _after_ Istio is not supported.

### 2. Creating the Cluster and Installing cert-manager

Kind will automatically set up kubectl to point to the newly created cluster.

We install cert-manager [using helm](https://cert-manager.io/docs/installation/helm/) here, but if you've got a preferred method you can install in any way.

```console
kind create cluster

# Helm setup
helm repo add jetstack https://charts.jetstack.io --force-update

# install cert-manager; this might take a little time
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version [[VAR::cert_manager_latest_version]] \
  --set crds.enabled=true

# We need this namespace to exist since our cert will be placed there
kubectl create namespace istio-system
```

### 3. Create a cert-manager Issuer and Issuing Certificate

An Issuer tells cert-manager how to issue certificates; we'll create a self-signed root CA in our cluster because it's really simple to configure.

The approach of using a locally generated root certificate would work in a production deployment too, but there are also several [other issuers](https://cert-manager.io/docs/configuration/) in cert-manager which could be used. Note that the ACME issuer **will not work**, since it can't add the required fields to issued certificates.

There are also some comments on the [example-issuer](https://github.com/cert-manager/website/blob/7f5b2be9dd67831574b9bde2407bed4a920b691c/content/docs/tutorials/istio-csr/example/example-issuer.yaml) providing a little more detail. Note also that this guide only uses `Issuer`s and not `ClusterIssuer`s - using a `ClusterIssuer` isn't a drop-in replacement, and in any case we recommend that production deployments use Issuers for easier access controls and scoping.

```console
kubectl apply -f https://raw.githubusercontent.com/cert-manager/website/7f5b2be9dd67831574b9bde2407bed4a920b691c/content/docs/tutorials/istio-csr/example/example-issuer.yaml
```

### 4. Export the Root CA to a Local File

While it's possible to configure Istio such that it can automatically "discover" the root CA, this can be dangerous in
some specific scenarios involving other security holes, enabling [signer hijacking attacks](https://github.com/cert-manager/istio-csr/issues/103#issuecomment-923882792).

As such, we'll export our Root CA and configure Istio later using that static cert.

```console
# Export our cert from the secret it's stored in, and base64 decode to get the PEM data.
kubectl get -n istio-system secret istio-ca -ogo-template='{{index .data "tls.crt"}}' | base64 -d > ca.pem

# Out of interest, we can check out what our CA looks like
openssl x509 -in ca.pem -noout -text

# Add our CA to a secret
kubectl create secret generic -n cert-manager istio-root-ca --from-file=ca.pem=ca.pem
```

### 5. Installing istio-csr

istio-csr is best installed via Helm, and it should be simple and quick to install. There
are a bunch of other configuration options for the helm chart, which you can check out [here](../../usage/istio-csr/README.md).

```console
helm repo add jetstack https://charts.jetstack.io --force-update

# We set a few helm template values so we can point at our static root CA
helm upgrade cert-manager-istio-csr jetstack/cert-manager-istio-csr \
  --install \
  --namespace cert-manager \
  --wait \
  --set "app.tls.rootCAFile=/var/run/secrets/istio-csr/ca.pem" \
  --set "volumeMounts[0].name=root-ca" \
  --set "volumeMounts[0].mountPath=/var/run/secrets/istio-csr" \
  --set "volumes[0].name=root-ca" \
  --set "volumes[0].secret.secretName=istio-root-ca"

# Check to see that the istio-csr pod is running and ready
kubectl get pods -n cert-manager
NAME                                       READY   STATUS    RESTARTS   AGE
cert-manager-aaaaaaaaaa-11111              1/1     Running   0          9m46s
cert-manager-cainjector-aaaaaaaaaa-22222   1/1     Running   0          9m46s
cert-manager-istio-csr-bbbbbbbbbb-00000    1/1     Running   0          63s
cert-manager-webhook-aaaaaaaaa-33333       1/1     Running   0          9m46s
```

### 6. Installing Istio

If you're not running on kind, you may need to do some additional [setup tasks](https://istio.io/latest/docs/setup/platform-setup/) before installing Istio.

We use the `istioctl` CLI to install Istio, configured using a custom IstioOperator manifest.

The custom manifest does the following:

- Disables the CA server in istiod,
- Ensures that Istio workloads request certificates from istio-csr,
- Ensures that the istiod certificates and keys are mounted from the Certificate created when installing istio-csr.

First we download our demo manifest and then we apply it.

```console
curl -sSL https://raw.githubusercontent.com/cert-manager/website/7f5b2be9dd67831574b9bde2407bed4a920b691c/content/docs/tutorials/istio-csr/example/istio-config-getting-started.yaml > istio-install-config.yaml
```

You may wish to inspect and tweak `istio-install-config.yaml` if you know what you're doing,
but this manifest should work for example purposes as-is.

If you set a custom `app.tls.trustDomain` when installing istio-csr via helm earlier, you'll need to ensure that
value is repeated in `istio-install-config.yaml`.

This final command will install Istio; the exact command you need might vary on different platforms,
and will certainly vary on OpenShift.

```console
# This takes a little time to complete
istioctl install -f istio-install-config.yaml

# If you're on OpenShift, you need a different profile:
# istioctl install --set profile=openshift -f istio-install-config.yaml
```

You will be prompted for input to confirm your choice of Istio profile:

```console
This will install the Istio 1.24.0 profile "demo" into the cluster. Proceed?
```

Confirm your selection by entering `y` into the console to proceed with installation.

## Validating Install

The following steps are option but can be followed to validate everything is hooked correctly:

1. Deploy a sample application & watch for `certificaterequests.cert-manager.io` resources
2. Verify `cert-manager` logs for new `certificaterequests` and responses
3. Verify the CA Endpoint being used in a `istio-proxy` sidecar container
4. Using `istioctl` to fetch the certificate info for the `istio-proxy` container

To see this all in action, lets deploy a very simple sample application from the
[Istio samples](https://github.com/istio/istio/tree/master/samples/httpbin).

First set some environment variables whose values could be changed if needed:

```shell
# Set namespace for sample application
export NAMESPACE=default
# Set env var for the value of the app label in manifests
export APP=httpbin
# Grab the installed version of istio
export ISTIO_VERSION=$(istioctl version -o json | jq -r '.meshVersion[0].Info.version')
```

We use the `default` namespace for simplicity, so let's label the namespace for Istio injection:

```shell
kubectl label namespace $NAMESPACE istio-injection=enabled --overwrite
```

In a separate terminal you should now follow the logs for `cert-manager`:

```shell
kubectl logs -n cert-manager $(kubectl get pods -n cert-manager -o jsonpath='{.items..metadata.name}' --selector app=cert-manager) --since 2m -f
```

In another separate terminal, lets watch the `istio-system` namespace for `certificaterequests`:

```shell
kubectl get certificaterequests.cert-manager.io -n istio-system -w
```

Now deploy the sample application `httpbin` in the labeled namespace. Note the use of a
variable to match the manifest version to your installed Istio version:

```shell
kubectl apply -n $NAMESPACE -f https://raw.githubusercontent.com/istio/istio/$ISTIO_VERSION/samples/httpbin/httpbin.yaml
```

You should see something similar to the output here for `certificaterequests`:

```
NAME             APPROVED   DENIED   READY   ISSUER       REQUESTOR                                         AGE
istio-ca-74bnl   True                True    selfsigned   system:serviceaccount:cert-manager:cert-manager   2d2h
istiod-w9zh6     True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager   27m
istio-csr-8ddcs                               istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                        istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
istio-csr-8ddcs   True                True    istio-ca     system:serviceaccount:cert-manager:cert-manager-istio-csr   0s
```

The key request being `istio-csr-8ddcs` in our example output. You should then check your
`cert-manager` log output for two log lines with this request being "Approved" and "Ready":

```
I0113 16:51:59.186482       1 conditions.go:261] Setting lastTransitionTime for CertificateRequest "istio-csr-8ddcs" condition "Approved" to 2022-01-13 16:51:59.186455713 +0000 UTC m=+3507.098466775
I0113 16:51:59.258876       1 conditions.go:261] Setting lastTransitionTime for CertificateRequest "istio-csr-8ddcs" condition "Ready" to 2022-01-13 16:51:59.258837897 +0000 UTC m=+3507.170859959
```

You should now see the application is running with both the application container and the sidecar:

```shell
~ kubectl get pods -n $NAMESPACE
NAME                       READY   STATUS    RESTARTS   AGE
httpbin-74fb669cc6-559cg   2/2     Running   0           4m
```

To validate that the `istio-proxy` sidecar container has requested the certificate from the correct
service, check the container logs:

```shell
kubectl logs $(kubectl get pod -n $NAMESPACE -o jsonpath="{.items...metadata.name}" --selector app=$APP) -c istio-proxy
```

You should see some early logs similar to this example:

```
2022-01-13T16:51:58.495493Z	info	CA Endpoint cert-manager-istio-csr.cert-manager.svc:443, provider Citadel
2022-01-13T16:51:58.495817Z	info	Using CA cert-manager-istio-csr.cert-manager.svc:443 cert with certs: var/run/secrets/istio/root-cert.pem
2022-01-13T16:51:58.495941Z	info	citadelclient	Citadel client using custom root cert: var/run/secrets/istio/root-cert.pem
```

Finally we can inspect the certificate being used in memory by Envoy. This one liner should return you the certificate being used:

```shell
istioctl proxy-config secret $(kubectl get pods -n $NAMESPACE -o jsonpath='{.items..metadata.name}' --selector app=$APP) -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 --decode | openssl x509 -text -noout
```

In particular look for the following sections:

```
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=cert-manager, O=cluster.local, CN=istio-ca
        Validity
            Not Before: Jan 13 16:51:59 2022 GMT
            Not After : Jan 13 17:51:59 2022 GMT
...
            X509v3 Subject Alternative Name:
                URI:spiffe://cluster.local/ns/default/sa/httpbin
```

You should see the relevant Trust Domain inside the Issuer. In the default case, it should be:
`cluster.local` as above. Note that the SPIFFE URI may be different if you used a different
namespace or application.

## Clean up

Assuming your running inside kind, you can simply remove the cluster:

```shell
kind delete cluster
```

## Installation with Runtime Configuration

There are two options for installing with runtime configuration:

1. Install after cert-manager, still providing an explicit `issuerRef` in the Helm chart
2. Blank out the `issuerRef` in the Helm chart and use pure runtime configuration

Both options will require a ConfigMap to be created to point at an issuer. This ConfigMap can be created
before or after installation, and must be created in the same namespace as the istio-csr pods.

### Creating the ConfigMap

Three keys are required, specifying the issuer name, kind and group. Any method of creating a ConfigMap will work. For example:

```bash
kubectl create configmap -n cert-manager istio-issuer \
  --from-literal=issuer-name=my-issuer-name \
  --from-literal=issuer-kind=ClusterIssuer \
  --from-literal=issuer-group=cert-manager.io
```

The Helm chart includes the ability to create the runtime configuration ConfigMap at install time if desired, through the `app.runtimeConfiguration.issuer` values:

```yaml
app:
  runtimeConfiguration:
    issuer:
      name: my-issuer-name
      kind: Issuer
      group: cert-manager.io
```

### Option 1: Installation after cert-manager

If cert-manager is already installed, you can use the same `helm upgrade` command as above but also specifying the name of the runtime configuration ConfigMap:

```bash
helm upgrade cert-manager-istio-csr jetstack/cert-manager-istio-csr \
  --install \
  --namespace cert-manager \
  --wait \
  ...
  --set "app.runtimeConfiguration.name=istio-issuer"
```

In this scenario, the issuer defined in `app.certmanager.issuer` will be used at startup and to create the `istiod` certificate.

When istio-csr detects the runtime ConfigMap, it'll use the issuer configured there. If the ConfigMap is updated, istio-csr will respect the update dynamically.

If the runtime ConfigMap is deleted, istio-csr will revert to using the value from `app.certmanager.issuer`.

### Option 2: Pure Runtime Configuration

Pure runtime configuration is only practical with istio-csr `v0.11.0` or newer.

Pure runtime configuration requires more values to be set:

1. The `app.certmanager.issuer` values must be blanked out (as they're set to a default value in the chart)
2. The `istiod` certificate must not be provisioned alongside the istio-csr resources. By passing `app.tls.istiodCertificateEnable=dynamic`, the istiod will be dynamically generated when runtime configuration is available.
3. `app.runtimeConfiguration.name` must be set.

An example `values.yaml` file for pure runtime configuration is as follows:

```yaml
app:
  runtimeIssuanceConfigMap: istio-issuer
  certmanager:
    issuer:
      enabled: false # Important: the default issuer is enabled by default
  tls:
    rootCAFile: "/var/run/secrets/istio-csr/ca.pem"
    istiodCertificateEnable: dynamic
volumeMounts:
- name: root-ca
  mountPath: /var/run/secrets/istio-csr
volumes:
- name: root-ca
  secret:
    secretName: istio-root-ca
```

This file could then be used with the following command:

```bash
helm upgrade cert-manager-istio-csr jetstack/cert-manager-istio-csr \
  --install \
  --namespace cert-manager \
  --wait \
  --values values.yaml
```

#### Completing a Pure Runtime Installation

To make istio-csr easier to install alongside cert-manager, pure runtime configuration slightly modifies the behavior of
istio-csr's health checks. This is because Helm will not complete an install until the health checks are passing.

If and only if using pure runtime configuration, istio-csr's health checks will report as healthy until runtime configuration is available for the first time.

After runtime configuration becomes available for the first time, the health checks will revert to their normal operation.

## Usage

> 📖 Read the [istio-csr docs](./README.md).
