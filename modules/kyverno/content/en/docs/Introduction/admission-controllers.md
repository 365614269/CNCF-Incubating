---
title: Admission Controllers
description: A Guide to Kubernetes Admission Controllers
weight: 35
---

## About Admission Controllers

In Kubernetes, Admission Controllers are responsible for intercepting requests coming to the API server after authenticating and authorizing them but before persisting (saving) them in the backend. They are commonly used to extend Kubernetes beyond its native capabilities.

For example, whenever a new Pod gets created, a request will be sent to the Kubernetes API server. If configured, an admission controller intercepts the request and it may validate, mutate, or do both with the request.

<br>

<img src="/images/kubernetes-admission-controllers.png" alt="Kubernetes Admission Controllers" />

<center>
<i>Credit: Kubernetes documentation.</i>
</center>
<br></br>

Kubernetes provides us with compiled-in admission controllers like LimitRanger that validates if any object in a Kubernetes deployment violates the constraints specified in the LimitRange object. However, these highly specific controllers may not be enough for many organizations with their own policies and default set of practices. For that, in addition to compiled-in admission controllers, dynamic admission controllers can be developed as extensions and run as webhooks configured at runtime.

There are two specific admission controllers which enable extending the API functionality via webhooks:

- _MutatingAdmissionWebhook_: can modify a request.
- _ValidatingAdmissionWebhook_: can validate whether the request should be allowed to run at all.

## Why do we need admission controllers?

Admission controllers were introduced in Kubernetes as a set of plugins for improving cluster security. While some are enabled by default, others must be explicitly enabled by cluster creators or operators.

Some aspects of the built-in Kubernetes operations are in fact governed by admission controllers. For example, when a namespace is deleted and subsequently enters the Terminating state, the NamespaceLifecycle admission controller is what prevents any new objects from being created in this namespace.

The following is the list of some use cases for admission controllers:

- **Pod security:** Admission controllers can increase security by mandating a reasonable security baseline across an entire namespace or cluster. For example, `PodSecurityPolicy` is a built-in admission controller that can be used for disallowing containers from running as root or making sure the container’s root filesystem is always mounted read-only (for example).

- **Governance:** Using Admission controllers you can enforce the adherence to certain practices like having good labels, annotations, resource limits, or other settings. For example, you can enforce label validation on different objects to ensure proper labels are being used, such as every object being assigned to a team or project, or every deployment specifying an app label. In another example, You can enforce annotations automatically being added to objects, such as attributing the correct cost center for a “dev” deployment resource.

- **Configuration management:** Admission controllers allow you to validate the configuration of the objects running in the cluster and prevent any obvious misconfigurations from hitting your cluster. Admission controllers can be useful in detecting and fixing images deployed without semantic tags, such as by automatically adding resource limits or validating resource limits, ensuring reasonable labels are added to pods, or ensuring image references used in production deployments are not using the latest tags, or tags with a -dev suffix.

- **Fine-grained RBAC:** Traditional RBAC (Role-based access control) defines roles and permissions to perform specific actions within a Kubernetes cluster, but it lacks the granularity needed for certain scenarios. Admission controllers addresses this gap by allowing administrators to impose detailed conditions on top of standard RBAC policies. Admission controllers by implementing a more fine grained RBAC enhances security and compliance by enabling administrators to define highly specific conditions for resource creation.

- **Multi-tenancy:** Multi-tenancy enhances resource utilization, reduces operational costs, and promotes agility and collaboration as multiple teams share the same cluster. Many organizations operate internally as multi-tenanted businesses. Kubernetes doesn’t have a native way to enforce boundaries between these tenants, hence admission controllers (like `ResourceQuota` and `LimitRanger`) can be used to enforce limits on consumption and creation of cluster resources (such as CPU time, memory, and persistent storage) within a specified namespace.

- **Cost control:** you can limit specific resources that may have cost implications on your infrastructure. A Predominant cost control measure is to enforce restriction that only one Service of type LoadBalancer can be created.

- **Supply chain security:** Admission controllers act as gatekeepers, validating and authorizing requests based on predefined policies before allowing resources to be admitted into the cluster. Admission controllers can help incorparte supply chain security measures like ensuring images originate from trusted sources, preventing unauthorized modifications, enforcing security policies and much more. For example, with Kyverno you can enforce all images with a specific criteria, such as name, registry or repository etc. must be signed and attested using a specified key.

## Admission Controllers Phases

Admission Controllers can be thought of as a gatekeeper to the API server. They intercept incoming API requests and may change the request object or deny the request altogether. This process of admission control has two phases: the mutating phase (where mutating admission controllers are run), followed by the validating phase (where validating admission controllers are run). Some of the admission controllers act as a combination of both. If any of the admission controllers reject the request, the entire request is rejected and an error is returned to the end-user.

For example, the LimitRanger admission controller can augment pods with default resource requests and limits (mutating phase) if the request doesn't specify it already, as well as it can verify that the pods with explicitly set resource requirements do not exceed the per-namespace limits specified in the LimitRange object (validating phase). Thus acting as a combination of both Mutating as well as Validating admission controller.

## Using Admission Controllers

Admission Controllers can be added by the administrator typically at the time of cluster creating by passing a flag to the `kube-apiserver`.

```sh
kube-apiserver --enable-admision-plugins=NamespaceLifecycle
```

 You can find which admission plugins are enabled by:

```sh
kube-apiserver -h | grep enable-admission-plugins
```

disable-admission-plugins flag is used to disable a comma-delimited list of admission controllers. This list may also include admission controllers enabled by default.

```sh
kube-apiserver --disable-admission-plugins=PodNodeSelector,AlwaysDeny
```

Other than compiled-in admission controllers, you can dynamically configure what resources are subject to what admission webhooks via `ValidatingWebhookConfiguration` or `MutatingWebhookConfiguration`.

Admission webhooks are HTTP callbacks that receive admission requests and do something with them. You can define two types of admission webhooks - validating admission webhook and mutating admission webhook. The following is an example `MutatingWebhookConfiguration`, a validating webhook configuration is similar to this.

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: demo-webhook
webhooks:
  - name: webhook-server.webhook-demo.svc
    clientConfig:
      service:
        name: webhook-server
        namespace: example-namespace
        path: "/mutate"
      caBundle: ${CA_PEM_B64}
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
```

The configuration defines a webhook `webhook-server.webhook-demo.svc`, and instructs the Kubernetes API server to consult the service `webhook-server` in namespace `example-namespace` whenever a pod is created by making a HTTP POST request to the */mutate* URL.

## Admission Controllers (Kubernetes v1.28)

Following is a list of some of the admission controllers enabled by default in the Kubernetes v1.28

| Admission Controllers | Description |
| --- | --- | --- |
| NamespaceLifecycle | Enforces that no new objects can be created when a namespace is in the terminating state |
| LimitRanger | Using the "LimitRange" object type, you set the default and limit CPU/memory resources within a namespace. The LimitRanger admission controller will ensure these defaults and limits are applied |
| ServiceAccount | Implements the ServiceAccount feature |
| DefaultIngressClass | This admission controller observes creation of Ingress objects that do not request any specific ingress class and automatically adds a default ingress class to them. |
| PodSecurity | The PodSecurity admission controller checks new Pods before they are admitted, determines if it should be admitted based on the requested security context and the restrictions on permitted Pod Security Standards for the namespace that the Pod would be in. |

The complete list of admission controllers with their descriptions can be found in [the official Kubernetes docs](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#what-does-each-admission-controller-do).
