---
title: "Enforce Istio Strict mTLS"
category: Istio
version: 1.6.0
subject: PeerAuthentication
policyType: "validate"
description: >
    Strict mTLS requires that mutual TLS be enabled across the entire service mesh, which can be set using a PeerAuthentication resource on a per-Namespace basis and, if set on the `istio-system` Namespace could disable it across the entire mesh. Disabling mTLS can reduce the security for traffic within that portion of the mesh and should be controlled. This policy prevents disabling strict mTLS in a PeerAuthentication resource by requiring the `mode` be set to either `UNSET` or `STRICT`.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//istio/enforce-strict-mtls/enforce-strict-mtls.yaml" target="-blank">/istio/enforce-strict-mtls/enforce-strict-mtls.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-strict-mtls
  annotations:
    policies.kyverno.io/title: Enforce Istio Strict mTLS
    policies.kyverno.io/category: Istio
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: PeerAuthentication
    kyverno.io/kyverno-version: 1.8.0
    policies.kyverno.io/minversion: 1.6.0
    kyverno.io/kubernetes-version: "1.24"
    policies.kyverno.io/description: >- 
      Strict mTLS requires that mutual TLS be enabled across the entire service mesh, which
      can be set using a PeerAuthentication resource on a per-Namespace basis and, if set on
      the `istio-system` Namespace could disable it across the entire mesh. Disabling mTLS
      can reduce the security for traffic within that portion of the mesh and should be controlled.
      This policy prevents disabling strict mTLS in a PeerAuthentication resource by requiring
      the `mode` be set to either `UNSET` or `STRICT`.
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: validate-mtls
    match:
      any:
      - resources:
          kinds:
          - PeerAuthentication
    validate:
      message: "PeerAuthentication resources may only set UNSET or STRICT for the mode."
      pattern:
        =(spec):
          =(mtls):
            =(mode): "UNSET | STRICT"
```
