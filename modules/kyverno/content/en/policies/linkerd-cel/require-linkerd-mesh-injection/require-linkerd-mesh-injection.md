---
title: "Require Linkerd Mesh Injection in CEL expressions"
category: Linkerd in CEL
version: 1.11.0
subject: Namespace, Annotation
policyType: "validate"
description: >
    Sidecar proxy injection in Linkerd may be handled at the Namespace level by setting the annotation `linkerd.io/inject` to `enabled`. This policy enforces that all Namespaces contain the annotation `linkerd.io/inject` set to `enabled`.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//linkerd-cel/require-linkerd-mesh-injection/require-linkerd-mesh-injection.yaml" target="-blank">/linkerd-cel/require-linkerd-mesh-injection/require-linkerd-mesh-injection.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-linkerd-mesh-injection
  annotations:
    policies.kyverno.io/title: Require Linkerd Mesh Injection in CEL expressions
    policies.kyverno.io/category: Linkerd in CEL 
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Namespace, Annotation
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      Sidecar proxy injection in Linkerd may be handled at the Namespace level by
      setting the annotation `linkerd.io/inject` to `enabled`. This policy enforces that
      all Namespaces contain the annotation `linkerd.io/inject` set to `enabled`.
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: require-mesh-annotation
    match:
      any:
      - resources:
          kinds:
          - Namespace
          operations:
          - CREATE
          - UPDATE
    validate:
      cel:
        expressions:
          - expression: "object.metadata.?annotations[?'linkerd.io/inject'].orValue('') == 'enabled'"
            message: "All Namespaces must set the annotation `linkerd.io/inject` to `enabled`."


```
