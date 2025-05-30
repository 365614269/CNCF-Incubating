---
title: "Require Ingress HTTPS in CEL expressions"
category: Other in CEL
version: 
subject: Ingress
policyType: "validate"
description: >
    Ingress resources should only allow secure traffic by disabling HTTP and therefore only allowing HTTPS. This policy requires that all Ingress resources set the annotation `kubernetes.io/ingress.allow-http` to `"false"` and specify TLS in the spec.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other-cel/require-ingress-https/require-ingress-https.yaml" target="-blank">/other-cel/require-ingress-https/require-ingress-https.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ingress-https
  annotations:
    policies.kyverno.io/title: Require Ingress HTTPS in CEL expressions
    policies.kyverno.io/category: Other in CEL 
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/subject: Ingress
    policies.kyverno.io/description: >-
      Ingress resources should only allow secure traffic by disabling
      HTTP and therefore only allowing HTTPS. This policy requires that all
      Ingress resources set the annotation `kubernetes.io/ingress.allow-http` to
      `"false"` and specify TLS in the spec.
spec:
  background: true
  validationFailureAction: Audit
  rules:
  - name: has-annotation
    match:
      any:
      - resources:
          kinds:
          - Ingress
          operations:
          - CREATE
          - UPDATE
    validate:
      cel:
        expressions:
          - expression: >-
              object.metadata.?annotations[?'kubernetes.io/ingress.allow-http'].orValue('default') == 'false'
            message: "The kubernetes.io/ingress.allow-http annotation must be set to false."
  - name: has-tls
    match:
      any:
      - resources:
          kinds:
          - Ingress
          operations:
          - CREATE
          - UPDATE
    validate:
      cel:
        expressions:
          - expression: "has(object.spec.tls)"
            message: "TLS must be defined."


```
