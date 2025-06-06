---
title: "Disallow procMount in CEL expressions"
category: Pod Security Standards (Baseline) in CEL
version: 1.11.0
subject: Pod
policyType: "validate"
description: >
    The default /proc masks are set up to reduce attack surface and should be required. This policy ensures nothing but the default procMount can be specified. Note that in order for users to deviate from the `Default` procMount requires setting a feature gate at the API server.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-cel/baseline/disallow-proc-mount/disallow-proc-mount.yaml" target="-blank">/pod-security-cel/baseline/disallow-proc-mount/disallow-proc-mount.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-proc-mount
  annotations:
    policies.kyverno.io/title: Disallow procMount in CEL expressions
    policies.kyverno.io/category: Pod Security Standards (Baseline) in CEL
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kyverno-version: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      The default /proc masks are set up to reduce attack surface and should be required. This policy
      ensures nothing but the default procMount can be specified. Note that in order for users
      to deviate from the `Default` procMount requires setting a feature gate at the API
      server.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: check-proc-mount
      match:
        any:
        - resources:
            kinds:
              - Pod
            operations:
            - CREATE
            - UPDATE
      validate:
        cel:
          variables:
            - name: allContainers
              expression: "(object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : []) + (has(object.spec.ephemeralContainers) ? object.spec.ephemeralContainers : []))"
          expressions:
            - expression: "variables.allContainers.all(container, container.?securityContext.?procMount.orValue('Default') == 'Default')"
              message: "Changing the proc mount from the default is not allowed."

```
