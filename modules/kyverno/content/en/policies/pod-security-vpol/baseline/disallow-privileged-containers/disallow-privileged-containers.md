---
title: "Disallow Privileged Containers in ValidatingPolicy"
category: Pod Security Standards (Baseline) in ValidatingPolicy
version: 1.14.0
subject: Pod
policyType: "validate"
description: >
    Privileged mode disables most security mechanisms and must not be allowed. This policy ensures Pods do not call for privileged mode.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-vpol/baseline/disallow-privileged-containers/disallow-privileged-containers.yaml" target="-blank">/pod-security-vpol/baseline/disallow-privileged-containers/disallow-privileged-containers.yaml</a>

```yaml
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers in ValidatingPolicy
    policies.kyverno.io/category: Pod Security Standards (Baseline) in ValidatingPolicy
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.14.0
    kyverno.io/kyverno-version: 1.14.0
    kyverno.io/kubernetes-version: "1.30+"
    policies.kyverno.io/description: >-
      Privileged mode disables most security mechanisms and must not be allowed. This policy
      ensures Pods do not call for privileged mode.
spec:
  validationActions:
     - Audit
  evaluation:
    background:
      enabled: true
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE", "UPDATE"]
        resources:   ["pods"]
  variables:
  - name: allContainers
    expression: >-
        object.spec.containers + 
        object.spec.?initContainers.orValue([]) + 
        object.spec.?ephemeralContainers.orValue([])
  validations:
    - expression: "variables.allContainers.all(container, container.?securityContext.?privileged.orValue(false) == false)"
      message: "Privileged mode is disallowed. All containers must set the securityContext.privileged field to `false` or unset the field."
```
