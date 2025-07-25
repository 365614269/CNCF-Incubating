---
title: "Disallow hostPorts in ValidatingPolicy"
category: Pod Security Standards (Baseline) in ValidatingPolicy
version: 1.14.0
subject: Pod
policyType: "validate"
description: >
    Access to host ports allows potential snooping of network traffic and should not be allowed, or at minimum restricted to a known list. This policy ensures the `hostPort` field is unset or set to `0`. 
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-vpol/baseline/disallow-host-ports/disallow-host-ports.yaml" target="-blank">/pod-security-vpol/baseline/disallow-host-ports/disallow-host-ports.yaml</a>

```yaml
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: disallow-host-ports
  annotations:
    policies.kyverno.io/title: Disallow hostPorts in ValidatingPolicy
    policies.kyverno.io/category: Pod Security Standards (Baseline) in ValidatingPolicy
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.14.0
    kyverno.io/kubernetes-version: "1.30+"
    policies.kyverno.io/description: >-
      Access to host ports allows potential snooping of network traffic and should not be
      allowed, or at minimum restricted to a known list. This policy ensures the `hostPort`
      field is unset or set to `0`. 
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
    - expression: >- 
        variables.allContainers.all(container, 
          container.?ports.orValue([]).all(port, port.?hostPort.orValue(0) == 0))
      message: >-
        Use of host ports is disallowed. The field spec.containers[*].ports[*].hostPort
        must either be unset or set to `0`.
```
