---
title: "Disallow hostPorts Range (Alternate) in CEL expressions"
category: Pod Security Standards (Baseline) in CEL
version: 1.11.0
subject: Pod
policyType: "validate"
description: >
    Access to host ports allows potential snooping of network traffic and should not be allowed, or at minimum restricted to a known list. This policy ensures the `hostPort` field is set to one in the designated list. Note that Kubernetes Pod Security Admission does not support this rule.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-cel/baseline/disallow-host-ports-range/disallow-host-ports-range.yaml" target="-blank">/pod-security-cel/baseline/disallow-host-ports-range/disallow-host-ports-range.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-ports-range
  annotations:
    policies.kyverno.io/title: Disallow hostPorts Range (Alternate) in CEL expressions
    policies.kyverno.io/category: Pod Security Standards (Baseline) in CEL
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      Access to host ports allows potential snooping of network traffic and should not be
      allowed, or at minimum restricted to a known list. This policy ensures the `hostPort`
      field is set to one in the designated list. Note that Kubernetes Pod Security Admission
      does not support this rule.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: host-port-range
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
              expression: >-
               object.spec.containers + 
               object.spec.?initContainers.orValue([]) + 
               object.spec.?ephemeralContainers.orValue([])
          expressions:
            - expression: >- 
                variables.allContainers.all(container, 
                container.?ports.orValue([]).all(port,
                size(port) == 0 ||
                !has(port.hostPort) || (port.hostPort >= 5000 && port.hostPort <= 6000) ))             
              message: >-
                The only permitted hostPorts are in the range 5000-6000.

```
