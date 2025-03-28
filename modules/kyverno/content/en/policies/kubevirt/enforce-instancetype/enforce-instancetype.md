---
title: "Enforce instanceTypes"
category: KubeVirt
version: 
subject: VirtualMachine
policyType: "validate"
description: >
    Check VirtualMachines and validate that they are using an instance type and preference.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//kubevirt/enforce-instancetype/enforce-instancetype.yaml" target="-blank">/kubevirt/enforce-instancetype/enforce-instancetype.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: k6t-enforce-instancetype
  annotations:
    policies.kyverno.io/title: Enforce instanceTypes
    policies.kyverno.io/category: KubeVirt
    policies.kyverno.io/subject: VirtualMachine
    policies.kyverno.io/description: >-
      Check VirtualMachines and validate that they are using an instance type and preference.
    kyverno.io/kyverno-version: "1.8.0-rc2"
    kyverno.io/kubernetes-version: "1.24-1.25"
spec:
  validationFailureAction: Enforce
  rules:
  - name: k6t-ensure-instance-type-and-preference
    match:
      any: 
      - resources:
          kinds:
          - VirtualMachine
    validate:
      message: "VirtualMachines must use instance types and preferences"
      pattern:
        spec:
          instancetype:
            name: ?*
          preference:
            name: ?*

```
