---
title: "Disallow Capabilities in ValidatingPolicy"
category: Pod Security Standards (Baseline) in ValidatingPolicy
version: 1.14.0
subject: Pod
policyType: "validate"
description: >
    Adding capabilities beyond those listed in the policy must be disallowed.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-vpol/baseline/disallow-capabilities/disallow-capabilities.yaml" target="-blank">/pod-security-vpol/baseline/disallow-capabilities/disallow-capabilities.yaml</a>

```yaml
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: disallow-capabilities
  annotations:
    policies.kyverno.io/title: Disallow Capabilities in ValidatingPolicy
    policies.kyverno.io/category: Pod Security Standards (Baseline) in ValidatingPolicy
    policies.kyverno.io/severity: medium
    policies.kyverno.io/minversion: 1.14.0
    kyverno.io/kubernetes-version: "1.30+"
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Adding capabilities beyond those listed in the policy must be disallowed.
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
    - name: allowedCapabilities
      expression: >-
        ['AUDIT_WRITE','CHOWN','DAC_OVERRIDE','FOWNER','FSETID','KILL','MKNOD','NET_BIND_SERVICE','SETFCAP','SETGID','SETPCAP','SETUID','SYS_CHROOT']
    - name: allContainers
      expression: >-
        (object.spec.containers + 
        object.spec.?initContainers.orValue([]) + 
        object.spec.?ephemeralContainers.orValue([]))
  validations:
    - expression: >-
        variables.allContainers.all(container, 
        container.?securityContext.?capabilities.?add.orValue([]).all(capability, capability == '' ||
        capability in variables.allowedCapabilities))
      message: >-
          Any capabilities added beyond the allowed list (AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER,
          FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT)
          are disallowed.

```
