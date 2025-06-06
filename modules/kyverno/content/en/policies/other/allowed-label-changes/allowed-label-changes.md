---
title: "Allowed Label Changes"
category: Other
version: 1.6.0
subject: Pod,Label
policyType: "validate"
description: >
    In some cases, operations teams need a type of limited access to change resources during troubleshooting or outage mitigation. This policy demonstrates how to prevent modification to labels except one with the key `breakglass`. Changing, adding, or deleting any other labels is denied.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/allowed-label-changes/allowed-label-changes.yaml" target="-blank">/other/allowed-label-changes/allowed-label-changes.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: allowed-label-changes
  annotations:
    pod-policies.kyverno.io/autogen-controllers: none
    policies.kyverno.io/title: Allowed Label Changes
    policies.kyverno.io/category: Other
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.6.0
    policies.kyverno.io/minversion: 1.6.0
    kyverno.io/kubernetes-version: "1.23"
    policies.kyverno.io/subject: Pod,Label
    policies.kyverno.io/description: >-
      In some cases, operations teams need a type of limited access to
      change resources during troubleshooting or outage mitigation.
      This policy demonstrates how to prevent modification to labels
      except one with the key `breakglass`. Changing, adding, or deleting
      any other labels is denied.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: safe-label
    match:
      any:
      - resources:
          kinds:
          - Pod
          - Deployment
          - StatefulSet
          - DaemonSet
          - Job
          - CronJob
    preconditions:
      all:
      - key: "{{ request.operation || 'BACKGROUND' }}"
        operator: Equals
        value: UPDATE
    validate:
      message: "The only label that may be removed or changed is `breakglass`."
      deny:
        conditions:
          any:
            - key: "{{ request.object.metadata.labels || `{}` |  merge(@, {breakglass:null}) }}"
              operator: NotEquals
              value: "{{ request.oldObject.metadata.labels || `{}` |  merge(@, {breakglass:null}) }}"
```
