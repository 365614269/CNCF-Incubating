---
title: "Require Non-Root Groups"
category: Sample, EKS Best Practices
version: 1.3.6
subject: Pod
policyType: "validate"
description: >
    Containers should be forbidden from running with a root primary or supplementary GID. This policy ensures the `runAsGroup`, `supplementalGroups`, and `fsGroup` fields are set to a number greater than zero (i.e., non root). A known issue prevents a policy such as this using `anyPattern` from being persisted properly in Kubernetes 1.23.0-1.23.2.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/require-non-root-groups/require-non-root-groups.yaml" target="-blank">/other/require-non-root-groups/require-non-root-groups.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root-groups
  annotations:
    policies.kyverno.io/title: Require Non-Root Groups
    policies.kyverno.io/category: Sample, EKS Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/minversion: 1.3.6
    kyverno.io/kyverno-version: 1.6.0
    kyverno.io/kubernetes-version: "1.22-1.23"
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Containers should be forbidden from running with a root primary or supplementary GID.
      This policy ensures the `runAsGroup`, `supplementalGroups`, and `fsGroup` fields are set to a number
      greater than zero (i.e., non root). A known issue prevents a policy such as this
      using `anyPattern` from being persisted properly in Kubernetes 1.23.0-1.23.2.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: check-runasgroup
      match:
        any:
        - resources:
            kinds:
              - Pod
      validate:
        message: >-
          Running with root group IDs is disallowed. The fields
          spec.securityContext.runAsGroup, spec.containers[*].securityContext.runAsGroup,
          spec.initContainers[*].securityContext.runAsGroup, and
          spec.ephemeralContainers[*].securityContext.runAsGroup must be
          set to a value greater than zero.
        anyPattern:
        - spec:
            securityContext:
              runAsGroup: ">0"
            =(ephemeralContainers):
              - =(securityContext):
                  =(runAsGroup): ">0"
            =(initContainers):
              - =(securityContext):
                  =(runAsGroup): ">0"
            containers:
              - =(securityContext):
                  =(runAsGroup): ">0"
        - spec:
            =(ephemeralContainers):
              - securityContext:
                  runAsGroup: ">0"
            =(initContainers):
              - securityContext:
                  runAsGroup: ">0"
            containers:
              - securityContext:
                  runAsGroup: ">0"
    - name: check-supplementalgroups
      match:
        any:
        - resources:
            kinds:
              - Pod
      validate:
        message: >-
          Containers cannot run with a root primary or supplementary GID. The field
          spec.securityContext.supplementalGroups must be unset or
          set to a value greater than zero.
        pattern:
          spec:
            =(securityContext):
              =(supplementalGroups): ">0"
    - name: check-fsgroup
      match:
        any:
        - resources:
            kinds:
              - Pod
      validate:
        message: >-
          Containers cannot run with a root primary or supplementary GID. The field
          spec.securityContext.fsGroup must be unset or set to a value greater than zero.
        pattern:
          spec:
            =(securityContext):
              =(fsGroup): ">0"

```
