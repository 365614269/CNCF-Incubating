---
title: "Restrict sysctls in CEL expressions"
category: Pod Security Standards (Baseline) in CEL
version: 1.11.0
subject: Pod
policyType: "validate"
description: >
    Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed "safe" subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node. This policy ensures that only those "safe" subsets can be specified in a Pod.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//pod-security-cel/baseline/restrict-sysctls/restrict-sysctls.yaml" target="-blank">/pod-security-cel/baseline/restrict-sysctls/restrict-sysctls.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-sysctls
  annotations:
    policies.kyverno.io/title: Restrict sysctls in CEL expressions
    policies.kyverno.io/category: Pod Security Standards (Baseline) in CEL
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kyverno-version: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      Sysctls can disable security mechanisms or affect all containers on a
      host, and should be disallowed except for an allowed "safe" subset. A
      sysctl is considered safe if it is namespaced in the container or the
      Pod, and it is isolated from other Pods or processes on the same Node.
      This policy ensures that only those "safe" subsets can be specified in
      a Pod.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: check-sysctls
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
            - name: allowedSysctls
              expression: "['kernel.shm_rmid_forced','net.ipv4.ip_local_port_range','net.ipv4.ip_unprivileged_port_start','net.ipv4.tcp_syncookies','net.ipv4.ping_group_range']"
          expressions:
            - expression: >- 
                object.spec.?securityContext.?sysctls.orValue([]).all(sysctl, sysctl == '' ||
                has(sysctl.name) && sysctl.name in variables.allowedSysctls)
              message: >-
                Setting additional sysctls above the allowed type is disallowed.
                The field spec.securityContext.sysctls must be unset or not use any other names
                than kernel.shm_rmid_forced, net.ipv4.ip_local_port_range,
                net.ipv4.ip_unprivileged_port_start, net.ipv4.tcp_syncookies and
                net.ipv4.ping_group_range.

```
