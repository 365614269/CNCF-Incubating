---
title: "Drop CAP_NET_RAW"
category: Best Practices
version: 1.6.0
subject: Pod
policyType: "validate"
description: >
    Capabilities permit privileged actions without giving full root access. The CAP_NET_RAW capability, enabled by default, allows processes in a container to forge packets and bind to any interface potentially leading to MitM attacks. This policy ensures that all containers explicitly drop the CAP_NET_RAW ability. Note that this policy also illustrates how to cover drop entries in any case although this may not strictly conform to the Pod Security Standards.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//best-practices/require-drop-cap-net-raw/require-drop-cap-net-raw.yaml" target="-blank">/best-practices/require-drop-cap-net-raw/require-drop-cap-net-raw.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: drop-cap-net-raw
  annotations:
    policies.kyverno.io/title: Drop CAP_NET_RAW
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/minversion: 1.6.0
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Capabilities permit privileged actions without giving full root access. The
      CAP_NET_RAW capability, enabled by default, allows processes in a container to
      forge packets and bind to any interface potentially leading to MitM attacks.
      This policy ensures that all containers explicitly drop the CAP_NET_RAW
      ability. Note that this policy also illustrates how to cover drop entries in any
      case although this may not strictly conform to the Pod Security Standards.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: require-drop-cap-net-raw
      match:
        any:
        - resources:
            kinds:
              - Pod
      preconditions:
        all:
        - key: "{{ request.operation || 'BACKGROUND' }}"
          operator: NotEquals
          value: DELETE
      validate:
        message: >-
          Containers must drop the `CAP_NET_RAW` capability.
        foreach:
          - list: request.object.spec.[ephemeralContainers, initContainers, containers][]
            deny:
              conditions:
                all:
                - key: CAP_NET_RAW
                  operator: AnyNotIn
                  value: "{{ element.securityContext.capabilities.drop[].to_upper(@) || `[]` }}"
                - key: NET_RAW
                  operator: AnyNotIn
                  value: "{{ element.securityContext.capabilities.drop[].to_upper(@) || `[]` }}"

```
