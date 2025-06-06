---
title: "Require QoS Guaranteed"
category: Other, Multi-Tenancy
version: 
subject: Pod
policyType: "validate"
description: >
    Pod Quality of Service (QoS) is a mechanism to ensure Pods receive certain priority guarantees based upon the resources they define. When Pods define both requests and limits for both memory and CPU, and the requests and limits are equal to each other, Kubernetes grants the QoS class as guaranteed which allows them to run at a higher priority than others. This policy requires that all containers within a Pod run with this definition resulting in a guaranteed QoS. This policy is provided with the intention that users will need to control its scope by using exclusions, preconditions, and other policy language mechanisms.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/require-qos-guaranteed/require-qos-guaranteed.yaml" target="-blank">/other/require-qos-guaranteed/require-qos-guaranteed.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-qos-guaranteed
  annotations:
    policies.kyverno.io/title: Require QoS Guaranteed
    policies.kyverno.io/category: Other, Multi-Tenancy
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Pod Quality of Service (QoS) is a mechanism to ensure Pods receive certain
      priority guarantees based upon the resources they define. When Pods define both
      requests and limits for both memory and CPU, and the requests and limits are equal
      to each other, Kubernetes grants the QoS class as guaranteed which allows them to run
      at a higher priority than others. This policy requires that all containers within a Pod
      run with this definition resulting in a guaranteed QoS. This policy is provided with the
      intention that users will need to control its scope by using
      exclusions, preconditions, and other policy language mechanisms.
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: guaranteed
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "All containers must define memory and CPU requests and limits where they are equal."
      foreach:
      - list: "request.object.spec.containers"
        pattern:
          resources:
            requests:
              cpu: "?*"
              memory: "?*"
            limits:
              cpu: "{{element.resources.requests.cpu}}"
              memory: "{{element.resources.requests.memory}}"
```
