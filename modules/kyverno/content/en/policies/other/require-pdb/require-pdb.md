---
title: "Require PodDisruptionBudget"
category: Sample, EKS Best Practices
version: 1.6.0
subject: Deployment, PodDisruptionBudget
policyType: "validate"
description: >
    PodDisruptionBudget resources are useful to ensuring minimum availability is maintained at all times. This policy checks all incoming Deployments and StatefulSets to ensure they have a matching, preexisting PodDisruptionBudget. Note: This policy must be run in `enforce` mode to ensure accuracy.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/require-pdb/require-pdb.yaml" target="-blank">/other/require-pdb/require-pdb.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pdb
  annotations:
    policies.kyverno.io/title: Require PodDisruptionBudget
    policies.kyverno.io/category: Sample, EKS Best Practices
    policies.kyverno.io/minversion: 1.6.0
    kyverno.io/kyverno-version: 1.6.2
    kyverno.io/kubernetes-version: "1.23"
    policies.kyverno.io/subject: Deployment, PodDisruptionBudget
    policies.kyverno.io/description: >-
      PodDisruptionBudget resources are useful to ensuring minimum availability
      is maintained at all times. This policy checks all incoming Deployments and StatefulSets
      to ensure they have a matching, preexisting PodDisruptionBudget.
      Note: This policy must be run in `enforce` mode to ensure accuracy.
spec:
  validationFailureAction: Audit
  background: false
  rules:
    - name: require-pdb
      match:
        any:
          - resources:
              kinds:
                - Deployment
                - StatefulSet
      preconditions:
        all:
          - key: "{{request.operation || 'BACKGROUND'}}"
            operator: Equals
            value: CREATE
          - key: "{{ request.object.spec.replicas }}"
            operator: GreaterThanOrEquals
            value: 3
      context:
        - name: pdb_count
          apiCall:
            urlPath: "/apis/policy/v1/namespaces/{{request.namespace}}/poddisruptionbudgets"
            jmesPath: "items[?label_match(spec.selector.matchLabels, `{{request.object.spec.template.metadata.labels}}`)] | length(@)"
      validate:
        message: "There is no corresponding PodDisruptionBudget found for this Deployment."
        deny:
          conditions:
            any:
              - key: "{{pdb_count}}"
                operator: LessThan
                value: 1

```
