---
title: "Restrict Service Account"
category: Sample
version: 1.6.0
subject: Pod,ServiceAccount
policyType: "validate"
description: >
    Users may be able to specify any ServiceAccount which exists in their Namespace without restrictions. Confining Pods to a list of authorized ServiceAccounts can be useful to ensure applications in those Pods do not have more privileges than they should. This policy verifies that in the `staging` Namespace the ServiceAccount being specified is matched based on the image and name of the container. For example: 'sa-name: ["registry/image-name"]'
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/restrict-service-account/restrict-service-account.yaml" target="-blank">/other/restrict-service-account/restrict-service-account.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-service-account
  annotations:
    policies.kyverno.io/title: Restrict Service Account
    policies.kyverno.io/category: Sample
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod,ServiceAccount
    policies.kyverno.io/minversion: 1.6.0
    kyverno.io/kyverno-version: 1.6.2
    kyverno.io/kubernetes-version: "1.23"
    policies.kyverno.io/description: >-
      Users may be able to specify any ServiceAccount which exists in their Namespace without
      restrictions. Confining Pods to a list of authorized ServiceAccounts can be useful to
      ensure applications in those Pods do not have more privileges than they should.
      This policy verifies that in the `staging` Namespace the ServiceAccount being
      specified is matched based on the image and name of the container. For example:
      'sa-name: ["registry/image-name"]'
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: validate-service-account
    context:
    - name: saMap
      configMap:
        name: sa-map
        namespace: staging
    match:
      any:
      - resources:
          kinds:
          - Pod
          namespaces:
          - staging
    validate:
      message: "Invalid service account {{ request.object.spec.serviceAccountName }} for image {{ images.containers.*.registry | [0] }}/{{ images.containers.*.name | [0] }}"
      deny:
        conditions:
          any:
          - key: "{{ images.containers.*.registry | [0] }}/{{ images.containers.*.name | [0] }}"
            operator: AnyNotIn
            value: "{{ saMap.data.\"{{ request.object.spec.serviceAccountName }}\" }}"
```
