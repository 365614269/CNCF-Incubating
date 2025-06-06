---
title: "Add PSA Namespace Reporting in CEL expressions"
category: Pod Security Admission, EKS Best Practices in CEL
version: 1.11.0
subject: Namespace
policyType: "validate"
description: >
    This policy is valuable as it ensures that all namespaces within a Kubernetes  cluster are labeled with Pod Security Admission (PSA) labels, which are crucial for defining security levels and ensuring that pods within a namespace operate  under the defined Pod Security Standard (PSS). By enforcing namespace labeling, This policy audits namespaces to verify the presence of PSA labels.  If a namespace is found without the required labels, it generates and maintain  and ClusterPolicy Report in default namespace.  This helps administrators identify namespaces that do not comply with the  organization's security practices and take appropriate action to rectify the  situation.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//psa-cel/add-psa-namespace-reporting/add-psa-namespace-reporting.yaml" target="-blank">/psa-cel/add-psa-namespace-reporting/add-psa-namespace-reporting.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-psa-namespace-reporting
  annotations:
    policies.kyverno.io/title: Add PSA Namespace Reporting in CEL expressions
    policies.kyverno.io/category: Pod Security Admission, EKS Best Practices in CEL 
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.11.0
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/subject: Namespace
    policies.kyverno.io/description: >-
      This policy is valuable as it ensures that all namespaces within a Kubernetes 
      cluster are labeled with Pod Security Admission (PSA) labels, which are crucial
      for defining security levels and ensuring that pods within a namespace operate 
      under the defined Pod Security Standard (PSS). By enforcing namespace labeling,
      This policy audits namespaces to verify the presence of PSA labels. 
      If a namespace is found without the required labels, it generates and maintain 
      and ClusterPolicy Report in default namespace. 
      This helps administrators identify namespaces that do not comply with the 
      organization's security practices and take appropriate action to rectify the 
      situation.
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: check-namespace-labels
    match:
      any:
      - resources:
          kinds:
            - Namespace
          operations:
          - CREATE
          - UPDATE
    validate:
      cel:
        expressions:
          - expression: "object.metadata.?labels.orValue([]).exists(label, label.startsWith('pod-security.kubernetes.io/') && object.metadata.labels[label] != '')"
            message: This Namespace is missing a PSA label.


```
