---
title: "Metadata Matches Regex in CEL expressions"
category: Other in CEL
version: 1.11.0
subject: Pod, Label
policyType: "validate"
description: >
    Rather than a simple check to see if given metadata such as labels and annotations are present, in some cases they need to be present and the values match a specified regular expression. This policy illustrates how to ensure a label with key `corp.org/version` is both present and matches a given regex, in this case ensuring semver is met.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other-cel/metadata-match-regex/metadata-match-regex.yaml" target="-blank">/other-cel/metadata-match-regex/metadata-match-regex.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: metadata-match-regex
  annotations:
    policies.kyverno.io/title: Metadata Matches Regex in CEL expressions
    policies.kyverno.io/category: Other in CEL 
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod, Label
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      Rather than a simple check to see if given metadata such as labels and annotations are present,
      in some cases they need to be present and the values match a specified regular expression. This
      policy illustrates how to ensure a label with key `corp.org/version` is both present and matches
      a given regex, in this case ensuring semver is met.
spec:
  validationFailureAction: Audit
  background: false
  rules:
  - name: check-for-regex
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
        expressions:
          - expression: >-
              object.metadata.?labels[?'corp.org/version'].orValue('default').matches('^v[0-9].[0-9].[0-9]$')
            message: >-
              The label `corp.org/version` is required and must match the specified regex: ^v[0-9].[0-9].[0-9]$


```
