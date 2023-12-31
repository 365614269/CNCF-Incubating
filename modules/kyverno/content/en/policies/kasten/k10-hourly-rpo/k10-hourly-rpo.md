---
title: "Check Hourly RPO"
category: Kasten K10 by Veeam
version: 1.6.2
subject: Policy
policyType: "validate"
description: >
    K10 Policy resources can be educated to adhere to common Recovery Point Objective (RPO) best practices.  This policy is advising to use an RPO frequency that with hourly granularity if it has the appPriority: Mission Critical
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//kasten/k10-hourly-rpo/k10-hourly-rpo.yaml" target="-blank">/kasten/k10-hourly-rpo/k10-hourly-rpo.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: k10-policy-hourly-rpo
  annotations:
    policies.kyverno.io/title: Check Hourly RPO
    policies.kyverno.io/category: Kasten K10 by Veeam
    kyverno.io/kyverno-version: 1.6.2
    policies.kyverno.io/minversion: 1.6.2
    kyverno.io/kubernetes-version: "1.21-1.22"
    policies.kyverno.io/subject: Policy
    policies.kyverno.io/description: >-
      K10 Policy resources can be educated to adhere to common Recovery Point Objective (RPO) best practices. 
      This policy is advising to use an RPO frequency that with hourly granularity if it has the appPriority: Mission Critical
spec:
  validationFailureAction: audit  
  rules:
  - name: k10-policy-hourly-rpo
    match:
      any:
      - resources:
          kinds:
          - config.kio.kasten.io/v1alpha1/Policy
          selector:
            matchLabels:
              appPriority: Mission-Critical
    validate:
      message: "Mission Critical RPO frequency should use no shorter than @hourly frequency"
      pattern:
        spec:
          frequency: '@hourly'  # In K10, this is checking Hourly at the action: backup level. By default, any action: export will use the action: backup frequency.


```
