---
title: "Validate Schedule"
category: Velero
version: 
subject: Schedule
policyType: "validate"
description: >
    A Velero Schedule is given in Cron format and must be accurate to ensure operation. This policy validates that the schedule is a valid Cron format.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//velero/validate-cron-schedule/validate-cron-schedule.yaml" target="-blank">/velero/validate-cron-schedule/validate-cron-schedule.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: validate-cron-schedule
  annotations:
    policies.kyverno.io/title: Validate Schedule
    policies.kyverno.io/category: Velero
    policies.kyverno.io/subject: Schedule
    policies.kyverno.io/description: >-
      A Velero Schedule is given in Cron format and must be accurate to ensure
      operation. This policy validates that the schedule is a valid Cron format.
spec:
  background: true
  validationFailureAction: Audit
  rules:
  - name: validate-cron
    match:
      any:
      - resources:
          kinds:
          - velero.io/v1/Schedule
    validate:
      message: The backup schedule must be in a valid cron format.
      deny:
        conditions:
          any:
          - key: "{{ regex_match('^((?:\\*|[0-5]?[0-9](?:(?:-[0-5]?[0-9])|(?:,[0-5]?[0-9])+)?)(?:\\/[0-9]+)?)\\s+((?:\\*|(?:1?[0-9]|2[0-3])(?:(?:-(?:1?[0-9]|2[0-3]))|(?:,(?:1?[0-9]|2[0-3]))+)?)(?:\\/[0-9]+)?)\\s+((?:\\*|(?:[1-9]|[1-2][0-9]|3[0-1])(?:(?:-(?:[1-9]|[1-2][0-9]|3[0-1]))|(?:,(?:[1-9]|[1-2][0-9]|3[0-1]))+)?)(?:\\/[0-9]+)?)\\s+((?:\\*|(?:[1-9]|1[0-2])(?:(?:-(?:[1-9]|1[0-2]))|(?:,(?:[1-9]|1[0-2]))+)?)(?:\\/[0-9]+)?)\\s+((?:\\*|[0-7](?:-[0-7]|(?:,[0-7])+)?)(?:\\/[0-9]+)?)$', '{{request.object.spec.schedule}}') }}"
            operator: Equals
            value: false

```
