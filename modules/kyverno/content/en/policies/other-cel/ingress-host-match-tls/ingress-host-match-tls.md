---
title: "Ingress Host Match TLS in CEL expressions"
category: Other in CEL
version: 1.11.0
subject: Ingress
policyType: "validate"
description: >
    Ingress resources which name a host name that is not present in the TLS section can produce ingress routing failures as a TLS certificate may not correspond to the destination host. This policy ensures that the host name in an Ingress rule is also found in the list of TLS hosts.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other-cel/ingress-host-match-tls/ingress-host-match-tls.yaml" target="-blank">/other-cel/ingress-host-match-tls/ingress-host-match-tls.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: ingress-host-match-tls
  annotations:
    policies.kyverno.io/title: Ingress Host Match TLS in CEL expressions
    policies.kyverno.io/category: Other in CEL 
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.11.0
    policies.kyverno.io/minversion: 1.11.0
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/subject: Ingress
    policies.kyverno.io/description: >-
      Ingress resources which name a host name that is not present
      in the TLS section can produce ingress routing failures as a TLS
      certificate may not correspond to the destination host. This policy
      ensures that the host name in an Ingress rule is also found
      in the list of TLS hosts.
spec:
  background: false
  validationFailureAction: Audit
  rules:
  - name: host-match-tls
    match:
      any:
      - resources:
          kinds:
          - Ingress
          operations:
          - CREATE
          - UPDATE
    validate:
      cel:
        variables:
          - name: tls
            expression: "object.spec.?tls.orValue([])"
        expressions:
          - expression: >-
              object.spec.rules.all(rule, 
              !has(rule.host) || 
              variables.tls.exists(tls, tls.?hosts.orValue([]).exists(tlsHost, tlsHost == rule.host)))
            message: "The host(s) in spec.rules[].host must match those in spec.tls[].hosts[]."


```
