---
title: "Restrict NGINX Ingress path values in CEL expressions"
category: Security, NGINX Ingress in CEL
version: 1.11.0
subject: Ingress
policyType: "validate"
description: >
    This policy mitigates CVE-2021-25745 by restricting `spec.rules[].http.paths[].path` to safe values. Additional paths can be added as required. This issue has been fixed in NGINX Ingress v1.2.0.  Please refer to the CVE for details.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//nginx-ingress-cel/restrict-ingress-paths/restrict-ingress-paths.yaml" target="-blank">/nginx-ingress-cel/restrict-ingress-paths/restrict-ingress-paths.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-ingress-paths
  annotations:
    policies.kyverno.io/title: Restrict NGINX Ingress path values in CEL expressions  
    policies.kyverno.io/category: Security, NGINX Ingress in CEL 
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Ingress
    policies.kyverno.io/minversion: "1.11.0"
    kyverno.io/kyverno-version: "1.11.0"
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      This policy mitigates CVE-2021-25745 by restricting `spec.rules[].http.paths[].path` to safe values.
      Additional paths can be added as required. This issue has been fixed in NGINX Ingress v1.2.0. 
      Please refer to the CVE for details.
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-paths
      match:
        any:
        - resources:
            kinds:
            - networking.k8s.io/v1/Ingress
            operations:
            - CREATE
            - UPDATE
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.?rules.orValue([]).all(rule, 
                rule.?http.?paths.orValue([]).all(p, 
                !p.path.contains('/etc') && !p.path.contains('/var/run/secrets') &&
                !p.path.contains('/root') && !p.path.contains('/var/run/kubernetes/serviceaccount') &&
                !p.path.contains('/etc/kubernetes/admin.conf')))
              message: "spec.rules[].http.paths[].path value is not allowed"


```
