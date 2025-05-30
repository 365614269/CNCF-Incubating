---
title: "Disallow Custom Snippets in CEL expressions"
category: Security, NGINX Ingress in CEL
version: 1.11.0
subject: ConfigMap, Ingress
policyType: "validate"
description: >
    Users that can create or update ingress objects can use the custom snippets  feature to obtain all secrets in the cluster (CVE-2021-25742). This policy  disables allow-snippet-annotations in the ingress-nginx configuration and  blocks *-snippet annotations on an Ingress. See: https://github.com/kubernetes/ingress-nginx/issues/7837
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//nginx-ingress-cel/disallow-ingress-nginx-custom-snippets/disallow-ingress-nginx-custom-snippets.yaml" target="-blank">/nginx-ingress-cel/disallow-ingress-nginx-custom-snippets/disallow-ingress-nginx-custom-snippets.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-ingress-nginx-custom-snippets
  annotations:
    policies.kyverno.io/title: Disallow Custom Snippets in CEL expressions
    policies.kyverno.io/category: Security, NGINX Ingress in CEL 
    policies.kyverno.io/subject: ConfigMap, Ingress
    policies.kyverno.io/minversion: "1.11.0"
    kyverno.io/kyverno-version: "1.11.0"
    kyverno.io/kubernetes-version: "1.26-1.27"
    policies.kyverno.io/description: >-
      Users that can create or update ingress objects can use the custom snippets 
      feature to obtain all secrets in the cluster (CVE-2021-25742). This policy 
      disables allow-snippet-annotations in the ingress-nginx configuration and 
      blocks *-snippet annotations on an Ingress.
      See: https://github.com/kubernetes/ingress-nginx/issues/7837
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-config-map
      match:
        any:
        - resources:
            kinds:
            - ConfigMap
            operations:
            - CREATE
            - UPDATE      
      validate:
        cel:
          expressions:
            - expression: "object.?data[?'allow-snippet-annotations'].orValue('false') == 'false'"
              message: "ingress-nginx allow-snippet-annotations must be set to false"
    - name: check-ingress-annotations
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
            - expression: "!object.metadata.?annotations.orValue([]).exists(annotation, annotation.endsWith('-snippet'))"
              message: "ingress-nginx custom snippets are not allowed"


```
