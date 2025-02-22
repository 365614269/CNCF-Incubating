---
title: "Restrict Cluster Role CSR"
category: Other
version: 
subject: ClusterRole
policyType: "validate"
description: >
    ClusterRoles that grant permissions to approve CertificateSigningRequests should be minimized to reduce powerful identities in the cluster. Approving CertificateSigningRequests allows one to issue new credentials for any user or group. As such, ClusterRoles that grant permissions to approve CertificateSigningRequests are granting cluster admin privileges. Minimize such ClusterRoles to limit the number of powerful credentials that if compromised could take over the entire cluster. For more information, refer to https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/ensure-clusterroles-that-grant-permissions-to-approve-certificatesigningrequests-are-minimized.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/restrict-clusterrole-csr/restrict-clusterrole-csr.yaml" target="-blank">/other/restrict-clusterrole-csr/restrict-clusterrole-csr.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-clusterrole-csr
  annotations:
    policies.kyverno.io/title: Restrict Cluster Role CSR
    policies.kyverno.io/category: Other
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: ClusterRole
    kyverno.io/kyverno-version: 1.11.5
    kyverno.io/kubernetes-version: "1.27"
    policies.kyverno.io/description: >-
      ClusterRoles that grant permissions to approve CertificateSigningRequests should be minimized to reduce powerful identities in the cluster. Approving CertificateSigningRequests allows one to issue new credentials for any user or group. As such, ClusterRoles that grant permissions to approve CertificateSigningRequests are granting cluster admin privileges. Minimize such ClusterRoles to limit the number of powerful credentials that if compromised could take over the entire cluster. For more information, refer to https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/ensure-clusterroles-that-grant-permissions-to-approve-certificatesigningrequests-are-minimized.
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: certificatesigningrequests-update-prevention
    match:
      any:
      - resources:
          kinds:
          - ClusterRole
    validate:
      message: "Use of verbs `update` and `patch` are forbidden for certificatesigningrequests/approval."
      foreach:
      - list: "request.object.rules[?resources.contains(@,'certificatesigningrequests/approval')]"
        deny:
          conditions:
            any:
            - key: ["update", "patch"]
              operator: AnyIn
              value: "{{ element.verbs[] }}"
            - key: "{{ contains(element.verbs[], '*') }}"
              operator: Equals
              value: true
  - name: signers-approve-prevention
    match:
      any:
      - resources:
          kinds:
          - ClusterRole
    validate:
      message: "Use of verbs `approve` are forbidden for signers."
      foreach:
      - list: "request.object.rules[?resources.contains(@,'signers')]"
        deny:
          conditions:
            any:
            - key: ["approve"]
              operator: AnyIn
              value: "{{ element.verbs[] }}"
            - key: "{{ contains(element.verbs[], '*') }}"
              operator: Equals
              value: true

```
