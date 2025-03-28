---
title: "Inject Infrastructure Name"
category: OpenShift
version: 1.10.0
subject: MachineSet
policyType: "mutate"
description: >
    A required component of a MachineSet is the infrastructure name which is a random string created in a separate resource. It can be tedious or impossible to know this for each MachineSet created. This policy fetches the value of the infrastructure name from the Cluster resource and replaces all instances of TEMPLATE in a MachineSet with that name.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//openshift/inject-infrastructurename/inject-infrastructurename.yaml" target="-blank">/openshift/inject-infrastructurename/inject-infrastructurename.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: inject-infrastructurename
  annotations:
    policies.kyverno.io/title: Inject Infrastructure Name
    policies.kyverno.io/category: OpenShift
    policies.kyverno.io/severity: medium
    kyverno.io/kyverno-version: 1.10.0
    policies.kyverno.io/minversion: 1.10.0
    kyverno.io/kubernetes-version: "1.26"
    policies.kyverno.io/subject: MachineSet
    policies.kyverno.io/description: >-
      A required component of a MachineSet is the infrastructure name which is a random string
      created in a separate resource. It can be tedious or impossible to know this for each
      MachineSet created. This policy fetches the value of the infrastructure name from the
      Cluster resource and replaces all instances of TEMPLATE in a MachineSet with that name.
spec:
  rules:
  - name: replace-template
    match:
      any:
      - resources:
          kinds:
          - machine.openshift.io/v1beta1/MachineSet
          operations:
          - CREATE
    context:
    - name: cluster
      apiCall:
        urlPath: /apis/config.openshift.io/v1/infrastructures/cluster
    - name: infraid
      variable:
        jmesPath: cluster.status.infrastructureName
    mutate:
      patchesJson6902: |-
        - op: replace
          path: /metadata
          value: {{ replace_all(to_string(request.object.metadata),'TEMPLATE', infraid) }}
        - op: replace
          path: /spec
          value: {{ replace_all(to_string(request.object.spec),'TEMPLATE', infraid) }}

```
