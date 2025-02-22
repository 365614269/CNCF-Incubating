---
title: "Require Run As ContainerUser (Windows)"
category: Windows Security
version: 
subject: Pod
policyType: "validate"
description: >
    Containers must be required to run as ContainerUser. This policy ensures that the fields  spec.securityContext.windowsOptions.runAsUserName, spec.containers[*].securityContext.windowsOptions.runAsUserName,  spec.initContainers[*].securityContext.windowsOptions.runAsUserName, and  is either unset or set to ContainerUser.
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//windows-security/require-run-as-containeruser/require-run-as-containeruser.yaml" target="-blank">/windows-security/require-run-as-containeruser/require-run-as-containeruser.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-run-as-containeruser
  annotations:
    policies.kyverno.io/title: Require Run As ContainerUser (Windows)
    policies.kyverno.io/category: Windows Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: 1.6.0
    kyverno.io/kubernetes-version: "1.22-1.28"
    policies.kyverno.io/description: >-
      Containers must be required to run as ContainerUser. This policy ensures that the fields 
      spec.securityContext.windowsOptions.runAsUserName,
      spec.containers[*].securityContext.windowsOptions.runAsUserName, 
      spec.initContainers[*].securityContext.windowsOptions.runAsUserName,
      and  is either unset or set to ContainerUser.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: require-run-as-containeruser
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >-
          Running the container as ContainerAdministrator,NT AUTHORITY\NETWORK SERVICE, NT AUTHORITY\LOCAL SERVICE is not allowed.
        pattern:
          spec:
            =(securityContext):
              =(windowsOptions):
                =(runAsUserName): "ContainerUser"
            =(initContainers):
              - =(securityContext):
                  =(windowsOptions):
                    =(runAsUserName): "ContainerUser"
            containers:
              - =(securityContext):
                  =(windowsOptions):
                    =(runAsUserName): "ContainerUser"

```
