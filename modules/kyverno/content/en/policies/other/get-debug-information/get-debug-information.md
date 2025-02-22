---
title: "Collect Debug Information for Pods in CrashLoopBackOff"
category: Other
version: 
subject: Pod
policyType: "generate"
description: >
    This policy generates a job which gathers troubleshooting data (including logs, kubectl describe output and events from the namespace) from pods that are in CrashLoopBackOff and have 3 restarts. This data can further be used to automatically create a Jira issue using some kind of automation or another Kyverno policy. For more information on the image used in this policy in addition to the necessary RBAC resources required in order for this policy to operate, see the documentation at https://github.com/nirmata/SRE-Operational-Usecases/tree/main/get-troubleshooting-data/get-debug-data. 
---

## Policy Definition
<a href="https://github.com/kyverno/policies/raw/main//other/get-debug-information/get-debug-information.yaml" target="-blank">/other/get-debug-information/get-debug-information.yaml</a>

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: get-debug-data-policy
  annotations:
    policies.kyverno.io/title: Collect Debug Information for Pods in CrashLoopBackOff
    policies.kyverno.io/category: Other
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: 1.11.5
    kyverno.io/kubernetes-version: "1.27"
    policies.kyverno.io/description: >-
      This policy generates a job which gathers troubleshooting data (including logs, kubectl describe output and events from the namespace) from pods that are in CrashLoopBackOff and have 3 restarts. This data can further be used to automatically create a Jira issue using some kind of automation or another Kyverno policy. For more information on the image used in this policy in addition to the necessary RBAC resources required in order for this policy to operate, see the documentation at https://github.com/nirmata/SRE-Operational-Usecases/tree/main/get-troubleshooting-data/get-debug-data. 
spec:
  rules:
  - name: get-debug-data-policy-rule
    match:
      any:
      - resources:
          kinds:
          - v1/Pod.status
    context:
    - name: pdcount
      apiCall:
        urlPath: "/api/v1/namespaces/{{request.namespace}}/pods?labelSelector=requestpdname=pod-{{request.object.metadata.name}}"
        jmesPath: "items | length(@)"
    preconditions:
      all:
      - key: "{{ sum(request.object.status.containerStatuses[*].restartCount || `0`) }}"
        operator: Equals
        value: 3
      - key: "{{ request.object.metadata.labels.deleteme || 'empty' }}"
        operator: Equals
        value: "empty"
      - key: "{{ pdcount }}"
        operator: Equals
        value: 0
    generate:
      apiVersion: batch/v1
      kind: Job
      name: get-debug-data-{{request.object.metadata.name}}-{{ random('[0-9a-z]{8}') }}
      namespace: "{{request.namespace}}"
      synchronize: false
      data:
        metadata:
          labels:
            deleteme: allow
        spec:
          template:
            metadata:
              labels:
                app: my-app
                deleteme: allow
                requestpdname: "pod-{{request.object.metadata.name}}"
            spec:
              restartPolicy: OnFailure
              containers:
              - name: my-container
                image: sagarkundral/my-python-app:v52
                ports:
                - containerPort: 8080
                volumeMounts:
                - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
                  name: token
                  readOnly: true
                args:
                - "/app/get-debug-jira-v2.sh"
                - "{{request.namespace}}"
                - "{{request.object.metadata.name}}"
              serviceAccount: default # This serviceaccount needs the necessary RBAC in order for the policy to operate. 
              volumes:
              - name: token
                projected:
                  defaultMode: 420
                  sources:
                  - serviceAccountToken:
                      expirationSeconds: 3607
                      path: token
                  - configMap:
                      items:
                      - key: ca.crt
                        path: ca.crt
                      name: kube-root-ca.crt

```
