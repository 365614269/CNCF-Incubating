# v1alpha2

Reference information for lifecycle.keptn.sh/v1alpha2

<!-- markdownlint-disable -->

## Packages
- [lifecycle.keptn.sh/v1alpha2](#lifecyclekeptnshv1alpha2)


## lifecycle.keptn.sh/v1alpha2

Package v1alpha2 contains API Schema definitions for the lifecycle v1alpha2 API group

### Resource Types
- [KeptnApp](#keptnapp)
- [KeptnAppList](#keptnapplist)
- [KeptnAppVersion](#keptnappversion)
- [KeptnAppVersionList](#keptnappversionlist)
- [KeptnEvaluation](#keptnevaluation)
- [KeptnEvaluationDefinition](#keptnevaluationdefinition)
- [KeptnEvaluationDefinitionList](#keptnevaluationdefinitionlist)
- [KeptnEvaluationList](#keptnevaluationlist)
- [KeptnTask](#keptntask)
- [KeptnTaskDefinition](#keptntaskdefinition)
- [KeptnTaskDefinitionList](#keptntaskdefinitionlist)
- [KeptnTaskList](#keptntasklist)
- [KeptnWorkload](#keptnworkload)
- [KeptnWorkloadInstance](#keptnworkloadinstance)
- [KeptnWorkloadInstanceList](#keptnworkloadinstancelist)
- [KeptnWorkloadList](#keptnworkloadlist)



#### ConfigMapReference





_Appears in:_
- [FunctionSpec](#functionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `name` _string_ |  || ✓ |




#### EvaluationStatusItem





_Appears in:_
- [KeptnEvaluationStatus](#keptnevaluationstatus)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `value` _string_ |  || x |
| `status` _string_ |  || x |
| `message` _string_ |  || ✓ |


#### FunctionReference





_Appears in:_
- [FunctionSpec](#functionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `name` _string_ |  || ✓ |


#### FunctionSpec





_Appears in:_
- [KeptnTaskDefinitionSpec](#keptntaskdefinitionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `functionRef` _[FunctionReference](#functionreference)_ |  || ✓ |
| `inline` _[Inline](#inline)_ |  || ✓ |
| `httpRef` _[HttpReference](#httpreference)_ |  || ✓ |
| `configMapRef` _[ConfigMapReference](#configmapreference)_ |  || ✓ |
| `parameters` _[TaskParameters](#taskparameters)_ |  || ✓ |
| `secureParameters` _[SecureParameters](#secureparameters)_ |  || ✓ |


#### FunctionStatus





_Appears in:_
- [KeptnTaskDefinitionStatus](#keptntaskdefinitionstatus)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `configMap` _string_ |  || ✓ |


#### HttpReference





_Appears in:_
- [FunctionSpec](#functionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `url` _string_ |  || ✓ |


#### Inline





_Appears in:_
- [FunctionSpec](#functionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `code` _string_ |  || ✓ |


#### ItemStatus





_Appears in:_
- [KeptnAppVersionStatus](#keptnappversionstatus)
- [KeptnWorkloadInstanceStatus](#keptnworkloadinstancestatus)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `definitionName` _string_ | DefinitionName is the name of the EvaluationDefinition/TaskDefinition || ✓ |
| `status` _string_ |  |Pending| ✓ |
| `name` _string_ | Name is the name of the Evaluation/Task || ✓ |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `endTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |


#### KeptnApp



KeptnApp is the Schema for the keptnapps API

_Appears in:_
- [KeptnAppList](#keptnapplist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnApp` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnAppSpec](#keptnappspec)_ |  || ✓ |
| `status` _[KeptnAppStatus](#keptnappstatus)_ |  || ✓ |


#### KeptnAppList



KeptnAppList contains a list of KeptnApp



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnAppList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnApp](#keptnapp) array_ |  || x |


#### KeptnAppSpec



KeptnAppSpec defines the desired state of KeptnApp

_Appears in:_
- [KeptnApp](#keptnapp)
- [KeptnAppVersionSpec](#keptnappversionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `version` _string_ |  || x |
| `revision` _integer_ |  |1| ✓ |
| `workloads` _[KeptnWorkloadRef](#keptnworkloadref) array_ |  || ✓ |
| `preDeploymentTasks` _string array_ |  || ✓ |
| `postDeploymentTasks` _string array_ |  || ✓ |
| `preDeploymentEvaluations` _string array_ |  || ✓ |
| `postDeploymentEvaluations` _string array_ |  || ✓ |


#### KeptnAppStatus



KeptnAppStatus defines the observed state of KeptnApp

_Appears in:_
- [KeptnApp](#keptnapp)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `currentVersion` _string_ |  || ✓ |


#### KeptnAppVersion



KeptnAppVersion is the Schema for the keptnappversions API

_Appears in:_
- [KeptnAppVersionList](#keptnappversionlist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnAppVersion` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnAppVersionSpec](#keptnappversionspec)_ |  || ✓ |
| `status` _[KeptnAppVersionStatus](#keptnappversionstatus)_ |  || ✓ |


#### KeptnAppVersionList



KeptnAppVersionList contains a list of KeptnAppVersion



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnAppVersionList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnAppVersion](#keptnappversion) array_ |  || x |


#### KeptnAppVersionSpec



KeptnAppVersionSpec defines the desired state of KeptnAppVersion

_Appears in:_
- [KeptnAppVersion](#keptnappversion)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `version` _string_ |  || x |
| `revision` _integer_ |  |1| ✓ |
| `workloads` _[KeptnWorkloadRef](#keptnworkloadref) array_ |  || ✓ |
| `preDeploymentTasks` _string array_ |  || ✓ |
| `postDeploymentTasks` _string array_ |  || ✓ |
| `preDeploymentEvaluations` _string array_ |  || ✓ |
| `postDeploymentEvaluations` _string array_ |  || ✓ |
| `appName` _string_ |  || x |
| `previousVersion` _string_ |  || ✓ |
| `traceId` _object (keys:string, values:string)_ |  || ✓ |


#### KeptnAppVersionStatus



KeptnAppVersionStatus defines the observed state of KeptnAppVersion

_Appears in:_
- [KeptnAppVersion](#keptnappversion)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `preDeploymentStatus` _string_ |  |Pending| ✓ |
| `postDeploymentStatus` _string_ |  |Pending| ✓ |
| `preDeploymentEvaluationStatus` _string_ |  |Pending| ✓ |
| `postDeploymentEvaluationStatus` _string_ |  |Pending| ✓ |
| `workloadOverallStatus` _string_ |  |Pending| ✓ |
| `workloadStatus` _[WorkloadStatus](#workloadstatus) array_ |  || ✓ |
| `currentPhase` _string_ |  || ✓ |
| `preDeploymentTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `postDeploymentTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `preDeploymentEvaluationTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `postDeploymentEvaluationTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `phaseTraceIDs` _[MapCarrier](https://pkg.go.dev/go.opentelemetry.io/otel/propagation#MapCarrier)_ |  || ✓ |
| `status` _string_ |  |Pending| ✓ |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `endTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |


#### KeptnEvaluation



KeptnEvaluation is the Schema for the keptnevaluations API

_Appears in:_
- [KeptnEvaluationList](#keptnevaluationlist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnEvaluation` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnEvaluationSpec](#keptnevaluationspec)_ |  || ✓ |
| `status` _[KeptnEvaluationStatus](#keptnevaluationstatus)_ |  || ✓ |


#### KeptnEvaluationDefinition



KeptnEvaluationDefinition is the Schema for the keptnevaluationdefinitions API

_Appears in:_
- [KeptnEvaluationDefinitionList](#keptnevaluationdefinitionlist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnEvaluationDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnEvaluationDefinitionSpec](#keptnevaluationdefinitionspec)_ |  || ✓ |
| `status` _string_ | unused field || ✓ |


#### KeptnEvaluationDefinitionList



KeptnEvaluationDefinitionList contains a list of KeptnEvaluationDefinition



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnEvaluationDefinitionList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnEvaluationDefinition](#keptnevaluationdefinition) array_ |  || x |


#### KeptnEvaluationDefinitionSpec



KeptnEvaluationDefinitionSpec defines the desired state of KeptnEvaluationDefinition

_Appears in:_
- [KeptnEvaluationDefinition](#keptnevaluationdefinition)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `source` _string_ |  || x |
| `objectives` _[Objective](#objective) array_ |  || x |


#### KeptnEvaluationList



KeptnEvaluationList contains a list of KeptnEvaluation



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnEvaluationList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnEvaluation](#keptnevaluation) array_ |  || x |




#### KeptnEvaluationSpec



KeptnEvaluationSpec defines the desired state of KeptnEvaluation

_Appears in:_
- [KeptnEvaluation](#keptnevaluation)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `workload` _string_ |  || ✓ |
| `workloadVersion` _string_ |  || x |
| `appName` _string_ |  || ✓ |
| `appVersion` _string_ |  || ✓ |
| `evaluationDefinition` _string_ |  || x |
| `retries` _integer_ |  |10| ✓ |
| `retryInterval` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#duration-v1-meta)_ |  |5s| ✓ |
| `failAction` _string_ |  || ✓ |
| `checkType` _string_ |  || ✓ |


#### KeptnEvaluationStatus



KeptnEvaluationStatus defines the observed state of KeptnEvaluation

_Appears in:_
- [KeptnEvaluation](#keptnevaluation)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `retryCount` _integer_ |  |0| x |
| `evaluationStatus` _object (keys:string, values:[EvaluationStatusItem](#evaluationstatusitem))_ |  || x |
| `overallStatus` _string_ |  |Pending| x |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `endTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |


#### KeptnTask



KeptnTask is the Schema for the keptntasks API

_Appears in:_
- [KeptnTaskList](#keptntasklist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnTask` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnTaskSpec](#keptntaskspec)_ |  || ✓ |
| `status` _[KeptnTaskStatus](#keptntaskstatus)_ |  || ✓ |


#### KeptnTaskDefinition



KeptnTaskDefinition is the Schema for the keptntaskdefinitions API

_Appears in:_
- [KeptnTaskDefinitionList](#keptntaskdefinitionlist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnTaskDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnTaskDefinitionSpec](#keptntaskdefinitionspec)_ |  || ✓ |
| `status` _[KeptnTaskDefinitionStatus](#keptntaskdefinitionstatus)_ |  || ✓ |


#### KeptnTaskDefinitionList



KeptnTaskDefinitionList contains a list of KeptnTaskDefinition



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnTaskDefinitionList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnTaskDefinition](#keptntaskdefinition) array_ |  || x |


#### KeptnTaskDefinitionSpec



KeptnTaskDefinitionSpec defines the desired state of KeptnTaskDefinition

_Appears in:_
- [KeptnTaskDefinition](#keptntaskdefinition)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `function` _[FunctionSpec](#functionspec)_ |  || ✓ |


#### KeptnTaskDefinitionStatus



KeptnTaskDefinitionStatus defines the observed state of KeptnTaskDefinition

_Appears in:_
- [KeptnTaskDefinition](#keptntaskdefinition)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `function` _[FunctionStatus](#functionstatus)_ |  || ✓ |


#### KeptnTaskList



KeptnTaskList contains a list of KeptnTask



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnTaskList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnTask](#keptntask) array_ |  || x |


#### KeptnTaskSpec



KeptnTaskSpec defines the desired state of KeptnTask

_Appears in:_
- [KeptnTask](#keptntask)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `workload` _string_ |  || x |
| `workloadVersion` _string_ |  || x |
| `app` _string_ |  || x |
| `appVersion` _string_ |  || x |
| `taskDefinition` _string_ |  || x |
| `context` _[TaskContext](#taskcontext)_ |  || x |
| `parameters` _[TaskParameters](#taskparameters)_ |  || ✓ |
| `secureParameters` _[SecureParameters](#secureparameters)_ |  || ✓ |
| `checkType` _string_ |  || ✓ |


#### KeptnTaskStatus



KeptnTaskStatus defines the observed state of KeptnTask

_Appears in:_
- [KeptnTask](#keptntask)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `jobName` _string_ |  || ✓ |
| `status` _string_ |  |Pending| ✓ |
| `message` _string_ |  || ✓ |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `endTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |


#### KeptnWorkload



KeptnWorkload is the Schema for the keptnworkloads API

_Appears in:_
- [KeptnWorkloadList](#keptnworkloadlist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnWorkload` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnWorkloadSpec](#keptnworkloadspec)_ |  || ✓ |
| `status` _[KeptnWorkloadStatus](#keptnworkloadstatus)_ |  || ✓ |


#### KeptnWorkloadInstance



KeptnWorkloadInstance is the Schema for the keptnworkloadinstances API

_Appears in:_
- [KeptnWorkloadInstanceList](#keptnworkloadinstancelist)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnWorkloadInstance` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation about [`metadata`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/#attaching-metadata-to-objects). || ✓ |
| `spec` _[KeptnWorkloadInstanceSpec](#keptnworkloadinstancespec)_ |  || ✓ |
| `status` _[KeptnWorkloadInstanceStatus](#keptnworkloadinstancestatus)_ |  || ✓ |


#### KeptnWorkloadInstanceList



KeptnWorkloadInstanceList contains a list of KeptnWorkloadInstance



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnWorkloadInstanceList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnWorkloadInstance](#keptnworkloadinstance) array_ |  || x |


#### KeptnWorkloadInstanceSpec



KeptnWorkloadInstanceSpec defines the desired state of KeptnWorkloadInstance

_Appears in:_
- [KeptnWorkloadInstance](#keptnworkloadinstance)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `app` _string_ |  || x |
| `version` _string_ |  || x |
| `preDeploymentTasks` _string array_ |  || ✓ |
| `postDeploymentTasks` _string array_ |  || ✓ |
| `preDeploymentEvaluations` _string array_ |  || ✓ |
| `postDeploymentEvaluations` _string array_ |  || ✓ |
| `resourceReference` _[ResourceReference](#resourcereference)_ |  || x |
| `workloadName` _string_ |  || x |
| `previousVersion` _string_ |  || ✓ |
| `traceId` _object (keys:string, values:string)_ |  || ✓ |


#### KeptnWorkloadInstanceStatus



KeptnWorkloadInstanceStatus defines the observed state of KeptnWorkloadInstance

_Appears in:_
- [KeptnWorkloadInstance](#keptnworkloadinstance)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `preDeploymentStatus` _string_ |  |Pending| ✓ |
| `deploymentStatus` _string_ |  |Pending| ✓ |
| `preDeploymentEvaluationStatus` _string_ |  |Pending| ✓ |
| `postDeploymentEvaluationStatus` _string_ |  |Pending| ✓ |
| `postDeploymentStatus` _string_ |  |Pending| ✓ |
| `preDeploymentTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `postDeploymentTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `preDeploymentEvaluationTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `postDeploymentEvaluationTaskStatus` _[ItemStatus](#itemstatus) array_ |  || ✓ |
| `startTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `endTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta)_ |  || ✓ |
| `currentPhase` _string_ |  || ✓ |
| `phaseTraceIDs` _[MapCarrier](https://pkg.go.dev/go.opentelemetry.io/otel/propagation#MapCarrier)_ |  || ✓ |
| `status` _string_ |  |Pending| ✓ |


#### KeptnWorkloadList



KeptnWorkloadList contains a list of KeptnWorkload



| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `lifecycle.keptn.sh/v1alpha2` | | |
| `kind` _string_ | `KeptnWorkloadList` | | |
| `metadata` _[ListMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#listmeta-v1-meta)_ |  || ✓ |
| `items` _[KeptnWorkload](#keptnworkload) array_ |  || x |


#### KeptnWorkloadRef





_Appears in:_
- [KeptnAppSpec](#keptnappspec)
- [KeptnAppVersionSpec](#keptnappversionspec)
- [WorkloadStatus](#workloadstatus)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `name` _string_ |  || x |
| `version` _string_ |  || x |


#### KeptnWorkloadSpec



KeptnWorkloadSpec defines the desired state of KeptnWorkload

_Appears in:_
- [KeptnWorkload](#keptnworkload)
- [KeptnWorkloadInstanceSpec](#keptnworkloadinstancespec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `app` _string_ |  || x |
| `version` _string_ |  || x |
| `preDeploymentTasks` _string array_ |  || ✓ |
| `postDeploymentTasks` _string array_ |  || ✓ |
| `preDeploymentEvaluations` _string array_ |  || ✓ |
| `postDeploymentEvaluations` _string array_ |  || ✓ |
| `resourceReference` _[ResourceReference](#resourcereference)_ |  || x |


#### KeptnWorkloadStatus



KeptnWorkloadStatus defines the observed state of KeptnWorkload

_Appears in:_
- [KeptnWorkload](#keptnworkload)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `currentVersion` _string_ |  || ✓ |


#### Objective





_Appears in:_
- [KeptnEvaluationDefinitionSpec](#keptnevaluationdefinitionspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `name` _string_ |  || x |
| `query` _string_ |  || x |
| `evaluationTarget` _string_ |  || x |


#### ResourceReference





_Appears in:_
- [KeptnWorkloadInstanceSpec](#keptnworkloadinstancespec)
- [KeptnWorkloadSpec](#keptnworkloadspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `uid` _string_ |  || x |
| `kind` _string_ |  || x |
| `name` _string_ |  || x |


#### SecureParameters





_Appears in:_
- [FunctionSpec](#functionspec)
- [KeptnTaskSpec](#keptntaskspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `secret` _string_ |  || ✓ |


#### TaskContext





_Appears in:_
- [KeptnTaskSpec](#keptntaskspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `workloadName` _string_ |  || x |
| `appName` _string_ |  || x |
| `appVersion` _string_ |  || x |
| `workloadVersion` _string_ |  || x |
| `taskType` _string_ |  || x |
| `objectType` _string_ |  || x |


#### TaskParameters





_Appears in:_
- [FunctionSpec](#functionspec)
- [KeptnTaskSpec](#keptntaskspec)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `map` _object (keys:string, values:string)_ |  || ✓ |


#### WorkloadStatus





_Appears in:_
- [KeptnAppVersionStatus](#keptnappversionstatus)

| Field | Description | Default | Optional |
| --- | --- | --- | --- |
| `workload` _[KeptnWorkloadRef](#keptnworkloadref)_ |  || ✓ |
| `status` _string_ |  |Pending| ✓ |


