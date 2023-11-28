/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	"fmt"
	"time"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1alpha2/common"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KeptnWorkloadInstanceSpec defines the desired state of KeptnWorkloadInstance
type KeptnWorkloadInstanceSpec struct {
	KeptnWorkloadSpec `json:",inline"`
	WorkloadName      string `json:"workloadName"`
	// +optional
	PreviousVersion string `json:"previousVersion,omitempty"`
	// +optional
	TraceId map[string]string `json:"traceId,omitempty"`
}

// KeptnWorkloadInstanceStatus defines the observed state of KeptnWorkloadInstance
type KeptnWorkloadInstanceStatus struct {
	// +kubebuilder:default:=Pending
	// +optional
	PreDeploymentStatus common.KeptnState `json:"preDeploymentStatus,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	DeploymentStatus common.KeptnState `json:"deploymentStatus,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	PreDeploymentEvaluationStatus common.KeptnState `json:"preDeploymentEvaluationStatus,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	PostDeploymentEvaluationStatus common.KeptnState `json:"postDeploymentEvaluationStatus,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	PostDeploymentStatus common.KeptnState `json:"postDeploymentStatus,omitempty"`
	// +optional
	PreDeploymentTaskStatus []ItemStatus `json:"preDeploymentTaskStatus,omitempty"`
	// +optional
	PostDeploymentTaskStatus []ItemStatus `json:"postDeploymentTaskStatus,omitempty"`
	// +optional
	PreDeploymentEvaluationTaskStatus []ItemStatus `json:"preDeploymentEvaluationTaskStatus,omitempty"`
	// +optional
	PostDeploymentEvaluationTaskStatus []ItemStatus `json:"postDeploymentEvaluationTaskStatus,omitempty"`
	// +optional
	StartTime metav1.Time `json:"startTime,omitempty"`
	// +optional
	EndTime metav1.Time `json:"endTime,omitempty"`
	// +optional
	CurrentPhase string `json:"currentPhase,omitempty"`
	// +optional
	PhaseTraceIDs common.PhaseTraceID `json:"phaseTraceIDs,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	Status common.KeptnState `json:"status,omitempty"`
}

type ItemStatus struct {
	// DefinitionName is the name of the EvaluationDefinition/TaskDefinition
	// +optional
	DefinitionName string `json:"definitionName,omitempty"`
	// +kubebuilder:default:=Pending
	// +optional
	Status common.KeptnState `json:"status,omitempty"`
	// Name is the name of the Evaluation/Task
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	StartTime metav1.Time `json:"startTime,omitempty"`
	// +optional
	EndTime metav1.Time `json:"endTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=keptnworkloadinstances,shortName=kwi
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="AppName",type=string,JSONPath=`.spec.app`
// +kubebuilder:printcolumn:name="WorkloadName",type=string,JSONPath=`.spec.workloadName`
// +kubebuilder:printcolumn:name="WorkloadVersion",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.currentPhase`
// +kubebuilder:printcolumn:name="PreDeploymentStatus",priority=1,type=string,JSONPath=`.status.preDeploymentStatus`
// +kubebuilder:printcolumn:name="PreDeploymentEvaluationStatus",priority=1,type=string,JSONPath=`.status.preDeploymentEvaluationStatus`
// +kubebuilder:printcolumn:name="DeploymentStatus",type=string,priority=1,JSONPath=`.status.deploymentStatus`
// +kubebuilder:printcolumn:name="PostDeploymentStatus",type=string,priority=1,JSONPath=`.status.postDeploymentStatus`
// +kubebuilder:printcolumn:name="PostDeploymentEvaluationStatus",priority=1,type=string,JSONPath=`.status.postDeploymentEvaluationStatus`

// KeptnWorkloadInstance is the Schema for the keptnworkloadinstances API
type KeptnWorkloadInstance struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec KeptnWorkloadInstanceSpec `json:"spec,omitempty"`
	// +optional
	Status KeptnWorkloadInstanceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnWorkloadInstanceList contains a list of KeptnWorkloadInstance
type KeptnWorkloadInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnWorkloadInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnWorkloadInstance{}, &KeptnWorkloadInstanceList{})
}

func (w KeptnWorkloadInstanceList) GetItems() []client.Object {
	var b []client.Object
	for i := 0; i < len(w.Items); i++ {
		b = append(b, &w.Items[i])
	}
	return b
}

func (w KeptnWorkloadInstance) IsPreDeploymentCompleted() bool {
	return w.Status.PreDeploymentStatus.IsCompleted()
}

func (w KeptnWorkloadInstance) IsPreDeploymentEvaluationCompleted() bool {
	return w.Status.PreDeploymentEvaluationStatus.IsCompleted()
}

func (w KeptnWorkloadInstance) IsPreDeploymentSucceeded() bool {
	return w.Status.PreDeploymentStatus.IsSucceeded()
}

func (w KeptnWorkloadInstance) IsPreDeploymentFailed() bool {
	return w.Status.PreDeploymentStatus.IsFailed()
}

func (w KeptnWorkloadInstance) IsPreDeploymentEvaluationSucceeded() bool {
	return w.Status.PreDeploymentEvaluationStatus.IsSucceeded()
}

func (w KeptnWorkloadInstance) IsPreDeploymentEvaluationFailed() bool {
	return w.Status.PreDeploymentEvaluationStatus.IsFailed()
}

func (w KeptnWorkloadInstance) IsPostDeploymentCompleted() bool {
	return w.Status.PostDeploymentStatus.IsCompleted()
}

func (w KeptnWorkloadInstance) IsPostDeploymentEvaluationCompleted() bool {
	return w.Status.PostDeploymentEvaluationStatus.IsCompleted()
}

func (w KeptnWorkloadInstance) IsPostDeploymentSucceeded() bool {
	return w.Status.PostDeploymentStatus.IsSucceeded()
}

func (w KeptnWorkloadInstance) IsPostDeploymentFailed() bool {
	return w.Status.PostDeploymentStatus.IsFailed()
}

func (w KeptnWorkloadInstance) IsPostDeploymentEvaluationSucceeded() bool {
	return w.Status.PostDeploymentEvaluationStatus.IsSucceeded()
}

func (w KeptnWorkloadInstance) IsPostDeploymentEvaluationFailed() bool {
	return w.Status.PostDeploymentEvaluationStatus.IsFailed()
}

func (w KeptnWorkloadInstance) IsDeploymentCompleted() bool {
	return w.Status.DeploymentStatus.IsCompleted()
}

func (w KeptnWorkloadInstance) IsDeploymentSucceeded() bool {
	return w.Status.DeploymentStatus.IsSucceeded()
}

func (w KeptnWorkloadInstance) IsDeploymentFailed() bool {
	return w.Status.DeploymentStatus.IsFailed()
}

func (w *KeptnWorkloadInstance) SetStartTime() {
	if w.Status.StartTime.IsZero() {
		w.Status.StartTime = metav1.NewTime(time.Now().UTC())
	}
}

func (w *KeptnWorkloadInstance) SetEndTime() {
	if w.Status.EndTime.IsZero() {
		w.Status.EndTime = metav1.NewTime(time.Now().UTC())
	}
}

func (w *KeptnWorkloadInstance) IsStartTimeSet() bool {
	return !w.Status.StartTime.IsZero()
}

func (w *KeptnWorkloadInstance) IsEndTimeSet() bool {
	return !w.Status.EndTime.IsZero()
}

func (w KeptnWorkloadInstance) GetStartTime() time.Time {
	return w.Status.StartTime.Time
}

func (w KeptnWorkloadInstance) GetEndTime() time.Time {
	return w.Status.EndTime.Time
}

func (w *KeptnWorkloadInstance) Complete() {
	w.SetEndTime()
}

func (e *ItemStatus) SetStartTime() {
	if e.StartTime.IsZero() {
		e.StartTime = metav1.NewTime(time.Now().UTC())
	}
}

func (e *ItemStatus) SetEndTime() {
	if e.EndTime.IsZero() {
		e.EndTime = metav1.NewTime(time.Now().UTC())
	}
}

func (w KeptnWorkloadInstance) GetActiveMetricsAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		common.AppName.String(w.Spec.AppName),
		common.WorkloadName.String(w.Spec.WorkloadName),
		common.WorkloadVersion.String(w.Spec.Version),
		common.WorkloadNamespace.String(w.Namespace),
	}
}

func (w KeptnWorkloadInstance) GetMetricsAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		common.AppName.String(w.Spec.AppName),
		common.WorkloadName.String(w.Spec.WorkloadName),
		common.WorkloadVersion.String(w.Spec.Version),
		common.WorkloadNamespace.String(w.Namespace),
		common.WorkloadStatus.String(string(w.Status.Status)),
	}
}

func (w KeptnWorkloadInstance) GetDurationMetricsAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		common.AppName.String(w.Spec.AppName),
		common.WorkloadName.String(w.Spec.WorkloadName),
		common.WorkloadVersion.String(w.Spec.Version),
		common.WorkloadPreviousVersion.String(w.Spec.PreviousVersion),
	}
}

func (w KeptnWorkloadInstance) GetState() common.KeptnState {
	return w.Status.Status
}

func (w KeptnWorkloadInstance) GetPreDeploymentTasks() []string {
	return w.Spec.PreDeploymentTasks
}

func (w KeptnWorkloadInstance) GetPostDeploymentTasks() []string {
	return w.Spec.PostDeploymentTasks
}

func (w KeptnWorkloadInstance) GetPreDeploymentTaskStatus() []ItemStatus {
	return w.Status.PreDeploymentTaskStatus
}

func (w KeptnWorkloadInstance) GetPostDeploymentTaskStatus() []ItemStatus {
	return w.Status.PostDeploymentTaskStatus
}

func (w KeptnWorkloadInstance) GetPreDeploymentEvaluations() []string {
	return w.Spec.PreDeploymentEvaluations
}

func (w KeptnWorkloadInstance) GetPostDeploymentEvaluations() []string {
	return w.Spec.PostDeploymentEvaluations
}

func (w KeptnWorkloadInstance) GetPreDeploymentEvaluationTaskStatus() []ItemStatus {
	return w.Status.PreDeploymentEvaluationTaskStatus
}

func (w KeptnWorkloadInstance) GetPostDeploymentEvaluationTaskStatus() []ItemStatus {
	return w.Status.PostDeploymentEvaluationTaskStatus
}

func (w KeptnWorkloadInstance) GetAppName() string {
	return w.Spec.AppName
}

func (w KeptnWorkloadInstance) GetPreviousVersion() string {
	return w.Spec.PreviousVersion
}

func (w KeptnWorkloadInstance) GetParentName() string {
	return w.Spec.WorkloadName
}

func (w KeptnWorkloadInstance) GetNamespace() string {
	return w.Namespace
}

func (w *KeptnWorkloadInstance) SetState(state common.KeptnState) {
	w.Status.Status = state
}

func (w KeptnWorkloadInstance) GetCurrentPhase() string {
	return w.Status.CurrentPhase
}

func (w *KeptnWorkloadInstance) SetCurrentPhase(phase string) {
	w.Status.CurrentPhase = phase
}

func (w KeptnWorkloadInstance) GetVersion() string {
	return w.Spec.Version
}

func (w KeptnWorkloadInstance) GenerateTask(taskDefinition string, checkType common.CheckType) KeptnTask {
	return KeptnTask{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.GenerateTaskName(checkType, taskDefinition),
			Namespace: w.Namespace,
		},
		Spec: KeptnTaskSpec{
			AppName:          w.GetAppName(),
			WorkloadVersion:  w.GetVersion(),
			Workload:         w.GetParentName(),
			TaskDefinition:   taskDefinition,
			Parameters:       TaskParameters{},
			SecureParameters: SecureParameters{},
			Type:             checkType,
		},
	}
}

func (w KeptnWorkloadInstance) GenerateEvaluation(evaluationDefinition string, checkType common.CheckType) KeptnEvaluation {
	return KeptnEvaluation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.GenerateEvaluationName(checkType, evaluationDefinition),
			Namespace: w.Namespace,
		},
		Spec: KeptnEvaluationSpec{
			AppName:              w.GetAppName(),
			WorkloadVersion:      w.GetVersion(),
			Workload:             w.GetParentName(),
			EvaluationDefinition: evaluationDefinition,
			Type:                 checkType,
			RetryInterval: metav1.Duration{
				Duration: 5 * time.Second,
			},
		},
	}
}

func (w KeptnWorkloadInstance) GetSpanAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		common.AppName.String(w.Spec.AppName),
		common.WorkloadName.String(w.Spec.WorkloadName),
		common.WorkloadVersion.String(w.Spec.Version),
		common.WorkloadNamespace.String(w.Namespace),
	}
}

func (w KeptnWorkloadInstance) GetSpanKey(phase string) string {
	return fmt.Sprintf("%s.%s.%s.%s", w.Spec.TraceId["traceparent"], w.Spec.WorkloadName, w.Spec.Version, phase)
}

func (w KeptnWorkloadInstance) GetSpanName(phase string) string {
	if phase == "" {
		return w.Name
	}
	return fmt.Sprintf("%s/%s", w.Spec.WorkloadName, phase)
}

func (w KeptnWorkloadInstance) SetSpanAttributes(span trace.Span) {
	span.SetAttributes(w.GetSpanAttributes()...)
}

//nolint:dupl
func (w *KeptnWorkloadInstance) DeprecateRemainingPhases(phase common.KeptnPhaseType) {
	// no need to deprecate anything when post-eval tasks fail
	if phase == common.PhaseWorkloadPostEvaluation {
		return
	}
	// deprecate post evaluation when post tasks failed
	if phase == common.PhaseWorkloadPostDeployment {
		w.Status.PostDeploymentEvaluationStatus = common.StateDeprecated
	}
	// deprecate post evaluation and tasks when app deployment failed
	if phase == common.PhaseWorkloadDeployment {
		w.Status.PostDeploymentStatus = common.StateDeprecated
		w.Status.PostDeploymentEvaluationStatus = common.StateDeprecated
	}
	// deprecate app deployment, post tasks and evaluations if app pre-eval failed
	if phase == common.PhaseWorkloadPreEvaluation {
		w.Status.PostDeploymentStatus = common.StateDeprecated
		w.Status.PostDeploymentEvaluationStatus = common.StateDeprecated
		w.Status.DeploymentStatus = common.StateDeprecated
	}
	// deprecate pre evaluations, app deployment and post tasks and evaluations when pre-tasks failed
	if phase == common.PhaseWorkloadPreDeployment {
		w.Status.PostDeploymentStatus = common.StateDeprecated
		w.Status.PostDeploymentEvaluationStatus = common.StateDeprecated
		w.Status.DeploymentStatus = common.StateDeprecated
		w.Status.PreDeploymentEvaluationStatus = common.StateDeprecated
	}
	// deprecate completely everything
	if phase == common.PhaseDeprecated {
		w.Status.PostDeploymentStatus = common.StateDeprecated
		w.Status.PostDeploymentEvaluationStatus = common.StateDeprecated
		w.Status.DeploymentStatus = common.StateDeprecated
		w.Status.PreDeploymentEvaluationStatus = common.StateDeprecated
		w.Status.PreDeploymentStatus = common.StateDeprecated
		w.Status.Status = common.StateDeprecated
		return
	}

	w.Status.Status = common.StateFailed
}

func (w *KeptnWorkloadInstance) SetPhaseTraceID(phase string, carrier propagation.MapCarrier) {
	if w.Status.PhaseTraceIDs == nil {
		w.Status.PhaseTraceIDs = common.PhaseTraceID{}
	}
	w.Status.PhaseTraceIDs[common.GetShortPhaseName(phase)] = carrier
}

func (w KeptnWorkloadInstance) GetEventAnnotations() map[string]string {
	return map[string]string{
		"appName":              w.Spec.AppName,
		"workloadName":         w.Spec.WorkloadName,
		"workloadVersion":      w.Spec.Version,
		"workloadInstanceName": w.Name,
	}
}
