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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeptnEvaluationDefinitionSpec defines the desired state of KeptnEvaluationDefinition
type KeptnEvaluationDefinitionSpec struct {
	// Objectives is a list of objectives that have to be met for a KeptnEvaluation referencing this
	// KeptnEvaluationDefinition to be successful.
	Objectives []Objective `json:"objectives"`
	// FailureConditions represent the failure conditions (number of retries and retry interval)
	// for the evaluation to be considered as failed
	FailureConditions `json:",inline"`
}

// FailureConditions represent the failure conditions (number of retries and retry interval)
// for the evaluation to be considered as failed
type FailureConditions struct {
	// Retries indicates how many times the KeptnEvaluation can be attempted in the case of an error or
	// missed evaluation objective, before considering the KeptnEvaluation to be failed.
	// +kubebuilder:default:=10
	// +optional
	Retries int `json:"retries,omitempty"`
	// RetryInterval specifies the interval at which the KeptnEvaluation is retried in the case of an error
	// or a missed objective.
	// +kubebuilder:default:="5s"
	// +kubebuilder:validation:Pattern="^0|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
	// +kubebuilder:validation:Type:=string
	// +optional
	RetryInterval metav1.Duration `json:"retryInterval,omitempty"`
}

type Objective struct {
	// KeptnMetricRef references the KeptnMetric that should be evaluated.
	KeptnMetricRef KeptnMetricReference `json:"keptnMetricRef"`
	// EvaluationTarget specifies the target value for the references KeptnMetric.
	// Needs to start with either '<' or '>', followed by the target value (e.g. '<10').
	EvaluationTarget string `json:"evaluationTarget"`
}

type KeptnMetricReference struct {
	// Name is the name of the referenced KeptnMetric.
	Name string `json:"name"`
	// Namespace is the namespace where the referenced KeptnMetric is located.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=keptnevaluationdefinitions,shortName=ked

// KeptnEvaluationDefinition is the Schema for the keptnevaluationdefinitions API
type KeptnEvaluationDefinition struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired state of the KeptnEvaluationDefinition.
	// +optional
	Spec KeptnEvaluationDefinitionSpec `json:"spec,omitempty"`
	// unused field
	// +optional
	Status string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnEvaluationDefinitionList contains a list of KeptnEvaluationDefinition
type KeptnEvaluationDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnEvaluationDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnEvaluationDefinition{}, &KeptnEvaluationDefinitionList{})
}
