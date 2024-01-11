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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeptnTaskDefinitionSpec defines the desired state of KeptnTaskDefinition
type KeptnTaskDefinitionSpec struct {
	// Deprecated
	// Function contains the definition for the function that is to be executed in KeptnTasks based on
	// the KeptnTaskDefinitions.
	// +optional
	Function *RuntimeSpec `json:"function,omitempty"`
	// Python contains the definition for the python function that is to be executed in KeptnTasks based on
	//	the KeptnTaskDefinitions.
	// +optional
	Python *RuntimeSpec `json:"python,omitempty"`
	// Deno contains the definition for the Deno function that is to be executed in KeptnTasks based on
	//	the KeptnTaskDefinitions.
	// +optional
	Deno *RuntimeSpec `json:"deno,omitempty"`
	// Container contains the definition for the container that is to be used in Job based on
	// the KeptnTaskDefinitions.
	// +optional
	Container *ContainerSpec `json:"container,omitempty"`
	// Retries specifies how many times a job executing the KeptnTaskDefinition should be restarted in the case
	// of an unsuccessful attempt.
	// +kubebuilder:default:=10
	// +optional
	Retries *int32 `json:"retries,omitempty"`
	// Timeout specifies the maximum time to wait for the task to be completed successfully.
	// If the task does not complete successfully within this time frame, it will be
	// considered to be failed.
	// +kubebuilder:default:="5m"
	// +kubebuilder:validation:Pattern="^0|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
	// +kubebuilder:validation:Type:=string
	// +optional
	Timeout metav1.Duration `json:"timeout,omitempty"`
	// ServiceAccount specifies the service account to be used in jobs to authenticate with the Kubernetes API and access cluster resources.
	// +optional
	ServiceAccount *ServiceAccountSpec `json:"serviceAccount,omitempty"`
	// AutomountServiceAccountToken allows to enable K8s to assign cluster API credentials to a pod, if set to false
	// the pod will decline the service account
	// +optional
	AutomountServiceAccountToken *AutomountServiceAccountTokenSpec `json:"automountServiceAccountToken,omitempty"`
	// TTLSecondsAfterFinished controller makes a job eligible to be cleaned up after it is finished.
	// The timer starts when the status shows up to be Complete or Failed.
	// +kubebuilder:default:=300
	// +optional
	TTLSecondsAfterFinished *int32 `json:"ttlSecondsAfterFinished,omitempty"`
	// ImagePullSecrets is an optional field to specify the names of secrets to use for pulling container images
	// +optional
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

type RuntimeSpec struct {
	// FunctionReference allows to reference another KeptnTaskDefinition which contains the source code of the
	// function to be executes for KeptnTasks based on this KeptnTaskDefinition. This can be useful when you have
	// multiple KeptnTaskDefinitions that should execute the same logic, but each with different parameters.
	// +optional
	FunctionReference FunctionReference `json:"functionRef,omitempty"`
	// Inline allows to specify the code that should be executed directly in the KeptnTaskDefinition, as a multi-line
	// string.
	// +optional
	Inline Inline `json:"inline,omitempty"`
	// HttpReference allows to point to an HTTP URL containing the code of the function.
	// +optional
	HttpReference HttpReference `json:"httpRef,omitempty"`
	// ConfigMapReference allows to reference a ConfigMap containing the code of the function.
	// When referencing a ConfigMap, the code of the function must be available as a value of the 'code' key
	// of the referenced ConfigMap.
	// +optional
	ConfigMapReference ConfigMapReference `json:"configMapRef,omitempty"`
	// Parameters contains parameters that will be passed to the job that executes the task as env variables.
	// +optional
	Parameters TaskParameters `json:"parameters,omitempty"`
	// SecureParameters contains secure parameters that will be passed to the job that executes the task.
	// These will be stored and accessed as secrets in the cluster.
	// +optional
	SecureParameters SecureParameters `json:"secureParameters,omitempty"`
	// CmdParameters contains parameters that will be passed to the command
	// +optional
	CmdParameters string `json:"cmdParameters,omitempty"`
}

type ConfigMapReference struct {
	// Name is the name of the referenced ConfigMap.
	// +optional
	Name string `json:"name,omitempty"`
}

type FunctionReference struct {
	// Name is the name of the referenced KeptnTaskDefinition.
	// +optional
	Name string `json:"name,omitempty"`
}

type Inline struct {
	// Code contains the code of the function.
	// +optional
	Code string `json:"code,omitempty"`
}

type HttpReference struct {
	// Url is the URL containing the code of the function.
	// +optional
	Url string `json:"url,omitempty"`
}

type ContainerSpec struct {
	*v1.Container `json:",inline"`
}

type AutomountServiceAccountTokenSpec struct {
	Type *bool `json:"type"`
}
type ServiceAccountSpec struct {
	Name string `json:"name"`
}

// KeptnTaskDefinitionStatus defines the observed state of KeptnTaskDefinition
type KeptnTaskDefinitionStatus struct {
	// Function contains status information of the function definition for the task.
	// +optional
	Function FunctionStatus `json:"function,omitempty"`
}

type FunctionStatus struct {
	// ConfigMap indicates the ConfigMap in which the function code is stored.
	// +optional
	ConfigMap string `json:"configMap,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// KeptnTaskDefinition is the Schema for the keptntaskdefinitions API
type KeptnTaskDefinition struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired state of the KeptnTaskDefinition.
	// +optional
	Spec KeptnTaskDefinitionSpec `json:"spec,omitempty"`
	// Status describes the current state of the KeptnTaskDefinition.
	// +optional
	Status KeptnTaskDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnTaskDefinitionList contains a list of KeptnTaskDefinition
type KeptnTaskDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnTaskDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnTaskDefinition{}, &KeptnTaskDefinitionList{})
}

func (d *KeptnTaskDefinition) GetServiceAccount() string {
	if d.Spec.ServiceAccount == nil {
		return ""
	}
	return d.Spec.ServiceAccount.Name
}

func (d *KeptnTaskDefinition) GetAutomountServiceAccountToken() *bool {
	if d.Spec.AutomountServiceAccountToken == nil {
		return nil
	}
	return d.Spec.AutomountServiceAccountToken.Type
}
