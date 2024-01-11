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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KeptnEvaluationProviderSpec defines the desired state of KeptnEvaluationProvider
type KeptnEvaluationProviderSpec struct {
	TargetServer string `json:"targetServer"`
	// +optional
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=keptnevaluationproviders,shortName=kep

// KeptnEvaluationProvider is the Schema for the keptnevaluationproviders API
type KeptnEvaluationProvider struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec KeptnEvaluationProviderSpec `json:"spec,omitempty"`
	// unused field
	// +optional
	Status string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnEvaluationProviderList contains a list of KeptnEvaluationProvider
type KeptnEvaluationProviderList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnEvaluationProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnEvaluationProvider{}, &KeptnEvaluationProviderList{})
}
