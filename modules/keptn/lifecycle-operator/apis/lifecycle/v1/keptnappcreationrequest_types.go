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

package v1

import (
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeptnAppCreationRequestSpec defines the desired state of KeptnAppCreationRequest
type KeptnAppCreationRequestSpec struct {
	// AppName is the name of the KeptnApp the KeptnAppCreationRequest should create if no user-defined object with that name is found.
	AppName string `json:"appName"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// KeptnAppCreationRequest is the Schema for the keptnappcreationrequests API
type KeptnAppCreationRequest struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired state of the KeptnAppCreationRequest.
	// +optional
	Spec KeptnAppCreationRequestSpec `json:"spec,omitempty"`
	// Status describes the current state of the KeptnAppCreationRequest.
	// +optional
	Status string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnAppCreationRequestList contains a list of KeptnAppCreationRequest
type KeptnAppCreationRequestList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnAppCreationRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnAppCreationRequest{}, &KeptnAppCreationRequestList{})
}

func (kacr KeptnAppCreationRequest) IsSingleService() bool {
	return kacr.Annotations[common.AppTypeAnnotation] == string(common.AppTypeSingleService)
}

func (kacr KeptnAppCreationRequest) SetSpanAttributes(span trace.Span) {
	span.SetAttributes(kacr.GetSpanAttributes()...)
}

func (kacr KeptnAppCreationRequest) GetSpanAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		common.AppName.String(kacr.Name),
	}
}
