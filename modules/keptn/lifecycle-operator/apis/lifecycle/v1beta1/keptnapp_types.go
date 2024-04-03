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

// KeptnAppSpec defines the desired state of KeptnApp
type KeptnAppSpec struct {
	// Version defines the version of the application. For automatically created KeptnApps,
	// the version is a function of all KeptnWorkloads that are part of the KeptnApp.
	Version string `json:"version"`
	// Revision can be modified to trigger another deployment of a KeptnApp of the same version.
	// This can be used for restarting a KeptnApp which failed to deploy,
	// e.g. due to a failed preDeploymentEvaluation/preDeploymentTask.
	// +kubebuilder:default:=1
	// +optional
	Revision uint `json:"revision,omitempty"`
	// Workloads is a list of all KeptnWorkloads that are part of the KeptnApp.
	// +optional
	Workloads []KeptnWorkloadRef `json:"workloads,omitempty"`
}

// KeptnAppStatus defines the observed state of KeptnApp
type KeptnAppStatus struct {
	// CurrentVersion indicates the version that is currently deployed or being reconciled.
	// +optional
	CurrentVersion string `json:"currentVersion,omitempty"`
}

// KeptnWorkloadRef refers to a KeptnWorkload that is part of a KeptnApp
type KeptnWorkloadRef struct {
	// Name is the name of the KeptnWorkload.
	Name string `json:"name"`
	// Version is the version of the KeptnWorkload.
	Version string `json:"version"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// KeptnApp is the Schema for the keptnapps API
type KeptnApp struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the desired state of the KeptnApp.
	// +optional
	Spec KeptnAppSpec `json:"spec,omitempty"`
	// Status describes the current state of the KeptnApp.
	// +optional
	Status KeptnAppStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnAppList contains a list of KeptnApp
type KeptnAppList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnApp `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnApp{}, &KeptnAppList{})
}
