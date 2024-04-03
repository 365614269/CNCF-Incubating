/*
Copyright 2023.

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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeptnMetricsProviderSpec defines the desired state of KeptnMetricsProvider
type KeptnMetricsProviderSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=cortex|datadog|dql|dynatrace|prometheus|thanos
	// Type represents the provider type. This can be one of cortex, datadog, dql, dynatrace, prometheus or thanos.
	Type string `json:"type"`
	// TargetServer defines URL (including port and protocol) at which the metrics provider is reachable.
	TargetServer string `json:"targetServer"`
	// +kubebuilder:validation:Optional
	// SecretKeyRef defines an optional secret for access credentials to the metrics provider.
	// +optional
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=keptnmetricsproviders,shortName=kmp
// +kubebuilder:storageversion

// KeptnMetricsProvider is the Schema for the keptnmetricsproviders API
type KeptnMetricsProvider struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec KeptnMetricsProviderSpec `json:"spec,omitempty"`
	// unused field
	// +optional
	Status string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnMetricsProviderList contains a list of KeptnMetricsProvider resources
type KeptnMetricsProviderList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnMetricsProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnMetricsProvider{}, &KeptnMetricsProviderList{})
}

func (p *KeptnMetricsProvider) HasSecretDefined() bool {
	if p.Spec.SecretKeyRef == (corev1.SecretKeySelector{}) {
		return false
	}
	// if the secret name exists the secret is defined
	if strings.TrimSpace(p.Spec.SecretKeyRef.Name) == "" {
		return false
	}
	return true
}

func (p *KeptnMetricsProvider) HasSecretKeyDefined() bool {
	if p.Spec.SecretKeyRef == (corev1.SecretKeySelector{}) {
		return false
	}
	// if the secret name exists the secret is defined
	if strings.TrimSpace(p.Spec.SecretKeyRef.Key) == "" {
		return false
	}
	return true
}

func (p *KeptnMetricsProvider) GetType() string {
	if p.Spec.Type != "" {
		return p.Spec.Type
	}
	return p.Name
}
