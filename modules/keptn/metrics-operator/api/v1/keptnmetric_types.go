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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeptnMetricSpec defines the desired state of KeptnMetric
type KeptnMetricSpec struct {
	// Provider represents the provider object
	Provider ProviderRef `json:"provider"`
	// Query represents the query to be run
	Query string `json:"query"`
	// FetchIntervalSeconds represents the update frequency in seconds that is used to update the metric
	FetchIntervalSeconds uint `json:"fetchIntervalSeconds"`
	// Range represents the time range for which data is to be queried
	// +optional
	Range *RangeSpec `json:"range,omitempty"`
}

// KeptnMetricStatus defines the observed state of KeptnMetric
type KeptnMetricStatus struct {
	// Value represents the resulting value
	// +optional
	Value string `json:"value,omitempty"`
	// RawValue represents the resulting value in raw format
	// +optional
	RawValue []byte `json:"rawValue,omitempty"`
	// LastUpdated represents the time when the status data was last updated
	// +optional
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
	// ErrMsg represents the error details when the query could not be evaluated
	// +optional
	ErrMsg string `json:"errMsg,omitempty"`
	// IntervalResults contain a slice of all the interval results
	// +optional
	IntervalResults []IntervalResult `json:"intervalResults,omitempty"`
}

// ProviderRef represents the provider object
type ProviderRef struct {
	// Name of the provider
	Name string `json:"name"`
}

// RangeSpec defines the time range for which data is to be queried
type RangeSpec struct {
	// Interval specifies the duration of the time interval for the data query
	// +kubebuilder:default:="5m"
	// +optional
	Interval string `json:"interval,omitempty"`
	// Step represents the query resolution step width for the data query
	// +optional
	Step string `json:"step,omitempty"`
	// Aggregation defines the type of aggregation function to be applied on the data. Accepted values: p90, p95, p99, max, min, avg, median
	// +kubebuilder:validation:Enum:=p90;p95;p99;max;min;avg;median
	// +optional
	Aggregation string `json:"aggregation,omitempty"`
	// StoredResults indicates the upper limit of how many past results should be stored in the status of a KeptnMetric
	// +kubebuilder:validation:Maximum:=255
	// +optional
	StoredResults uint `json:"storedResults,omitempty"`
}

type IntervalResult struct {
	// Value represents the resulting value
	Value string `json:"value"`
	// Range represents the time range for which this data was queried
	Range *RangeSpec `json:"range"`
	// LastUpdated represents the time when the status data was last updated
	LastUpdated metav1.Time `json:"lastUpdated"`
	// ErrMsg represents the error details when the query could not be evaluated
	// +optional
	ErrMsg string `json:"errMsg,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider.name`
// +kubebuilder:printcolumn:name="Query",type=string,JSONPath=`.spec.query`
// +kubebuilder:printcolumn:name="Interval",type=string,JSONPath=`.spec.range.interval`
// +kubebuilder:printcolumn:name="Value",type=string,JSONPath=`.status.value`
// +kubebuilder:printcolumn:name="Step",type=string,JSONPath=`.spec.range.step`
// +kubebuilder:printcolumn:name="Aggregation",type=string,JSONPath=`.spec.range.aggregation`
// +kubebuilder:storageversion

// KeptnMetric is the Schema for the keptnmetrics API
type KeptnMetric struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec KeptnMetricSpec `json:"spec,omitempty"`
	// +optional
	Status KeptnMetricStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeptnMetricList contains a list of KeptnMetric resources
type KeptnMetricList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeptnMetric `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeptnMetric{}, &KeptnMetricList{})
}

func (s *KeptnMetric) IsStatusSet() bool {
	return s.Status.Value != ""
}
