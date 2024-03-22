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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AnalysisSpec defines the desired state of Analysis
type AnalysisSpec struct {
	// Timeframe specifies the range for the corresponding query in the AnalysisValueTemplate. Please note that either
	// a combination of 'from' and 'to' or the 'recent' property may be set. If neither is set, the Analysis can
	// not be added to the cluster.
	Timeframe `json:"timeframe"`
	// Args corresponds to a map of key/value pairs that can be used to substitute placeholders in the AnalysisValueTemplate query. i.e. for args foo:bar the query could be "query:percentile(95)?scope=tag(my_foo_label:{{.foo}})".
	// +optional
	Args map[string]string `json:"args,omitempty"`
	// AnalysisDefinition refers to the AnalysisDefinition, a CRD that stores the AnalysisValuesTemplates
	AnalysisDefinition ObjectReference `json:"analysisDefinition"`
}

// ProviderResult stores reference of already collected provider query associated to its objective template
type ProviderResult struct {
	// Objective store reference to corresponding objective template
	// +optional
	Objective ObjectReference `json:"objectiveReference,omitempty"`
	// Query represents the executed query
	// +optional
	Query string `json:"query,omitempty"`
	// Value is the value the provider returned
	// +optional
	Value string `json:"value,omitempty"`
	// ErrMsg stores any possible error at retrieval time
	// +optional
	ErrMsg string `json:"errMsg,omitempty"`
}

type Timeframe struct {
	// From is the time of start for the query. This field follows RFC3339 time format
	// +optional
	From metav1.Time `json:"from,omitempty"`
	// To is the time of end for the query. This field follows RFC3339 time format
	// +optional
	To metav1.Time `json:"to,omitempty"`
	// Recent describes a recent timeframe using a duration string. E.g. Setting this to '5m' provides an Analysis
	// for the last five minutes
	// +optional
	// +kubebuilder:validation:Pattern="^0|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$"
	// +kubebuilder:validation:Type:=string
	// +optional
	Recent metav1.Duration `json:"recent,omitempty"`
}

// AnalysisStatus stores the status of the overall analysis returns also pass or warnings
type AnalysisStatus struct {
	// Timeframe describes the time frame which is evaluated by the Analysis
	Timeframe Timeframe `json:"timeframe"`
	// Raw contains the raw result of the SLO computation
	// +optional
	Raw string `json:"raw,omitempty"`
	// Pass returns whether the SLO is satisfied
	// +optional
	Pass bool `json:"pass,omitempty"`
	// Warning returns whether the analysis returned a warning
	// +optional
	Warning bool `json:"warning,omitempty"`
	// State describes the current state of the Analysis (Pending/Progressing/Completed)
	State AnalysisState `json:"state"`
	// StoredValues contains all analysis values that have already been retrieved successfully
	// +optional
	StoredValues map[string]ProviderResult `json:"storedValues,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="AnalysisDefinition",type=string,JSONPath=.spec.analysisDefinition.name
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
//+kubebuilder:printcolumn:name="Warning",type=string,JSONPath=`.status.warning`
//+kubebuilder:printcolumn:name="Pass",type=string,JSONPath=`.status.pass`

// Analysis is the Schema for the analyses API
type Analysis struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec AnalysisSpec `json:"spec,omitempty"`
	// +optional
	Status AnalysisStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AnalysisList contains a list of Analysis resources
type AnalysisList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Analysis `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Analysis{}, &AnalysisList{})
}
