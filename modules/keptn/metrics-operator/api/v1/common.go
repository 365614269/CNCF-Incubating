package v1

type ObjectReference struct {
	// Name defines the name of the referenced object
	Name string `json:"name"`
	// Namespace defines the namespace of the referenced object
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

func (o *ObjectReference) IsNamespaceSet() bool {
	return o.Namespace != ""
}

func (o *ObjectReference) GetNamespace(defaultNamespace string) string {
	if o.IsNamespaceSet() {
		return o.Namespace
	}

	return defaultNamespace
}

// AnalysisState represents the state of the analysis
type AnalysisState string

const (
	StatePending     AnalysisState = "Pending"
	StateProgressing AnalysisState = "Progressing"
	StateCompleted   AnalysisState = "Completed"
)

func (s AnalysisState) IsPending() bool {
	return s == StatePending || s == ""
}

func (s AnalysisState) IsCompleted() bool {
	return s == StateCompleted
}
