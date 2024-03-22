package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestObjectReference_IsNamespaceSet(t *testing.T) {
	o := ObjectReference{}

	require.False(t, o.IsNamespaceSet())

	o.Namespace = "ns"

	require.True(t, o.IsNamespaceSet())
}

func TestObjectReference_GetNamespace(t *testing.T) {
	o := ObjectReference{}

	require.Equal(t, "default", o.GetNamespace("default"))

	o.Namespace = "ns"

	require.Equal(t, "ns", o.GetNamespace("default"))
}

func TestAnalysisState_IsPending(t *testing.T) {
	a := StatePending
	require.True(t, a.IsPending())

	a = ""
	require.True(t, a.IsPending())

	a = StateCompleted
	require.False(t, a.IsPending())
}

func TestAnalysisState_IsCompleted(t *testing.T) {
	a := StateCompleted
	require.True(t, a.IsCompleted())

	a = StateProgressing
	require.False(t, a.IsCompleted())
}
