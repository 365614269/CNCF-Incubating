package keptnappversion

import (
	"context"
	"testing"

	lfcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

//nolint:dogsled
func TestKeptnAppVersionReconciler_reconcileWorkloads_noWorkloads(t *testing.T) {
	appVersion := &lfcv1beta1.KeptnAppVersion{
		ObjectMeta: v1.ObjectMeta{
			Name:      "appversion",
			Namespace: "default",
		},
		Spec: lfcv1beta1.KeptnAppVersionSpec{
			AppName: "app",
		},
	}
	r, _, _ := setupReconciler(appVersion)

	state, err := r.reconcileWorkloads(context.TODO(), appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateSucceeded, state)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateSucceeded, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 0)
}

//nolint:dogsled
func TestKeptnAppVersionReconciler_reconcileWorkloads(t *testing.T) {
	appVersion := &lfcv1beta1.KeptnAppVersion{
		ObjectMeta: v1.ObjectMeta{
			Name:      "appversion",
			Namespace: "default",
		},
		Spec: lfcv1beta1.KeptnAppVersionSpec{
			KeptnAppSpec: lfcv1beta1.KeptnAppSpec{
				Workloads: []lfcv1beta1.KeptnWorkloadRef{
					{
						Name:    "workload",
						Version: "ver1",
					},
				},
			},
			AppName: "app",
		},
	}
	r, _, _ := setupReconciler(appVersion)

	// No workloadVersions are created yet, should stay in Pending state

	state, err := r.reconcileWorkloads(context.TODO(), appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StatePending, state)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StatePending, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 1)
	require.Equal(t, []lfcv1beta1.WorkloadStatus{
		{
			Workload: lfcv1beta1.KeptnWorkloadRef{
				Name:    "workload",
				Version: "ver1",
			},
			Status: apicommon.StatePending,
		},
	}, appVersion.Status.WorkloadStatus)

	// Creating WorkloadInstace that is not part of the App -> should stay Pending

	wi1 := &lfcv1beta1.KeptnWorkloadVersion{
		ObjectMeta: v1.ObjectMeta{
			Name:      "workload",
			Namespace: "default",
		},
		Spec: lfcv1beta1.KeptnWorkloadVersionSpec{
			KeptnWorkloadSpec: lfcv1beta1.KeptnWorkloadSpec{
				AppName: "app2",
			},
		},
	}

	err = r.Client.Create(context.TODO(), wi1)
	require.Nil(t, err)

	state, err = r.reconcileWorkloads(context.TODO(), appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StatePending, state)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StatePending, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 1)
	require.Equal(t, []lfcv1beta1.WorkloadStatus{
		{
			Workload: lfcv1beta1.KeptnWorkloadRef{
				Name:    "workload",
				Version: "ver1",
			},
			Status: apicommon.StatePending,
		},
	}, appVersion.Status.WorkloadStatus)

	// Creating WorkloadVersion of App with progressing state -> appVersion should be Progressing

	wi2 := &lfcv1beta1.KeptnWorkloadVersion{
		ObjectMeta: v1.ObjectMeta{
			Name:      "app-workload-ver1",
			Namespace: "default",
		},
		Spec: lfcv1beta1.KeptnWorkloadVersionSpec{
			KeptnWorkloadSpec: lfcv1beta1.KeptnWorkloadSpec{
				AppName: "app",
			},
		},
	}

	err = r.Client.Create(context.TODO(), wi2)
	require.Nil(t, err)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: wi2.Namespace, Name: wi2.Name}, wi2)
	require.Nil(t, err)

	wi2.Status.Status = apicommon.StateProgressing
	err = r.Client.Update(context.TODO(), wi2)
	require.Nil(t, err)

	state, err = r.reconcileWorkloads(context.TODO(), appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateProgressing, state)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateProgressing, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 1)
	require.Equal(t, []lfcv1beta1.WorkloadStatus{
		{
			Workload: lfcv1beta1.KeptnWorkloadRef{
				Name:    "workload",
				Version: "ver1",
			},
			Status: apicommon.StateProgressing,
		},
	}, appVersion.Status.WorkloadStatus)

	// Updating WorkloadVersion of App with succeeded state -> appVersion should be Succeeded

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: wi2.Namespace, Name: wi2.Name}, wi2)
	require.Nil(t, err)

	wi2.Status.Status = apicommon.StateSucceeded
	err = r.Client.Update(context.TODO(), wi2)
	require.Nil(t, err)

	state, err = r.reconcileWorkloads(context.TODO(), appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateSucceeded, state)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateSucceeded, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 1)
	require.Equal(t, []lfcv1beta1.WorkloadStatus{
		{
			Workload: lfcv1beta1.KeptnWorkloadRef{
				Name:    "workload",
				Version: "ver1",
			},
			Status: apicommon.StateSucceeded,
		},
	}, appVersion.Status.WorkloadStatus)
}

//nolint:dogsled
func TestKeptnAppVersionReconciler_handleUnaccessibleWorkloadVersionList(t *testing.T) {
	appVersion := &lfcv1beta1.KeptnAppVersion{
		ObjectMeta: v1.ObjectMeta{
			Name:      "appversion",
			Namespace: "default",
		},
		Spec: lfcv1beta1.KeptnAppVersionSpec{
			KeptnAppSpec: lfcv1beta1.KeptnAppSpec{
				Workloads: []lfcv1beta1.KeptnWorkloadRef{
					{
						Name:    "workload",
						Version: "ver1",
					},
				},
			},
			AppName: "app",
		},
	}
	r, _, _ := setupReconciler(appVersion)

	err := r.handleUnaccessibleWorkloadVersionList(context.TODO(), appVersion)
	require.Nil(t, err)

	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: appVersion.Namespace, Name: appVersion.Name}, appVersion)
	require.Nil(t, err)
	require.Equal(t, apicommon.StateUnknown, appVersion.Status.WorkloadOverallStatus)
	require.Len(t, appVersion.Status.WorkloadStatus, 1)
	require.Equal(t, []lfcv1beta1.WorkloadStatus{
		{
			Workload: lfcv1beta1.KeptnWorkloadRef{
				Name:    "workload",
				Version: "ver1",
			},
			Status: apicommon.StateUnknown,
		},
	}, appVersion.Status.WorkloadStatus)
}
