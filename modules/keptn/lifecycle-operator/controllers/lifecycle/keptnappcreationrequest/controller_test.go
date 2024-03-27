package keptnappcreationrequest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/go-logr/logr"
	apilifecycle "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/config/fake"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const KeptnNamespace = "test"

func TestKeptnAppCreationRequestReconciler_CreateAppAfterTimeout_SingleWorkload(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)

	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w1",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0+rc0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload1)
	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}
	// invoke the first reconciliation
	res, err := r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.Equal(t, 30*time.Second, res.RequeueAfter)

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get a KeptnApp as a result
	res, err = r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	// the App version is the same of the single workload
	require.Equal(t, workload1.Spec.Version, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 1)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))
}

func TestKeptnAppCreationRequestReconciler_CreateAppAfterTimeout(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)

	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w1",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	workload2 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w2",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "2.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload1)
	require.Nil(t, err)
	err = fakeClient.Create(context.TODO(), workload2)
	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}
	// invoke the first reconciliation
	res, err := r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.Equal(t, 30*time.Second, res.RequeueAfter)

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get a KeptnApp as a result
	res, err = r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 2)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload2.Name,
		Version: workload2.Spec.Version,
	})

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))
}

func TestKeptnAppCreationRequestReconciler_UpdateWorkloadsWithNewWorkload(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)
	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w1",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload1)
	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get a KeptnApp as a result
	res, err := r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 1)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})

	firstVersion := kApp.Spec.Version

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))

	// create a new workload

	workload2 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w2",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "2.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload2)
	require.Nil(t, err)

	// create a new instance of a CreationRequest
	newKACR := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}
	err = fakeClient.Create(context.TODO(), newKACR)
	require.Nil(t, err)

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get an updated KeptnApp as a result
	res, err = r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp = &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.NotEqual(t, firstVersion, kApp.Spec.Version)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})
	// now we should see the new workload as well
	require.Len(t, kApp.Spec.Workloads, 2)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload2.Name,
		Version: workload2.Spec.Version,
	})
}

func TestKeptnAppCreationRequestReconciler_UpdateWorkloadsWithNewVersion(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)
	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w1",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload1)
	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get a KeptnApp as a result
	res, err := r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 1)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})

	firstVersion := kApp.Spec.Version

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))

	// update the workload with a new version

	workload1.Spec.Version = "2.0"
	err = fakeClient.Update(context.TODO(), workload1)
	require.Nil(t, err)

	// create a new instance of a CreationRequest
	newKACR := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}
	err = fakeClient.Create(context.TODO(), newKACR)
	require.Nil(t, err)

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	res, err = r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp = &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	// the version number of the app should have been changed
	require.NotEqual(t, firstVersion, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 1)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})
}

func TestKeptnAppCreationRequestReconciler_RemoveWorkload(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)
	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w1",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload1)
	require.Nil(t, err)

	workload2 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "w2",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	err = fakeClient.Create(context.TODO(), workload2)
	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}

	// turn the clock forward and reconcile
	theClock.Add(1 * time.Minute)
	res, err := r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.Len(t, kApp.Spec.Workloads, 2)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload1.Name,
		Version: workload1.Spec.Version,
	})
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload2.Name,
		Version: workload2.Spec.Version,
	})

	firstVersion := kApp.Spec.Version

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))

	// delete one of the workloads
	err = fakeClient.Delete(context.TODO(), workload1)
	require.Nil(t, err)

	// create a new instance of a CreationRequest
	newKACR := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}
	err = fakeClient.Create(context.TODO(), newKACR)
	require.Nil(t, err)

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile again - now we should get an updated KeptnApp as a result
	res, err = r.Reconcile(context.TODO(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp = &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)

	require.NotEmpty(t, kApp.Spec.Version)
	require.NotEqual(t, firstVersion, kApp.Spec.Version)
	// now we should see only one workload
	require.Len(t, kApp.Spec.Workloads, 1)
	require.Contains(t, kApp.Spec.Workloads, apilifecycle.KeptnWorkloadRef{
		Name:    workload2.Name,
		Version: workload2.Spec.Version,
	})
}

func TestKeptnAppCreationRequestReconciler_DoNotOverwriteUserDefinedApp(t *testing.T) {
	r, fakeClient, theClock := setupReconcilerAndClient(t)
	const namespace = "my-namespace"
	const appName = "my-app"
	kacr := &apilifecycle.KeptnAppCreationRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "my-kacr",
			Namespace:         namespace,
			CreationTimestamp: metav1.Time{Time: theClock.Now()},
		},
		Spec: apilifecycle.KeptnAppCreationRequestSpec{
			AppName: appName,
		},
	}

	err := fakeClient.Create(context.TODO(), kacr)
	require.Nil(t, err)

	existingApp := &apilifecycle.KeptnApp{
		ObjectMeta: metav1.ObjectMeta{
			Name:      appName,
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnAppSpec{
			Version: "1.0",
		},
	}

	err = fakeClient.Create(context.TODO(), existingApp)

	require.Nil(t, err)

	request := controllerruntime.Request{
		NamespacedName: types.NamespacedName{
			Namespace: kacr.Namespace,
			Name:      kacr.Name,
		},
	}

	// turn the clock forward
	theClock.Add(1 * time.Minute)

	// reconcile - this should not result in the creation of a KeptnApp
	res, err := r.Reconcile(context.Background(), request)

	require.Nil(t, err)
	require.False(t, res.Requeue)
	require.Zero(t, res.RequeueAfter)

	kApp := &apilifecycle.KeptnApp{}

	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: kacr.Spec.AppName, Namespace: kacr.Namespace}, kApp)

	require.Nil(t, err)
	require.NotEmpty(t, kApp)
	// verify that the existing app has not been modified
	require.Equal(t, existingApp.Spec.Version, kApp.Spec.Version)

	// verify that the creationRequest has been deleted
	cr := &apilifecycle.KeptnAppCreationRequest{}

	err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: kacr.Name, Namespace: kacr.Namespace}, cr)

	require.True(t, errors.IsNotFound(err))
}

func setupReconcilerAndClient(t *testing.T) (*KeptnAppCreationRequestReconciler, client.Client, *clock.Mock) {
	scheme := runtime.NewScheme()

	err := apilifecycle.AddToScheme(scheme)
	require.Nil(t, err)

	workloadAppIndexer := func(obj client.Object) []string {
		workload, _ := obj.(*apilifecycle.KeptnWorkload)
		return []string{workload.Spec.AppName}
	}

	fakeClient := k8sfake.NewClientBuilder().WithScheme(scheme).WithObjects().WithIndex(&apilifecycle.KeptnWorkload{}, "spec.app", workloadAppIndexer).Build()

	theClock := clock.NewMock()
	r := &KeptnAppCreationRequestReconciler{
		Client: fakeClient,
		Scheme: fakeClient.Scheme(),
		Log:    logr.Logger{},
		clock:  theClock,
		config: &fake.MockConfig{
			GetCreationRequestTimeoutFunc: func() time.Duration {
				return 30 * time.Second
			},
			GetDefaultNamespaceFunc: func() string {
				return KeptnNamespace
			},
		},
	}
	return r, fakeClient, theClock
}

func TestKeptnAppCreationRequestReconciler_cleanupWorkloads(t *testing.T) {
	mySlice := []string{"a", "b", "c", "d"}

	res := append(mySlice[:2], mySlice[2+1:]...)

	fmt.Println(cap(mySlice))
	fmt.Println(cap(res))
}

func TestKeptnAppCreationRequestReconciler_getWorkloads(t *testing.T) {
	namespace := "my-namespace"

	appName := "my-app"

	workload1 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workloadA",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	workload2 := &apilifecycle.KeptnWorkload{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "workloadB",
			Namespace: namespace,
		},
		Spec: apilifecycle.KeptnWorkloadSpec{
			AppName: appName,
			Version: "1.0",
		},
	}

	type args struct {
		ctx             context.Context
		creationRequest *apilifecycle.KeptnAppCreationRequest
	}
	tests := []struct {
		name               string
		args               args
		workloadsInCluster []apilifecycle.KeptnWorkload
		want               []apilifecycle.KeptnWorkload
		wantErr            bool
	}{
		{
			name: "get workloads in alphabetical order - already sorted",
			args: args{
				ctx: context.Background(),
				creationRequest: &apilifecycle.KeptnAppCreationRequest{
					Spec: apilifecycle.KeptnAppCreationRequestSpec{
						AppName: appName,
					},
				},
			},
			workloadsInCluster: []apilifecycle.KeptnWorkload{*workload1, *workload2},
			want:               []apilifecycle.KeptnWorkload{*workload1, *workload2},
			wantErr:            false,
		},
		{
			name: "get workloads in alphabetical order - not sorted",
			args: args{
				ctx: context.Background(),
				creationRequest: &apilifecycle.KeptnAppCreationRequest{
					Spec: apilifecycle.KeptnAppCreationRequestSpec{
						AppName: appName,
					},
				},
			},
			workloadsInCluster: []apilifecycle.KeptnWorkload{*workload2, *workload1},
			want:               []apilifecycle.KeptnWorkload{*workload1, *workload2},
			wantErr:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, fakeClient, _ := setupReconcilerAndClient(t)

			for _, workload := range tt.workloadsInCluster {
				err := fakeClient.Create(context.Background(), &workload)
				require.Nil(t, err)
			}
			got, err := c.getWorkloads(tt.args.ctx, tt.args.creationRequest)
			if !tt.wantErr {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
			}
			require.Equal(t, len(tt.want), len(got))

			for i, wantWorkload := range tt.want {
				require.Equal(t, wantWorkload.Name, got[i].Name)
			}
		})
	}
}
