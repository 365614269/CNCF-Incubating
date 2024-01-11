package keptnappversion

import (
	"context"
	"fmt"

	klcv1beta1 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1"
	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1beta1/common"
	operatorcommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/common"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *KeptnAppVersionReconciler) reconcileWorkloads(ctx context.Context, appVersion *klcv1beta1.KeptnAppVersion) (apicommon.KeptnState, error) {
	r.Log.Info("Reconciling Workloads")
	var summary apicommon.StatusSummary
	summary.Total = len(appVersion.Spec.Workloads)

	phase := apicommon.PhaseReconcileWorkload

	workloadVersionList, err := r.getWorkloadVersionList(ctx, appVersion.Namespace, appVersion.Spec.AppName)
	if err != nil {
		r.Log.Error(err, "Could not get workloads of appVersion '%s'", appVersion.Name)
		return apicommon.StateUnknown, r.handleUnaccessibleWorkloadVersionList(ctx, appVersion)
	}

	newStatus := make([]klcv1beta1.WorkloadStatus, 0, len(appVersion.Spec.Workloads))
	for _, w := range appVersion.Spec.Workloads {
		r.Log.Info("Reconciling workload " + w.Name)
		workloadStatus := apicommon.StatePending
		found := false
		instanceName := getWorkloadVersionName(appVersion.Spec.AppName, w.Name, w.Version)
		for _, i := range workloadVersionList.Items {
			// additional filtering of the retrieved WIs is needed, as the List() method retrieves all
			// WIs for a specific KeptnApp. The result can contain also WIs, that are not part of the
			// latest KeptnAppVersion, so it's needed to double check them
			// no need to compare version, as it is part of WI name
			if instanceName == i.Name {
				found = true
				workloadStatus = i.Status.Status
			}
		}

		if !found {
			r.EventSender.Emit(phase, "Warning", appVersion, apicommon.PhaseStateNotFound, fmt.Sprintf("could not find KeptnWorkloadVersion for KeptnWorkload: %s ", w.Name), appVersion.GetVersion())
		}

		newStatus = append(newStatus, klcv1beta1.WorkloadStatus{
			Workload: w,
			Status:   workloadStatus,
		})
		summary = apicommon.UpdateStatusSummary(workloadStatus, summary)
	}

	overallState := apicommon.GetOverallState(summary)
	appVersion.Status.WorkloadOverallStatus = overallState
	r.Log.Info("Overall state of workloads", "state", appVersion.Status.WorkloadOverallStatus)

	appVersion.Status.WorkloadStatus = newStatus
	r.Log.Info("Workload status", "status", appVersion.Status.WorkloadStatus)

	// Write Status Field
	err = r.Client.Status().Update(ctx, appVersion)
	return overallState, err
}

func (r *KeptnAppVersionReconciler) getWorkloadVersionList(ctx context.Context, namespace string, appName string) (*klcv1beta1.KeptnWorkloadVersionList, error) {
	workloadVersionList := &klcv1beta1.KeptnWorkloadVersionList{}
	err := r.Client.List(ctx, workloadVersionList, client.InNamespace(namespace), client.MatchingFields{
		"spec.app": appName,
	})
	return workloadVersionList, err
}

func (r *KeptnAppVersionReconciler) handleUnaccessibleWorkloadVersionList(ctx context.Context, appVersion *klcv1beta1.KeptnAppVersion) error {
	newStatus := make([]klcv1beta1.WorkloadStatus, 0, len(appVersion.Spec.Workloads))
	for _, w := range appVersion.Spec.Workloads {
		newStatus = append(newStatus, klcv1beta1.WorkloadStatus{
			Workload: w,
			Status:   apicommon.StateUnknown,
		})
	}
	appVersion.Status.WorkloadOverallStatus = apicommon.StateUnknown
	appVersion.Status.WorkloadStatus = newStatus
	return r.Client.Status().Update(ctx, appVersion)
}

func getWorkloadVersionName(appName string, workloadName string, version string) string {
	return operatorcommon.CreateResourceName(apicommon.MaxK8sObjectLength, apicommon.MinKeptnNameLen, appName, workloadName, version)
}
