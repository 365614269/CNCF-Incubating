//nolint:dupl
package keptnworkloadversion

import (
	"context"
	"fmt"

	apicommon "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1alpha3/common"
	klcv1alpha4 "github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1alpha4"
	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/controllers/common/evaluation"
)

func (r *KeptnWorkloadVersionReconciler) reconcilePrePostEvaluation(ctx context.Context, phaseCtx context.Context, workloadVersion *klcv1alpha4.KeptnWorkloadVersion, checkType apicommon.CheckType) (apicommon.KeptnState, error) {
	evaluationCreateAttributes := evaluation.CreateEvaluationAttributes{
		SpanName:  fmt.Sprintf(apicommon.CreateWorkloadEvalSpanName, checkType),
		CheckType: checkType,
	}

	newStatus, state, err := r.EvaluationHandler.ReconcileEvaluations(ctx, phaseCtx, workloadVersion, evaluationCreateAttributes)
	if err != nil {
		return apicommon.StateUnknown, err
	}

	overallState := apicommon.GetOverallState(state)

	switch checkType {
	case apicommon.PreDeploymentEvaluationCheckType:
		workloadVersion.Status.PreDeploymentEvaluationStatus = overallState
		workloadVersion.Status.PreDeploymentEvaluationTaskStatus = newStatus
	case apicommon.PostDeploymentEvaluationCheckType:
		workloadVersion.Status.PostDeploymentEvaluationStatus = overallState
		workloadVersion.Status.PostDeploymentEvaluationTaskStatus = newStatus
	}

	// Write Status Field
	err = r.Client.Status().Update(ctx, workloadVersion)
	if err != nil {
		return apicommon.StateUnknown, err
	}
	return overallState, nil
}
