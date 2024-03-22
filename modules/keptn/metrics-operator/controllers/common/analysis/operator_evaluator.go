package analysis

import (
	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	"github.com/keptn/lifecycle-toolkit/metrics-operator/controllers/common/analysis/types"
)

type OperatorEvaluator struct{}

func (te *OperatorEvaluator) Evaluate(val float64, t *metricsapi.Operator) types.OperatorResult {
	result := types.OperatorResult{
		Operator:  *t,
		Fulfilled: false,
	}

	if t.EqualTo != nil {
		result.Fulfilled = (val == t.EqualTo.GetFloatValue())
	} else if t.LessThanOrEqual != nil {
		result.Fulfilled = (val <= t.LessThanOrEqual.GetFloatValue())
	} else if t.LessThan != nil {
		result.Fulfilled = (val < t.LessThan.GetFloatValue())
	} else if t.GreaterThanOrEqual != nil {
		result.Fulfilled = (val >= t.GreaterThanOrEqual.GetFloatValue())
	} else if t.GreaterThan != nil {
		result.Fulfilled = (val > t.GreaterThan.GetFloatValue())
	} else if t.InRange != nil {
		result.Fulfilled = (val >= t.InRange.LowBound.AsApproximateFloat64() && val <= t.InRange.HighBound.AsApproximateFloat64())
	} else if t.NotInRange != nil {
		result.Fulfilled = (val < t.NotInRange.LowBound.AsApproximateFloat64() || val > t.NotInRange.HighBound.AsApproximateFloat64())
	}

	return result
}
