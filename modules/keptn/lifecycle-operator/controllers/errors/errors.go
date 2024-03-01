package errors

import (
	"fmt"

	"github.com/pkg/errors"
)

var ErrCannotWrapToPhaseItem = fmt.Errorf("provided object does not implement PhaseItem interface")
var ErrCannotWrapToListItem = fmt.Errorf("provided object does not implement ListItem interface")
var ErrCannotWrapToMetricsObject = fmt.Errorf("provided object does not implement MetricsObject interface")
var ErrCannotWrapToActiveMetricsObject = fmt.Errorf("provided object does not implement ActiveMetricsObject interface")
var ErrCannotWrapToEventObject = fmt.Errorf("provided object does not implement EventObject interface")
var ErrCannotWrapToSpanItem = fmt.Errorf("provided object does not implement SpanItem interface")
var ErrRetryCountExceeded = fmt.Errorf("retryCount for evaluation exceeded")
var ErrNoValues = fmt.Errorf("no values")
var ErrInvalidOperator = fmt.Errorf("invalid operator")
var ErrCannotMarshalParams = fmt.Errorf("could not marshal parameters")
var ErrNoTaskDefinitionSpec = fmt.Errorf("the TaskDefinition specs are empty")
var ErrUnsupportedWorkloadVersionResourceReference = fmt.Errorf("unsupported Resource Reference")
var ErrCannotGetKeptnTaskDefinition = fmt.Errorf("cannot retrieve KeptnTaskDefinition")
var ErrCannotGetKeptnEvaluationDefinition = fmt.Errorf("cannot retrieve KeptnEvaluationDefinition")
var ErrNoMatchingAppVersionFound = fmt.Errorf("no matching KeptnAppVersion found")

var ErrCannotRetrieveConfigMsg = "could not retrieve KeptnConfig: %w"
var ErrCannotRetrieveInstancesMsg = "could not retrieve instances: %w"
var ErrCannotFetchAppMsg = "could not retrieve KeptnApp: %w"
var ErrCannotFetchAppVersionMsg = "could not retrieve KeptnappVersion: %w"
var ErrCannotRetrieveWorkloadVersionMsg = "could not retrieve KeptnWorkloadVersion: %w"
var ErrCannotRetrieveWorkloadMsg = "could not retrieve KeptnWorkload: %w"
var ErrNoLabelsFoundTask = "no labels found for task: %s"
var ErrNoConfigMapMsg = "no ConfigMap specified or HTTP source specified in TaskDefinition / Namespace: %s, Name: %s"
var ErrCannotGetFunctionConfigMap = "could not get function configMap: %w"
var ErrCannotFetchAppVersionForWorkloadVersionMsg = "could not fetch AppVersion for KeptnWorkloadVersion: "
var ErrCouldNotUnbindSpan = "could not unbind span for %s"

// IgnoreReferencedResourceNotFound returns nil on NotFound errors.
// All other values that are not NotFound errors or nil are returned unmodified.
func IgnoreReferencedResourceNotFound(err error) error {
	if errors.Is(err, ErrNoMatchingAppVersionFound) {
		return nil
	}
	return err
}
