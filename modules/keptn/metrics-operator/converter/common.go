package converter

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"gopkg.in/inf.v0"
)

func NewInvalidOperatorErr(msg string) error {
	return fmt.Errorf("invalid operator: '%s'", msg)
}

func NewInconvertibleValueErr(msg string) error {
	return fmt.Errorf("unable to convert value '%s' to decimal", msg)
}

func NewUnsupportedIntervalCombinationErr(op []string) error {
	return fmt.Errorf("unsupported interval combination '%v'", op)
}

func NewEmptyOperatorErr(op []string) error {
	return fmt.Errorf("empty operators: '%v'", op)
}

func NewInconvertibleOperatorCombinationErr(op1, op2 string) error {
	return fmt.Errorf("inconvertible combination of operators: '%s', '%s'", op1, op2)
}

func NewUnsupportedResourceNameErr(name string) error {
	return fmt.Errorf(
		"unsupported resource name: %s. Provided resource name must match the pattern %s and must not have more than %d characters.",
		name,
		K8sResourceNameRegexp,
		MaxResourceNameLength,
	)
}

const MaxInt = math.MaxInt
const MinInt = -MaxInt - 1

const MaxResourceNameLength = 253
const K8sResourceNameRegexp = "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"

type Operator struct {
	Value     *inf.Dec
	Operation string
}

type Interval struct {
	Start *inf.Dec
	End   *inf.Dec
}

func isGreaterOrEqual(op string) bool {
	return op == ">" || op == ">="
}

func isLessOrEqual(op string) bool {
	return op == "<" || op == "<="
}

func ValidateResourceName(name string) error {
	pattern := "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"

	// Compile the regular expression.
	regex := regexp.MustCompile(pattern)

	// Check if the provided name matches the pattern.
	if !regex.MatchString(name) || len(name) > MaxResourceNameLength {
		return NewUnsupportedResourceNameErr(name)
	}
	return nil
}

func ConvertResourceName(name string) string {
	// Replace non-alphanumeric characters with '-'
	re := regexp.MustCompile("[^a-z0-9]+")
	normalized := re.ReplaceAllString(strings.ToLower(name), "-")

	// Remove leading and trailing '-'
	normalized = strings.Trim(normalized, "-")

	// Ensure the name is no longer than 253 characters
	if len(normalized) > MaxResourceNameLength {
		normalized = normalized[:MaxResourceNameLength]
	}

	return normalized
}
