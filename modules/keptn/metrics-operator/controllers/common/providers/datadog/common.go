package datadog

import (
	"context"
	"errors"
	"fmt"

	metricsapi "github.com/keptn/lifecycle-toolkit/metrics-operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const apiKey, appKey = "DD_CLIENT_API_KEY", "DD_CLIENT_APP_KEY"

var ErrSecretKeyRefNotDefined = errors.New("the SecretKeyRef property with the DataDog API Key is missing")

func getDDSecret(ctx context.Context, provider metricsapi.KeptnMetricsProvider, k8sClient client.Client) (string, string, error) {
	if !provider.HasSecretDefined() {
		return "", "", ErrSecretKeyRefNotDefined
	}
	ddCredsSecret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: provider.Spec.SecretKeyRef.Name, Namespace: provider.Namespace}, ddCredsSecret); err != nil {
		return "", "", err
	}

	apiKeyVal := ddCredsSecret.Data[apiKey]
	appKeyVal := ddCredsSecret.Data[appKey]
	if len(apiKeyVal) == 0 || len(appKeyVal) == 0 {
		return "", "", fmt.Errorf("secret does not contain %s or %s", apiKey, appKey)
	}
	return string(apiKeyVal), string(appKeyVal), nil
}
