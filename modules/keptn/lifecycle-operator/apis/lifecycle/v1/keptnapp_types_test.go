package v1

import (
	"testing"

	"github.com/keptn/lifecycle-toolkit/lifecycle-operator/apis/lifecycle/v1/common"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKeptnApp(t *testing.T) {
	app := &KeptnApp{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "app",
			Namespace:  "namespace",
			Generation: 1,
		},
		Spec: KeptnAppSpec{
			Version: "version",
		},
	}

	appVersionName := app.GetAppVersionName()
	require.Equal(t, "app-version-6b86b273", appVersionName)

	appVersion := app.GenerateAppVersion("prev")
	require.Equal(t, KeptnAppVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-version-6b86b273",
			Namespace: "namespace",
		},
		Spec: KeptnAppVersionSpec{
			KeptnAppSpec: KeptnAppSpec{
				Version: "version",
			},
			AppName:         "app",
			PreviousVersion: "prev",
		},
	}, appVersion)

	require.Equal(t, []attribute.KeyValue{
		common.AppName.String("app"),
		common.AppVersion.String("version"),
	}, app.GetSpanAttributes())

	require.Equal(t, map[string]string{
		"appName":     "app",
		"appVersion":  "version",
		"appRevision": "6b86b273",
	}, app.GetEventAnnotations())
}
