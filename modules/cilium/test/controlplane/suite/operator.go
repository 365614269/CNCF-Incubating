// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

type operatorHandle struct {
	t *testing.T

	hive *hive.Hive
	log  *slog.Logger
}

func (h *operatorHandle) tearDown() {
	// If hive is nil, we have not yet started.
	if h.hive != nil {
		if err := h.hive.Stop(h.log, context.TODO()); err != nil {
			h.t.Fatalf("Operator hive failed to stop: %s", err)
		}
	}
}

func setupCiliumOperatorHive(clients *k8sFakeClient.FakeClientset) *hive.Hive {
	return hive.New(
		cell.Provide(func() k8sClient.Clientset {
			return clients
		}),
		k8sFakeClient.FakeClientBuilderCell(),
		cmd.ControlPlane,
	)
}

func populateCiliumOperatorOptions(
	log *slog.Logger,
	vp *viper.Viper,
	modConfig func(*option.OperatorConfig),
	modCellConfig func(vp *viper.Viper),
) {
	option.Config.Populate(log, vp)

	// Apply the controlplane tests default configuration
	vp.Set(apis.SkipCRDCreation, true)

	// Apply the test-specific operator configuration modifier
	modConfig(option.Config)

	// Apply the test specific operator cells configuration modifier
	//
	// Unlike global configuration options, cell-specific configuration options
	// (i.e. the ones defined through cell.Config(...)) will not be loaded from
	// agentOption or operatorOption, but from the *viper.Viper object bound to
	// the agent or operator hive, respectively.
	// modCellConfig function exposes the operator hive viper struct to each
	// controlplane test, so to allow changing those options as needed.
	modCellConfig(vp)

}

func startCiliumOperator(h *hive.Hive, log *slog.Logger) error {
	return h.Start(log, context.TODO())
}
