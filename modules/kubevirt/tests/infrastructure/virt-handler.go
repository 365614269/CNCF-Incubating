/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2017 Red Hat, Inc.
 *
 */

package infrastructure

import (
	"context"
	"fmt"
	"time"

	"kubevirt.io/kubevirt/tests/framework/kubevirt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"kubevirt.io/kubevirt/tests/decorators"

	"kubevirt.io/kubevirt/tests/libnode"
	"kubevirt.io/kubevirt/tests/util"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"kubevirt.io/kubevirt/tests"
)

var _ = DescribeInfra("virt-handler", func() {

	var (
		virtClient       kubecli.KubevirtClient
		originalKubeVirt *v1.KubeVirt
		nodesToEnableKSM []*k8sv1.Node
	)

	type ksmTestFunc func() (*v1.KSMConfiguration, []*k8sv1.Node)

	getNodesWithKSMAvailable := func(virtCli kubecli.KubevirtClient) []*k8sv1.Node {
		nodes := libnode.GetAllSchedulableNodes(virtCli)

		nodesWithKSM := make([]*k8sv1.Node, 0)
		for _, node := range nodes.Items {
			command := []string{"cat", "/sys/kernel/mm/ksm/run"}
			_, err := tests.ExecuteCommandInVirtHandlerPod(node.Name, command)
			if err == nil {
				nodesWithKSM = append(nodesWithKSM, &node)
			}
		}
		return nodesWithKSM
	}

	BeforeEach(func() {
		virtClient = kubevirt.Client()

		nodesToEnableKSM = getNodesWithKSMAvailable(virtClient)
		if len(nodesToEnableKSM) == 0 {
			Fail("There isn't any node with KSM available")
		}
		originalKubeVirt = util.GetCurrentKv(virtClient)
	})

	AfterEach(func() {
		tests.UpdateKubeVirtConfigValueAndWait(originalKubeVirt.Spec.Configuration)
	})

	DescribeTable("should enable/disable ksm and add/remove annotation", decorators.KSMRequired, func(ksmConfigFun ksmTestFunc) {
		kvConfig := originalKubeVirt.Spec.Configuration.DeepCopy()
		ksmConfig, expectedEnabledNodes := ksmConfigFun()
		kvConfig.KSMConfiguration = ksmConfig
		tests.UpdateKubeVirtConfigValueAndWait(*kvConfig)
		By("Ensure ksm is enabled and annotation is added in the expected nodes")
		for _, node := range expectedEnabledNodes {
			Eventually(func() (string, error) {
				command := []string{"cat", "/sys/kernel/mm/ksm/run"}
				ksmValue, err := tests.ExecuteCommandInVirtHandlerPod(node.Name, command)
				if err != nil {
					return "", err
				}

				return ksmValue, nil
			}, 30*time.Second, 2*time.Second).Should(BeEquivalentTo("1\n"), fmt.Sprintf("KSM should be enabled in node %s", node.Name))

			Eventually(func() (bool, error) {
				node, err := virtClient.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				_, found := node.GetAnnotations()[v1.KSMHandlerManagedAnnotation]
				return found, nil
			}, 30*time.Second, 2*time.Second).Should(BeTrue(), fmt.Sprintf("Node %s should have %s annotation", node.Name, v1.KSMHandlerManagedAnnotation))
		}

		tests.UpdateKubeVirtConfigValueAndWait(originalKubeVirt.Spec.Configuration)

		By("Ensure ksm is disabled and annotation is removed in the expected nodes")
		for _, node := range expectedEnabledNodes {
			Eventually(func() (string, error) {
				command := []string{"cat", "/sys/kernel/mm/ksm/run"}
				ksmValue, err := tests.ExecuteCommandInVirtHandlerPod(node.Name, command)
				if err != nil {
					return "", err
				}

				return ksmValue, nil
			}, 30*time.Second, 2*time.Second).Should(BeEquivalentTo("0\n"), fmt.Sprintf("KSM should be disabled in node %s", node.Name))

			Eventually(func() (bool, error) {
				node, err := virtClient.CoreV1().Nodes().Get(context.Background(), node.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				_, found := node.GetAnnotations()[v1.KSMHandlerManagedAnnotation]
				return found, nil
			}, 30*time.Second, 2*time.Second).Should(BeFalse(), fmt.Sprintf("Annotation %s should be removed from the node %s", v1.KSMHandlerManagedAnnotation, node.Name))
		}
	},
		Entry("in specific nodes when the selector with MatchLabels matches the node label", func() (*v1.KSMConfiguration, []*k8sv1.Node) {
			return &v1.KSMConfiguration{
				NodeLabelSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"kubernetes.io/hostname": nodesToEnableKSM[0].Name,
					},
				},
			}, []*k8sv1.Node{nodesToEnableKSM[0]}
		}),
		Entry("in specific nodes when the selector with MatchExpressions matches the node label", func() (*v1.KSMConfiguration, []*k8sv1.Node) {
			return &v1.KSMConfiguration{
				NodeLabelSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/hostname",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{nodesToEnableKSM[0].Name},
						},
					},
				},
			}, []*k8sv1.Node{nodesToEnableKSM[0]}
		}),
		Entry("in all the nodes when the selector is empty", func() (*v1.KSMConfiguration, []*k8sv1.Node) {
			return &v1.KSMConfiguration{
				NodeLabelSelector: &metav1.LabelSelector{},
			}, nodesToEnableKSM
		}),
	)
})
