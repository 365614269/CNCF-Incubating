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
 * Copyright 2024 The KubeVirt Authors.
 *
 */

package multus_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	k8scorev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"kubevirt.io/kubevirt/pkg/network/multus"
)

var _ = Describe("Network Status", func() {
	const multusNetworkStatusWithPrimaryNet = `[{"name":"k8s-pod-network","ips":["10.244.196.146","fd10:244::c491"],"default":true,"dns":{}}]`

	DescribeTable("It should return empty", func(annotations map[string]string) {
		result := multus.NonDefaultNetworkStatusIndexedByIfaceName(newStubPod(annotations))
		Expect(result).To(BeEmpty())
	},
		Entry("when network-status is missing", map[string]string{}),
		Entry("when network-status contains only pod network",
			map[string]string{networkv1.NetworkStatusAnnot: multusNetworkStatusWithPrimaryNet},
		),
	)

	It("Should return a map of pod interface name to network status when interface name is hashed", func() {
		const (
			multusNetworksAnnotation                       = `[{"name":"meganet","namespace":"default","interface":"pod7e0055a6880"}]`
			multusNetworkStatusWithPrimaryAndSecondaryNets = `[` +
				`{"name":"k8s-pod-network","ips":["10.244.196.146","fd10:244::c491"],"default":true,"dns":{}},` +
				`{"name":"meganet","interface":"pod7e0055a6880","mac":"8a:37:d9:e7:0f:18","dns":{}}` +
				`]`
		)

		annotations := map[string]string{
			networkv1.NetworkAttachmentAnnot: multusNetworksAnnotation,
			networkv1.NetworkStatusAnnot:     multusNetworkStatusWithPrimaryAndSecondaryNets,
		}

		result := multus.NonDefaultNetworkStatusIndexedByIfaceName(newStubPod(annotations))

		expectedResult := map[string]networkv1.NetworkStatus{
			"pod7e0055a6880": {
				Name:      "meganet",
				Interface: "pod7e0055a6880",
				Mac:       "8a:37:d9:e7:0f:18",
				Default:   false,
			},
		}

		Expect(result).To(Equal(expectedResult))
	})

	It("Should return a map of pod interface name to network status when interface name is ordinal", func() {
		const (
			multusOrdinalNetworksAnnotation                       = `[{"name":"meganet","namespace":"default","interface":"net1"}]`
			multusNetworkStatusWithPrimaryAndOrdinalSecondaryNets = `[` +
				`{"name":"k8s-pod-network","ips":["10.244.196.146","fd10:244::c491"],"default":true,"dns":{}},` +
				`{"name":"meganet","interface":"net1","mac":"8a:37:d9:e7:0f:18","dns":{}}` +
				`]`
		)

		annotations := map[string]string{
			networkv1.NetworkAttachmentAnnot: multusOrdinalNetworksAnnotation,
			networkv1.NetworkStatusAnnot:     multusNetworkStatusWithPrimaryAndOrdinalSecondaryNets,
		}

		result := multus.NonDefaultNetworkStatusIndexedByIfaceName(newStubPod(annotations))

		expectedResult := map[string]networkv1.NetworkStatus{
			"net1": {
				Name:      "meganet",
				Interface: "net1",
				Mac:       "8a:37:d9:e7:0f:18",
				Default:   false,
			},
		}

		Expect(result).To(Equal(expectedResult))
	})
})

func newStubPod(annotations map[string]string) *k8scorev1.Pod {
	return &k8scorev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
		},
	}
}
