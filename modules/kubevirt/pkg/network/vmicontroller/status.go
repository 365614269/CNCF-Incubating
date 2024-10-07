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

package vmicontroller

import (
	"fmt"

	k8scorev1 "k8s.io/api/core/v1"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/network/multus"
	"kubevirt.io/kubevirt/pkg/network/namescheme"
	"kubevirt.io/kubevirt/pkg/network/vmispec"
)

func UpdateStatus(vmi *v1.VirtualMachineInstance, pod *k8scorev1.Pod) error {
	indexedMultusStatusIfaces := multus.NonDefaultNetworkStatusIndexedByIfaceName(pod)
	ifaceNamingScheme := namescheme.CreateNetworkNameSchemeByPodNetworkStatus(vmi.Spec.Networks, indexedMultusStatusIfaces)
	for _, network := range vmi.Spec.Networks {
		vmiIfaceStatus := vmispec.LookupInterfaceStatusByName(vmi.Status.Interfaces, network.Name)
		podIfaceName, wasFound := ifaceNamingScheme[network.Name]
		if !wasFound {
			return fmt.Errorf("could not find the pod interface name for network [%s]", network.Name)
		}

		_, exists := indexedMultusStatusIfaces[podIfaceName]
		switch {
		case exists && vmiIfaceStatus == nil:
			vmi.Status.Interfaces = append(vmi.Status.Interfaces, v1.VirtualMachineInstanceNetworkInterface{
				Name:       network.Name,
				InfoSource: vmispec.InfoSourceMultusStatus,
			})
		case exists && vmiIfaceStatus != nil:
			vmiIfaceStatus.InfoSource = vmispec.AddInfoSource(vmiIfaceStatus.InfoSource, vmispec.InfoSourceMultusStatus)
		case !exists && vmiIfaceStatus != nil:
			vmiIfaceStatus.InfoSource = vmispec.RemoveInfoSource(vmiIfaceStatus.InfoSource, vmispec.InfoSourceMultusStatus)
		}
	}

	return nil
}
