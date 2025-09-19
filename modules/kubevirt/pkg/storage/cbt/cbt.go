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
 * Copyright The KubeVirt Authors.
 *
 */

package cbt

import (
	"path/filepath"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/log"

	"kubevirt.io/kubevirt/pkg/util"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
)

var (
	CBTKey   = "changedBlockTracking"
	CBTLabel = map[string]string{"changedBlockTracking": "true"}
)

func CBTState(status *v1.ChangedBlockTrackingStatus) v1.ChangedBlockTrackingState {
	if status == nil {
		return v1.ChangedBlockTrackingUndefined
	}
	return status.State
}

func SetCBTState(status **v1.ChangedBlockTrackingStatus, state v1.ChangedBlockTrackingState) {
	if state == v1.ChangedBlockTrackingUndefined {
		*status = nil
		return
	}
	*status = &v1.ChangedBlockTrackingStatus{State: state}
}

func CompareCBTState(status *v1.ChangedBlockTrackingStatus, state v1.ChangedBlockTrackingState) bool {
	return CBTState(status) == state
}

func cbtStateUndefined(status *v1.ChangedBlockTrackingStatus) bool {
	return status == nil || CompareCBTState(status, v1.ChangedBlockTrackingUndefined)
}

func cbtStateDisabled(status *v1.ChangedBlockTrackingStatus) bool {
	return CompareCBTState(status, v1.ChangedBlockTrackingUndefined) ||
		CompareCBTState(status, v1.ChangedBlockTrackingDisabled)
}

func HasCBTStateEnabled(status *v1.ChangedBlockTrackingStatus) bool {
	return CompareCBTState(status, v1.ChangedBlockTrackingInitializing) ||
		CompareCBTState(status, v1.ChangedBlockTrackingEnabled)
}

// vmMatchesChangedBlockTrackingSelectors checks if a VM should have CBT enabled based on cluster config
func vmMatchesChangedBlockTrackingSelectors(vm *v1.VirtualMachine, clusterConfig *virtconfig.ClusterConfig, nsStore cache.Store) bool {
	labelSelectors := clusterConfig.GetConfig().ChangedBlockTrackingLabelSelectors
	if labelSelectors == nil {
		return false
	}

	logger := log.Log.Object(vm)
	vmSelector := labelSelectors.VirtualMachineLabelSelector
	namespaceSelector := labelSelectors.NamespaceLabelSelector

	return vmMatchesVMSelector(vmSelector, vm.Labels, logger) ||
		vmMatchesNamespaceSelector(namespaceSelector, vm.Namespace, nsStore, logger)
}

func vmMatchesVMSelector(labelSelector *metav1.LabelSelector, vmLabels map[string]string, logger *log.FilteredLogger) bool {
	if labelSelector == nil {
		return false
	}
	vmSelector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		logger.Reason(err).Warning("invalid changedBlockTracking virtualMachineSelector set, assuming none")
		return false
	}

	return vmSelector.Matches(labels.Set(vmLabels))
}

func vmMatchesNamespaceSelector(labelSelector *metav1.LabelSelector, namespace string, nsStore cache.Store, logger *log.FilteredLogger) bool {
	if labelSelector == nil {
		return false
	}
	nsSelector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		logger.Reason(err).Warning("invalid changedBlockTracking namespaceSelector set, assuming none")
		return false
	}

	ns := getNamespaceFromStore(namespace, nsStore, logger)
	if ns == nil {
		return false
	}

	return nsSelector.Matches(labels.Set(ns.Labels))
}

func getNamespaceFromStore(namespace string, nsStore cache.Store, logger *log.FilteredLogger) *k8sv1.Namespace {
	if nsStore == nil {
		logger.Warning("namespace informer not available")
		return nil
	}

	obj, exists, err := nsStore.GetByKey(namespace)
	if err != nil {
		logger.Reason(err).Warning("failed to retrieve namespace from informer")
		return nil
	}

	if !exists {
		logger.Warningf("namespace %s not found in informer", namespace)
		return nil
	}

	ns, ok := obj.(*k8sv1.Namespace)
	if !ok {
		logger.Errorf("failed to cast object to Namespace: %+v", obj)
		return nil
	}

	return ns
}

func SyncVMChangedBlockTrackingState(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance, clusterConfig *virtconfig.ClusterConfig, nsStore cache.Store) {
	// If the status is already updated to ChangedBlockTrackingFGDisabled and the FG is still
	// disabled, skip.
	if CompareCBTState(vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingFGDisabled) &&
		!clusterConfig.IncrementalBackupEnabled() {
		return
	}
	vmMatchesSelector := vmMatchesChangedBlockTrackingSelectors(vm, clusterConfig, nsStore)
	if vmMatchesSelector {
		// If vm matches the labelSelector but IncrementalBackupGate is not enabled
		// update the status and return
		if !clusterConfig.IncrementalBackupEnabled() {
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingFGDisabled)
			return
		}
		enableChangedBlockTracking(vm, vmi)
	} else {
		disableChangedBlockTracking(vm, vmi)
	}
}

func enableChangedBlockTracking(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance) {
	if vmi != nil {
		enableChangedBlockTrackingVMIExists(vm, vmi)
	} else {
		enableChangedBlockTrackingNoVMI(vm)
	}
}

// enableChangedBlockTrackingVMIExists manages CBT state when both VM and VMI exist
func enableChangedBlockTrackingVMIExists(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance) {
	vmState := CBTState(vm.Status.ChangedBlockTracking)
	vmiState := CBTState(vmi.Status.ChangedBlockTracking)

	switch vmState {
	case v1.ChangedBlockTrackingUndefined, v1.ChangedBlockTrackingFGDisabled:
		// New CBT request - need restart to enable
		SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingPendingRestart)

	case v1.ChangedBlockTrackingPendingRestart, v1.ChangedBlockTrackingDisabled:
		// VM waiting for restart or disabled - check VMI state
		switch vmiState {
		case v1.ChangedBlockTrackingInitializing:
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingInitializing)
		case v1.ChangedBlockTrackingEnabled:
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingEnabled)
		default:
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingPendingRestart)
		}

	case v1.ChangedBlockTrackingInitializing, v1.ChangedBlockTrackingEnabled:
		// VM actively using CBT - sync with VMI state
		switch vmiState {
		case v1.ChangedBlockTrackingEnabled:
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingEnabled)
		default:
			SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingInitializing)
		}

	default:
		resetInvalidState(vm)
	}
}

// enableChangedBlockTrackingNoVMI manages CBT state when only VM exists (no VMI)
func enableChangedBlockTrackingNoVMI(vm *v1.VirtualMachine) {
	vmState := CBTState(vm.Status.ChangedBlockTracking)

	switch vmState {
	case v1.ChangedBlockTrackingUndefined,
		v1.ChangedBlockTrackingPendingRestart,
		v1.ChangedBlockTrackingInitializing,
		v1.ChangedBlockTrackingDisabled,
		v1.ChangedBlockTrackingFGDisabled:
		// VM without VMI - set to initializing
		SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingInitializing)

	case v1.ChangedBlockTrackingEnabled:
		// Keep enabled state when no VMI exists
		SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingEnabled)

	default:
		resetInvalidState(vm)
	}
}

// disableChangedBlockTracking handles disabling CBT for VMs that no longer match selectors
func disableChangedBlockTracking(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance) {
	// No action needed if VM cbtState is already undefined or disabled
	if cbtStateDisabled(vm.Status.ChangedBlockTracking) {
		return
	}

	// Disable immediately if no VMI or VMI cbtState is undefined or disabled
	if vmi == nil || cbtStateDisabled(vmi.Status.ChangedBlockTracking) {
		SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingDisabled)
		return
	}

	// Handle active states that need to transition through restart
	switch CBTState(vm.Status.ChangedBlockTracking) {
	case v1.ChangedBlockTrackingPendingRestart,
		v1.ChangedBlockTrackingInitializing,
		v1.ChangedBlockTrackingEnabled,
		v1.ChangedBlockTrackingFGDisabled:

		SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingPendingRestart)
	default:
		resetInvalidState(vm)
	}
}

func resetInvalidState(vm *v1.VirtualMachine) {
	log.Log.Object(vm).Warningf("invalid changedBlockTracking state %s, resetting to undefined", vm.Status.ChangedBlockTracking)
	SetCBTState(&vm.Status.ChangedBlockTracking, v1.ChangedBlockTrackingUndefined)
}

func SetChangedBlockTrackingOnVMI(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance, clusterConfig *virtconfig.ClusterConfig, nsStore cache.Store) {
	if !clusterConfig.IncrementalBackupEnabled() {
		SetCBTState(&vmi.Status.ChangedBlockTracking, v1.ChangedBlockTrackingUndefined)
		return
	}

	vmMatchesSelector := vmMatchesChangedBlockTrackingSelectors(vm, clusterConfig, nsStore)
	if vmMatchesSelector {
		SetCBTState(&vmi.Status.ChangedBlockTracking, v1.ChangedBlockTrackingInitializing)
	} else if !cbtStateUndefined(vm.Status.ChangedBlockTracking) {
		SetCBTState(&vmi.Status.ChangedBlockTracking, v1.ChangedBlockTrackingDisabled)
	}
}

func IsCBTEligibleVolume(volume *v1.Volume) bool {
	return volume.VolumeSource.PersistentVolumeClaim != nil ||
		volume.VolumeSource.DataVolume != nil ||
		volume.VolumeSource.HostDisk != nil
}

func SetChangedBlockTrackingOnVMIFromDomain(vmi *v1.VirtualMachineInstance, domain *api.Domain) {
	if domain == nil || vmi.Status.ChangedBlockTracking == nil {
		return
	}

	cbtSet := true
	for _, volume := range vmi.Spec.Volumes {
		if !IsCBTEligibleVolume(&volume) {
			continue
		}
		found := false
		for _, disk := range domain.Spec.Devices.Disks {
			if disk.Alias.GetName() == volume.Name {
				found = true
				if disk.Source.DataStore == nil {
					cbtSet = false
				}
				break
			}
		}
		// If we didn't find a matching disk for an eligible volume, disable CBT
		if !found {
			cbtSet = false
			break
		}
	}

	if cbtSet {
		SetCBTState(&vmi.Status.ChangedBlockTracking, v1.ChangedBlockTrackingEnabled)
	}
}

func PathForCBT(vmi *v1.VirtualMachineInstance) string {
	cbtPath := "/var/lib/libvirt/qemu/cbt"
	if util.IsNonRootVMI(vmi) {
		cbtPath = filepath.Join(util.VirtPrivateDir, "libvirt", "qemu", "cbt")
	}

	return cbtPath
}

func GetQCOW2OverlayPath(vmi *v1.VirtualMachineInstance, volumeName string) string {
	cbtPath := PathForCBT(vmi)
	return filepath.Join(cbtPath, volumeName+".qcow2")
}
