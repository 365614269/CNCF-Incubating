// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"sync/atomic"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var (
	preAllocateMapSetting uint32 = unix.BPF_F_NO_PREALLOC
	noCommonLRUMapSetting uint32 = 0
)

// EnableMapPreAllocation enables BPF map pre-allocation on map types that
// support it. This does not take effect on existing map although some map
// types could be recreated later when objCheck() runs.
func EnableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// DisableMapPreAllocation disables BPF map pre-allocation as a default
// setting. Some map types enforces pre-alloc strategy so this does not
// take effect in that case. Also note that this does not take effect on
// existing map although could be recreated later when objCheck() runs.
func DisableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, unix.BPF_F_NO_PREALLOC)
}

// EnableMapDistributedLRU enables the LRU map no-common-LRU feature which
// splits backend memory pools among CPUs to avoid sharing a common backend
// pool where frequent allocation/frees might content on internal spinlocks.
func EnableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, unix.BPF_F_NO_COMMON_LRU)
}

// DisableMapDistributedLRU disables the LRU map no-common-LRU feature which
// is the default case.
func DisableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, 0)
}

// GetMapMemoryFlags returns relevant map memory allocation flags which
// the user requested.
func GetMapMemoryFlags(t ebpf.MapType) uint32 {
	switch t {
	// LPM Tries don't support preallocation.
	case ebpf.LPMTrie:
		return unix.BPF_F_NO_PREALLOC
	// Support disabling preallocation for these map types.
	case ebpf.Hash, ebpf.PerCPUHash, ebpf.HashOfMaps:
		return atomic.LoadUint32(&preAllocateMapSetting)
	// Support no-common LRU backend memory
	case ebpf.LRUHash, ebpf.LRUCPUHash:
		return atomic.LoadUint32(&noCommonLRUMapSetting)
	}

	return 0
}
