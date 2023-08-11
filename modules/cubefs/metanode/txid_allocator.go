// Copyright 2018 The CubeFS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.k

package metanode

import (
	"sync"
	"sync/atomic"
)

// TxIDAllocator generates and allocates ids
type TxIDAllocator struct {
	mpTxID   uint64
	txIDLock sync.RWMutex
}

//func newTxIDAllocator(mpID uint64, partition raftstore.Partition) (alloc *TxIDAllocator) {
func newTxIDAllocator() (alloc *TxIDAllocator) {
	alloc = new(TxIDAllocator)
	return
}

func (alloc *TxIDAllocator) Reset() {
	atomic.StoreUint64(&alloc.mpTxID, 0)
}

func (alloc *TxIDAllocator) setTransactionID(id uint64) {
	atomic.StoreUint64(&alloc.mpTxID, id)
}

func (alloc *TxIDAllocator) getTransactionID() uint64 {
	return atomic.LoadUint64(&alloc.mpTxID)
}

func (alloc *TxIDAllocator) allocateTransactionID() (mpTxID uint64) {
	alloc.txIDLock.Lock()
	defer alloc.txIDLock.Unlock()
	mpTxID = atomic.LoadUint64(&alloc.mpTxID) + 1
	alloc.setTransactionID(mpTxID)
	return
}
