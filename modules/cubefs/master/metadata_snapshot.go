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
// permissions and limitations under the License.

package master

import (
	"fmt"
	"github.com/tecbot/gorocksdb"
	"io"
)

// MetadataSnapshot represents the snapshot of a meta partition
type MetadataSnapshot struct {
	fsm      *MetadataFsm
	applied  uint64
	snapshot *gorocksdb.Snapshot
	iterator *gorocksdb.Iterator
}

// ApplyIndex implements the Snapshot interface
func (ms *MetadataSnapshot) ApplyIndex() uint64 {
	return ms.applied
}

// Close implements the Snapshot interface
func (ms *MetadataSnapshot) Close() {
	ms.fsm.store.ReleaseSnapshot(ms.snapshot)
}

// Next implements the Snapshot interface
func (ms *MetadataSnapshot) Next() (data []byte, err error) {
	md := new(RaftCmd)
	if ms.iterator.Valid() {
		key := ms.iterator.Key()
		md.K = string(key.Data())
		md.setOpType()
		value := ms.iterator.Value()
		if value != nil {
			md.V = value.Data()
		}
		if data, err = md.Marshal(); err != nil {
			err = fmt.Errorf("action[Next],marshal kv:%v,err:%v", md, err.Error())
			return nil, err
		}
		ms.iterator.Next()
		return data, nil
	}
	return nil, io.EOF
}
