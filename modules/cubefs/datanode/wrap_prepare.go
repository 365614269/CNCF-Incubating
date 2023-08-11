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

package datanode

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"sync/atomic"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/repl"
	"github.com/cubefs/cubefs/storage"
)

func (s *DataNode) Prepare(p *repl.Packet) (err error) {
	defer func() {
		p.SetPacketHasPrepare()
		if err != nil {
			p.PackErrorBody(repl.ActionPreparePkt, err.Error())
		} else {
			p.AfterPre = true
		}
	}()
	if p.IsMasterCommand() {
		return
	}
	atomic.AddUint64(&s.metricsCnt, 1)
	if !s.shallDegrade() {
		p.BeforeTp(s.clusterID)
		p.UnsetDegrade()
	} else {
		p.SetDegrade()
	}
	err = s.checkStoreMode(p)
	if err != nil {
		return
	}
	if err = s.checkCrc(p); err != nil {
		return
	}
	if err = s.checkPartition(p); err != nil {
		return
	}
	// For certain packet, we meed to add some additional extent information.
	if err = s.addExtentInfo(p); err != nil {
		return
	}

	return
}

func (s *DataNode) checkStoreMode(p *repl.Packet) (err error) {
	if p.ExtentType == proto.TinyExtentType || p.ExtentType == proto.NormalExtentType {
		return nil
	}
	return ErrIncorrectStoreType
}

func (s *DataNode) checkCrc(p *repl.Packet) (err error) {
	if !p.IsWriteOperation() {
		return
	}
	crc := crc32.ChecksumIEEE(p.Data[:p.Size])
	if crc != p.CRC {
		return storage.CrcMismatchError
	}

	return
}

func (s *DataNode) checkPartition(p *repl.Packet) (err error) {
	dp := s.space.Partition(p.PartitionID)
	if dp == nil {
		err = proto.ErrDataPartitionNotExists
		return
	}
	p.Object = dp
	if p.IsWriteOperation() || p.IsCreateExtentOperation() {
		if dp.Available() <= 0 {
			err = storage.NoSpaceError
			return
		}
	}
	if p.IsWriteOperation() || p.IsRandomWrite() {
		dp.disk.allocCheckLimit(proto.FlowWriteType, uint32(p.Size))
		dp.disk.allocCheckLimit(proto.IopsWriteType, 1)
	}
	return
}

func (s *DataNode) addExtentInfo(p *repl.Packet) error {
	partition := p.Object.(*DataPartition)
	store := p.Object.(*DataPartition).ExtentStore()
	var (
		extentID uint64
		err      error
	)
	if p.IsLeaderPacket() && p.IsTinyExtentType() && p.IsWriteOperation() {
		extentID, err = store.GetAvailableTinyExtent()
		if err != nil {
			return fmt.Errorf("addExtentInfo partition %v GetAvailableTinyExtent error %v", p.PartitionID, err.Error())
		}
		p.ExtentID = extentID
		p.ExtentOffset, err = store.GetTinyExtentOffset(extentID)
		if err != nil {
			return fmt.Errorf("addExtentInfo partition %v  %v GetTinyExtentOffset error %v", p.PartitionID, extentID, err.Error())
		}
	} else if p.IsLeaderPacket() && p.IsCreateExtentOperation() {
		if partition.isNormalType() && partition.GetExtentCount() >= storage.MaxExtentCount*3 {
			return fmt.Errorf("addExtentInfo partition %v has reached maxExtentId", p.PartitionID)
		}
		p.ExtentID, err = store.NextExtentID()
		if err != nil {
			return fmt.Errorf("addExtentInfo partition %v allocCheckLimit NextExtentId error %v", p.PartitionID, err)
		}
	} else if p.IsLeaderPacket() && p.IsMarkDeleteExtentOperation() && p.IsTinyExtentType() {
		record := new(proto.TinyExtentDeleteRecord)
		if err := json.Unmarshal(p.Data[:p.Size], record); err != nil {
			return fmt.Errorf("addExtentInfo failed %v", err.Error())
		}
		p.Data, _ = json.Marshal(record)
		p.Size = uint32(len(p.Data))
	}

	if (p.IsCreateExtentOperation() || p.IsWriteOperation()) && p.ExtentID == 0 {
		return fmt.Errorf("addExtentInfo partition %v invalid extent id. ", p.PartitionID)
	}

	p.OrgBuffer = p.Data

	return nil
}
