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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cubefs/cubefs/depends/tiglabs/raft"
	raftProto "github.com/cubefs/cubefs/depends/tiglabs/raft/proto"
	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/repl"
	"github.com/cubefs/cubefs/storage"
	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/errors"
	"github.com/cubefs/cubefs/util/exporter"
	"github.com/cubefs/cubefs/util/log"
)

var ErrForbiddenDataPartition = errors.New("the data partition is forbidden")

func (s *DataNode) getPacketTpLabels(p *repl.Packet) map[string]string {
	labels := make(map[string]string)
	labels[exporter.Vol] = ""
	labels[exporter.Op] = ""
	labels[exporter.PartId] = ""
	labels[exporter.Disk] = ""

	if part, ok := p.Object.(*DataPartition); ok {
		labels[exporter.Vol] = part.volumeID
		labels[exporter.Op] = p.GetOpMsg()
		if exporter.EnablePid {
			labels[exporter.PartId] = fmt.Sprintf("%d", part.partitionID)
			labels[exporter.Disk] = part.path
		}
	}

	return labels
}

func isColdVolExtentDelErr(p *repl.Packet) bool {
	if p.Object == nil {
		return false
	}

	partition, ok := p.Object.(*DataPartition)
	if !ok {
		return false
	}

	if proto.IsNormalDp(partition.partitionType) {
		return false
	}

	if p.ResultCode == proto.OpNotExistErr {
		return true
	}

	return false
}

func (s *DataNode) OperatePacket(p *repl.Packet, c net.Conn) (err error) {
	var (
		tpLabels map[string]string
		tpObject *exporter.TimePointCount
	)

	shallDegrade := p.ShallDegrade()
	sz := p.Size
	if !shallDegrade {
		tpObject = exporter.NewTPCnt(p.GetOpMsg())
		tpLabels = s.getPacketTpLabels(p)
	}
	start := time.Now().UnixNano()
	defer func() {
		resultSize := p.Size
		p.Size = sz
		if p.IsErrPacket() {
			err = fmt.Errorf("op(%v) error(%v)", p.GetOpMsg(), string(p.Data[:resultSize]))
			logContent := fmt.Sprintf("action[OperatePacket] %v.",
				p.LogMessage(p.GetOpMsg(), c.RemoteAddr().String(), start, err))
			if isColdVolExtentDelErr(p) {
				log.LogInfof(logContent)
			} else {
				log.LogErrorf(logContent)
			}
		} else {
			logContent := fmt.Sprintf("action[OperatePacket] %v.",
				p.LogMessage(p.GetOpMsg(), c.RemoteAddr().String(), start, nil))
			switch p.Opcode {
			case proto.OpStreamRead, proto.OpRead, proto.OpExtentRepairRead, proto.OpStreamFollowerRead:
			case proto.OpReadTinyDeleteRecord:
				log.LogRead(logContent)
			case proto.OpWrite, proto.OpRandomWrite,
				proto.OpRandomWriteVer, proto.OpSyncRandomWriteVer,
				proto.OpRandomWriteAppend, proto.OpSyncRandomWriteAppend,
				proto.OpTryWriteAppend, proto.OpSyncTryWriteAppend,
				proto.OpSyncRandomWrite, proto.OpSyncWrite, proto.OpMarkDelete, proto.OpSplitMarkDelete:
				log.LogWrite(logContent)
			default:
				log.LogInfo(logContent)
			}
		}
		p.Size = resultSize
		if !shallDegrade {
			tpObject.SetWithLabels(err, tpLabels)
		}
	}()
	switch p.Opcode {
	case proto.OpCreateExtent:
		s.handlePacketToCreateExtent(p)
	case proto.OpWrite, proto.OpSyncWrite:
		s.handleWritePacket(p)
	case proto.OpStreamRead:
		s.handleStreamReadPacket(p, c, StreamRead)
	case proto.OpStreamFollowerRead:
		s.extentRepairReadPacket(p, c, StreamRead)
	case proto.OpExtentRepairRead:
		s.handleExtentRepairReadPacket(p, c, RepairRead)
	case proto.OpTinyExtentRepairRead:
		s.handleTinyExtentRepairReadPacket(p, c)
	case proto.OpMarkDelete, proto.OpSplitMarkDelete:
		s.handleMarkDeletePacket(p, c)
	case proto.OpBatchDeleteExtent:
		s.handleBatchMarkDeletePacket(p, c)
	case proto.OpRandomWrite, proto.OpSyncRandomWrite,
		proto.OpRandomWriteAppend, proto.OpSyncRandomWriteAppend,
		proto.OpTryWriteAppend, proto.OpSyncTryWriteAppend,
		proto.OpRandomWriteVer, proto.OpSyncRandomWriteVer:
		s.handleRandomWritePacket(p)
	case proto.OpNotifyReplicasToRepair:
		s.handlePacketToNotifyExtentRepair(p)
	case proto.OpGetAllWatermarks:
		s.handlePacketToGetAllWatermarks(p)
	case proto.OpCreateDataPartition:
		s.handlePacketToCreateDataPartition(p)
	case proto.OpLoadDataPartition:
		s.handlePacketToLoadDataPartition(p)
	case proto.OpDeleteDataPartition:
		s.handlePacketToDeleteDataPartition(p)
	case proto.OpDataNodeHeartbeat:
		s.handleHeartbeatPacket(p)
	case proto.OpGetAppliedId:
		s.handlePacketToGetAppliedID(p)
	case proto.OpDecommissionDataPartition:
		s.handlePacketToDecommissionDataPartition(p)
	case proto.OpAddDataPartitionRaftMember:
		s.handlePacketToAddDataPartitionRaftMember(p)
	case proto.OpRemoveDataPartitionRaftMember:
		s.handlePacketToRemoveDataPartitionRaftMember(p)
	case proto.OpDataPartitionTryToLeader:
		s.handlePacketToDataPartitionTryToLeader(p)
	case proto.OpGetPartitionSize:
		s.handlePacketToGetPartitionSize(p)
	case proto.OpGetMaxExtentIDAndPartitionSize:
		s.handlePacketToGetMaxExtentIDAndPartitionSize(p)
	case proto.OpReadTinyDeleteRecord:
		s.handlePacketToReadTinyDeleteRecordFile(p, c)
	case proto.OpBroadcastMinAppliedID:
		s.handleBroadcastMinAppliedID(p)
	case proto.OpVersionOperation:
		s.handleUpdateVerPacket(p)
	case proto.OpStopDataPartitionRepair:
		s.handlePacketToStopDataPartitionRepair(p)
	default:
		p.PackErrorBody(repl.ErrorUnknownOp.Error(), repl.ErrorUnknownOp.Error()+strconv.Itoa(int(p.Opcode)))
	}

	return
}

// Handle OpCreateExtent packet.
func (s *DataNode) handlePacketToCreateExtent(p *repl.Packet) {
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionCreateExtent, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	partition := p.Object.(*DataPartition)
	if partition.Available() <= 0 || !partition.disk.CanWrite() {
		err = storage.NoSpaceError
		return
	} else if partition.disk.Status == proto.Unavailable {
		err = storage.BrokenDiskError
		return
	}

	// in case too many extents
	if partition.GetExtentCount() >= storage.MaxExtentCount+10 {
		err = storage.NoSpaceError
		return
	}

	partition.disk.allocCheckLimit(proto.IopsWriteType, 1)

	err = partition.ExtentStore().Create(p.ExtentID)
}

// Handle OpCreateDataPartition packet.
func (s *DataNode) handlePacketToCreateDataPartition(p *repl.Packet) {
	var (
		err   error
		bytes []byte
		dp    *DataPartition
	)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionCreateDataPartition, err.Error())
		}
	}()
	task := &proto.AdminTask{}
	if err = json.Unmarshal(p.Data, task); err != nil {
		err = fmt.Errorf("cannnot unmashal adminTask")
		return
	}
	request := &proto.CreateDataPartitionRequest{}
	if task.OpCode != proto.OpCreateDataPartition {
		err = fmt.Errorf("from master Task(%v) failed,error unavali opcode(%v)", task.ToString(), task.OpCode)
		return
	}

	bytes, err = json.Marshal(task.Request)
	if err != nil {
		err = fmt.Errorf("from master Task(%v) cannot unmashal CreateDataPartition, err %s", task.ToString(), err.Error())
		return
	}
	p.AddMesgLog(string(bytes))
	if err = json.Unmarshal(bytes, request); err != nil {
		err = fmt.Errorf("from master Task(%v) cannot unmashal CreateDataPartitionRequest struct, err(%s)", task.ToString(), err.Error())
		return
	}
	p.PartitionID = request.PartitionId
	if dp, err = s.space.CreatePartition(request); err != nil {
		err = fmt.Errorf("from master Task(%v) cannot create Partition err(%v)", task.ToString(), err)
		return
	}
	p.PacketOkWithBody([]byte(dp.Disk().Path))
}

func (s *DataNode) commitDelVersion(volumeID string, verSeq uint64) (err error) {
	for _, partition := range s.space.partitions {
		if partition.config.VolName != volumeID {
			continue
		}
		verListMgr := partition.volVersionInfoList
		verListMgr.Lock()
		for i, ver := range verListMgr.VerList {
			if i == len(verListMgr.VerList)-1 {
				log.LogWarnf("action[fsmVersionOp] mp[%v] seq %v, seqArray size %v newest ver %v",
					partition.config.PartitionID, verSeq, len(verListMgr.VerList), ver.Ver)
				break
			}
			if ver.Ver == verSeq {
				log.LogInfof("action[fsmVersionOp] mp[%v] seq %v,seqArray size %v", partition.config.PartitionID, verSeq, len(verListMgr.VerList))
				// mp.multiVersionList = append(mp.multiVersionList[:i], mp.multiVersionList[i+1:]...)
				verListMgr.VerList = append(verListMgr.VerList[:i], verListMgr.VerList[i+1:]...)
				break
			}
		}
		verListMgr.Unlock()
	}
	return
}

func (s *DataNode) commitCreateVersion(req *proto.MultiVersionOpRequest) (err error) {

	log.LogInfof("action[commitCreateVersion] handle master version reqeust seq %v", req.VerSeq)
	if value, ok := s.volUpdating.Load(req.VolumeID); ok {
		ver2Phase := value.(*verOp2Phase)
		log.LogWarnf("action[commitCreateVersion] try commit volume %v prepare seq %v with commit seq %v",
			req.VolumeID, ver2Phase.verPrepare, req.VerSeq)
		if req.VerSeq < ver2Phase.verSeq {
			log.LogWarnf("vol %v seq %v create less than loal %v", req.VolumeID, req.VerSeq, ver2Phase.verSeq)
			return
		}
		if ver2Phase.step != proto.CreateVersionPrepare {
			log.LogWarnf("action[commitCreateVersion] vol %v seq %v step not prepare", req.VolumeID, ver2Phase.step)
		}

		s.space.partitionMutex.RLock()
		defer s.space.partitionMutex.RUnlock()
		for _, partition := range s.space.partitions {
			if partition.config.VolName != req.VolumeID {
				continue
			}

			partition.volVersionInfoList.Lock()
			if len(partition.volVersionInfoList.VerList) == 0 {
				log.LogWarnf("action[commitCreateVersion] reqeust ver %v verlist  %v  dp verlist nil and set", req.VerSeq, req.VolVerList)
				partition.volVersionInfoList.VerList = req.VolVerList
				partition.verSeq = req.VerSeq
				partition.volVersionInfoList.Unlock()
				continue
			}

			lastVerInfo := partition.volVersionInfoList.GetLastVolVerInfo()
			log.LogInfof("action[commitCreateVersion] reqeust seq %v lessOrEqual last exist snapshot seq %v op %v",
				lastVerInfo.Ver, req.VerSeq, req.Op)

			if lastVerInfo.Ver >= req.VerSeq {
				if lastVerInfo.Ver == req.VerSeq {
					if req.Op == proto.CreateVersionCommit {
						lastVerInfo.Status = proto.VersionNormal
					}
				}
				partition.volVersionInfoList.Unlock()
				continue
			}

			var status uint8 = proto.VersionPrepare
			if req.Op == proto.CreateVersionCommit {
				status = proto.VersionNormal
			}
			partition.volVersionInfoList.VerList = append(partition.volVersionInfoList.VerList, &proto.VolVersionInfo{
				Status: status,
				Ver:    req.VerSeq,
			})
			log.LogInfof("action[commitCreateVersion] reqeust add new seq %v verlist (%v)", req.VerSeq, partition.volVersionInfoList)
			partition.verSeq = req.VerSeq
			partition.volVersionInfoList.Unlock()
		}

		if req.Op == proto.CreateVersionPrepare {
			return
		}
		ver2Phase.verSeq = req.VerSeq
		ver2Phase.step = proto.CreateVersionCommit
		ver2Phase.status = proto.VersionWorkingFinished
		log.LogInfof("action[commitCreateVersion] commit volume %v prepare seq %v with commit seq %v",
			req.VolumeID, ver2Phase.verPrepare, req.VerSeq)

		return
	}

	log.LogWarnf("action[commitCreateVersion] vol %v not found seq %v", req.VolumeID, req.VerSeq)
	return
}

func (s *DataNode) prepareCreateVersion(req *proto.MultiVersionOpRequest) (err error, opAagin bool) {
	var ver2Phase *verOp2Phase
	if value, ok := s.volUpdating.Load(req.VolumeID); ok {
		ver2Phase = value.(*verOp2Phase)
		if req.VerSeq < ver2Phase.verSeq {
			err = fmt.Errorf("seq %v create less than loal %v", req.VerSeq, ver2Phase.verSeq)
			log.LogInfof("action[prepareCreateVersion] volume %v update to ver %v step %v", req.VolumeID, req.VerSeq, ver2Phase.step)
			return
		} else if req.VerSeq == ver2Phase.verPrepare {
			if ver2Phase.step == proto.VersionWorking {
				opAagin = true
				return
			}
		}
	}
	ver2Phase = &verOp2Phase{}
	ver2Phase.step = uint32(req.Op)
	ver2Phase.status = proto.VersionWorking
	ver2Phase.verPrepare = req.VerSeq

	s.volUpdating.Store(req.VolumeID, ver2Phase)

	log.LogWarnf("action[prepareCreateVersion] volume %v update to step %v step %v",
		req.VolumeID, req.VerSeq, ver2Phase.step)
	return
}

// Handle OpHeartbeat packet.
func (s *DataNode) handleUpdateVerPacket(p *repl.Packet) {
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionUpdateVersion, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()

	task := &proto.AdminTask{}
	err = json.Unmarshal(p.Data, task)
	if err != nil {
		log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
		return
	}
	request := &proto.MultiVersionOpRequest{}
	response := &proto.MultiVersionOpResponse{}
	response.Op = task.OpCode
	response.Status = proto.TaskSucceeds

	if task.OpCode == proto.OpVersionOperation {
		marshaled, _ := json.Marshal(task.Request)
		if err = json.Unmarshal(marshaled, request); err != nil {
			log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
			response.Status = proto.TaskFailed
			goto end
		}

		if request.Op == proto.CreateVersionPrepare {
			if err, _ = s.prepareCreateVersion(request); err != nil {
				log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
				goto end
			}
			if err = s.commitCreateVersion(request); err != nil {
				log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
				goto end
			}
		} else if request.Op == proto.CreateVersionCommit {
			if err = s.commitCreateVersion(request); err != nil {
				log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
				goto end
			}
		} else if request.Op == proto.DeleteVersion {
			if err = s.commitDelVersion(request.VolumeID, request.VerSeq); err != nil {
				log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
				goto end
			}
		}

		response.VerSeq = request.VerSeq
		response.Op = request.Op
		response.Addr = request.Addr
		response.VolumeID = request.VolumeID

	} else {
		err = fmt.Errorf("illegal opcode")
		log.LogErrorf("action[handleUpdateVerPacket] handle master version reqeust err %v", err)
		goto end
	}
end:
	if err != nil {
		response.Result = err.Error()
	}
	task.Response = response
	log.LogInfof("action[handleUpdateVerPacket] rsp to client,req vol %v, verseq %v, op %v", request.VolumeID, request.VerSeq, request.Op)
	if err = MasterClient.NodeAPI().ResponseDataNodeTask(task); err != nil {
		err = errors.Trace(err, "handleUpdateVerPacket to master failed.")
		log.LogErrorf(err.Error())
		return
	}

}

func (s *DataNode) checkVolumeForbidden(volNames []string) {
	s.space.RangePartitions(func(partition *DataPartition) bool {
		for _, volName := range volNames {
			if volName == partition.volumeID {
				partition.SetForbidden(true)
				return true
			}
		}
		partition.SetForbidden(false)
		return true
	})
}

// Handle OpHeartbeat packet.
func (s *DataNode) handleHeartbeatPacket(p *repl.Packet) {
	var err error
	task := &proto.AdminTask{}
	err = json.Unmarshal(p.Data, task)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionCreateDataPartition, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	if err != nil {
		return
	}

	go func() {
		request := &proto.HeartBeatRequest{}
		response := &proto.DataNodeHeartbeatResponse{}
		s.buildHeartBeatResponse(response)

		if task.OpCode == proto.OpDataNodeHeartbeat {
			marshaled, _ := json.Marshal(task.Request)
			_ = json.Unmarshal(marshaled, request)
			response.Status = proto.TaskSucceeds
			if s.diskQosEnableFromMaster != request.EnableDiskQos {
				log.LogWarnf("action[handleHeartbeatPacket] master command disk qos enable change to [%v], local conf enable [%v]",
					request.EnableDiskQos,
					s.diskQosEnable)
			}

			// set volume forbidden
			s.checkVolumeForbidden(request.ForbiddenVols)

			s.diskQosEnableFromMaster = request.EnableDiskQos

			var needUpdate bool
			if request.QosFlowWriteLimit > 0 && request.QosFlowWriteLimit != s.diskFlowWriteLimit {
				s.diskFlowWriteLimit = request.QosFlowWriteLimit
				needUpdate = true
			}
			if request.QosFlowReadLimit > 0 && request.QosFlowReadLimit != s.diskFlowReadLimit {
				s.diskFlowReadLimit = request.QosFlowReadLimit
				needUpdate = true
			}
			if request.QosIopsWriteLimit > 0 && request.QosIopsWriteLimit != s.diskIopsWriteLimit {
				s.diskIopsWriteLimit = request.QosIopsWriteLimit
				needUpdate = true
			}
			if request.QosIopsReadLimit > 0 && request.QosIopsReadLimit != s.diskIopsReadLimit {
				s.diskIopsReadLimit = request.QosIopsReadLimit
				needUpdate = true
			}

			// set cpu util and io used in here
			response.CpuUtil = s.cpuUtil.Load()
			response.IoUtils = s.space.GetDiskUtils()

			if needUpdate {
				log.LogWarnf("action[handleHeartbeatPacket] master change disk qos limit to [flowWrite %v, flowRead %v, iopsWrite %v, iopsRead %v]",
					s.diskFlowWriteLimit,
					s.diskFlowReadLimit,
					s.diskIopsWriteLimit,
					s.diskIopsReadLimit)
				s.updateQosLimit()
			}
		} else {
			response.Status = proto.TaskFailed
			err = fmt.Errorf("illegal opcode")
			response.Result = err.Error()
		}
		task.Response = response
		if err = MasterClient.NodeAPI().ResponseDataNodeTask(task); err != nil {
			err = errors.Trace(err, "heartbeat to master(%v) failed.", request.MasterAddr)
			log.LogErrorf(err.Error())
			return
		}
	}()
}

// Handle OpDeleteDataPartition packet.
func (s *DataNode) handlePacketToDeleteDataPartition(p *repl.Packet) {
	task := &proto.AdminTask{}
	err := json.Unmarshal(p.Data, task)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionDeleteDataPartition, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	if err != nil {
		return
	}
	request := &proto.DeleteDataPartitionRequest{}
	if task.OpCode == proto.OpDeleteDataPartition {
		bytes, _ := json.Marshal(task.Request)
		p.AddMesgLog(string(bytes))
		err = json.Unmarshal(bytes, request)
		if err != nil {
			return
		} else {
			s.space.DeletePartition(request.PartitionId)
		}
	} else {
		err = fmt.Errorf("illegal opcode ")
	}
	if err != nil {
		err = errors.Trace(err, "delete DataPartition failed,PartitionID(%v)", request.PartitionId)
		log.LogErrorf("action[handlePacketToDeleteDataPartition] err(%v).", err)
	}
	log.LogInfof(fmt.Sprintf("action[handlePacketToDeleteDataPartition] %v error(%v)", request.PartitionId, err))
}

// Handle OpLoadDataPartition packet.
func (s *DataNode) handlePacketToLoadDataPartition(p *repl.Packet) {
	task := &proto.AdminTask{}
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionLoadDataPartition, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	err = json.Unmarshal(p.Data, task)
	p.PacketOkReply()
	go s.asyncLoadDataPartition(task)
}

func (s *DataNode) asyncLoadDataPartition(task *proto.AdminTask) {
	var err error
	request := &proto.LoadDataPartitionRequest{}
	response := &proto.LoadDataPartitionResponse{}
	if task.OpCode == proto.OpLoadDataPartition {
		bytes, _ := json.Marshal(task.Request)
		json.Unmarshal(bytes, request)
		dp := s.space.Partition(request.PartitionId)
		if dp == nil {
			response.Status = proto.TaskFailed
			response.PartitionId = uint64(request.PartitionId)
			err = fmt.Errorf(fmt.Sprintf("DataPartition(%v) not found", request.PartitionId))
			response.Result = err.Error()
		} else {
			response = dp.Load()
			response.PartitionId = uint64(request.PartitionId)
			response.Status = proto.TaskSucceeds
		}
	} else {
		response.PartitionId = uint64(request.PartitionId)
		response.Status = proto.TaskFailed
		err = fmt.Errorf("illegal opcode")
		response.Result = err.Error()
	}
	task.Response = response
	if err = MasterClient.NodeAPI().ResponseDataNodeTask(task); err != nil {
		err = errors.Trace(err, "load DataPartition failed,PartitionID(%v)", request.PartitionId)
		log.LogError(errors.Stack(err))
	}
}

// Handle OpMarkDelete packet.
func (s *DataNode) handleMarkDeletePacket(p *repl.Packet, c net.Conn) {
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionBatchMarkDelete, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()

	partition := p.Object.(*DataPartition)
	// NOTE: we cannot prevent mark delete
	// even the partition is forbidden, because
	// the inode already be deleted in meta partition
	// if we prevent it, we will get "orphan extents"
	if proto.IsTinyExtentType(p.ExtentType) || p.Opcode == proto.OpSplitMarkDelete {
		ext := new(proto.TinyExtentDeleteRecord)
		err = json.Unmarshal(p.Data, ext)
		if err == nil {
			log.LogInfof("handleMarkDeletePacket Delete PartitionID(%v)_Extent(%v)_Offset(%v)_Size(%v)",
				p.PartitionID, p.ExtentID, ext.ExtentOffset, ext.Size)
			partition.disk.allocCheckLimit(proto.IopsWriteType, 1)
			partition.ExtentStore().MarkDelete(p.ExtentID, int64(ext.ExtentOffset), int64(ext.Size))
		}
	} else {
		log.LogInfof("handleMarkDeletePacket Delete PartitionID(%v)_Extent(%v)",
			p.PartitionID, p.ExtentID)
		partition.disk.allocCheckLimit(proto.IopsWriteType, 1)
		partition.ExtentStore().MarkDelete(p.ExtentID, 0, 0)
	}
}

// Handle OpMarkDelete packet.
func (s *DataNode) handleBatchMarkDeletePacket(p *repl.Packet, c net.Conn) {
	var err error
	defer func() {
		if err != nil {
			log.LogErrorf(fmt.Sprintf("(%v) error(%v).", p.GetUniqueLogId(), err))
			p.PackErrorBody(ActionBatchMarkDelete, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	partition := p.Object.(*DataPartition)
	// NOTE: we cannot prevent mark delete
	// even the partition is forbidden, because
	// the inode already be deleted in meta partition
	// if we prevent it, we will get "orphan extents"
	var exts []*proto.ExtentKey
	err = json.Unmarshal(p.Data, &exts)
	store := partition.ExtentStore()
	if err == nil {
		for _, ext := range exts {
			if deleteLimiteRater.Allow() {
				log.LogInfof(fmt.Sprintf("recive DeleteExtent (%v) from (%v)", ext, c.RemoteAddr().String()))
				partition.disk.allocCheckLimit(proto.IopsWriteType, 1)
				store.MarkDelete(ext.ExtentId, int64(ext.ExtentOffset), int64(ext.Size))
			} else {
				log.LogInfof("delete limiter reach(%v), remote (%v) try again.", deleteLimiteRater.Limit(), c.RemoteAddr().String())
				err = storage.TryAgainError
			}
		}
	}
}

// Handle OpWrite packet.
func (s *DataNode) handleWritePacket(p *repl.Packet) {
	var (
		err                     error
		metricPartitionIOLabels map[string]string
		partitionIOMetric       *exporter.TimePointCount
	)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionWrite, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	partition := p.Object.(*DataPartition)
	if partition.IsForbidden() {
		err = ErrForbiddenDataPartition
		return
	}
	shallDegrade := p.ShallDegrade()
	if !shallDegrade {
		metricPartitionIOLabels = GetIoMetricLabels(partition, "write")
	}
	if partition.Available() <= 0 || !partition.disk.CanWrite() {
		err = storage.NoSpaceError
		return
	} else if partition.disk.Status == proto.Unavailable {
		err = storage.BrokenDiskError
		return
	}
	store := partition.ExtentStore()
	if proto.IsTinyExtentType(p.ExtentType) {
		if !shallDegrade {
			partitionIOMetric = exporter.NewTPCnt(MetricPartitionIOName)
		}

		partition.disk.allocCheckLimit(proto.FlowWriteType, uint32(p.Size))
		partition.disk.allocCheckLimit(proto.IopsWriteType, 1)

		_, err = store.Write(p.ExtentID, p.ExtentOffset, int64(p.Size), p.Data, p.CRC, storage.AppendWriteType, p.IsSyncWrite())
		if !shallDegrade {
			s.metrics.MetricIOBytes.AddWithLabels(int64(p.Size), metricPartitionIOLabels)
			partitionIOMetric.SetWithLabels(err, metricPartitionIOLabels)
		}
		partition.checkIsDiskError(err, WriteFlag)
		return
	}

	if p.Size <= util.BlockSize {
		if !shallDegrade {
			partitionIOMetric = exporter.NewTPCnt(MetricPartitionIOName)
		}

		partition.disk.allocCheckLimit(proto.FlowWriteType, uint32(p.Size))
		partition.disk.allocCheckLimit(proto.IopsWriteType, 1)

		_, err = store.Write(p.ExtentID, p.ExtentOffset, int64(p.Size), p.Data, p.CRC, storage.AppendWriteType, p.IsSyncWrite())
		if !shallDegrade {
			s.metrics.MetricIOBytes.AddWithLabels(int64(p.Size), metricPartitionIOLabels)
			partitionIOMetric.SetWithLabels(err, metricPartitionIOLabels)
		}
		partition.checkIsDiskError(err, WriteFlag)
	} else {
		size := p.Size
		offset := 0
		for size > 0 {
			if size <= 0 {
				break
			}
			currSize := util.Min(int(size), util.BlockSize)
			data := p.Data[offset : offset+currSize]
			crc := crc32.ChecksumIEEE(data)
			if !shallDegrade {
				partitionIOMetric = exporter.NewTPCnt(MetricPartitionIOName)
			}

			partition.disk.allocCheckLimit(proto.FlowWriteType, uint32(currSize))
			partition.disk.allocCheckLimit(proto.IopsWriteType, 1)

			_, err = store.Write(p.ExtentID, p.ExtentOffset+int64(offset), int64(currSize), data, crc, storage.AppendWriteType, p.IsSyncWrite())
			if !shallDegrade {
				s.metrics.MetricIOBytes.AddWithLabels(int64(p.Size), metricPartitionIOLabels)
				partitionIOMetric.SetWithLabels(err, metricPartitionIOLabels)
			}
			partition.checkIsDiskError(err, WriteFlag)
			if err != nil {
				break
			}
			size -= uint32(currSize)
			offset += currSize
		}
	}
}

func (s *DataNode) handleRandomWritePacket(p *repl.Packet) {
	var (
		err error

		metricPartitionIOLabels map[string]string
		partitionIOMetric       *exporter.TimePointCount
	)

	defer func() {
		log.LogDebugf("action[handleRandomWritePacket opcod %v seq %v dpid %v resultCode %v extid %v err %v",
			p.Opcode, p.VerSeq, p.PartitionID, p.ResultCode, p.ExtentID, err)
		if err != nil {
			p.PackErrorBody(ActionWrite, err.Error())
		} else {
			// avoid rsp pack ver info into package which client need do more work to read buffer
			if p.Opcode == proto.OpRandomWriteVer || p.Opcode == proto.OpSyncRandomWriteVer {
				p.Opcode = proto.OpSyncRandomWriteVerRsp
			}
			if p.Opcode == proto.OpTryWriteAppend && p.ResultCode == proto.OpTryOtherExtent {
				p.PackErrorBody(ActionWrite, storage.SnapshotNeedNewExtentError.Error())
				p.ResultCode = proto.OpTryOtherExtent
				log.LogDebugf("action[handleRandomWritePacket opcod %v seq %v dpid %v resultCode %v extid %v", p.Opcode, p.VerSeq, p.PartitionID, p.ResultCode, p.ExtentID)
				return
			}
			p.PacketOkReply()
		}
	}()

	partition := p.Object.(*DataPartition)
	if partition.IsForbidden() {
		err = ErrForbiddenDataPartition
		return
	}
	log.LogDebugf("action[handleRandomWritePacket opcod %v seq %v dpid %v dpseq %v extid %v", p.Opcode, p.VerSeq, p.PartitionID, partition.verSeq, p.ExtentID)
	// cache or preload partition not support raft and repair.
	if !partition.isNormalType() {
		err = raft.ErrStopped
		return
	}

	_, isLeader := partition.IsRaftLeader()
	if !isLeader {
		err = raft.ErrNotLeader
		return
	}
	shallDegrade := p.ShallDegrade()
	if !shallDegrade {
		metricPartitionIOLabels = GetIoMetricLabels(partition, "randwrite")
		partitionIOMetric = exporter.NewTPCnt(MetricPartitionIOName)
	}

	err = partition.RandomWriteSubmit(p)
	if !shallDegrade {
		s.metrics.MetricIOBytes.AddWithLabels(int64(p.Size), metricPartitionIOLabels)
		partitionIOMetric.SetWithLabels(err, metricPartitionIOLabels)
	}

	if err != nil && strings.Contains(err.Error(), raft.ErrNotLeader.Error()) {
		err = raft.ErrNotLeader
		log.LogErrorf("action[handleRandomWritePacket] opcod %v seq %v dpid %v dpseq %v extid %v err %v", p.Opcode, p.VerSeq, p.PartitionID, partition.verSeq, p.ExtentID, err)
		return
	}

	if err == nil && p.ResultCode != proto.OpOk && p.ResultCode != proto.OpTryOtherExtent {
		log.LogErrorf("action[handleRandomWritePacket] opcod %v seq %v dpid %v dpseq %v extid %v ResultCode %v",
			p.Opcode, p.VerSeq, p.PartitionID, partition.verSeq, p.ExtentID, p.ResultCode)
		err = storage.TryAgainError
		return
	}
	log.LogDebugf("action[handleRandomWritePacket] opcod %v seq %v dpid %v dpseq %v after raft submit err %v resultCode %v",
		p.Opcode, p.VerSeq, p.PartitionID, partition.verSeq, err, p.ResultCode)
}

func (s *DataNode) handleStreamReadPacket(p *repl.Packet, connect net.Conn, isRepairRead bool) {
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionStreamRead, err.Error())
			p.WriteToConn(connect)
		}
	}()
	partition := p.Object.(*DataPartition)

	// cache or preload partition not support raft and repair.
	if !partition.isNormalType() {
		err = raft.ErrStopped
		return
	}

	if err = partition.CheckLeader(p, connect); err != nil {
		return
	}
	s.extentRepairReadPacket(p, connect, isRepairRead)
}

func (s *DataNode) handleExtentRepairReadPacket(p *repl.Packet, connect net.Conn, isRepairRead bool) {
	var err error
	log.LogDebugf("handleExtentRepairReadPacket %v", p)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionStreamRead, err.Error())
			p.WriteToConn(connect)
			return
		}
		fininshDoExtentRepair()
	}()

	err = requestDoExtentRepair()
	if err != nil {
		return
	}

	s.extentRepairReadPacket(p, connect, isRepairRead)
}

func (s *DataNode) handleTinyExtentRepairReadPacket(p *repl.Packet, connect net.Conn) {
	s.tinyExtentRepairRead(p, connect)
}

func (s *DataNode) extentRepairReadPacket(p *repl.Packet, connect net.Conn, isRepairRead bool) {
	var (
		err error

		metricPartitionIOLabels     map[string]string
		partitionIOMetric, tpObject *exporter.TimePointCount
	)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionStreamRead, err.Error())
			p.WriteToConn(connect)
		}
	}()
	partition := p.Object.(*DataPartition)
	needReplySize := p.Size
	offset := p.ExtentOffset
	store := partition.ExtentStore()
	shallDegrade := p.ShallDegrade()
	if !shallDegrade {
		metricPartitionIOLabels = GetIoMetricLabels(partition, "read")
	}
	log.LogDebugf("extentRepairReadPacket dp %v offset %v needSize %v", partition.partitionID, offset, needReplySize)
	for {
		if needReplySize <= 0 {
			break
		}
		err = nil
		reply := repl.NewStreamReadResponsePacket(p.ReqID, p.PartitionID, p.ExtentID)
		reply.StartT = p.StartT
		currReadSize := uint32(util.Min(int(needReplySize), util.ReadBlockSize))
		if currReadSize == util.ReadBlockSize {
			reply.Data, _ = proto.Buffers.Get(util.ReadBlockSize)
		} else {
			reply.Data = make([]byte, currReadSize)
		}
		if !shallDegrade {
			partitionIOMetric = exporter.NewTPCnt(MetricPartitionIOName)
			tpObject = exporter.NewTPCnt(fmt.Sprintf("Repair_%s", p.GetOpMsg()))
		}
		reply.ExtentOffset = offset
		p.Size = currReadSize
		p.ExtentOffset = offset

		partition.Disk().allocCheckLimit(proto.IopsReadType, 1)
		partition.Disk().allocCheckLimit(proto.FlowReadType, currReadSize)

		reply.CRC, err = store.Read(reply.ExtentID, offset, int64(currReadSize), reply.Data, isRepairRead)
		if !shallDegrade {
			s.metrics.MetricIOBytes.AddWithLabels(int64(p.Size), metricPartitionIOLabels)
			partitionIOMetric.SetWithLabels(err, metricPartitionIOLabels)
			tpObject.Set(err)
		}
		partition.checkIsDiskError(err, ReadFlag)
		p.CRC = reply.CRC
		if err != nil {
			return
		}
		reply.Size = currReadSize
		reply.ResultCode = proto.OpOk
		reply.Opcode = p.Opcode
		p.ResultCode = proto.OpOk
		if err = reply.WriteToConn(connect); err != nil {
			return
		}
		needReplySize -= currReadSize
		offset += int64(currReadSize)
		if currReadSize == util.ReadBlockSize {
			proto.Buffers.Put(reply.Data)
		}
		logContent := fmt.Sprintf("action[operatePacket] %v.",
			reply.LogMessage(reply.GetOpMsg(), connect.RemoteAddr().String(), reply.StartT, err))
		log.LogReadf(logContent)
	}
	p.PacketOkReply()
}

func (s *DataNode) handlePacketToGetAllWatermarks(p *repl.Packet) {
	var (
		buf       []byte
		fInfoList []*storage.ExtentInfo
		err       error
	)
	partition := p.Object.(*DataPartition)
	store := partition.ExtentStore()
	if proto.IsNormalExtentType(p.ExtentType) {
		fInfoList, _, err = store.GetAllWatermarks(storage.NormalExtentFilter())
	} else {
		extents := make([]uint64, 0)
		err = json.Unmarshal(p.Data, &extents)
		if err == nil {
			fInfoList, _, err = store.GetAllWatermarks(storage.TinyExtentFilter(extents))
		}
	}
	if err != nil {
		p.PackErrorBody(ActionGetAllExtentWatermarks, err.Error())
	} else {
		buf, err = json.Marshal(fInfoList)
		if err != nil {
			p.PackErrorBody(ActionGetAllExtentWatermarks, err.Error())
		} else {
			p.PacketOkWithByte(buf)
		}
	}
}

func (s *DataNode) writeEmptyPacketOnTinyExtentRepairRead(reply *repl.Packet, newOffset, currentOffset int64, connect net.Conn) (replySize int64, err error) {
	replySize = newOffset - currentOffset
	reply.Data = make([]byte, 0)
	reply.Size = 0
	reply.CRC = crc32.ChecksumIEEE(reply.Data)
	reply.ResultCode = proto.OpOk
	reply.ExtentOffset = currentOffset
	reply.Arg[0] = EmptyResponse
	binary.BigEndian.PutUint64(reply.Arg[1:9], uint64(replySize))
	err = reply.WriteToConn(connect)
	reply.Size = uint32(replySize)
	logContent := fmt.Sprintf("action[operatePacket] %v.",
		reply.LogMessage(reply.GetOpMsg(), connect.RemoteAddr().String(), reply.StartT, err))
	log.LogReadf(logContent)

	return
}

func (s *DataNode) attachAvaliSizeOnTinyExtentRepairRead(reply *repl.Packet, avaliSize uint64) {
	binary.BigEndian.PutUint64(reply.Arg[9:17], avaliSize)
}

// Handle tinyExtentRepairRead packet.
func (s *DataNode) tinyExtentRepairRead(request *repl.Packet, connect net.Conn) {
	var (
		err                 error
		needReplySize       int64
		tinyExtentFinfoSize uint64
	)

	defer func() {
		if err != nil {
			request.PackErrorBody(ActionStreamReadTinyExtentRepair, err.Error())
			request.WriteToConn(connect)
		}
	}()
	if !storage.IsTinyExtent(request.ExtentID) {
		err = fmt.Errorf("unavali extentID (%v)", request.ExtentID)
		return
	}

	partition := request.Object.(*DataPartition)
	store := partition.ExtentStore()
	tinyExtentFinfoSize, err = store.TinyExtentGetFinfoSize(request.ExtentID)
	if err != nil {
		return
	}
	needReplySize = int64(request.Size)
	offset := request.ExtentOffset
	if uint64(request.ExtentOffset)+uint64(request.Size) > tinyExtentFinfoSize {
		needReplySize = int64(tinyExtentFinfoSize - uint64(request.ExtentOffset))
	}
	avaliReplySize := uint64(needReplySize)

	var newOffset, newEnd int64
	for {
		if needReplySize <= 0 {
			break
		}
		reply := repl.NewTinyExtentStreamReadResponsePacket(request.ReqID, request.PartitionID, request.ExtentID)
		reply.ArgLen = TinyExtentRepairReadResponseArgLen
		reply.Arg = make([]byte, TinyExtentRepairReadResponseArgLen)
		s.attachAvaliSizeOnTinyExtentRepairRead(reply, avaliReplySize)
		newOffset, newEnd, err = store.TinyExtentAvaliOffset(request.ExtentID, offset)
		if err != nil {
			return
		}
		if newOffset > offset {
			var replySize int64
			if replySize, err = s.writeEmptyPacketOnTinyExtentRepairRead(reply, newOffset, offset, connect); err != nil {
				return
			}
			needReplySize -= replySize
			offset += replySize
			continue
		}
		currNeedReplySize := newEnd - newOffset
		currReadSize := uint32(util.Min(int(currNeedReplySize), util.ReadBlockSize))
		if currReadSize == util.ReadBlockSize {
			reply.Data, _ = proto.Buffers.Get(util.ReadBlockSize)
		} else {
			reply.Data = make([]byte, currReadSize)
		}
		reply.ExtentOffset = offset
		reply.CRC, err = store.Read(reply.ExtentID, offset, int64(currReadSize), reply.Data, false)
		if err != nil {
			return
		}
		reply.Size = uint32(currReadSize)
		reply.ResultCode = proto.OpOk
		if err = reply.WriteToConn(connect); err != nil {
			connect.Close()
			return
		}
		needReplySize -= int64(currReadSize)
		offset += int64(currReadSize)
		if currReadSize == util.ReadBlockSize {
			proto.Buffers.Put(reply.Data)
		}
		logContent := fmt.Sprintf("action[operatePacket] %v.",
			reply.LogMessage(reply.GetOpMsg(), connect.RemoteAddr().String(), reply.StartT, err))
		log.LogReadf(logContent)
	}

	request.PacketOkReply()
}

func (s *DataNode) handlePacketToReadTinyDeleteRecordFile(p *repl.Packet, connect net.Conn) {
	var err error
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionStreamReadTinyDeleteRecord, err.Error())
			p.WriteToConn(connect)
		}
	}()
	partition := p.Object.(*DataPartition)
	store := partition.ExtentStore()
	localTinyDeleteFileSize, err := store.LoadTinyDeleteFileOffset()
	if err != nil {
		return
	}
	needReplySize := localTinyDeleteFileSize - p.ExtentOffset
	offset := p.ExtentOffset
	reply := repl.NewReadTinyDeleteRecordResponsePacket(p.ReqID, p.PartitionID)
	reply.StartT = time.Now().UnixNano()
	for {
		if needReplySize <= 0 {
			break
		}
		err = nil
		currReadSize := uint32(util.Min(int(needReplySize), MaxSyncTinyDeleteBufferSize))
		reply.Data = make([]byte, currReadSize)
		reply.ExtentOffset = offset
		reply.CRC, err = store.ReadTinyDeleteRecords(offset, int64(currReadSize), reply.Data)
		if err != nil {
			err = fmt.Errorf(ActionStreamReadTinyDeleteRecord+" localTinyDeleteRecordSize(%v) offset(%v)"+
				" currReadSize(%v) err(%v)", localTinyDeleteFileSize, offset, currReadSize, err)
			return
		}
		reply.Size = uint32(currReadSize)
		reply.ResultCode = proto.OpOk
		if err = reply.WriteToConn(connect); err != nil {
			return
		}
		needReplySize -= int64(currReadSize)
		offset += int64(currReadSize)
	}
	p.PacketOkReply()
}

// Handle OpNotifyReplicasToRepair packet.
func (s *DataNode) handlePacketToNotifyExtentRepair(p *repl.Packet) {
	var err error
	partition := p.Object.(*DataPartition)
	mf := new(DataPartitionRepairTask)
	err = json.Unmarshal(p.Data, mf)
	if err != nil {
		p.PackErrorBody(ActionRepair, err.Error())
		return
	}
	partition.DoExtentStoreRepair(mf)
	p.PacketOkReply()
}

// Handle OpBroadcastMinAppliedID
func (s *DataNode) handleBroadcastMinAppliedID(p *repl.Packet) {
	partition := p.Object.(*DataPartition)
	minAppliedID := binary.BigEndian.Uint64(p.Data)
	if minAppliedID > 0 {
		partition.SetMinAppliedID(minAppliedID)
	}
	log.LogDebugf("[handleBroadcastMinAppliedID] partition(%v) minAppliedID(%v)", partition.partitionID, minAppliedID)
	p.PacketOkReply()
}

// Handle handlePacketToGetAppliedID packet.
func (s *DataNode) handlePacketToGetAppliedID(p *repl.Packet) {
	partition := p.Object.(*DataPartition)
	appliedID := partition.GetAppliedID()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, appliedID)
	p.PacketOkWithBody(buf)
	p.AddMesgLog(fmt.Sprintf("_AppliedID(%v)", appliedID))
}

func (s *DataNode) handlePacketToGetPartitionSize(p *repl.Packet) {
	partition := p.Object.(*DataPartition)
	usedSize := partition.extentStore.StoreSizeExtentID(p.ExtentID)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(usedSize))
	p.AddMesgLog(fmt.Sprintf("partitionSize_(%v)", usedSize))
	p.PacketOkWithBody(buf)
}

func (s *DataNode) handlePacketToGetMaxExtentIDAndPartitionSize(p *repl.Packet) {
	partition := p.Object.(*DataPartition)
	maxExtentID, totalPartitionSize := partition.extentStore.GetMaxExtentIDAndPartitionSize()

	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(maxExtentID))
	binary.BigEndian.PutUint64(buf[8:16], totalPartitionSize)
	p.PacketOkWithBody(buf)
}

func (s *DataNode) handlePacketToDecommissionDataPartition(p *repl.Packet) {
	var (
		err          error
		reqData      []byte
		isRaftLeader bool
		req          = &proto.DataPartitionDecommissionRequest{}
	)

	defer func() {
		if err != nil {
			p.PackErrorBody(ActionDecommissionPartition, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()

	adminTask := &proto.AdminTask{}
	decode := json.NewDecoder(bytes.NewBuffer(p.Data))
	decode.UseNumber()
	if err = decode.Decode(adminTask); err != nil {
		return
	}

	reqData, err = json.Marshal(adminTask.Request)
	if err != nil {
		return
	}
	if err = json.Unmarshal(reqData, req); err != nil {
		return
	}
	p.AddMesgLog(string(reqData))
	dp := s.space.Partition(req.PartitionId)
	if dp == nil {
		err = fmt.Errorf("partition %v not exsit", req.PartitionId)
		return
	}
	p.PartitionID = req.PartitionId

	isRaftLeader, err = s.forwardToRaftLeader(dp, p, false)
	if !isRaftLeader {
		err = raft.ErrNotLeader
		return
	}
	if req.AddPeer.ID == req.RemovePeer.ID {
		err = errors.NewErrorf("[opOfflineDataPartition]: AddPeer(%v) same withRemovePeer(%v)", req.AddPeer, req.RemovePeer)
		return
	}
	if req.AddPeer.ID != 0 {
		_, err = dp.ChangeRaftMember(raftProto.ConfAddNode, raftProto.Peer{ID: req.AddPeer.ID}, reqData)
		if err != nil {
			return
		}
	}
	_, err = dp.ChangeRaftMember(raftProto.ConfRemoveNode, raftProto.Peer{ID: req.RemovePeer.ID}, reqData)
	if err != nil {
		return
	}
}

func (s *DataNode) handlePacketToAddDataPartitionRaftMember(p *repl.Packet) {
	var (
		err          error
		reqData      []byte
		isRaftLeader bool
		req          = &proto.AddDataPartitionRaftMemberRequest{}
	)

	defer func() {
		if err != nil {
			p.PackErrorBody(ActionAddDataPartitionRaftMember, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()

	adminTask := &proto.AdminTask{}
	decode := json.NewDecoder(bytes.NewBuffer(p.Data))
	decode.UseNumber()
	if err = decode.Decode(adminTask); err != nil {
		return
	}

	reqData, err = json.Marshal(adminTask.Request)
	if err != nil {
		return
	}
	if err = json.Unmarshal(reqData, req); err != nil {
		return
	}

	log.LogInfof("action[handlePacketToAddDataPartitionRaftMember] %v, partition id %v", req.AddPeer, req.PartitionId)

	p.AddMesgLog(string(reqData))
	dp := s.space.Partition(req.PartitionId)
	if dp == nil {
		err = proto.ErrDataPartitionNotExists
		return
	}
	p.PartitionID = req.PartitionId
	if dp.IsExsitReplica(req.AddPeer.Addr) {
		log.LogInfof("handlePacketToAddDataPartitionRaftMember recive MasterCommand: %v "+
			"addRaftAddr(%v) has exsit", string(reqData), req.AddPeer.Addr)
		return
	}
	isRaftLeader, err = s.forwardToRaftLeader(dp, p, false)
	if !isRaftLeader {
		return
	}
	log.LogInfof("action[handlePacketToAddDataPartitionRaftMember] before ChangeRaftMember %v which is sync. partition id %v", req.AddPeer, req.PartitionId)

	if req.AddPeer.ID != 0 {
		_, err = dp.ChangeRaftMember(raftProto.ConfAddNode, raftProto.Peer{ID: req.AddPeer.ID}, reqData)
		if err != nil {
			return
		}
	}
	log.LogInfof("action[handlePacketToAddDataPartitionRaftMember] after ChangeRaftMember %v, partition id %v", req.AddPeer, &req.PartitionId)
}

func (s *DataNode) handlePacketToRemoveDataPartitionRaftMember(p *repl.Packet) {
	var (
		err          error
		reqData      []byte
		isRaftLeader bool
		req          = &proto.RemoveDataPartitionRaftMemberRequest{}
	)

	defer func() {
		if err != nil {
			p.PackErrorBody(ActionRemoveDataPartitionRaftMember, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()

	adminTask := &proto.AdminTask{}
	decode := json.NewDecoder(bytes.NewBuffer(p.Data))
	decode.UseNumber()
	if err = decode.Decode(adminTask); err != nil {
		return
	}

	reqData, err = json.Marshal(adminTask.Request)
	p.AddMesgLog(string(reqData))
	if err != nil {
		return
	}
	if err = json.Unmarshal(reqData, req); err != nil {
		return
	}

	dp := s.space.Partition(req.PartitionId)
	if dp == nil {
		return
	}

	log.LogWarnf("action[handlePacketToRemoveDataPartitionRaftMember], req %v (%s) RemoveRaftPeer(%s) dp %v replicaNum %v",
		p.GetReqID(), string(reqData), req.RemovePeer.Addr, dp.partitionID, dp.replicaNum)

	p.PartitionID = req.PartitionId

	if !dp.IsExsitReplica(req.RemovePeer.Addr) {
		log.LogInfof("action[handlePacketToRemoveDataPartitionRaftMember] receive MasterCommand:  req %v[%v] "+
			"RemoveRaftPeer(%v) has not exsit", p.GetReqID(), string(reqData), req.RemovePeer.Addr)
		return
	}

	isRaftLeader, err = s.forwardToRaftLeader(dp, p, req.Force)
	if !isRaftLeader {
		log.LogInfof("handlePacketToRemoveDataPartitionRaftMember return no leader")
		return
	}
	if err = dp.CanRemoveRaftMember(req.RemovePeer, req.Force); err != nil {
		log.LogWarnf("action[handlePacketToRemoveDataPartitionRaftMember] CanRemoveRaftMember failed "+
			"req %v dp %v err %v",
			p.GetReqID(), dp.partitionID, err.Error())
		return
	}

	if req.Force {
		cc := &raftProto.ConfChange{
			Type: raftProto.ConfRemoveNode,
			Peer: raftProto.Peer{
				ID: req.RemovePeer.ID,
			},
			Context: reqData,
		}
		s.raftStore.RaftServer().RemoveRaftForce(dp.partitionID, cc)
		dp.ApplyMemberChange(cc, 0)
		dp.PersistMetadata()
		return
	}

	if req.RemovePeer.ID != 0 {
		log.LogDebugf("action[handlePacketToRemoveDataPartitionRaftMember] ChangeRaftMember "+
			"req %v dp %v RemovePeer.ID %v", p.GetReqID(), dp.partitionID, req.RemovePeer.ID)
		_, err = dp.ChangeRaftMember(raftProto.ConfRemoveNode, raftProto.Peer{ID: req.RemovePeer.ID}, reqData)
		if err != nil {
			return
		}
	}
	log.LogDebugf("action[handlePacketToRemoveDataPartitionRaftMember] CanRemoveRaftMember complete "+
		"req %v dp %v ", p.GetReqID(), dp.partitionID)
}

func (s *DataNode) handlePacketToDataPartitionTryToLeader(p *repl.Packet) {
	var err error

	defer func() {
		if err != nil {
			p.PackErrorBody(ActionDataPartitionTryToLeader, err.Error())
			log.LogWarnf("handlePacketToDataPartitionTryToLeader: %v ", err.Error())
		} else {
			p.PacketOkReply()
			log.LogDebugf("handlePacketToDataPartitionTryToLeader: partition %v success ", p.PartitionID)
		}
	}()
	log.LogDebugf("handlePacketToDataPartitionTryToLeader: partition %v ", p.PartitionID)
	dp := s.space.Partition(p.PartitionID)
	if dp == nil {
		err = fmt.Errorf("partition %v not exsit", p.PartitionID)
		return
	}

	if dp.raftStatus != RaftStatusRunning {
		err = fmt.Errorf("partition %v raft not running", p.PartitionID)
		return
	}

	if dp.raftPartition.IsRaftLeader() {
		log.LogWarnf("handlePacketToDataPartitionTryToLeader: %v is already leader", p.PartitionID)
		return
	}
	err = dp.raftPartition.TryToLeader(dp.partitionID)
}

func (s *DataNode) forwardToRaftLeader(dp *DataPartition, p *repl.Packet, force bool) (ok bool, err error) {
	var (
		conn       *net.TCPConn
		leaderAddr string
	)

	if leaderAddr, ok = dp.IsRaftLeader(); ok {
		return
	}
	// return NoLeaderError if leaderAddr is nil
	if leaderAddr == "" {
		if force {
			ok = true
			log.LogInfof("action[forwardToRaftLeader] no leader but replica num %v continue", dp.replicaNum)
			return
		}
		err = storage.NoLeaderError
		return
	}

	// forward the packet to the leader if local one is not the leader
	conn, err = gConnPool.GetConnect(leaderAddr)
	if err != nil {
		return
	}
	defer func() {
		gConnPool.PutConnect(conn, err != nil)
	}()
	err = p.WriteToConn(conn)
	if err != nil {
		return
	}
	if err = p.ReadFromConnWithVer(conn, proto.NoReadDeadlineTime); err != nil {
		return
	}

	return
}

func (s *DataNode) handlePacketToStopDataPartitionRepair(p *repl.Packet) {
	task := &proto.AdminTask{}
	err := json.Unmarshal(p.Data, task)
	defer func() {
		if err != nil {
			p.PackErrorBody(ActionStopDataPartitionRepair, err.Error())
		} else {
			p.PacketOkReply()
		}
	}()
	if err != nil {
		return
	}
	request := &proto.StopDataPartitionRepairRequest{}
	if task.OpCode != proto.OpStopDataPartitionRepair {
		err = fmt.Errorf("action[handlePacketToStopDataPartitionRepair] illegal opcode ")
		log.LogWarnf("action[handlePacketToStopDataPartitionRepair] illegal opcode ")
		return
	}

	bytes, _ := json.Marshal(task.Request)
	p.AddMesgLog(string(bytes))
	err = json.Unmarshal(bytes, request)
	if err != nil {
		return
	}
	log.LogDebugf("action[handlePacketToStopDataPartitionRepair] try stop %v", request.PartitionId)
	dp := s.space.Partition(request.PartitionId)
	if dp == nil {
		err = proto.ErrDataPartitionNotExists
		log.LogWarnf("action[handlePacketToStopDataPartitionRepair] cannot find dp %v", request.PartitionId)
		return
	}
	dp.StopDecommissionRecover(request.Stop)
	log.LogInfof("action[handlePacketToStopDataPartitionRepair] %v stop %v success", request.PartitionId, request.Stop)
}
