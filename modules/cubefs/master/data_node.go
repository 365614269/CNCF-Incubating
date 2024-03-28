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
	"sync"
	"sync/atomic"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/atomicutil"
	"github.com/cubefs/cubefs/util/log"
)

// DataNode stores all the information about a data node
type DataNode struct {
	Total                     uint64 `json:"TotalWeight"`
	Used                      uint64 `json:"UsedWeight"`
	AvailableSpace            uint64
	ID                        uint64
	ZoneName                  string `json:"Zone"`
	Addr                      string
	DomainAddr                string
	ReportTime                time.Time
	StartTime                 int64
	LastUpdateTime            time.Time
	isActive                  bool
	sync.RWMutex              `graphql:"-"`
	UsageRatio                float64           // used / total space
	SelectedTimes             uint64            // number times that this datanode has been selected as the location for a data partition.
	TaskManager               *AdminTaskManager `graphql:"-"`
	DataPartitionReports      []*proto.DataPartitionReport
	DataPartitionCount        uint32
	TotalPartitionSize        uint64
	NodeSetID                 uint64
	PersistenceDataPartitions []uint64
	BadDisks                  []string            // Keep this old field for compatibility
	BadDiskStats              []proto.BadDiskStat // key: disk path
	DecommissionedDisks       sync.Map
	ToBeOffline               bool
	RdOnly                    bool
	MigrateLock               sync.RWMutex
	QosIopsRLimit             uint64
	QosIopsWLimit             uint64
	QosFlowRLimit             uint64
	QosFlowWLimit             uint64
	DecommissionStatus        uint32
	DecommissionDstAddr       string
	DecommissionRaftForce     bool
	DecommissionRetry         uint8
	DecommissionLimit         int
	DecommissionCompleteTime  int64
	DpCntLimit                DpCountLimiter     `json:"-"` // max count of data partition in a data node
	CpuUtil                   atomicutil.Float64 `json:"-"`
	ioUtils                   atomic.Value       `json:"-"`
	DecommissionDiskList      []string
	DecommissionDpTotal       int
}

func newDataNode(addr, zoneName, clusterID string) (dataNode *DataNode) {
	dataNode = new(DataNode)
	dataNode.Total = 1
	dataNode.Addr = addr
	dataNode.ZoneName = zoneName
	dataNode.LastUpdateTime = time.Now().Add(-time.Minute)
	dataNode.TaskManager = newAdminTaskManager(dataNode.Addr, clusterID)
	dataNode.DecommissionStatus = DecommissionInitial
	dataNode.DpCntLimit = newDpCountLimiter(nil)
	dataNode.CpuUtil.Store(0)
	dataNode.SetIoUtils(make(map[string]float64))
	return
}

func (dataNode *DataNode) GetIoUtils() map[string]float64 {
	return dataNode.ioUtils.Load().(map[string]float64)
}

func (dataNode *DataNode) SetIoUtils(used map[string]float64) {
	dataNode.ioUtils.Store(used)
}

func (dataNode *DataNode) checkLiveness() {
	dataNode.Lock()
	defer dataNode.Unlock()
	log.LogInfof("action[checkLiveness] datanode[%v] report time[%v],since report time[%v], need gap [%v]",
		dataNode.Addr, dataNode.ReportTime, time.Since(dataNode.ReportTime), time.Second*time.Duration(defaultNodeTimeOutSec))
	if time.Since(dataNode.ReportTime) > time.Second*time.Duration(defaultNodeTimeOutSec) {
		dataNode.isActive = false
	}

	return
}

func (dataNode *DataNode) badPartitions(diskPath string, c *Cluster) (partitions []*DataPartition) {
	partitions = make([]*DataPartition, 0)
	vols := c.copyVols()
	if len(vols) == 0 {
		return partitions
	}
	for _, vol := range vols {
		dps := vol.dataPartitions.checkBadDiskDataPartitions(diskPath, dataNode.Addr)
		partitions = append(partitions, dps...)
	}
	return
}

func (dataNode *DataNode) getDisks(c *Cluster) (diskPaths []string) {
	diskPaths = make([]string, 0)
	vols := c.copyVols()
	if len(vols) == 0 {
		return diskPaths
	}
	for _, vol := range vols {
		disks := vol.dataPartitions.getReplicaDiskPaths(dataNode.Addr)
		for _, disk := range disks {
			if inStingList(disk, diskPaths) {
				continue
			}
			diskPaths = append(diskPaths, disk)
		}
	}

	return
}

func (dataNode *DataNode) updateNodeMetric(resp *proto.DataNodeHeartbeatResponse) {
	dataNode.Lock()
	defer dataNode.Unlock()
	dataNode.DomainAddr = util.ParseIpAddrToDomainAddr(dataNode.Addr)
	dataNode.Total = resp.Total
	dataNode.Used = resp.Used
	if dataNode.AvailableSpace > resp.Available ||
		time.Since(dataNode.LastUpdateTime) > defaultNodeTimeOutSec*time.Second {
		dataNode.AvailableSpace = resp.Available
		dataNode.LastUpdateTime = time.Now()
	}
	dataNode.ZoneName = resp.ZoneName
	dataNode.DataPartitionCount = resp.CreatedPartitionCnt
	dataNode.DataPartitionReports = resp.PartitionReports
	dataNode.TotalPartitionSize = resp.TotalPartitionSize

	dataNode.BadDisks = resp.BadDisks
	dataNode.BadDiskStats = resp.BadDiskStats

	dataNode.StartTime = resp.StartTime
	if dataNode.Total == 0 {
		dataNode.UsageRatio = 0.0
	} else {
		dataNode.UsageRatio = (float64)(dataNode.Used) / (float64)(dataNode.Total)
	}
	dataNode.ReportTime = time.Now()
	dataNode.isActive = true
	log.LogDebugf("updateNodeMetric. datanode id %v addr %v total %v used %v avaliable %v", dataNode.ID, dataNode.Addr,
		dataNode.Total, dataNode.Used, dataNode.AvailableSpace)
}

func (dataNode *DataNode) canAlloc() bool {
	dataNode.RLock()
	defer dataNode.RUnlock()

	if !overSoldLimit() {
		return true
	}

	maxCapacity := overSoldCap(dataNode.Total)
	if maxCapacity < dataNode.TotalPartitionSize {
		return false
	}

	return true
}

func (dataNode *DataNode) isWriteAble() (ok bool) {
	dataNode.RLock()
	defer dataNode.RUnlock()

	if dataNode.isActive && dataNode.AvailableSpace > 10*util.GB && !dataNode.RdOnly {
		ok = true
	}

	return
}

func (dataNode *DataNode) canAllocDp() bool {
	if !dataNode.isWriteAble() {
		return false
	}

	if dataNode.ToBeOffline {
		log.LogWarnf("action[canAllocDp] dataNode [%v] is offline ", dataNode.Addr)
		return false
	}

	if !dataNode.dpCntInLimit() {
		return false
	}

	return true
}

func (dataNode *DataNode) GetDpCntLimit() uint32 {
	return uint32(dataNode.DpCntLimit.GetCntLimit())
}

func (dataNode *DataNode) dpCntInLimit() bool {
	return dataNode.DataPartitionCount <= dataNode.GetDpCntLimit()
}

func (dataNode *DataNode) isWriteAbleWithSize(size uint64) (ok bool) {
	dataNode.RLock()
	defer dataNode.RUnlock()

	if dataNode.isActive == true && dataNode.AvailableSpace > size {
		ok = true
	}

	return
}

func (dataNode *DataNode) GetID() uint64 {
	dataNode.RLock()
	defer dataNode.RUnlock()
	return dataNode.ID
}

func (dataNode *DataNode) GetAddr() string {
	dataNode.RLock()
	defer dataNode.RUnlock()
	return dataNode.Addr
}

// SelectNodeForWrite implements "SelectNodeForWrite" in the Node interface
func (dataNode *DataNode) SelectNodeForWrite() {
	dataNode.Lock()
	defer dataNode.Unlock()
	dataNode.UsageRatio = float64(dataNode.Used) / float64(dataNode.Total)
	dataNode.SelectedTimes++
}

func (dataNode *DataNode) clean() {
	dataNode.TaskManager.exitCh <- struct{}{}
}

func (dataNode *DataNode) createHeartbeatTask(masterAddr string, enableDiskQos bool) (task *proto.AdminTask) {
	request := &proto.HeartBeatRequest{
		CurrTime:   time.Now().Unix(),
		MasterAddr: masterAddr,
	}
	request.EnableDiskQos = enableDiskQos
	request.QosIopsReadLimit = dataNode.QosIopsRLimit
	request.QosIopsWriteLimit = dataNode.QosIopsWLimit
	request.QosFlowReadLimit = dataNode.QosFlowRLimit
	request.QosFlowWriteLimit = dataNode.QosFlowWLimit
	request.DecommissionDisks = dataNode.getDecommissionedDisks()

	task = proto.NewAdminTask(proto.OpDataNodeHeartbeat, dataNode.Addr, request)
	return
}

func (dataNode *DataNode) addDecommissionedDisk(diskPath string) (exist bool) {
	_, exist = dataNode.DecommissionedDisks.LoadOrStore(diskPath, struct{}{})
	log.LogInfof("action[addDecommissionedDisk] finish, exist[%v], decommissioned disk[%v], dataNode[%v]", exist, diskPath, dataNode.Addr)
	return
}

func (dataNode *DataNode) deleteDecommissionedDisk(diskPath string) (exist bool) {
	_, exist = dataNode.DecommissionedDisks.LoadAndDelete(diskPath)
	log.LogInfof("action[deleteDecommissionedDisk] finish, exist[%v], decommissioned disk[%v], dataNode[%v]", exist, diskPath, dataNode.Addr)
	return
}

func (dataNode *DataNode) getDecommissionedDisks() (decommissionedDisks []string) {
	dataNode.DecommissionedDisks.Range(func(key, value interface{}) bool {
		if diskPath, ok := key.(string); ok {
			decommissionedDisks = append(decommissionedDisks, diskPath)
		}
		return true
	})
	return
}

func (dataNode *DataNode) updateDecommissionStatus(c *Cluster, debug bool) (uint32, float64) {
	var (
		partitionIds        []uint64
		failedPartitionIds  []uint64
		runningPartitionIds []uint64
		preparePartitionIds []uint64
		stopPartitionIds    []uint64
		totalDisk           = len(dataNode.DecommissionDiskList)
		markDiskNum         = 0
		successDiskNum      = 0
		progress            float64
	)
	if dataNode.GetDecommissionStatus() == DecommissionInitial {
		return DecommissionInitial, float64(0)
	}
	if dataNode.GetDecommissionStatus() == markDecommission {
		return markDecommission, float64(0)
	}
	if dataNode.GetDecommissionStatus() == DecommissionSuccess {
		return DecommissionSuccess, float64(1)
	}
	if dataNode.GetDecommissionStatus() == DecommissionFail {
		return DecommissionFail, float64(0)
	}
	if dataNode.GetDecommissionStatus() == DecommissionPause {
		return DecommissionPause, float64(0)
	}
	defer func() {
		c.syncUpdateDataNode(dataNode)
	}()
	// not enter running status
	if dataNode.DecommissionRetry >= defaultDecommissionRetryLimit {
		dataNode.markDecommissionFail()
		return DecommissionFail, float64(0)
	}

	log.LogDebugf("action[GetLatestDecommissionDataPartition]dataNode %v diskList %v",
		dataNode.Addr, dataNode.DecommissionDiskList)

	if totalDisk == 0 {
		dataNode.SetDecommissionStatus(DecommissionInitial)
		return DecommissionInitial, float64(0)
	}
	for _, disk := range dataNode.DecommissionDiskList {
		key := fmt.Sprintf("%s_%s", dataNode.Addr, disk)
		// if not found, may already success, so only care running disk
		if value, ok := c.DecommissionDisks.Load(key); ok {
			dd := value.(*DecommissionDisk)
			status := dd.GetDecommissionStatus()
			if status == DecommissionSuccess {
				successDiskNum++
			} else if status == markDecommission {
				markDiskNum++
			}
			_, diskProgress := dd.updateDecommissionStatus(c, debug)
			progress += diskProgress
		} else {
			successDiskNum++ // disk with DecommissionSuccess will be removed from cache
			progress += float64(1)
		}

	}
	// only care data node running/prepare/success
	// no disk get token
	if markDiskNum == totalDisk {
		dataNode.SetDecommissionStatus(DecommissionPrepare)
		return DecommissionPrepare, float64(0)
	} else {
		if successDiskNum == totalDisk {
			dataNode.SetDecommissionStatus(DecommissionSuccess)
			return DecommissionSuccess, float64(1)
		}
	}
	// update datanode or running status
	partitions := dataNode.GetLatestDecommissionDataPartition(c)
	// Get all dp on this dataNode
	failedNum := 0
	runningNum := 0
	prepareNum := 0
	stopNum := 0

	for _, dp := range partitions {
		if dp.IsDecommissionFailed() {
			failedNum++
			failedPartitionIds = append(failedPartitionIds, dp.PartitionID)
		}
		if dp.GetDecommissionStatus() == DecommissionRunning {
			runningNum++
			runningPartitionIds = append(runningPartitionIds, dp.PartitionID)
		}
		if dp.GetDecommissionStatus() == DecommissionPrepare {
			prepareNum++
			preparePartitionIds = append(preparePartitionIds, dp.PartitionID)
		}
		// datanode may stop before and will be counted into partitions
		if dp.GetDecommissionStatus() == DecommissionPause {
			stopNum++
			stopPartitionIds = append(stopPartitionIds, dp.PartitionID)
		}
		partitionIds = append(partitionIds, dp.PartitionID)
	}
	progress = progress / float64(totalDisk)
	if failedNum >= (len(partitions)-stopNum) && failedNum != 0 {
		dataNode.markDecommissionFail()
		return DecommissionFail, progress
	}
	dataNode.SetDecommissionStatus(DecommissionRunning)
	if debug {
		log.LogInfof("action[updateDecommissionStatus] dataNode[%v] progress[%v] totalNum[%v] "+
			"partitionIds %v  FailedNum[%v] failedPartitionIds %v, runningNum[%v] runningDp %v, prepareNum[%v] prepareDp %v "+
			"stopNum[%v] stopPartitionIds %v ",
			dataNode.Addr, progress, len(partitions), partitionIds, failedNum, failedPartitionIds, runningNum, runningPartitionIds,
			prepareNum, preparePartitionIds, stopNum, stopPartitionIds)
	}
	return DecommissionRunning, progress
}

func (dataNode *DataNode) GetLatestDecommissionDataPartition(c *Cluster) (partitions []*DataPartition) {
	log.LogDebugf("action[GetLatestDecommissionDataPartition]dataNode %v diskList %v", dataNode.Addr, dataNode.DecommissionDiskList)
	for _, disk := range dataNode.DecommissionDiskList {
		key := fmt.Sprintf("%s_%s", dataNode.Addr, disk)
		// if not found, may already success, so only care running disk
		if value, ok := c.DecommissionDisks.Load(key); ok {
			dd := value.(*DecommissionDisk)
			dps := c.getAllDecommissionDataPartitionByDiskAndTerm(dd.SrcAddr, dd.DiskPath, dd.DecommissionTerm)
			partitions = append(partitions, dps...)
			dpIds := make([]uint64, 0)
			for _, dp := range dps {
				dpIds = append(dpIds, dp.PartitionID)
			}
			log.LogDebugf("action[GetLatestDecommissionDataPartition]dataNode %v disk %v dps[%v]",
				dataNode.Addr, dd.DiskPath, dpIds)
		}
	}
	return
}

func (dataNode *DataNode) GetDecommissionStatus() uint32 {
	return atomic.LoadUint32(&dataNode.DecommissionStatus)
}

func (dataNode *DataNode) SetDecommissionStatus(status uint32) {
	atomic.StoreUint32(&dataNode.DecommissionStatus, status)
}

func (dataNode *DataNode) GetDecommissionFailedDPByTerm(c *Cluster) []uint64 {
	var failedDps []uint64
	partitions := dataNode.GetLatestDecommissionDataPartition(c)
	log.LogDebugf("action[GetDecommissionDataNodeFailedDP] partitions len %v", len(partitions))
	for _, dp := range partitions {
		if dp.IsRollbackFailed() {
			failedDps = append(failedDps, dp.PartitionID)
			log.LogWarnf("action[GetDecommissionDataNodeFailedDP] dp[%v] failed", dp.PartitionID)
		}
	}
	log.LogWarnf("action[GetDecommissionDataNodeFailedDP] failed dp list [%v]", failedDps)
	return failedDps
}

func (dataNode *DataNode) GetDecommissionFailedDP(c *Cluster) (error, []uint64) {
	var (
		failedDps []uint64
		err       error
	)
	if dataNode.GetDecommissionStatus() != DecommissionFail {
		err = fmt.Errorf("action[GetDecommissionDataNodeFailedDP]dataNode[%s] status must be failed,but[%d]",
			dataNode.Addr, dataNode.GetDecommissionStatus())
		return err, failedDps
	}
	partitions := c.getAllDecommissionDataPartitionByDataNode(dataNode.Addr)
	log.LogDebugf("action[GetDecommissionDataNodeFailedDP] partitions len %v", len(partitions))
	for _, dp := range partitions {
		if dp.IsDecommissionFailed() {
			failedDps = append(failedDps, dp.PartitionID)
			log.LogWarnf("action[GetDecommissionDataNodeFailedDP] dp[%v] failed", dp.PartitionID)
		}
	}
	log.LogWarnf("action[GetDecommissionDataNodeFailedDP] failed dp list [%v]", failedDps)
	return nil, failedDps
}

func (dataNode *DataNode) markDecommission(targetAddr string, raftForce bool, limit int) {
	dataNode.SetDecommissionStatus(markDecommission)
	dataNode.DecommissionRaftForce = raftForce
	dataNode.DecommissionDstAddr = targetAddr
	// reset decommission status for failed once
	dataNode.DecommissionRetry = 0
	dataNode.DecommissionLimit = limit
	dataNode.DecommissionDiskList = make([]string, 0)
}

func (dataNode *DataNode) canMarkDecommission() bool {
	status := dataNode.GetDecommissionStatus()
	// After partial decommissioning, it is still possible to decommission further
	return status == DecommissionInitial || status == DecommissionPause || status == DecommissionFail ||
		status == DecommissionSuccess
}

func (dataNode *DataNode) markDecommissionSuccess(c *Cluster) {
	dataNode.SetDecommissionStatus(DecommissionSuccess)
	partitions := c.getAllDataPartitionByDataNode(dataNode.Addr)
	// if only decommission part of data partitions, can alloc dp in future
	if len(partitions) != 0 {
		dataNode.ToBeOffline = false
	}
	dataNode.DecommissionCompleteTime = time.Now().Unix()
}

func (dataNode *DataNode) markDecommissionFail() {
	dataNode.SetDecommissionStatus(DecommissionFail)
	// dataNode.ToBeOffline = false
	// dataNode.DecommissionCompleteTime = time.Now().Unix()
}

func (dataNode *DataNode) resetDecommissionStatus() {
	dataNode.SetDecommissionStatus(DecommissionInitial)
	dataNode.DecommissionRaftForce = false
	dataNode.DecommissionDstAddr = ""
	dataNode.DecommissionRetry = 0
	dataNode.DecommissionLimit = 0
	dataNode.DecommissionCompleteTime = 0
	dataNode.DecommissionDiskList = make([]string, 0)
}

func (dataNode *DataNode) createVersionTask(volume string, version uint64, op uint8, addr string, verList []*proto.VolVersionInfo) (task *proto.AdminTask) {
	request := &proto.MultiVersionOpRequest{
		VolumeID:   volume,
		VerSeq:     version,
		Op:         uint8(op),
		Addr:       addr,
		VolVerList: verList,
	}
	log.LogInfof("action[createVersionTask] op %v  datanode addr %v addr %v volume %v seq %v", op, dataNode.Addr, addr, volume, version)
	task = proto.NewAdminTask(proto.OpVersionOperation, dataNode.Addr, request)
	return
}

func (dataNode *DataNode) CanBePaused() bool {
	status := dataNode.GetDecommissionStatus()
	if status == DecommissionRunning || status == markDecommission || status == DecommissionPause {
		return true
	}
	return false
}

func (dataNode *DataNode) delDecommissionDiskFromCache(c *Cluster) {
	for _, diskPath := range dataNode.DecommissionDiskList {
		key := fmt.Sprintf("%s_%s", dataNode.Addr, diskPath)
		c.DecommissionDisks.Delete(key)
		log.LogDebugf("action[delDecommissionDiskFromCache] remove  %v", key)
	}
}
