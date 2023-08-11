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
	"sync/atomic"
	"time"

	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/log"
)

func (c *Cluster) scheduleToCheckDiskRecoveryProgress() {
	go func() {
		for {
			if c.partition != nil && c.partition.IsRaftLeader() {
				if c.vols != nil {
					c.checkDiskRecoveryProgress()
				}
			}
			time.Sleep(time.Second * defaultIntervalToCheckDataPartition)
		}
	}()
}

func (c *Cluster) checkDiskRecoveryProgress() {
	defer func() {
		if r := recover(); r != nil {
			log.LogWarnf("checkDiskRecoveryProgress occurred panic,err[%v]", r)
			WarnBySpecialKey(fmt.Sprintf("%v_%v_scheduling_job_panic", c.Name, ModuleName),
				"checkDiskRecoveryProgress occurred panic")
		}
	}()

	c.badPartitionMutex.Lock()
	defer c.badPartitionMutex.Unlock()

	c.BadDataPartitionIds.Range(func(key, value interface{}) bool {
		badDataPartitionIds := value.([]uint64)
		newBadDpIds := make([]uint64, 0)
		for _, partitionID := range badDataPartitionIds {
			partition, err := c.getDataPartitionByID(partitionID)
			if err != nil {
				Warn(c.Name, fmt.Sprintf("checkDiskRecoveryProgress clusterID[%v],partitionID[%v] is not exist", c.Name, partitionID))
				continue
			}

			_, err = c.getVol(partition.VolName)
			if err != nil {
				Warn(c.Name, fmt.Sprintf("checkDiskRecoveryProgress clusterID[%v],partitionID[%v] vol(%s) is not exist",
					c.Name, partitionID, partition.VolName))
				continue
			}
			log.LogInfof("action[checkDiskRecoveryProgress] dp %v isSpec %v replics %v conf replics num %v",
				partition.PartitionID, partition.isSpecialReplicaCnt(), len(partition.Replicas), int(partition.ReplicaNum))
			if len(partition.Replicas) == 0 ||
				(!partition.isSpecialReplicaCnt() && len(partition.Replicas) < int(partition.ReplicaNum)) ||
				(partition.isSpecialReplicaCnt() && len(partition.Replicas) > int(partition.ReplicaNum)) {
				newBadDpIds = append(newBadDpIds, partitionID)
				log.LogInfof("action[checkDiskRecoveryProgress] dp %v newBadDpIds [%v] replics %v conf replics num %v",
					partition.PartitionID, newBadDpIds, len(partition.Replicas), int(partition.ReplicaNum))
				continue
			}

			if partition.getMinus() < util.GB {
				partition.isRecover = false
				partition.RLock()
				c.syncUpdateDataPartition(partition)
				partition.RUnlock()
				Warn(c.Name, fmt.Sprintf("clusterID[%v],partitionID[%v] has recovered success", c.Name, partitionID))
			} else {
				newBadDpIds = append(newBadDpIds, partitionID)
			}
		}

		if len(newBadDpIds) == 0 {
			Warn(c.Name, fmt.Sprintf("clusterID[%v],node:disk[%v] has recovered success", c.Name, key))
			c.BadDataPartitionIds.Delete(key)
		} else {
			c.BadDataPartitionIds.Store(key, newBadDpIds)
			log.LogInfof("BadDataPartitionIds key(%s) still have (%d) dp in recover", key, len(newBadDpIds))
		}

		return true
	})
}

func (c *Cluster) addAndSyncDecommissionedDisk(dataNode *DataNode, diskPath string) (err error) {
	if exist := dataNode.addDecommissionedDisk(diskPath); exist {
		return
	}
	if err = c.syncUpdateDataNode(dataNode); err != nil {
		dataNode.deleteDecommissionedDisk(diskPath)
		return
	}
	log.LogInfof("action[addAndSyncDecommissionedDisk] finish, remaining decommissioned disks[%v], dataNode[%v]", dataNode.getDecommissionedDisks(), dataNode.Addr)
	return
}

func (c *Cluster) deleteAndSyncDecommissionedDisk(dataNode *DataNode, diskPath string) (err error) {
	if exist := dataNode.deleteDecommissionedDisk(diskPath); !exist {
		return
	}
	if err = c.syncUpdateDataNode(dataNode); err != nil {
		dataNode.addDecommissionedDisk(diskPath)
		return
	}
	log.LogInfof("action[deleteAndSyncDecommissionedDisk] finish, remaining decommissioned disks[%v], dataNode[%v]", dataNode.getDecommissionedDisks(), dataNode.Addr)
	return
}

func (c *Cluster) decommissionDisk(dataNode *DataNode, raftForce bool, badDiskPath string,
	badPartitions []*DataPartition, diskDisable bool) (err error) {
	msg := fmt.Sprintf("action[decommissionDisk], Node[%v] OffLine,disk[%v]", dataNode.Addr, badDiskPath)
	log.LogWarn(msg)

	for _, dp := range badPartitions {
		go func(dp *DataPartition) {
			if err = c.decommissionDataPartition(dataNode.Addr, dp, raftForce, diskOfflineErr); err != nil {
				return
			}
		}(dp)

	}
	msg = fmt.Sprintf("action[decommissionDisk],clusterID[%v] node[%v] OffLine success",
		c.Name, dataNode.Addr)
	Warn(c.Name, msg)
	return
}

type DecommissionDisk struct {
	SrcAddr               string
	DiskPath              string
	DecommissionStatus    uint32
	DecommissionRaftForce bool
	DecommissionRetry     uint8
	DecommissionDpTotal   int
	DecommissionTerm      uint64
	DecommissionLimit     int
	DiskDisable           bool
}

func (dd *DecommissionDisk) GenerateKey() string {
	return fmt.Sprintf("%s_%s", dd.SrcAddr, dd.DiskPath)
}

func (dd *DecommissionDisk) updateDecommissionStatus(c *Cluster, debug bool) (uint32, float64) {
	var (
		progress            float64
		totalNum            = dd.DecommissionDpTotal
		partitionIds        []uint64
		failedPartitionIds  []uint64
		runningPartitionIds []uint64
		preparePartitionIds []uint64
		stopPartitionIds    []uint64
	)

	if dd.GetDecommissionStatus() == DecommissionInitial {
		return DecommissionInitial, float64(0)
	}

	if dd.GetDecommissionStatus() == markDecommission {
		return markDecommission, float64(0)
	}

	if totalNum == InvalidDecommissionDpCnt && dd.GetDecommissionStatus() == DecommissionFail {
		return DecommissionFail, float64(0)
	}

	if dd.GetDecommissionStatus() == DecommissionSuccess {
		return DecommissionSuccess, float64(1)
	}

	if dd.GetDecommissionStatus() == DecommissionStop {
		return DecommissionStop, float64(0)
	}

	defer func() {
		c.syncUpdateDecommissionDisk(dd)
	}()
	if dd.DecommissionRetry >= defaultDecommissionRetryLimit {
		dd.SetDecommissionStatus(DecommissionFail)
		return DecommissionFail, float64(0)
	}
	//Get all dp on this disk
	failedNum := 0
	runningNum := 0
	prepareNum := 0
	stopNum := 0
	partitions := c.getAllDecommissionDataPartitionByDiskAndTerm(dd.SrcAddr, dd.DiskPath, dd.DecommissionTerm)

	if len(partitions) == 0 {
		dd.SetDecommissionStatus(DecommissionSuccess)
		return DecommissionSuccess, float64(1)
	}

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
		//disk may stop before and will be counted into partitions
		if dp.GetDecommissionStatus() == DecommissionStop {
			stopNum++
			stopPartitionIds = append(stopPartitionIds, dp.PartitionID)
		}
		partitionIds = append(partitionIds, dp.PartitionID)
	}
	progress = float64(totalNum-len(partitions)+stopNum) / float64(totalNum)
	if debug {
		log.LogInfof("action[updateDecommissionDiskStatus] progress[%v] totalNum[%v] "+
			"partitionIds[%v] FailedNum[%v] failedPartitionIds[%v], runningNum[%v] runningDp[%v], prepareNum[%v] prepareDp[%v] "+
			"stopNum[%v] stopPartitionIds[%v]",
			progress, totalNum, partitionIds, failedNum, failedPartitionIds, runningNum, runningPartitionIds,
			prepareNum, preparePartitionIds, stopNum, stopPartitionIds)
	}
	if failedNum >= (len(partitions) - stopNum) {
		dd.SetDecommissionStatus(DecommissionFail)
		return DecommissionFail, progress
	}
	return dd.GetDecommissionStatus(), progress
}

func (dd *DecommissionDisk) GetDecommissionStatus() uint32 {
	return atomic.LoadUint32(&dd.DecommissionStatus)
}

func (dd *DecommissionDisk) SetDecommissionStatus(status uint32) {
	atomic.StoreUint32(&dd.DecommissionStatus, status)
}
func (dd *DecommissionDisk) GetDecommissionFailedDPByTerm(c *Cluster) (error, []uint64) {
	var (
		failedDps     []uint64
		err           error
		badPartitions []*DataPartition
	)
	if dd.GetDecommissionStatus() != DecommissionFail {
		err = fmt.Errorf("action[GetDecommissionDiskFailedDP]dataNode[%s] disk[%s] status must be failed,but[%d]",
			dd.SrcAddr, dd.DiskPath, dd.GetDecommissionStatus())
		return err, failedDps
	}

	badPartitions = c.getAllDecommissionDataPartitionByDiskAndTerm(dd.SrcAddr, dd.DiskPath, dd.DecommissionTerm)
	log.LogDebugf("action[GetDecommissionFailedDPByTerm] partitions len %v", len(badPartitions))
	for _, dp := range badPartitions {
		if dp.IsDecommissionFailed() {
			failedDps = append(failedDps, dp.PartitionID)
		}
	}
	log.LogWarnf("action[GetDecommissionDiskFailedDP] failed dp list [%v]", failedDps)
	return nil, failedDps
}

func (dd *DecommissionDisk) GetDecommissionFailedDP(c *Cluster) (error, []uint64) {
	var (
		failedDps     []uint64
		err           error
		badPartitions []*DataPartition
	)
	if dd.GetDecommissionStatus() != DecommissionFail {
		err = fmt.Errorf("action[GetDecommissionDiskFailedDP]dataNode[%s] disk[%s] status must be failed,but[%d]",
			dd.SrcAddr, dd.DiskPath, dd.GetDecommissionStatus())
		return err, failedDps
	}

	badPartitions = c.getAllDecommissionDataPartitionByDisk(dd.SrcAddr, dd.DiskPath)
	for _, dp := range badPartitions {
		if dp.IsDecommissionFailed() {
			failedDps = append(failedDps, dp.PartitionID)
		}
	}
	log.LogWarnf("action[GetDecommissionDiskFailedDP] failed dp list [%v]", failedDps)
	return nil, failedDps
}

func (dd *DecommissionDisk) markDecommission(raftForce bool, limit int) {
	dd.SetDecommissionStatus(markDecommission)
	//reset decommission status for failed once
	dd.DecommissionRetry = 0
	dd.DecommissionDpTotal = InvalidDecommissionDpCnt
	dd.DecommissionRaftForce = raftForce
	dd.DecommissionTerm = dd.DecommissionTerm + 1
	dd.DecommissionLimit = limit
}
