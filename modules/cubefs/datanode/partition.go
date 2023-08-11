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
	"io/ioutil"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cubefs/cubefs/util"

	"hash/crc32"
	"net"
	"sort"
	"syscall"

	raftProto "github.com/cubefs/cubefs/depends/tiglabs/raft/proto"
	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/raftstore"
	"github.com/cubefs/cubefs/repl"
	"github.com/cubefs/cubefs/storage"
	"github.com/cubefs/cubefs/util/errors"
	"github.com/cubefs/cubefs/util/exporter"
	"github.com/cubefs/cubefs/util/log"
)

const (
	DataPartitionPrefix           = "datapartition"
	CachePartitionPrefix          = "cachepartition"
	PreLoadPartitionPrefix        = "preloadpartition"
	DataPartitionMetadataFileName = "META"
	TempMetadataFileName          = ".meta"
	ApplyIndexFile                = "APPLY"
	TempApplyIndexFile            = ".apply"
	TimeLayout                    = "2006-01-02 15:04:05"
)

const (
	RaftStatusStopped = 0
	RaftStatusRunning = 1
)

type DataPartitionMetadata struct {
	VolumeID                string
	PartitionID             uint64
	PartitionSize           int
	PartitionType           int
	CreateTime              string
	Peers                   []proto.Peer
	Hosts                   []string
	DataPartitionCreateType int
	LastTruncateID          uint64
	ReplicaNum              int
}

type sortedPeers []proto.Peer

func (sp sortedPeers) Len() int {
	return len(sp)
}

func (sp sortedPeers) Less(i, j int) bool {
	return sp[i].ID < sp[j].ID
}

func (sp sortedPeers) Swap(i, j int) {
	sp[i], sp[j] = sp[j], sp[i]
}

func (md *DataPartitionMetadata) Validate() (err error) {
	md.VolumeID = strings.TrimSpace(md.VolumeID)
	if len(md.VolumeID) == 0 || md.PartitionID == 0 || md.PartitionSize == 0 {
		err = errors.New("illegal data partition metadata")
		return
	}
	return
}

type DataPartition struct {
	clusterID       string
	volumeID        string
	partitionID     uint64
	partitionStatus int
	partitionSize   int
	partitionType   int
	replicaNum      int
	replicas        []string // addresses of the replicas
	replicasLock    sync.RWMutex
	disk            *Disk
	dataNode        *DataNode
	isLeader        bool
	isRaftLeader    bool
	path            string
	used            int
	leaderSize      int
	extentStore     *storage.ExtentStore
	raftPartition   raftstore.Partition
	config          *dataPartitionCfg
	appliedID       uint64 // apply id used in Raft
	lastTruncateID  uint64 // truncate id used in Raft
	minAppliedID    uint64
	maxAppliedID    uint64

	stopOnce  sync.Once
	stopRaftC chan uint64
	storeC    chan uint64
	stopC     chan bool

	raftStatus int32

	intervalToUpdateReplicas      int64 // interval to ask the master for updating the replica information
	snapshot                      []*proto.File
	snapshotMutex                 sync.RWMutex
	intervalToUpdatePartitionSize int64
	loadExtentHeaderStatus        int
	DataPartitionCreateType       int
	isLoadingDataPartition        bool
	persistMetaMutex              sync.RWMutex
}

func CreateDataPartition(dpCfg *dataPartitionCfg, disk *Disk, request *proto.CreateDataPartitionRequest) (dp *DataPartition, err error) {

	if dp, err = newDataPartition(dpCfg, disk, true); err != nil {
		return
	}
	dp.ForceLoadHeader()
	if request.CreateType == proto.NormalCreateDataPartition {
		err = dp.StartRaft(false)
	} else {
		// init leaderSize to partitionSize
		disk.updateDisk(uint64(request.LeaderSize))
		go dp.StartRaftAfterRepair(false)
	}
	if err != nil {
		return nil, err
	}

	// persist file metadata
	go dp.StartRaftLoggingSchedule()
	dp.DataPartitionCreateType = request.CreateType
	dp.replicaNum = request.ReplicaNum
	err = dp.PersistMetadata()
	disk.AddSize(uint64(dp.Size()))
	return
}

func (dp *DataPartition) IsEquareCreateDataPartitionRequst(request *proto.CreateDataPartitionRequest) (err error) {
	if len(dp.config.Peers) != len(request.Members) {
		return fmt.Errorf("Exsit unavali Partition(%v) partitionHosts(%v) requestHosts(%v)", dp.partitionID, dp.config.Peers, request.Members)
	}
	for index, host := range dp.config.Hosts {
		requestHost := request.Hosts[index]
		if host != requestHost {
			return fmt.Errorf("Exsit unavali Partition(%v) partitionHosts(%v) requestHosts(%v)", dp.partitionID, dp.config.Hosts, request.Hosts)
		}
	}
	for index, peer := range dp.config.Peers {
		requestPeer := request.Members[index]
		if requestPeer.ID != peer.ID || requestPeer.Addr != peer.Addr {
			return fmt.Errorf("Exsit unavali Partition(%v) partitionHosts(%v) requestHosts(%v)", dp.partitionID, dp.config.Peers, request.Members)
		}
	}
	if dp.config.VolName != request.VolumeId {
		return fmt.Errorf("Exsit unavali Partition(%v) VolName(%v) requestVolName(%v)", dp.partitionID, dp.config.VolName, request.VolumeId)
	}

	return
}

func (dp *DataPartition) ForceSetDataPartitionToLoadding() {
	dp.isLoadingDataPartition = true
}

func (dp *DataPartition) ForceSetDataPartitionToFininshLoad() {
	dp.isLoadingDataPartition = false
}

func (dp *DataPartition) ForceSetRaftRunning() {
	atomic.StoreInt32(&dp.raftStatus, RaftStatusRunning)
}

// LoadDataPartition loads and returns a partition instance based on the specified directory.
// It reads the partition metadata file stored under the specified directory
// and creates the partition instance.
func LoadDataPartition(partitionDir string, disk *Disk) (dp *DataPartition, err error) {
	var (
		metaFileData []byte
	)
	if metaFileData, err = ioutil.ReadFile(path.Join(partitionDir, DataPartitionMetadataFileName)); err != nil {
		return
	}
	meta := &DataPartitionMetadata{}
	if err = json.Unmarshal(metaFileData, meta); err != nil {
		return
	}
	if err = meta.Validate(); err != nil {
		return
	}

	dpCfg := &dataPartitionCfg{
		VolName:       meta.VolumeID,
		PartitionSize: meta.PartitionSize,
		PartitionType: meta.PartitionType,
		PartitionID:   meta.PartitionID,
		ReplicaNum:    meta.ReplicaNum,
		Peers:         meta.Peers,
		Hosts:         meta.Hosts,
		RaftStore:     disk.space.GetRaftStore(),
		NodeID:        disk.space.GetNodeID(),
		ClusterID:     disk.space.GetClusterID(),
	}
	if dp, err = newDataPartition(dpCfg, disk, false); err != nil {
		return
	}
	dp.computeUsage()
	dp.ForceSetDataPartitionToLoadding()
	disk.space.AttachPartition(dp)
	if err = dp.LoadAppliedID(); err != nil {
		log.LogErrorf("action[loadApplyIndex] %v", err)
		return
	}
	log.LogInfof("Action(LoadDataPartition) PartitionID(%v) meta(%v)", dp.partitionID, meta)
	dp.DataPartitionCreateType = meta.DataPartitionCreateType
	dp.lastTruncateID = meta.LastTruncateID
	if meta.DataPartitionCreateType == proto.NormalCreateDataPartition {
		err = dp.StartRaft(true)
	} else {
		// init leaderSize to partitionSize
		dp.leaderSize = dp.partitionSize
		go dp.StartRaftAfterRepair(true)
	}
	if err != nil {
		log.LogErrorf("PartitionID(%v) start raft err(%v)..", dp.partitionID, err)
		disk.space.DetachDataPartition(dp.partitionID)
		return
	}

	go dp.StartRaftLoggingSchedule()
	disk.AddSize(uint64(dp.Size()))
	dp.ForceLoadHeader()
	return
}

func newDataPartition(dpCfg *dataPartitionCfg, disk *Disk, isCreate bool) (dp *DataPartition, err error) {
	partitionID := dpCfg.PartitionID
	var dataPath string

	if proto.IsNormalDp(dpCfg.PartitionType) {
		dataPath = path.Join(disk.Path, fmt.Sprintf(DataPartitionPrefix+"_%v_%v", partitionID, dpCfg.PartitionSize))
	} else if proto.IsCacheDp(dpCfg.PartitionType) {
		dataPath = path.Join(disk.Path, fmt.Sprintf(CachePartitionPrefix+"_%v_%v", partitionID, dpCfg.PartitionSize))
	} else if proto.IsPreLoadDp(dpCfg.PartitionType) {
		dataPath = path.Join(disk.Path, fmt.Sprintf(PreLoadPartitionPrefix+"_%v_%v", partitionID, dpCfg.PartitionSize))
	} else {
		return nil, fmt.Errorf("newDataPartition fail, dataPartitionCfg(%v)", dpCfg)
	}

	partition := &DataPartition{
		volumeID:        dpCfg.VolName,
		clusterID:       dpCfg.ClusterID,
		partitionID:     partitionID,
		replicaNum:      dpCfg.ReplicaNum,
		disk:            disk,
		dataNode:        disk.dataNode,
		path:            dataPath,
		partitionSize:   dpCfg.PartitionSize,
		partitionType:   dpCfg.PartitionType,
		replicas:        make([]string, 0),
		stopC:           make(chan bool, 0),
		stopRaftC:       make(chan uint64, 0),
		storeC:          make(chan uint64, 128),
		snapshot:        make([]*proto.File, 0),
		partitionStatus: proto.ReadWrite,
		config:          dpCfg,
		raftStatus:      RaftStatusStopped,
	}
	log.LogInfof("action[newDataPartition] dp %v replica num %v isCreate %v", partitionID, dpCfg.ReplicaNum, isCreate)
	partition.replicasInit()
	partition.extentStore, err = storage.NewExtentStore(partition.path, dpCfg.PartitionID, dpCfg.PartitionSize,
		partition.partitionType, isCreate)
	if err != nil {
		return
	}

	disk.AttachDataPartition(partition)
	dp = partition

	go partition.statusUpdateScheduler()
	go partition.startEvict()
	return
}

func (dp *DataPartition) replicasInit() {
	replicas := make([]string, 0)
	if dp.config.Hosts == nil {
		return
	}
	for _, host := range dp.config.Hosts {
		replicas = append(replicas, host)
	}
	dp.replicasLock.Lock()
	dp.replicas = replicas
	dp.replicasLock.Unlock()
	if dp.config.Hosts != nil && len(dp.config.Hosts) >= 1 {
		leaderAddr := strings.Split(dp.config.Hosts[0], ":")
		if len(leaderAddr) == 2 && strings.TrimSpace(leaderAddr[0]) == LocalIP {
			dp.isLeader = true
		}
	}
}

func (dp *DataPartition) GetExtentCount() int {
	return dp.extentStore.GetExtentCount()
}

func (dp *DataPartition) Path() string {
	return dp.path
}

// IsRaftLeader tells if the given address belongs to the raft leader.
func (dp *DataPartition) IsRaftLeader() (addr string, ok bool) {
	if dp.raftStopped() {
		return
	}
	leaderID, _ := dp.raftPartition.LeaderTerm()
	if leaderID == 0 {
		return
	}
	ok = leaderID == dp.config.NodeID
	for _, peer := range dp.config.Peers {
		if leaderID == peer.ID {
			addr = peer.Addr
			return
		}
	}
	return
}

func (dp *DataPartition) Replicas() []string {
	dp.replicasLock.RLock()
	defer dp.replicasLock.RUnlock()
	return dp.replicas
}

func (dp *DataPartition) getReplicaCopy() []string {
	dp.replicasLock.RLock()
	defer dp.replicasLock.RUnlock()

	var tmpCopy []string
	tmpCopy = make([]string, len(dp.replicas))
	copy(tmpCopy, dp.replicas)

	return tmpCopy
}

func (dp *DataPartition) getReplicaAddr(index int) string {
	dp.replicasLock.RLock()
	defer dp.replicasLock.RUnlock()
	return dp.replicas[index]
}

func (dp *DataPartition) getReplicaLen() int {
	dp.replicasLock.RLock()
	defer dp.replicasLock.RUnlock()
	return len(dp.replicas)
}

func (dp *DataPartition) needDeleteReplica(addr string) bool {
	if dp.IsExsitReplica(addr) {
		return true
	}

	if dp.config == nil {
		return false
	}

	for _, h := range dp.config.Hosts {
		if addr == h {
			return true
		}
	}

	return false
}

func (dp *DataPartition) IsExsitReplica(addr string) bool {
	dp.replicasLock.RLock()
	defer dp.replicasLock.RUnlock()
	for _, host := range dp.replicas {
		if host == addr {
			return true
		}
	}
	return false
}

func (dp *DataPartition) ReloadSnapshot() {
	files, err := dp.extentStore.SnapShot()
	if err != nil {
		return
	}
	dp.snapshotMutex.Lock()
	for _, f := range dp.snapshot {
		storage.PutSnapShotFileToPool(f)
	}
	dp.snapshot = files
	dp.snapshotMutex.Unlock()
}

// Snapshot returns the snapshot of the data partition.
func (dp *DataPartition) SnapShot() (files []*proto.File) {
	dp.snapshotMutex.RLock()
	defer dp.snapshotMutex.RUnlock()

	return dp.snapshot
}

// Stop close the store and the raft store.
func (dp *DataPartition) Stop() {
	dp.stopOnce.Do(func() {
		if dp.stopC != nil {
			close(dp.stopC)
		}
		// Close the store and raftstore.
		dp.stopRaft()
		dp.extentStore.Close()
		_ = dp.storeAppliedID(atomic.LoadUint64(&dp.appliedID))
	})
	return
}

// Disk returns the disk instance.
func (dp *DataPartition) Disk() *Disk {
	return dp.disk
}

// func (dp *DataPartition) IsRejectWrite() bool {
// 	return dp.Disk().RejectWrite
// }

// Status returns the partition status.
func (dp *DataPartition) Status() int {
	if dp.isNormalType() && dp.raftStatus == RaftStatusStopped {
		return proto.Unavailable
	}
	return dp.partitionStatus
}

// Size returns the partition size.
func (dp *DataPartition) Size() int {
	return dp.partitionSize
}

// Used returns the used space.
func (dp *DataPartition) Used() int {
	return dp.used
}

// Available returns the available space.
func (dp *DataPartition) Available() int {
	return dp.partitionSize - dp.used
}

func (dp *DataPartition) ForceLoadHeader() {
	dp.loadExtentHeaderStatus = FinishLoadDataPartitionExtentHeader
}

// PersistMetadata persists the file metadata on the disk.
func (dp *DataPartition) PersistMetadata() (err error) {
	dp.persistMetaMutex.Lock()
	defer dp.persistMetaMutex.Unlock()

	var (
		metadataFile *os.File
		metaData     []byte
	)
	fileName := path.Join(dp.Path(), TempMetadataFileName)
	if metadataFile, err = os.OpenFile(fileName, os.O_CREATE|os.O_RDWR, 0666); err != nil {
		return
	}
	defer func() {
		metadataFile.Sync()
		metadataFile.Close()
		os.Remove(fileName)
	}()

	sp := sortedPeers(dp.config.Peers)
	sort.Sort(sp)

	md := &DataPartitionMetadata{
		VolumeID:                dp.config.VolName,
		PartitionID:             dp.config.PartitionID,
		ReplicaNum:              dp.config.ReplicaNum,
		PartitionSize:           dp.config.PartitionSize,
		PartitionType:           dp.config.PartitionType,
		Peers:                   dp.config.Peers,
		Hosts:                   dp.config.Hosts,
		DataPartitionCreateType: dp.DataPartitionCreateType,
		CreateTime:              time.Now().Format(TimeLayout),
		LastTruncateID:          dp.lastTruncateID,
	}
	if metaData, err = json.Marshal(md); err != nil {
		return
	}
	if _, err = metadataFile.Write(metaData); err != nil {
		return
	}
	log.LogInfof("PersistMetadata DataPartition(%v) data(%v)", dp.partitionID, string(metaData))
	err = os.Rename(fileName, path.Join(dp.Path(), DataPartitionMetadataFileName))
	return
}
func (dp *DataPartition) statusUpdateScheduler() {
	ticker := time.NewTicker(time.Minute)
	snapshotTicker := time.NewTicker(time.Minute * 5)
	var index int
	for {
		select {
		case <-ticker.C:
			dp.statusUpdate()
			// only repair tiny extent
			if !dp.isNormalType() {
				dp.LaunchRepair(proto.TinyExtentType)
				continue
			}

			index++
			if index >= math.MaxUint32 {
				index = 0
			}

			if index%2 == 0 {
				dp.LaunchRepair(proto.TinyExtentType)
			} else {
				dp.LaunchRepair(proto.NormalExtentType)
			}
		case <-snapshotTicker.C:
			dp.ReloadSnapshot()
		case <-dp.stopC:
			ticker.Stop()
			snapshotTicker.Stop()
			return
		}
	}
}

func (dp *DataPartition) statusUpdate() {
	status := proto.ReadWrite
	dp.computeUsage()

	if dp.used >= dp.partitionSize {
		status = proto.ReadOnly
	}
	if dp.isNormalType() && dp.extentStore.GetExtentCount() >= storage.MaxExtentCount {
		status = proto.ReadOnly
	}
	if dp.isNormalType() && dp.raftStatus == RaftStatusStopped {
		status = proto.Unavailable
	}

	log.LogInfof("action[statusUpdate] dp %v raft status %v dp.status %v, status %v, dis status %v, res:%v",
		dp.partitionID, dp.raftStatus, dp.Status(), status, float64(dp.disk.Status), int(math.Min(float64(status), float64(dp.disk.Status))))
	dp.partitionStatus = int(math.Min(float64(status), float64(dp.disk.Status)))
}

func parseFileName(filename string) (extentID uint64, isExtent bool) {
	if isExtent = storage.RegexpExtentFile.MatchString(filename); !isExtent {
		return
	}
	var (
		err error
	)
	if extentID, err = strconv.ParseUint(filename, 10, 64); err != nil {
		isExtent = false
		return
	}
	isExtent = true
	return
}

func (dp *DataPartition) actualSize(path string, finfo os.FileInfo) (size int64) {
	name := finfo.Name()
	extentID, isExtent := parseFileName(name)
	if !isExtent {
		return 0
	}
	if storage.IsTinyExtent(extentID) {
		stat := new(syscall.Stat_t)
		err := syscall.Stat(fmt.Sprintf("%v/%v", path, finfo.Name()), stat)
		if err != nil {
			return finfo.Size()
		}
		return stat.Blocks * DiskSectorSize
	}

	return finfo.Size()
}

func (dp *DataPartition) computeUsage() {
	if time.Now().Unix()-dp.intervalToUpdatePartitionSize < IntervalToUpdatePartitionSize {
		return
	}
	dp.used = int(dp.ExtentStore().GetStoreUsedSize())
	dp.intervalToUpdatePartitionSize = time.Now().Unix()
}

func (dp *DataPartition) ExtentStore() *storage.ExtentStore {
	return dp.extentStore
}

func (dp *DataPartition) checkIsDiskError(err error) (diskError bool) {
	if err == nil {
		return
	}
	if IsDiskErr(err.Error()) {
		mesg := fmt.Sprintf("checkIsDiskError disk path %v error on %v", dp.Path(), LocalIP)
		exporter.Warning(mesg)
		log.LogErrorf(mesg)
		dp.stopRaft()
		dp.disk.incReadErrCnt()
		dp.disk.incWriteErrCnt()
		dp.disk.Status = proto.Unavailable
		dp.statusUpdate()
		dp.disk.ForceExitRaftStore()
		diskError = true
	}
	return
}

func newRaftApplyError(err error) error {
	return errors.NewErrorf("[Custom Error]: unhandled raft apply error, err(%s)", err)
}

func isRaftApplyError(errMsg string) bool {
	return strings.Contains(errMsg, "[Custom Error]: unhandled raft apply error")
}

// String returns the string format of the data partition information.
func (dp *DataPartition) String() (m string) {
	return fmt.Sprintf(DataPartitionPrefix+"_%v_%v", dp.partitionID, dp.partitionSize)
}

// LaunchRepair launches the repair of extents.
func (dp *DataPartition) LaunchRepair(extentType uint8) {
	if dp.partitionStatus == proto.Unavailable {
		return
	}
	if err := dp.updateReplicas(false); err != nil {
		log.LogErrorf("action[LaunchRepair] partition(%v) err(%v).", dp.partitionID, err)
		return
	}
	if !dp.isLeader {
		return
	}
	if dp.extentStore.BrokenTinyExtentCnt() == 0 {
		dp.extentStore.MoveAllToBrokenTinyExtentC(MinTinyExtentsToRepair)
	}
	dp.repair(extentType)
}

func (dp *DataPartition) updateReplicas(isForce bool) (err error) {
	if !isForce && time.Now().Unix()-dp.intervalToUpdateReplicas <= IntervalToUpdateReplica {
		return
	}
	dp.isLeader = false
	isLeader, replicas, err := dp.fetchReplicasFromMaster()
	if err != nil {
		return
	}
	dp.replicasLock.Lock()
	defer dp.replicasLock.Unlock()
	if !dp.compareReplicas(dp.replicas, replicas) {
		log.LogInfof("action[updateReplicas] partition(%v) replicas changed from (%v) to (%v).",
			dp.partitionID, dp.replicas, replicas)
	}
	dp.isLeader = isLeader
	dp.replicas = replicas
	dp.intervalToUpdateReplicas = time.Now().Unix()
	log.LogInfof(fmt.Sprintf("ActionUpdateReplicationHosts partiton(%v), force(%v)", dp.partitionID, isForce))

	return
}

// Compare the fetched replica with the local one.
func (dp *DataPartition) compareReplicas(v1, v2 []string) (equals bool) {
	equals = true
	if len(v1) == len(v2) {
		for i := 0; i < len(v1); i++ {
			if v1[i] != v2[i] {
				equals = false
				return
			}
		}
		equals = true
		return
	}
	equals = false
	return
}

// Fetch the replica information from the master.
func (dp *DataPartition) fetchReplicasFromMaster() (isLeader bool, replicas []string, err error) {

	var partition *proto.DataPartitionInfo
	var retry = 0
	for {
		if partition, err = MasterClient.AdminAPI().GetDataPartition(dp.volumeID, dp.partitionID); err != nil {
			retry++
			if retry > 5 {
				isLeader = false
				return
			}
		} else {
			break
		}
		time.Sleep(10 * time.Second)
	}

	for _, host := range partition.Hosts {
		replicas = append(replicas, host)
	}
	if partition.Hosts != nil && len(partition.Hosts) >= 1 {
		leaderAddr := strings.Split(partition.Hosts[0], ":")
		if len(leaderAddr) == 2 && strings.TrimSpace(leaderAddr[0]) == LocalIP {
			isLeader = true
		}
	}
	return
}

func (dp *DataPartition) Load() (response *proto.LoadDataPartitionResponse) {
	response = &proto.LoadDataPartitionResponse{}
	response.PartitionId = uint64(dp.partitionID)
	response.PartitionStatus = dp.partitionStatus
	response.Used = uint64(dp.Used())
	var err error
	if dp.loadExtentHeaderStatus != FinishLoadDataPartitionExtentHeader {
		response.PartitionSnapshot = make([]*proto.File, 0)
	} else {
		response.PartitionSnapshot = dp.SnapShot()
	}
	if err != nil {
		response.Status = proto.TaskFailed
		response.Result = err.Error()
		return
	}
	return
}

// DoExtentStoreRepair performs the repairs of the extent store.
// 1. when the extent size is smaller than the max size on the record, start to repair the missing part.
// 2. if the extent does not even exist, create the extent first, and then repair.
func (dp *DataPartition) DoExtentStoreRepair(repairTask *DataPartitionRepairTask) {
	store := dp.extentStore
	for _, extentInfo := range repairTask.ExtentsToBeCreated {
		if storage.IsTinyExtent(extentInfo.FileID) {
			continue
		}
		if store.HasExtent(uint64(extentInfo.FileID)) {
			continue
		}
		if !AutoRepairStatus {
			log.LogWarnf("AutoRepairStatus is False,so cannot Create extent(%v)", extentInfo.String())
			continue
		}

		dp.disk.allocCheckLimit(proto.IopsWriteType, 1)

		err := store.Create(uint64(extentInfo.FileID))
		if err != nil {
			continue
		}
	}

	var (
		wg           *sync.WaitGroup
		recoverIndex int
	)
	wg = new(sync.WaitGroup)
	for _, extentInfo := range repairTask.ExtentsToBeRepaired {

		if !store.HasExtent(uint64(extentInfo.FileID)) {
			continue
		}
		wg.Add(1)

		// repair the extents
		go dp.doStreamExtentFixRepair(wg, extentInfo)
		recoverIndex++

		if recoverIndex%NumOfFilesToRecoverInParallel == 0 {
			wg.Wait()
		}
	}
	wg.Wait()
	dp.doStreamFixTinyDeleteRecord(repairTask)
}

func (dp *DataPartition) pushSyncDeleteRecordFromLeaderMesg() bool {
	select {
	case dp.Disk().syncTinyDeleteRecordFromLeaderOnEveryDisk <- true:
		return true
	default:
		return false
	}
}

func (dp *DataPartition) consumeTinyDeleteRecordFromLeaderMesg() {
	select {
	case <-dp.Disk().syncTinyDeleteRecordFromLeaderOnEveryDisk:
		return
	default:
		return
	}
}

func (dp *DataPartition) doStreamFixTinyDeleteRecord(repairTask *DataPartitionRepairTask) {
	var (
		localTinyDeleteFileSize int64
		err                     error
		conn                    net.Conn
	)
	if !dp.pushSyncDeleteRecordFromLeaderMesg() {
		return
	}

	defer func() {
		dp.consumeTinyDeleteRecordFromLeaderMesg()
	}()
	if localTinyDeleteFileSize, err = dp.extentStore.LoadTinyDeleteFileOffset(); err != nil {
		return
	}

	log.LogInfof(ActionSyncTinyDeleteRecord+" start PartitionID(%v) localTinyDeleteFileSize(%v) leaderTinyDeleteFileSize(%v) leaderAddr(%v)",
		dp.partitionID, localTinyDeleteFileSize, repairTask.LeaderTinyDeleteRecordFileSize, repairTask.LeaderAddr)

	if localTinyDeleteFileSize >= repairTask.LeaderTinyDeleteRecordFileSize {
		return
	}

	if repairTask.LeaderTinyDeleteRecordFileSize-localTinyDeleteFileSize < MinTinyExtentDeleteRecordSyncSize {
		return
	}

	defer func() {
		log.LogInfof(ActionSyncTinyDeleteRecord+" end PartitionID(%v) localTinyDeleteFileSize(%v) leaderTinyDeleteFileSize(%v) leaderAddr(%v) err(%v)",
			dp.partitionID, localTinyDeleteFileSize, repairTask.LeaderTinyDeleteRecordFileSize, repairTask.LeaderAddr, err)
	}()

	p := repl.NewPacketToReadTinyDeleteRecord(dp.partitionID, localTinyDeleteFileSize)
	if conn, err = dp.getRepairConn(repairTask.LeaderAddr); err != nil {
		return
	}
	defer func() {
		dp.putRepairConn(conn, err != nil)
	}()
	if err = p.WriteToConn(conn); err != nil {
		return
	}
	store := dp.extentStore
	start := time.Now().Unix()
	for localTinyDeleteFileSize < repairTask.LeaderTinyDeleteRecordFileSize {
		if localTinyDeleteFileSize >= repairTask.LeaderTinyDeleteRecordFileSize {
			return
		}
		if err = p.ReadFromConn(conn, proto.ReadDeadlineTime); err != nil {
			return
		}
		if p.IsErrPacket() {
			logContent := fmt.Sprintf("action[doStreamFixTinyDeleteRecord] %v.",
				p.LogMessage(p.GetOpMsg(), conn.RemoteAddr().String(), start, fmt.Errorf(string(p.Data[:p.Size]))))
			err = fmt.Errorf(logContent)
			return
		}
		if p.CRC != crc32.ChecksumIEEE(p.Data[:p.Size]) {
			err = fmt.Errorf("crc not match")
			return
		}
		if p.Size%storage.DeleteTinyRecordSize != 0 {
			err = fmt.Errorf("unavali size")
			return
		}
		var index int
		for (index+1)*storage.DeleteTinyRecordSize <= int(p.Size) {
			record := p.Data[index*storage.DeleteTinyRecordSize : (index+1)*storage.DeleteTinyRecordSize]
			extentID, offset, size := storage.UnMarshalTinyExtent(record)
			localTinyDeleteFileSize += storage.DeleteTinyRecordSize
			index++
			if !storage.IsTinyExtent(extentID) {
				continue
			}
			DeleteLimiterWait()
			dp.disk.allocCheckLimit(proto.IopsWriteType, 1)
			//log.LogInfof("doStreamFixTinyDeleteRecord Delete PartitionID(%v)_Extent(%v)_Offset(%v)_Size(%v)", dp.partitionID, extentID, offset, size)
			store.MarkDelete(extentID, int64(offset), int64(size))
		}
	}
}

// ChangeRaftMember is a wrapper function of changing the raft member.
func (dp *DataPartition) ChangeRaftMember(changeType raftProto.ConfChangeType, peer raftProto.Peer, context []byte) (resp interface{}, err error) {
	resp, err = dp.raftPartition.ChangeMember(changeType, peer, context)
	return
}

//
func (dp *DataPartition) canRemoveSelf() (canRemove bool, err error) {
	var partition *proto.DataPartitionInfo
	if partition, err = MasterClient.AdminAPI().GetDataPartition(dp.volumeID, dp.partitionID); err != nil {
		log.LogErrorf("action[canRemoveSelf] err[%v]", err)
		return
	}
	canRemove = false
	var existInPeers bool
	for _, peer := range partition.Peers {
		if dp.config.NodeID == peer.ID {
			existInPeers = true
		}
	}
	if !existInPeers {
		canRemove = true
		return
	}
	if dp.config.NodeID == partition.OfflinePeerID {
		canRemove = true
		return
	}
	return
}

func (dp *DataPartition) getRepairConn(target string) (net.Conn, error) {
	return dp.dataNode.getRepairConnFunc(target)
}

func (dp *DataPartition) putRepairConn(conn net.Conn, forceClose bool) {
	log.LogDebugf("action[putRepairConn], forceClose: %v", forceClose)
	dp.dataNode.putRepairConnFunc(conn, forceClose)
	return
}

func (dp *DataPartition) isNormalType() bool {
	return proto.IsNormalDp(dp.partitionType)
}

type SimpleVolView struct {
	vv             *proto.SimpleVolView
	lastUpdateTime time.Time
}

type VolMap struct {
	sync.Mutex
	volMap map[string]*SimpleVolView
}

var volViews = VolMap{
	Mutex:  sync.Mutex{},
	volMap: make(map[string]*SimpleVolView),
}

func (vo *VolMap) getSimpleVolView(VolumeID string) (vv *proto.SimpleVolView, err error) {
	vo.Lock()
	if volView, ok := vo.volMap[VolumeID]; ok && time.Since(volView.lastUpdateTime) < 5*time.Minute {
		vo.Unlock()
		return volView.vv, nil
	}
	vo.Unlock()

	volView := &SimpleVolView{
		vv:             nil,
		lastUpdateTime: time.Time{},
	}

	if vv, err = MasterClient.AdminAPI().GetVolumeSimpleInfo(VolumeID); err != nil {
		log.LogErrorf("action[GetVolumeSimpleInfo] cannot get vol(%v) from master(%v) err(%v).",
			VolumeID, MasterClient.Leader(), err)
		return nil, err
	}

	log.LogDebugf("get volume info, vol(%s), vol(%v)", vv.Name, volView)

	volView.vv = vv
	volView.lastUpdateTime = time.Now()

	vo.Lock()
	vo.volMap[VolumeID] = volView
	vo.Unlock()

	return
}

func (dp *DataPartition) doExtentTtl(ttl int) {
	if ttl <= 0 {
		log.LogWarn("[doTTL] ttl is 0, set default 30", ttl)
		ttl = 30
	}

	extents := dp.extentStore.DumpExtents()

	for _, ext := range extents {
		if storage.IsTinyExtent(ext.FileID) {
			continue
		}

		if time.Now().Unix()-ext.AccessTime > int64(ttl)*util.OneDaySec() {
			log.LogDebugf("action[doExtentTtl] ttl delete dp(%v) extent(%v).", dp.partitionID, ext)
			dp.extentStore.MarkDelete(ext.FileID, 0, 0)
		}
	}
}

func (dp *DataPartition) doExtentEvict(vv *proto.SimpleVolView) {
	var (
		needDieOut      bool
		freeSpace       int
		freeExtentCount int
	)

	needDieOut = false
	if vv.CacheHighWater < vv.CacheLowWater || vv.CacheLowWater < 0 || vv.CacheHighWater > 100 {
		log.LogErrorf("action[doExtentEvict] invalid policy dp(%v), CacheHighWater(%v) CacheLowWater(%v).",
			dp.partitionID, vv.CacheHighWater, vv.CacheLowWater)
		return
	}

	// if dp use age larger than the space high water, do die out.
	freeSpace = 0
	if dp.Used()*100/dp.Size() > vv.CacheHighWater {
		needDieOut = true
		freeSpace = dp.Used() - dp.Size()*vv.CacheLowWater/100
	} else if dp.partitionStatus == proto.ReadOnly {
		needDieOut = true
		freeSpace = dp.Used() * (vv.CacheHighWater - vv.CacheLowWater) / 100
	}

	// if dp extent count larger than upper count, do die out.
	freeExtentCount = 0
	extInfos := dp.extentStore.DumpExtents()
	maxExtentCount := dp.Size() / util.DefaultTinySizeLimit
	if len(extInfos) > maxExtentCount {
		needDieOut = true
		freeExtentCount = len(extInfos) - vv.CacheLowWater*maxExtentCount/100
	}

	log.LogDebugf("action[doExtentEvict], vol %v, LRU(%v, %v), dp %v, usage %v, status(%d), extents %v, freeSpace %v, freeExtentCount %v, needDieOut %v",
		vv.Name, vv.CacheLowWater, vv.CacheHighWater, dp.partitionID, dp.Used()*100/dp.Size(), dp.partitionStatus, len(extInfos),
		freeSpace, freeExtentCount, needDieOut)

	if !needDieOut {
		return
	}

	sort.Sort(extInfos)

	for _, ext := range extInfos {
		if storage.IsTinyExtent(ext.FileID) {
			continue
		}

		freeSpace -= int(ext.Size)
		freeExtentCount--
		dp.extentStore.MarkDelete(ext.FileID, 0, 0)
		log.LogDebugf("action[doExtentEvict] die out. vol %v, dp(%v), extent(%v).", vv.Name, dp.partitionID, *ext)

		if freeSpace <= 0 && freeExtentCount <= 0 {
			log.LogDebugf("[doExtentEvict] die out done, vol(%s), dp (%d)", vv.Name, dp.partitionID)
			break
		}
	}

}

func (dp *DataPartition) startEvict() {
	// only cache or preload dp can't do evict.
	if !proto.IsCacheDp(dp.partitionType) {
		return
	}

	log.LogDebugf("[startEvict] start do dp(%d) evict op", dp.partitionID)

	vv, err := volViews.getSimpleVolView(dp.volumeID)
	if err != nil {
		err := fmt.Errorf("[startEvict] get vol [%s] info error, err %s", dp.volumeID, err.Error())
		log.LogError(err)
		panic(err)
	}

	lruInterval := getWithDefault(vv.CacheLruInterval, 5)
	cacheTtl := getWithDefault(vv.CacheTtl, 30)

	lruTimer := time.NewTicker(time.Duration(lruInterval) * time.Minute)
	ttlTimer := time.NewTicker(time.Duration(util.OneDaySec()) * time.Second)
	defer func() {
		lruTimer.Stop()
		ttlTimer.Stop()
	}()

	for {
		// check volume type and dp type.
		if proto.IsHot(vv.VolType) || !proto.IsCacheDp(dp.partitionType) {
			log.LogErrorf("action[startEvict] cannot startEvict, vol(%v), dp(%v).", vv.Name, dp.partitionID)
			return
		}

		select {
		case <-lruTimer.C:
			log.LogDebugf("start [doExtentEvict] vol(%s), dp(%d).", vv.Name, dp.partitionID)
			evictStart := time.Now()
			dp.doExtentEvict(vv)
			log.LogDebugf("action[doExtentEvict] vol(%v), dp(%v), cost (%v)ms, .", vv.Name, dp.partitionID, time.Since(evictStart))

		case <-ttlTimer.C:
			log.LogDebugf("start [doExtentTtl] vol(%s), dp(%d).", vv.Name, dp.partitionID)
			ttlStart := time.Now()
			dp.doExtentTtl(cacheTtl)
			log.LogDebugf("action[doExtentTtl] vol(%v), dp(%v), cost (%v)ms.", vv.Name, dp.partitionID, time.Since(ttlStart))

		case <-dp.stopC:
			log.LogWarn("task[doExtentTtl] stopped", dp.volumeID, dp.partitionID)
			return
		}

		// loop update vol info
		newVV, err := volViews.getSimpleVolView(dp.volumeID)
		if err != nil {
			err := fmt.Errorf("[startEvict] get vol [%s] info error, err %s", dp.volumeID, err.Error())
			log.LogError(err)
			continue
		}

		vv = newVV
		if lruInterval != vv.CacheLruInterval || cacheTtl != vv.CacheTtl {
			lruInterval = getWithDefault(vv.CacheLruInterval, 5)
			cacheTtl = getWithDefault(vv.CacheTtl, 30)

			lruTimer = time.NewTicker(time.Duration(lruInterval) * time.Minute)
			log.LogInfof("[startEvict] update vol config, dp(%d) %v ", dp.partitionID, *vv)
		}
	}
}

func getWithDefault(base, def int) int {
	if base <= 0 {
		return def
	}

	return base
}
