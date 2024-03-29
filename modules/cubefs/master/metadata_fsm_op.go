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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/cubefs/cubefs/depends/tiglabs/raft/proto"
	bsProto "github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/errors"
	"github.com/cubefs/cubefs/util/log"
)

/* We defines several "values" such as clusterValue, metaPartitionValue, dataPartitionValue, volValue, dataNodeValue,
   nodeSetValue, and metaNodeValue here. Those are the value objects that will be marshaled as a byte array to
   transferred over the network. */

type clusterValue struct {
	Name                        string
	CreateTime                  int64
	Threshold                   float32
	LoadFactor                  float32
	DisableAutoAllocate         bool
	ForbidMpDecommission        bool
	DataNodeDeleteLimitRate     uint64
	MetaNodeDeleteBatchCount    uint64
	MetaNodeDeleteWorkerSleepMs uint64
	DataNodeAutoRepairLimitRate uint64
	MaxDpCntLimit               uint64
	FaultDomain                 bool
	DiskQosEnable               bool
	QosLimitUpload              uint64
	DirChildrenNumLimit         uint32
	DecommissionLimit           uint64
	CheckDataReplicasEnable     bool
	FileStatsEnable             bool
	ClusterUuid                 string
	ClusterUuidEnable           bool
	MetaPartitionInodeIdStep    uint64
	MaxConcurrentLcNodes        uint64
	DpMaxRepairErrCnt           uint64
	DpRepairTimeOut             uint64
	EnableAutoDecommissionDisk  bool
	DecommissionDiskFactor      float64
	VolDeletionDelayTimeHour    int64
}

func newClusterValue(c *Cluster) (cv *clusterValue) {
	cv = &clusterValue{
		Name:                        c.Name,
		CreateTime:                  c.CreateTime,
		LoadFactor:                  c.cfg.ClusterLoadFactor,
		Threshold:                   c.cfg.MetaNodeThreshold,
		DataNodeDeleteLimitRate:     c.cfg.DataNodeDeleteLimitRate,
		MetaNodeDeleteBatchCount:    c.cfg.MetaNodeDeleteBatchCount,
		MetaNodeDeleteWorkerSleepMs: c.cfg.MetaNodeDeleteWorkerSleepMs,
		DataNodeAutoRepairLimitRate: c.cfg.DataNodeAutoRepairLimitRate,
		DisableAutoAllocate:         c.DisableAutoAllocate,
		ForbidMpDecommission:        c.ForbidMpDecommission,
		MaxDpCntLimit:               c.cfg.MaxDpCntLimit,
		FaultDomain:                 c.FaultDomain,
		DiskQosEnable:               c.diskQosEnable,
		QosLimitUpload:              uint64(c.QosAcceptLimit.Limit()),
		DirChildrenNumLimit:         c.cfg.DirChildrenNumLimit,
		DecommissionLimit:           c.DecommissionLimit,
		CheckDataReplicasEnable:     c.checkDataReplicasEnable,
		FileStatsEnable:             c.fileStatsEnable,
		ClusterUuid:                 c.clusterUuid,
		ClusterUuidEnable:           c.clusterUuidEnable,
		MetaPartitionInodeIdStep:    c.cfg.MetaPartitionInodeIdStep,
		MaxConcurrentLcNodes:        c.cfg.MaxConcurrentLcNodes,
		DpMaxRepairErrCnt:           c.cfg.DpMaxRepairErrCnt,
		DpRepairTimeOut:             c.cfg.DpRepairTimeOut,
		EnableAutoDecommissionDisk:  c.EnableAutoDecommissionDisk,
		DecommissionDiskFactor:      c.DecommissionDiskFactor,
		VolDeletionDelayTimeHour:    c.cfg.volDelayDeleteTimeHour,
	}
	return cv
}

type metaPartitionValue struct {
	PartitionID   uint64
	Start         uint64
	End           uint64
	VolID         uint64
	ReplicaNum    uint8
	Status        int8
	VolName       string
	Hosts         string
	OfflinePeerID uint64
	Peers         []bsProto.Peer
	IsRecover     bool
}

func newMetaPartitionValue(mp *MetaPartition) (mpv *metaPartitionValue) {
	mpv = &metaPartitionValue{
		PartitionID:   mp.PartitionID,
		Start:         mp.Start,
		End:           mp.End,
		VolID:         mp.volID,
		ReplicaNum:    mp.ReplicaNum,
		Status:        mp.Status,
		VolName:       mp.volName,
		Hosts:         mp.hostsToString(),
		Peers:         mp.Peers,
		OfflinePeerID: mp.OfflinePeerID,
		IsRecover:     mp.IsRecover,
	}
	return
}

type dataPartitionValue struct {
	PartitionID                    uint64
	ReplicaNum                     uint8
	Hosts                          string
	Peers                          []bsProto.Peer
	Status                         int8
	VolID                          uint64
	VolName                        string
	OfflinePeerID                  uint64
	Replicas                       []*replicaValue
	IsRecover                      bool
	PartitionType                  int
	PartitionTTL                   int64
	RdOnly                         bool
	IsDiscard                      bool
	DecommissionRetry              int
	DecommissionStatus             uint32
	DecommissionSrcAddr            string
	DecommissionDstAddr            string
	DecommissionRaftForce          bool
	DecommissionSrcDiskPath        string
	DecommissionTerm               uint64
	SpecialReplicaDecommissionStep uint32
	DecommissionDstAddrSpecify     bool
	DecommissionNeedRollback       bool
	RecoverStartTime               int64
	RecoverLastConsumeTime         float64
	Forbidden                      bool
	DecommissionWaitTimes          int
	DecommissionErrorMessage       string
}

func (dpv *dataPartitionValue) Restore(c *Cluster) (dp *DataPartition) {
	for i := 0; i < len(dpv.Peers); i++ {
		dn, ok := c.dataNodes.Load(dpv.Peers[i].Addr)
		if ok && dn.(*DataNode).ID != dpv.Peers[i].ID {
			dpv.Peers[i].ID = dn.(*DataNode).ID
		}
	}
	dp = newDataPartition(dpv.PartitionID, dpv.ReplicaNum, dpv.VolName, dpv.VolID, dpv.PartitionType, dpv.PartitionTTL)
	dp.Hosts = strings.Split(dpv.Hosts, underlineSeparator)
	dp.Peers = dpv.Peers
	dp.OfflinePeerID = dpv.OfflinePeerID
	dp.isRecover = dpv.IsRecover
	dp.RdOnly = dpv.RdOnly
	dp.IsDiscard = dpv.IsDiscard
	dp.DecommissionRaftForce = dpv.DecommissionRaftForce
	dp.DecommissionDstAddr = dpv.DecommissionDstAddr
	dp.DecommissionSrcAddr = dpv.DecommissionSrcAddr
	dp.DecommissionRetry = dpv.DecommissionRetry
	dp.DecommissionStatus = dpv.DecommissionStatus
	dp.DecommissionSrcDiskPath = dpv.DecommissionSrcDiskPath
	dp.DecommissionTerm = dpv.DecommissionTerm
	dp.SpecialReplicaDecommissionStep = dpv.SpecialReplicaDecommissionStep
	dp.DecommissionDstAddrSpecify = dpv.DecommissionDstAddrSpecify
	dp.DecommissionNeedRollback = dpv.DecommissionNeedRollback
	dp.RecoverStartTime = time.Unix(dpv.RecoverStartTime, 0)
	dp.RecoverLastConsumeTime = time.Duration(dpv.RecoverLastConsumeTime) * time.Second
	dp.DecommissionWaitTimes = dpv.DecommissionWaitTimes
	for _, rv := range dpv.Replicas {
		if !contains(dp.Hosts, rv.Addr) {
			continue
		}
		dp.afterCreation(rv.Addr, rv.DiskPath, c)
	}
	return dp
}

type replicaValue struct {
	Addr     string
	DiskPath string
}

func newDataPartitionValue(dp *DataPartition) (dpv *dataPartitionValue) {
	dpv = &dataPartitionValue{
		PartitionID:                    dp.PartitionID,
		ReplicaNum:                     dp.ReplicaNum,
		Hosts:                          dp.hostsToString(),
		Peers:                          dp.Peers,
		Status:                         dp.Status,
		VolID:                          dp.VolID,
		VolName:                        dp.VolName,
		OfflinePeerID:                  dp.OfflinePeerID,
		Replicas:                       make([]*replicaValue, 0),
		IsRecover:                      dp.isRecover,
		PartitionType:                  dp.PartitionType,
		PartitionTTL:                   dp.PartitionTTL,
		RdOnly:                         dp.RdOnly,
		IsDiscard:                      dp.IsDiscard,
		DecommissionRetry:              dp.DecommissionRetry,
		DecommissionStatus:             dp.DecommissionStatus,
		DecommissionSrcAddr:            dp.DecommissionSrcAddr,
		DecommissionDstAddr:            dp.DecommissionDstAddr,
		DecommissionRaftForce:          dp.DecommissionRaftForce,
		DecommissionSrcDiskPath:        dp.DecommissionSrcDiskPath,
		DecommissionTerm:               dp.DecommissionTerm,
		SpecialReplicaDecommissionStep: dp.SpecialReplicaDecommissionStep,
		DecommissionDstAddrSpecify:     dp.DecommissionDstAddrSpecify,
		DecommissionNeedRollback:       dp.DecommissionNeedRollback,
		RecoverStartTime:               dp.RecoverStartTime.Unix(),
		RecoverLastConsumeTime:         dp.RecoverLastConsumeTime.Seconds(),
		DecommissionWaitTimes:          dp.DecommissionWaitTimes,
		DecommissionErrorMessage:       dp.DecommissionErrorMessage,
	}
	for _, replica := range dp.Replicas {
		rv := &replicaValue{Addr: replica.Addr, DiskPath: replica.DiskPath}
		dpv.Replicas = append(dpv.Replicas, rv)
	}
	return
}

type volValue struct {
	ID                    uint64
	Name                  string
	ReplicaNum            uint8
	DpReplicaNum          uint8
	Status                uint8
	DataPartitionSize     uint64
	Capacity              uint64
	Owner                 string
	FollowerRead          bool
	Authenticate          bool
	DpReadOnlyWhenVolFull bool

	AuthKey        string
	DeleteExecTime time.Time
	User           *User

	CrossZone       bool
	DomainOn        bool
	ZoneName        string
	OSSAccessKey    string
	OSSSecretKey    string
	CreateTime      int64
	DeleteLockTime  int64
	Description     string
	DpSelectorName  string
	DpSelectorParm  string
	DefaultPriority bool
	DomainId        uint64
	VolType         int

	EbsBlkSize       int
	CacheCapacity    uint64
	CacheAction      int
	CacheThreshold   int
	CacheTTL         int
	CacheHighWater   int
	CacheLowWater    int
	CacheLRUInterval int
	CacheRule        string

	EnablePosixAcl bool
	EnableQuota    bool

	EnableTransaction       bsProto.TxOpMask
	TxTimeout               int64
	TxConflictRetryNum      int64
	TxConflictRetryInterval int64
	TxOpLimit               int

	VolQosEnable                                           bool
	DiskQosEnable                                          bool
	IopsRLimit, IopsWLimit, FlowRlimit, FlowWlimit         uint64
	IopsRMagnify, IopsWMagnify, FlowRMagnify, FlowWMagnify uint32
	ClientReqPeriod, ClientHitTriggerCnt                   uint32
	Forbidden                                              bool
	EnableAuditLog                                         bool
}

func (v *volValue) Bytes() (raw []byte, err error) {
	raw, err = json.Marshal(v)
	return
}

func newVolValue(vol *Vol) (vv *volValue) {
	vv = &volValue{
		ID:                      vol.ID,
		Name:                    vol.Name,
		ReplicaNum:              vol.mpReplicaNum,
		DpReplicaNum:            vol.dpReplicaNum,
		Status:                  vol.Status,
		DataPartitionSize:       vol.dataPartitionSize,
		Capacity:                vol.Capacity,
		Owner:                   vol.Owner,
		FollowerRead:            vol.FollowerRead,
		Authenticate:            vol.authenticate,
		CrossZone:               vol.crossZone,
		DomainOn:                vol.domainOn,
		ZoneName:                vol.zoneName,
		OSSAccessKey:            vol.OSSAccessKey,
		OSSSecretKey:            vol.OSSSecretKey,
		CreateTime:              vol.createTime,
		DeleteLockTime:          vol.DeleteLockTime,
		Description:             vol.description,
		DpSelectorName:          vol.dpSelectorName,
		DpSelectorParm:          vol.dpSelectorParm,
		DefaultPriority:         vol.defaultPriority,
		EnablePosixAcl:          vol.enablePosixAcl,
		EnableQuota:             vol.enableQuota,
		EnableTransaction:       vol.enableTransaction,
		TxTimeout:               vol.txTimeout,
		TxConflictRetryNum:      vol.txConflictRetryNum,
		TxConflictRetryInterval: vol.txConflictRetryInterval,
		TxOpLimit:               vol.txOpLimit,

		VolType:             vol.VolType,
		EbsBlkSize:          vol.EbsBlkSize,
		CacheCapacity:       vol.CacheCapacity,
		CacheAction:         vol.CacheAction,
		CacheThreshold:      vol.CacheThreshold,
		CacheTTL:            vol.CacheTTL,
		CacheHighWater:      vol.CacheHighWater,
		CacheLowWater:       vol.CacheLowWater,
		CacheLRUInterval:    vol.CacheLRUInterval,
		CacheRule:           vol.CacheRule,
		VolQosEnable:        vol.qosManager.qosEnable,
		IopsRLimit:          vol.qosManager.getQosLimit(bsProto.IopsReadType),
		IopsWLimit:          vol.qosManager.getQosLimit(bsProto.IopsWriteType),
		FlowRlimit:          vol.qosManager.getQosLimit(bsProto.FlowReadType),
		FlowWlimit:          vol.qosManager.getQosLimit(bsProto.FlowWriteType),
		IopsRMagnify:        vol.qosManager.getQosMagnify(bsProto.IopsReadType),
		IopsWMagnify:        vol.qosManager.getQosMagnify(bsProto.IopsWriteType),
		FlowRMagnify:        vol.qosManager.getQosMagnify(bsProto.FlowReadType),
		FlowWMagnify:        vol.qosManager.getQosMagnify(bsProto.FlowWriteType),
		ClientReqPeriod:     vol.qosManager.ClientReqPeriod,
		ClientHitTriggerCnt: vol.qosManager.ClientHitTriggerCnt,

		DpReadOnlyWhenVolFull: vol.DpReadOnlyWhenVolFull,
		Forbidden:             vol.Forbidden,
		EnableAuditLog:        vol.EnableAuditLog,
		AuthKey:               vol.authKey,
		DeleteExecTime:        vol.DeleteExecTime,
		User:                  vol.user,
	}

	return
}

func newVolValueFromBytes(raw []byte) (*volValue, error) {
	vv := &volValue{}
	if err := json.Unmarshal(raw, vv); err != nil {
		return nil, err
	}
	return vv, nil
}

type dataNodeValue struct {
	ID                       uint64
	NodeSetID                uint64
	Addr                     string
	ZoneName                 string
	RdOnly                   bool
	DecommissionedDisks      []string
	DecommissionStatus       uint32
	DecommissionDstAddr      string
	DecommissionRaftForce    bool
	DecommissionLimit        int
	DecommissionRetry        uint8
	DecommissionCompleteTime int64
	ToBeOffline              bool
	DecommissionDiskList     []string
	DecommissionDpTotal      int
}

func newDataNodeValue(dataNode *DataNode) *dataNodeValue {
	return &dataNodeValue{
		ID:                       dataNode.ID,
		NodeSetID:                dataNode.NodeSetID,
		Addr:                     dataNode.Addr,
		ZoneName:                 dataNode.ZoneName,
		RdOnly:                   dataNode.RdOnly,
		DecommissionedDisks:      dataNode.getDecommissionedDisks(),
		DecommissionStatus:       atomic.LoadUint32(&dataNode.DecommissionStatus),
		DecommissionDstAddr:      dataNode.DecommissionDstAddr,
		DecommissionRaftForce:    dataNode.DecommissionRaftForce,
		DecommissionLimit:        dataNode.DecommissionLimit,
		DecommissionRetry:        dataNode.DecommissionRetry,
		DecommissionCompleteTime: dataNode.DecommissionCompleteTime,
		ToBeOffline:              dataNode.ToBeOffline,
		DecommissionDiskList:     dataNode.DecommissionDiskList,
		DecommissionDpTotal:      dataNode.DecommissionDpTotal,
	}
}

type metaNodeValue struct {
	ID        uint64
	NodeSetID uint64
	Addr      string
	ZoneName  string
	RdOnly    bool
}

func newMetaNodeValue(metaNode *MetaNode) *metaNodeValue {
	return &metaNodeValue{
		ID:        metaNode.ID,
		NodeSetID: metaNode.NodeSetID,
		Addr:      metaNode.Addr,
		ZoneName:  metaNode.ZoneName,
		RdOnly:    metaNode.RdOnly,
	}
}

type nodeSetValue struct {
	ID               uint64
	Capacity         int
	ZoneName         string
	DataNodeSelector string
	MetaNodeSelector string
}

type domainNodeSetGrpValue struct {
	DomainId    uint64
	ID          uint64
	NodeSetsIds []uint64
	Status      uint8
}

type zoneDomainValue struct {
	ExcludeZoneMap       map[string]int
	NeedFaultDomain      bool
	DataRatio            float64
	domainNodeSetGrpVec  []*DomainNodeSetGrpManager
	DomainZoneName2IdMap map[string]uint64 // zoneName:domainId
	ExcludeZoneUseRatio  float64
}

func newZoneDomainValue() (ev *zoneDomainValue) {
	ev = &zoneDomainValue{
		ExcludeZoneMap: make(map[string]int),
	}
	return
}

func newNodeSetValue(nset *nodeSet) (nsv *nodeSetValue) {
	nsv = &nodeSetValue{
		ID:               nset.ID,
		Capacity:         nset.Capacity,
		ZoneName:         nset.zoneName,
		DataNodeSelector: nset.GetDataNodeSelector(),
		MetaNodeSelector: nset.GetMetaNodeSelector(),
	}
	return
}

func newNodeSetGrpValue(nset *nodeSetGroup) (nsv *domainNodeSetGrpValue) {
	nsv = &domainNodeSetGrpValue{
		DomainId:    nset.domainId,
		ID:          nset.ID,
		NodeSetsIds: nset.nodeSetsIds,
		Status:      nset.status,
	}
	return
}

// RaftCmd defines the Raft commands.
type RaftCmd struct {
	Op uint32 `json:"op"`
	K  string `json:"k"`
	V  []byte `json:"v"`
}

// Marshal converts the RaftCmd to a byte array.
func (m *RaftCmd) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal converts the byte array to a RaftCmd.
func (m *RaftCmd) Unmarshal(data []byte) (err error) {
	return json.Unmarshal(data, m)
}

func (m *RaftCmd) setOpType() {
	keyArr := strings.Split(m.K, keySeparator)
	if len(keyArr) < 2 {
		log.LogWarnf("action[setOpType] invalid length[%v]", keyArr)
		return
	}
	switch keyArr[1] {
	case metaNodeAcronym:
		m.Op = opSyncAddMetaNode
	case dataNodeAcronym:
		m.Op = opSyncAddDataNode
	case dataPartitionAcronym:
		m.Op = opSyncAddDataPartition
	case metaPartitionAcronym:
		m.Op = opSyncAddMetaPartition
	case volAcronym:
		m.Op = opSyncAddVol
	case clusterAcronym:
		m.Op = opSyncPutCluster
	case nodeSetAcronym:
		m.Op = opSyncAddNodeSet
	case maxDataPartitionIDKey:
		m.Op = opSyncAllocDataPartitionID
	case maxMetaPartitionIDKey:
		m.Op = opSyncAllocMetaPartitionID
	case maxCommonIDKey:
		m.Op = opSyncAllocCommonID
	case userAcronym:
		m.Op = opSyncAddUserInfo
	case akAcronym:
		m.Op = opSyncAddAKUser
	case volUserAcronym:
		m.Op = opSyncAddVolUser
	case lcNodeAcronym:
		m.Op = opSyncAddLcNode
	case lcConfigurationAcronym:
		m.Op = opSyncAddLcConf
	default:
		log.LogWarnf("action[setOpType] unknown opCode[%v]", keyArr[1])
	}
}

// key=#c#name
func (c *Cluster) syncPutCluster() (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opSyncPutCluster
	metadata.K = clusterPrefix + c.Name
	cv := newClusterValue(c)
	log.LogInfof("action[syncPutCluster] cluster value:[%+v]", cv)
	metadata.V, err = json.Marshal(cv)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) syncPutApiLimiterInfo(followerLimiter bool) (err error) {
	metadata := new(RaftCmd)
	if followerLimiter {
		metadata.Op = opSyncPutFollowerApiLimiterInfo
	} else {
		metadata.Op = opSyncPutApiLimiterInfo
	}

	metadata.K = apiLimiterPrefix + c.Name
	c.apiLimiter.m.RLock()
	metadata.V, err = json.Marshal(c.apiLimiter.limiterInfos)
	c.apiLimiter.m.RUnlock()
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) loadApiLimiterInfo() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(apiLimiterPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadApiLimiterInfo],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		// cv := &clusterValue{}
		limiterInfos := make(map[string]*ApiLimitInfo)
		if err = json.Unmarshal(value, &limiterInfos); err != nil {
			log.LogErrorf("action[loadApiLimiterInfo], unmarshal err:%v", err.Error())
			return err
		}
		for _, v := range limiterInfos {
			v.InitLimiter()
		}

		c.apiLimiter.m.Lock()
		c.apiLimiter.limiterInfos = limiterInfos
		c.apiLimiter.m.Unlock()
		// c.apiLimiter.Replace(limiterInfos)
		log.LogInfof("action[loadApiLimiterInfo], limiter info[%v]", value)
	}
	return
}

// key=#s#id
func (c *Cluster) syncAddNodeSet(nset *nodeSet) (err error) {
	return c.putNodeSetInfo(opSyncAddNodeSet, nset)
}

func (c *Cluster) syncUpdateNodeSet(nset *nodeSet) (err error) {
	return c.putNodeSetInfo(opSyncUpdateNodeSet, nset)
}

func (c *Cluster) putNodeSetInfo(opType uint32, nset *nodeSet) (err error) {
	log.LogInfof("action[putNodeSetInfo], type:[%v], gridId:[%v], name:[%v]", opType, nset.ID, nset.zoneName)
	metadata := new(RaftCmd)
	metadata.Op = opType
	metadata.K = nodeSetPrefix + strconv.FormatUint(nset.ID, 10)
	nsv := newNodeSetValue(nset)
	metadata.V, err = json.Marshal(nsv)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) putNodeSetGrpInfo(opType uint32, nsg *nodeSetGroup) (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opType
	metadata.K = nodeSetGrpPrefix + strconv.FormatUint(nsg.ID, 10)
	log.LogInfof("action[putNodeSetGrpInfo] nsg id[%v] status[%v] ids[%v]", nsg.ID, nsg.status, nsg.nodeSetsIds)
	nsv := newNodeSetGrpValue(nsg)
	log.LogInfof("action[putNodeSetGrpInfo] nsv id[%v] status[%v] ids[%v]", nsv.ID, nsv.Status, nsv.NodeSetsIds)
	metadata.V, err = json.Marshal(nsv)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

// key=#dp#volID#partitionID,value=json.Marshal(dataPartitionValue)
func (c *Cluster) syncAddDataPartition(dp *DataPartition) (err error) {
	return c.putDataPartitionInfo(opSyncAddDataPartition, dp)
}

func (c *Cluster) syncUpdateDataPartition(dp *DataPartition) (err error) {
	return c.putDataPartitionInfo(opSyncUpdateDataPartition, dp)
}

func (c *Cluster) syncDeleteDataPartition(dp *DataPartition) (err error) {
	return c.putDataPartitionInfo(opSyncDeleteDataPartition, dp)
}

func (c *Cluster) buildDataPartitionRaftCmd(opType uint32, dp *DataPartition) (metadata *RaftCmd, err error) {
	metadata = new(RaftCmd)
	metadata.Op = opType
	metadata.K = dataPartitionPrefix + strconv.FormatUint(dp.VolID, 10) + keySeparator + strconv.FormatUint(dp.PartitionID, 10)
	dpv := newDataPartitionValue(dp)
	metadata.V, err = json.Marshal(dpv)
	if err != nil {
		return
	}
	return
}

func (c *Cluster) putDataPartitionInfo(opType uint32, dp *DataPartition) (err error) {
	metadata, err := c.buildDataPartitionRaftCmd(opType, dp)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) submit(metadata *RaftCmd) (err error) {
	cmd, err := metadata.Marshal()
	if err != nil {
		return errors.New(err.Error())
	}
	if _, err = c.partition.Submit(cmd); err != nil {
		msg := fmt.Sprintf("action[metadata_submit] err:%v", err.Error())
		return errors.New(msg)
	}
	return
}

// key=#vol#volID,value=json.Marshal(vv)
func (c *Cluster) syncAddVol(vol *Vol) (err error) {
	return c.syncPutVolInfo(opSyncAddVol, vol)
}

func (c *Cluster) syncUpdateVol(vol *Vol) (err error) {
	return c.syncPutVolInfo(opSyncUpdateVol, vol)
}

func (c *Cluster) syncDeleteVol(vol *Vol) (err error) {
	return c.syncPutVolInfo(opSyncDeleteVol, vol)
}

func (c *Cluster) sycnPutZoneInfo(zone *Zone) error {
	var err error
	metadata := new(RaftCmd)
	metadata.Op = opSyncUpdateZone
	metadata.K = zonePrefix + zone.name
	vv := zone.getFsmValue()
	if vv.Name == "" {
		vv.Name = DefaultZoneName
	}
	log.LogInfof("action[sycnPutZoneInfo] zone name %v", vv.Name)
	if metadata.V, err = json.Marshal(vv); err != nil {
		return errors.New(err.Error())
	}
	return c.submit(metadata)
}

func (c *Cluster) buildVolInfoRaftCmd(opType uint32, vol *Vol) (metadata *RaftCmd, err error) {
	metadata = new(RaftCmd)
	metadata.Op = opType
	metadata.K = volPrefix + strconv.FormatUint(vol.ID, 10)
	vv := newVolValue(vol)
	if metadata.V, err = json.Marshal(vv); err != nil {
		return nil, errors.New(err.Error())
	}
	return
}

func (c *Cluster) syncPutVolInfo(opType uint32, vol *Vol) (err error) {
	metadata, err := c.buildVolInfoRaftCmd(opType, vol)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) syncAclList(vol *Vol, val []byte) (err error) {
	log.LogDebugf("syncAclList vol %v vallen %v", vol.Name, len(val))
	metadata := new(RaftCmd)
	metadata.Op = opSyncAcl
	metadata.K = AclPrefix + strconv.FormatUint(vol.ID, 10)
	metadata.V = val

	return c.submit(metadata)
}

func (c *Cluster) syncMultiVersion(vol *Vol, val []byte) (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opSyncMulitVersion
	metadata.K = MultiVerPrefix + strconv.FormatUint(vol.ID, 10)
	metadata.V = val
	if c == nil {
		log.LogErrorf("syncMultiVersion c is nil")
		return fmt.Errorf("vol %v but cluster is nil", vol.Name)
	}
	return c.submit(metadata)
}

func (c *Cluster) loadAclList(vol *Vol) (err error) {
	key := AclPrefix + strconv.FormatUint(vol.ID, 10)
	result, err := c.fsm.store.SeekForPrefix([]byte(key))
	if err != nil {
		log.LogErrorf("action[loadAclList] err %v", err)
		return
	}

	log.LogDebugf("loadAclList vol %v rocksdb value count %v", vol.Name, len(result))

	vol.aclMgr.init(c, vol)
	for _, value := range result {
		return vol.aclMgr.load(c, value)
	}
	return
}

func (c *Cluster) syncUidSpaceList(vol *Vol, val []byte) (err error) {
	log.LogDebugf("syncUidSpaceList vol %v vallen %v", vol.Name, len(val))
	metadata := new(RaftCmd)
	metadata.Op = opSyncUid
	metadata.K = UidPrefix + strconv.FormatUint(vol.ID, 10)
	metadata.V = val

	return c.submit(metadata)
}

func (c *Cluster) loadUidSpaceList(vol *Vol) (err error) {
	key := UidPrefix + strconv.FormatUint(vol.ID, 10)
	result, err := c.fsm.store.SeekForPrefix([]byte(key))
	if err != nil {
		log.LogErrorf("action[loadUidSpaceList] err %v", err)
		return
	}

	log.LogDebugf("loadUidSpaceList vol %v rocksdb value count %v", vol.Name, len(result))

	vol.initUidSpaceManager(c)
	for _, value := range result {
		return vol.uidSpaceManager.load(c, value)
	}
	return
}

func (c *Cluster) loadMultiVersion(vol *Vol) (err error) {
	key := MultiVerPrefix + strconv.FormatUint(vol.ID, 10)
	result, err := c.fsm.store.SeekForPrefix([]byte(key))
	if err != nil {
		log.LogErrorf("action[loadMultiVersion] err %v", err)
		return
	}
	if len(result) == 0 {
		log.LogWarnf("action[loadMultiVersion] MultiVersion zero and do init")
		return vol.VersionMgr.init(c)
	}
	vol.VersionMgr.c = c
	log.LogWarnf("action[loadMultiVersion] vol %v loadMultiVersion set cluster %v vol.VersionMgr %v", vol.Name, c, vol.VersionMgr)
	for _, value := range result {
		if err = vol.VersionMgr.loadMultiVersion(c, value); err != nil {
			log.LogErrorf("action[loadMultiVersion] vol %v err %v", vol.Name, err)
			return
		}
		log.LogWarnf("action[loadMultiVersion] vol %v MultiVersion zero and do init, verlist %v", vol.Name, vol.VersionMgr)
	}
	return
}

// key=#mp#volID#metaPartitionID,value=json.Marshal(metaPartitionValue)
func (c *Cluster) syncAddMetaPartition(mp *MetaPartition) (err error) {
	return c.putMetaPartitionInfo(opSyncAddMetaPartition, mp)
}

func (c *Cluster) syncUpdateMetaPartition(mp *MetaPartition) (err error) {
	return c.putMetaPartitionInfo(opSyncUpdateMetaPartition, mp)
}

func (c *Cluster) syncDeleteMetaPartition(mp *MetaPartition) (err error) {
	return c.putMetaPartitionInfo(opSyncDeleteMetaPartition, mp)
}

func (c *Cluster) putMetaPartitionInfo(opType uint32, mp *MetaPartition) (err error) {
	metadata, err := c.buildMetaPartitionRaftCmd(opType, mp)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) buildMetaPartitionRaftCmd(opType uint32, mp *MetaPartition) (metadata *RaftCmd, err error) {
	metadata = new(RaftCmd)
	metadata.Op = opType
	partitionID := strconv.FormatUint(mp.PartitionID, 10)
	metadata.K = metaPartitionPrefix + strconv.FormatUint(mp.volID, 10) + keySeparator + partitionID
	mpv := newMetaPartitionValue(mp)
	if metadata.V, err = json.Marshal(mpv); err != nil {
		return metadata, errors.New(err.Error())
	}
	return
}

func (c *Cluster) syncBatchCommitCmd(cmdMap map[string]*RaftCmd) (err error) {
	value, err := json.Marshal(cmdMap)
	if err != nil {
		return
	}
	cmd := &RaftCmd{
		Op: opSyncBatchPut,
		K:  "batch_put",
		V:  value,
	}
	return c.submit(cmd)
}

// key=#mn#id#addr,value = nil
func (c *Cluster) syncAddMetaNode(metaNode *MetaNode) (err error) {
	return c.syncPutMetaNode(opSyncAddMetaNode, metaNode)
}

func (c *Cluster) syncDeleteMetaNode(metaNode *MetaNode) (err error) {
	return c.syncPutMetaNode(opSyncDeleteMetaNode, metaNode)
}

func (c *Cluster) syncUpdateMetaNode(metaNode *MetaNode) (err error) {
	return c.syncPutMetaNode(opSyncUpdateMetaNode, metaNode)
}

func (c *Cluster) buildPutMetaNodeCmd(opType uint32, metaNode *MetaNode) (metadata *RaftCmd, err error) {
	metadata = new(RaftCmd)
	metadata.Op = opType
	metadata.K = metaNodePrefix + strconv.FormatUint(metaNode.ID, 10) + keySeparator + metaNode.Addr
	mnv := newMetaNodeValue(metaNode)
	metadata.V, err = json.Marshal(mnv)
	return
}

func (c *Cluster) buildAddMetaNodeCmd(metaNode *MetaNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutMetaNodeCmd(opSyncAddMetaNode, metaNode)
	return
}

func (c *Cluster) buildDeleteMetaNodeCmd(metaNode *MetaNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutMetaNodeCmd(opSyncDeleteMetaNode, metaNode)
	return
}

func (c *Cluster) buildUpdateMetaNodeCmd(metaNode *MetaNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutMetaNodeCmd(opSyncUpdateMetaNode, metaNode)
	return
}

func (c *Cluster) syncPutMetaNode(opType uint32, metaNode *MetaNode) (err error) {
	metadata, err := c.buildPutMetaNodeCmd(opType, metaNode)
	if err != nil {
		return errors.New(err.Error())
	}
	return c.submit(metadata)
}

// key=#dn#id#Addr,value = json.Marshal(dnv)
func (c *Cluster) syncAddDataNode(dataNode *DataNode) (err error) {
	return c.syncPutDataNode(opSyncAddDataNode, dataNode)
}

func (c *Cluster) syncDeleteDataNode(dataNode *DataNode) (err error) {
	return c.syncPutDataNode(opSyncDeleteDataNode, dataNode)
}

func (c *Cluster) syncUpdateDataNode(dataNode *DataNode) (err error) {
	return c.syncPutDataNode(opSyncUpdateDataNode, dataNode)
}

func (c *Cluster) buildAddDataNodeCmd(dataNode *DataNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutDataNodeCmd(opSyncAddDataNode, dataNode)
	return
}

func (c *Cluster) buildDeleteDataNodeCmd(dataNode *DataNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutDataNodeCmd(opSyncDeleteDataNode, dataNode)
	return
}

func (c *Cluster) buildUpdateDataNodeCmd(dataNode *DataNode) (metadata *RaftCmd, err error) {
	metadata, err = c.buildPutDataNodeCmd(opSyncUpdateDataNode, dataNode)
	return
}

func (c *Cluster) buildPutDataNodeCmd(opType uint32, dataNode *DataNode) (metadata *RaftCmd, err error) {
	metadata = new(RaftCmd)
	metadata.Op = opType
	metadata.K = dataNodePrefix + strconv.FormatUint(dataNode.ID, 10) + keySeparator + dataNode.Addr
	dnv := newDataNodeValue(dataNode)
	metadata.V, err = json.Marshal(dnv)
	if err != nil {
		return
	}
	return
}

func (c *Cluster) syncPutDataNode(opType uint32, dataNode *DataNode) (err error) {
	metadata, err := c.buildPutDataNodeCmd(opType, dataNode)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) addRaftNode(nodeID uint64, addr string) (err error) {
	log.LogInfof("action[addRaftNode] nodeID: %v, addr: %v:", nodeID, addr)

	peer := proto.Peer{ID: nodeID}
	_, err = c.partition.ChangeMember(proto.ConfAddNode, peer, []byte(addr))
	if err != nil {
		return errors.New("action[addRaftNode] error: " + err.Error())
	}
	return nil
}

func (c *Cluster) removeRaftNode(nodeID uint64, addr string) (err error) {
	log.LogInfof("action[removeRaftNode] nodeID: %v, addr: %v:", nodeID, addr)

	peer := proto.Peer{ID: nodeID}
	_, err = c.partition.ChangeMember(proto.ConfRemoveNode, peer, []byte(addr))
	if err != nil {
		return errors.New("action[removeRaftNode] error: " + err.Error())
	}
	return nil
}

func (c *Cluster) updateDirChildrenNumLimit(val uint32) {
	if val < bsProto.MinDirChildrenNumLimit {
		val = bsProto.DefaultDirChildrenNumLimit
	}
	atomic.StoreUint32(&c.cfg.DirChildrenNumLimit, val)
}

func (c *Cluster) updateMetaNodeDeleteBatchCount(val uint64) {
	atomic.StoreUint64(&c.cfg.MetaNodeDeleteBatchCount, val)
}

func (c *Cluster) updateMetaNodeDeleteWorkerSleepMs(val uint64) {
	atomic.StoreUint64(&c.cfg.MetaNodeDeleteWorkerSleepMs, val)
}

func (c *Cluster) updateDataPartitionMaxRepairErrCnt(val uint64) {
	atomic.StoreUint64(&c.cfg.DpMaxRepairErrCnt, val)
}

func (c *Cluster) updateDataPartitionRepairTimeOut(val uint64) {
	atomic.StoreUint64(&c.cfg.DpRepairTimeOut, val)
}

func (c *Cluster) updateDataNodeAutoRepairLimit(val uint64) {
	atomic.StoreUint64(&c.cfg.DataNodeAutoRepairLimitRate, val)
}

func (c *Cluster) updateDataNodeDeleteLimitRate(val uint64) {
	atomic.StoreUint64(&c.cfg.DataNodeDeleteLimitRate, val)
}

func (c *Cluster) updateMaxDpCntLimit(val uint64) {
	atomic.StoreUint64(&c.cfg.MaxDpCntLimit, val)
}

func (c *Cluster) updateInodeIdStep(val uint64) {
	atomic.StoreUint64(&c.cfg.MetaPartitionInodeIdStep, val)
}

func (c *Cluster) loadZoneValue() (err error) {
	var ok bool
	result, err := c.fsm.store.SeekForPrefix([]byte(zonePrefix))
	if err != nil {
		err = fmt.Errorf("action[loadZoneValue],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		cv := &zoneValue{}
		if err = json.Unmarshal(value, cv); err != nil {
			log.LogErrorf("action[loadZoneValue], unmarshal err:%v", err.Error())
			continue
		}
		var zoneInfo interface{}
		if zoneInfo, ok = c.t.zoneMap.Load(cv.Name); !ok {
			log.LogErrorf("action[loadZoneValue], zonename [%v] not found", cv.Name)
			continue
		}
		zone := zoneInfo.(*Zone)
		zone.QosFlowRLimit = cv.QosFlowRLimit
		zone.QosIopsWLimit = cv.QosIopsWLimit
		zone.QosFlowWLimit = cv.QosFlowWLimit
		zone.QosIopsRLimit = cv.QosIopsRLimit
		if zone.GetDataNodesetSelector() != cv.DataNodesetSelector {
			zone.dataNodesetSelector = NewNodesetSelector(cv.DataNodesetSelector, DataNodeType)
		}
		if zone.GetMetaNodesetSelector() != cv.MetaNodesetSelector {
			zone.metaNodesetSelector = NewNodesetSelector(cv.MetaNodesetSelector, MetaNodeType)
		}
		log.LogInfof("action[loadZoneValue] load zonename[%v] with limit [%v,%v,%v,%v]",
			zone.name, cv.QosFlowRLimit, cv.QosIopsWLimit, cv.QosFlowWLimit, cv.QosIopsRLimit)
		zone.loadDataNodeQosLimit()
	}

	return
}

func (c *Cluster) updateMaxConcurrentLcNodes(val uint64) {
	atomic.StoreUint64(&c.cfg.MaxConcurrentLcNodes, val)
}

// persist cluster value if not persisted; set create time for cluster being created.
func (c *Cluster) checkPersistClusterValue() {
	result, err := c.fsm.store.SeekForPrefix([]byte(clusterPrefix))
	if err != nil {
		err = fmt.Errorf("action[checkPersistClusterValue] seek cluster value err: %v", err.Error())
		panic(err)
	}
	if len(result) != 0 {
		log.LogInfo("action[checkPersistClusterValue] already has cluster value record, need to do nothing")
		return
	}
	/* when cluster value not persisted, it could be:
	   - cluster created by old version master which may not persist cluster value, not need set create time;
	   - cluster being created, need to set create time;
	 check whether persisted node set info to determine which scenario it is. */
	result, err = c.fsm.store.SeekForPrefix([]byte(nodeSetPrefix))
	if err != nil {
		err = fmt.Errorf("action[checkPersistClusterValue] seek node set err: %v", err.Error())
		panic(err)
	}
	oldVal := c.CreateTime
	var scenarioMsg string
	if len(result) != 0 {
		scenarioMsg = "cluster already created"
	} else {
		scenarioMsg = "cluster being created"
		c.CreateTime = time.Now().Unix()
	}
	log.LogInfo("action[checkPersistClusterValue] to add cluster value record for " + scenarioMsg)
	if err = c.syncPutCluster(); err != nil {
		c.CreateTime = oldVal
		log.LogErrorf("action[checkPersistClusterValue] put err[%v]", err.Error())
		panic(err)
	}
	log.LogInfo("action[checkPersistClusterValue] add cluster value record")
	return
}

func (c *Cluster) loadClusterValue() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(clusterPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadClusterValue],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		cv := &clusterValue{}
		if err = json.Unmarshal(value, cv); err != nil {
			log.LogErrorf("action[loadClusterValue], unmarshal err:%v", err.Error())
			return err
		}

		if cv.Name != c.Name {
			log.LogErrorf("action[loadClusterValue] loaded cluster value: %+v", cv)
			continue
		}

		log.LogDebugf("action[loadClusterValue] loaded cluster value: %+v", cv)
		c.CreateTime = cv.CreateTime

		if cv.MaxConcurrentLcNodes == 0 {
			cv.MaxConcurrentLcNodes = defaultMaxConcurrentLcNodes
		}

		c.cfg.MetaNodeThreshold = cv.Threshold
		// c.cfg.DirChildrenNumLimit = cv.DirChildrenNumLimit
		c.cfg.ClusterLoadFactor = cv.LoadFactor
		c.DisableAutoAllocate = cv.DisableAutoAllocate
		c.ForbidMpDecommission = cv.ForbidMpDecommission
		c.diskQosEnable = cv.DiskQosEnable
		c.cfg.QosMasterAcceptLimit = cv.QosLimitUpload
		c.DecommissionLimit = cv.DecommissionLimit // dont update nodesets limit for nodesets are not loaded
		c.fileStatsEnable = cv.FileStatsEnable
		c.clusterUuid = cv.ClusterUuid
		c.clusterUuidEnable = cv.ClusterUuidEnable
		c.DecommissionLimit = cv.DecommissionLimit
		c.EnableAutoDecommissionDisk = cv.EnableAutoDecommissionDisk
		c.DecommissionDiskFactor = cv.DecommissionDiskFactor
		c.cfg.volDelayDeleteTimeHour = cv.VolDeletionDelayTimeHour
		if c.cfg.QosMasterAcceptLimit < QosMasterAcceptCnt {
			c.cfg.QosMasterAcceptLimit = QosMasterAcceptCnt
		}
		c.QosAcceptLimit.SetLimit(rate.Limit(c.cfg.QosMasterAcceptLimit))
		log.LogInfof("action[loadClusterValue] qos limit %v", c.cfg.QosMasterAcceptLimit)

		c.updateDirChildrenNumLimit(cv.DirChildrenNumLimit)
		c.updateMetaNodeDeleteBatchCount(cv.MetaNodeDeleteBatchCount)
		c.updateMetaNodeDeleteWorkerSleepMs(cv.MetaNodeDeleteWorkerSleepMs)
		c.updateDataNodeDeleteLimitRate(cv.DataNodeDeleteLimitRate)
		c.updateDataNodeAutoRepairLimit(cv.DataNodeAutoRepairLimitRate)
		c.updateDataPartitionMaxRepairErrCnt(cv.DpMaxRepairErrCnt)
		c.updateDataPartitionRepairTimeOut(cv.DpRepairTimeOut)
		c.updateMaxDpCntLimit(cv.MaxDpCntLimit)
		if cv.MetaPartitionInodeIdStep == 0 {
			cv.MetaPartitionInodeIdStep = defaultMetaPartitionInodeIDStep
		}
		c.updateInodeIdStep(cv.MetaPartitionInodeIdStep)

		c.updateMaxConcurrentLcNodes(cv.MaxConcurrentLcNodes)
		log.LogInfof("action[loadClusterValue], metaNodeThreshold[%v]", cv.Threshold)

		c.checkDataReplicasEnable = cv.CheckDataReplicasEnable
	}
	return
}

func (c *Cluster) loadNodeSets() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(nodeSetPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadNodeSets],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		nsv := &nodeSetValue{}
		if err = json.Unmarshal(value, nsv); err != nil {
			log.LogErrorf("action[loadNodeSets], unmarshal err:%v", err.Error())
			return err
		}
		if nsv.ZoneName == "" {
			nsv.ZoneName = DefaultZoneName
		}
		cap := nsv.Capacity
		if cap < 3 {
			cap = c.cfg.nodeSetCapacity
		}

		ns := newNodeSet(c, nsv.ID, cap, nsv.ZoneName)
		ns.UpdateMaxParallel(int32(c.DecommissionLimit))
		ns.UpdateDecommissionDiskFactor(c.DecommissionDiskFactor)
		if nsv.DataNodeSelector != "" && ns.GetDataNodeSelector() != nsv.DataNodeSelector {
			ns.SetDataNodeSelector(nsv.DataNodeSelector)
		}
		if nsv.MetaNodeSelector != "" && ns.GetMetaNodeSelector() != nsv.MetaNodeSelector {
			ns.SetMetaNodeSelector(nsv.MetaNodeSelector)
		}
		zone, err := c.t.getZone(nsv.ZoneName)
		if err != nil {
			log.LogErrorf("action[loadNodeSets], getZone err:%v", err)
			zone = newZone(nsv.ZoneName)
			c.t.putZoneIfAbsent(zone)
		}

		zone.putNodeSet(ns)
		log.LogInfof("action[addNodeSetGrp] nodeSet[%v]", ns.ID)
		if err = c.addNodeSetGrp(ns, true); err != nil {
			log.LogErrorf("action[createNodeSet] nodeSet[%v] err[%v]", ns.ID, err)
			return err
		}
		log.LogInfof("action[loadNodeSets], nsId[%v],zone[%v]", ns.ID, zone.name)
	}
	return nil
}

// put exclude zone only be used one time when master update and restart
func (c *Cluster) putZoneDomain(init bool) (err error) {
	log.LogInfof("action[putZoneDomain]")
	metadata := new(RaftCmd)
	metadata.Op = opSyncExclueDomain
	metadata.K = DomainPrefix

	c.domainManager.RLock()
	defer c.domainManager.RUnlock()

	if init {
		for i := 0; i < len(c.t.zones); i++ {
			c.domainManager.excludeZoneListDomain[c.t.zones[i].name] = 0
			c.t.domainExcludeZones = append(c.t.domainExcludeZones, c.t.zones[i].name)
		}
		if len(c.t.zones) == 0 {
			c.needFaultDomain = true
		}
	}
	domainValue := newZoneDomainValue()
	domainValue.ExcludeZoneMap = c.domainManager.excludeZoneListDomain
	domainValue.NeedFaultDomain = c.needFaultDomain
	domainValue.domainNodeSetGrpVec = c.domainManager.domainNodeSetGrpVec
	domainValue.DomainZoneName2IdMap = c.domainManager.ZoneName2DomainIdMap
	if c.domainManager.dataRatioLimit > 0 {
		log.LogInfof("action[putZoneDomain] ratio %v", c.domainManager.dataRatioLimit)
		domainValue.DataRatio = c.domainManager.dataRatioLimit
	} else {
		domainValue.DataRatio = defaultDomainUsageThreshold
	}
	if c.domainManager.excludeZoneUseRatio > 0 && c.domainManager.excludeZoneUseRatio <= 1 {
		domainValue.ExcludeZoneUseRatio = c.domainManager.excludeZoneUseRatio
	} else {
		domainValue.ExcludeZoneUseRatio = defaultDomainUsageThreshold
	}

	metadata.V, err = json.Marshal(domainValue)
	if err != nil {
		return
	}
	return c.submit(metadata)
}

func (c *Cluster) loadZoneDomain() (ok bool, err error) {
	log.LogInfof("action[loadZoneDomain]")
	result, err := c.fsm.store.SeekForPrefix([]byte(DomainPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadZoneDomain],err:%v", err.Error())
		log.LogInfof("action[loadZoneDomain] err[%v]", err)
		return false, err
	}
	if len(result) == 0 {
		err = fmt.Errorf("action[loadZoneDomain],err:not found")
		log.LogInfof("action[loadZoneDomain] err[%v]", err)
		return false, nil
	}
	for _, value := range result {
		nsv := &zoneDomainValue{}
		if err = json.Unmarshal(value, nsv); err != nil {
			log.LogErrorf("action[loadNodeSets], unmarshal err:%v", err.Error())
			return true, err
		}
		log.LogInfof("action[loadZoneDomain] get value!exclue map[%v],need domain[%v] ratio [%v]", nsv.ExcludeZoneMap, nsv.NeedFaultDomain, nsv.DataRatio)
		c.domainManager.excludeZoneListDomain = nsv.ExcludeZoneMap
		for zoneName := range nsv.ExcludeZoneMap {
			c.t.domainExcludeZones = append(c.t.domainExcludeZones, zoneName)
		}

		c.needFaultDomain = nsv.NeedFaultDomain
		c.domainManager.dataRatioLimit = nsv.DataRatio
		c.domainManager.ZoneName2DomainIdMap = nsv.DomainZoneName2IdMap
		c.domainManager.excludeZoneUseRatio = nsv.ExcludeZoneUseRatio

		for zoneName, domainId := range c.domainManager.ZoneName2DomainIdMap {
			log.LogInfof("action[loadZoneDomain] zoneName %v domainid %v", zoneName, domainId)
			if domainIndex, ok := c.domainManager.domainId2IndexMap[domainId]; !ok {
				log.LogInfof("action[loadZoneDomain] zoneName %v domainid %v build new domainnodesetgrp manager", zoneName, domainId)
				domainGrp := newDomainNodeSetGrpManager()
				domainGrp.domainId = domainId
				c.domainManager.domainNodeSetGrpVec = append(c.domainManager.domainNodeSetGrpVec, domainGrp)
				domainIndex = len(c.domainManager.domainNodeSetGrpVec) - 1
				c.domainManager.domainId2IndexMap[domainId] = domainIndex
			}
		}

		break
	}
	log.LogInfof("action[loadZoneDomain] success!")
	return true, nil
}

func (c *Cluster) loadNodeSetGrps() (err error) {
	log.LogInfof("action[loadNodeSetGrps]")
	result, err := c.fsm.store.SeekForPrefix([]byte(nodeSetGrpPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadNodeSets],err:%v", err.Error())
		log.LogInfof("action[loadNodeSetGrps] seek failed, nsgId[%v]", err)
		return err
	}
	if len(result) > 0 {
		log.LogInfof("action[loadNodeSetGrps] get result len[%v]", len(result))
		c.domainManager.start()
	}
	log.LogInfof("action[loadNodeSetGrps] get result len[%v] before decode", len(result))
	for _, value := range result {
		domainInfoLoad := &domainNodeSetGrpValue{}
		if err = json.Unmarshal(value, domainInfoLoad); err != nil {
			log.LogFatalf("action[loadNodeSets], unmarshal err:%v", err.Error())
			return err
		}
		log.LogInfof("action[loadNodeSetGrps] get result domainid [%v] domainInfoLoad id[%v],status[%v],ids[%v]",
			domainInfoLoad.DomainId, domainInfoLoad.ID, domainInfoLoad.Status, domainInfoLoad.NodeSetsIds)
		nsg := newNodeSetGrp(c)
		nsg.nodeSetsIds = domainInfoLoad.NodeSetsIds
		nsg.ID = domainInfoLoad.ID
		nsg.status = domainInfoLoad.Status
		nsg.domainId = domainInfoLoad.DomainId
		domainId := domainInfoLoad.DomainId

		var domainIndex int
		var ok bool
		var domainGrp *DomainNodeSetGrpManager
		if domainIndex, ok = c.domainManager.domainId2IndexMap[domainId]; !ok {
			domainGrp = newDomainNodeSetGrpManager()
			domainGrp.domainId = domainId
			c.domainManager.domainNodeSetGrpVec = append(c.domainManager.domainNodeSetGrpVec, domainGrp)
			domainIndex = len(c.domainManager.domainNodeSetGrpVec) - 1
			c.domainManager.domainId2IndexMap[domainId] = domainIndex
		}
		domainGrp = c.domainManager.domainNodeSetGrpVec[domainIndex]
		domainGrp.nodeSetGrpMap = append(domainGrp.nodeSetGrpMap, nsg)
		var j int
		for j = 0; j < len(domainInfoLoad.NodeSetsIds); j++ {
			domainGrp.nsId2NsGrpMap[domainInfoLoad.NodeSetsIds[j]] = len(domainGrp.nodeSetGrpMap) - 1
			log.LogInfof("action[loadNodeSetGrps] get result index[%v] nodesetid[%v] nodesetgrp index [%v]",
				domainInfoLoad.ID, domainInfoLoad.NodeSetsIds[j], domainInfoLoad.Status)
		}
		log.LogInfof("action[loadNodeSetGrps], nsgId[%v],status[%v]", nsg.ID, nsg.status)
	}
	return
}

func (c *Cluster) loadDataNodes() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(dataNodePrefix))
	if err != nil {
		err = fmt.Errorf("action[loadDataNodes],err:%v", err.Error())
		return err
	}

	for _, value := range result {
		dnv := &dataNodeValue{}
		if err = json.Unmarshal(value, dnv); err != nil {
			err = fmt.Errorf("action[loadDataNodes],value:%v,unmarshal err:%v", string(value), err)
			return
		}
		if dnv.ZoneName == "" {
			dnv.ZoneName = DefaultZoneName
		}
		dataNode := newDataNode(dnv.Addr, dnv.ZoneName, c.Name)
		dataNode.DpCntLimit = newDpCountLimiter(&c.cfg.MaxDpCntLimit)
		dataNode.ID = dnv.ID
		dataNode.NodeSetID = dnv.NodeSetID
		dataNode.RdOnly = dnv.RdOnly
		for _, disk := range dnv.DecommissionedDisks {
			dataNode.addDecommissionedDisk(disk)
		}
		dataNode.DecommissionStatus = dnv.DecommissionStatus
		dataNode.DecommissionDstAddr = dnv.DecommissionDstAddr
		dataNode.DecommissionRaftForce = dnv.DecommissionRaftForce
		dataNode.DecommissionLimit = dnv.DecommissionLimit
		dataNode.DecommissionRetry = dnv.DecommissionRetry
		dataNode.DecommissionCompleteTime = dnv.DecommissionCompleteTime
		dataNode.ToBeOffline = dnv.ToBeOffline
		dataNode.DecommissionDiskList = dnv.DecommissionDiskList
		dataNode.DecommissionDpTotal = dnv.DecommissionDpTotal
		olddn, ok := c.dataNodes.Load(dataNode.Addr)
		if ok {
			if olddn.(*DataNode).ID <= dataNode.ID {
				log.LogDebugf("action[loadDataNodes]: skip addr %v old %v current %v", dataNode.Addr, olddn.(*DataNode).ID, dataNode.ID)
				continue
			}
		}
		c.dataNodes.Store(dataNode.Addr, dataNode)
		log.LogInfof("action[loadDataNodes],dataNode[%v],dataNodeID[%v],zone[%v],ns[%v] DecommissionStatus [%v] "+
			"DecommissionDstAddr[%v] DecommissionRaftForce[%v] DecommissionDpTotal[%v] DecommissionLimit[%v]  DecommissionRetry[%v] "+
			"DecommissionCompleteTime [%v] ToBeOffline[%v]",
			dataNode.Addr, dataNode.ID, dnv.ZoneName, dnv.NodeSetID, dataNode.DecommissionStatus, dataNode.DecommissionDstAddr,
			dataNode.DecommissionRaftForce, dataNode.DecommissionDpTotal, dataNode.DecommissionLimit, dataNode.DecommissionRetry,
			time.Unix(dataNode.DecommissionCompleteTime, 0).Format("2006-01-02 15:04:05"),
			dataNode.ToBeOffline)
	}
	return
}

func (c *Cluster) loadMetaNodes() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(metaNodePrefix))
	if err != nil {
		err = fmt.Errorf("action[loadMetaNodes],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		mnv := &metaNodeValue{}
		if err = json.Unmarshal(value, mnv); err != nil {
			err = fmt.Errorf("action[loadMetaNodes],unmarshal err:%v", err.Error())
			return err
		}
		if mnv.ZoneName == "" {
			mnv.ZoneName = DefaultZoneName
		}
		metaNode := newMetaNode(mnv.Addr, mnv.ZoneName, c.Name)
		metaNode.ID = mnv.ID
		metaNode.NodeSetID = mnv.NodeSetID
		metaNode.RdOnly = mnv.RdOnly

		oldmn, ok := c.metaNodes.Load(metaNode.Addr)
		if ok {
			if oldmn.(*MetaNode).ID <= metaNode.ID {
				continue
			}
		}
		c.metaNodes.Store(metaNode.Addr, metaNode)
		log.LogInfof("action[loadMetaNodes],metaNode[%v], metaNodeID[%v],zone[%v],ns[%v]", metaNode.Addr, metaNode.ID, mnv.ZoneName, mnv.NodeSetID)
	}
	return
}

func (c *Cluster) loadVolsViews() (err error, volViews []*volValue) {
	result, err := c.fsm.store.SeekForPrefix([]byte(volPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadVols],err:%v", err.Error())
		return
	}
	for _, value := range result {
		var vv *volValue
		if vv, err = newVolValueFromBytes(value); err != nil {
			err = fmt.Errorf("action[loadVols],value:%v,unmarshal err:%v", string(value), err)
			return
		}

		volViews = append(volViews, vv)
		log.LogInfof("action[loadVols],vol[%v]", vv.Name)
	}
	return
}

func (c *Cluster) loadVols() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(volPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadVols],err:%v", err.Error())
		return err
	}
	for _, value := range result {
		var vv *volValue
		if vv, err = newVolValueFromBytes(value); err != nil {
			err = fmt.Errorf("action[loadVols],value:%v,unmarshal err:%v", string(value), err)
			return err
		}
		vol := newVolFromVolValue(vv)
		vol.Status = vv.Status

		if err = c.loadAclList(vol); err != nil {
			log.LogInfof("action[loadVols],vol[%v] load acl manager error %v", vol.Name, err)
			continue
		}

		if err = c.loadUidSpaceList(vol); err != nil {
			log.LogInfof("action[loadVols],vol[%v] load uid manager error %v", vol.Name, err)
			continue
		}

		if err = c.loadMultiVersion(vol); err != nil {
			log.LogInfof("action[loadVols],vol[%v] load ver manager error %v c %v", vol.Name, err, c)
			continue
		}

		c.putVol(vol)
		log.LogInfof("action[loadVols],vol[%v]", vol.Name)
		if vol.Forbidden && vol.Status == bsProto.VolStatusMarkDelete {
			c.delayDeleteVolsInfo = append(c.delayDeleteVolsInfo, &delayDeleteVolInfo{volName: vol.Name, authKey: vol.authKey, execTime: vol.DeleteExecTime, user: vol.user})
			log.LogInfof("action[loadDelayDeleteVols],vol[%v]", vol.Name)
		}
	}
	return
}

func (c *Cluster) loadMetaPartitions() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(metaPartitionPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadMetaPartitions],err:%v", err.Error())
		return err
	}

	for _, value := range result {
		mpv := &metaPartitionValue{}
		if err = json.Unmarshal(value, mpv); err != nil {
			err = fmt.Errorf("action[loadMetaPartitions],value:%v,unmarshal err:%v", string(value), err)
			return err
		}
		vol, err1 := c.getVol(mpv.VolName)
		if err1 != nil {
			log.LogErrorf("action[loadMetaPartitions] err:%v", err1.Error())
			continue
		}
		if vol.ID != mpv.VolID {
			Warn(c.Name, fmt.Sprintf("action[loadMetaPartitions] has duplicate vol[%v],vol.gridId[%v],mpv.VolID[%v]", mpv.VolName, vol.ID, mpv.VolID))
			continue
		}
		for i := 0; i < len(mpv.Peers); i++ {
			mn, ok := c.metaNodes.Load(mpv.Peers[i].Addr)
			if ok && mn.(*MetaNode).ID != mpv.Peers[i].ID {
				mpv.Peers[i].ID = mn.(*MetaNode).ID
			}
		}
		mp := newMetaPartition(mpv.PartitionID, mpv.Start, mpv.End, vol.mpReplicaNum, vol.Name, mpv.VolID, 0)
		mp.setHosts(strings.Split(mpv.Hosts, underlineSeparator))
		mp.setPeers(mpv.Peers)
		mp.OfflinePeerID = mpv.OfflinePeerID
		mp.IsRecover = mpv.IsRecover
		vol.addMetaPartition(mp)
		c.addBadMetaParitionIdMap(mp)
		log.LogInfof("action[loadMetaPartitions],vol[%v],mp[%v]", vol.Name, mp.PartitionID)
	}
	return
}

func (c *Cluster) addBadMetaParitionIdMap(mp *MetaPartition) {
	if !mp.IsRecover {
		return
	}

	c.putBadMetaPartitions(mp.Hosts[0], mp.PartitionID)
}

func (c *Cluster) loadDataPartitions() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(dataPartitionPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadDataPartitions],err:%v", err.Error())
		return err
	}
	for _, value := range result {

		dpv := &dataPartitionValue{}
		if err = json.Unmarshal(value, dpv); err != nil {
			err = fmt.Errorf("action[loadDataPartitions],value:%v,unmarshal err:%v", string(value), err)
			return err
		}
		vol, err1 := c.getVol(dpv.VolName)
		if err1 != nil {
			log.LogErrorf("action[loadDataPartitions] err:%v %v", dpv.VolName, err1.Error())
			continue
		}
		if vol.ID != dpv.VolID {
			Warn(c.Name, fmt.Sprintf("action[loadDataPartitions] has duplicate vol[%v],vol.gridId[%v],mpv.VolID[%v]", dpv.VolName, vol.ID, dpv.VolID))
			continue
		}

		dp := dpv.Restore(c)
		vol.dataPartitions.put(dp)
		c.addBadDataPartitionIdMap(dp)
		// add to nodeset decommission list
		go dp.addToDecommissionList(c)
		log.LogInfof("action[loadDataPartitions],vol[%v],dp[%v] ", vol.Name, dp.PartitionID)
	}
	return
}

func (c *Cluster) loadQuota() (err error) {
	c.volMutex.RLock()
	defer c.volMutex.RUnlock()
	for name, vol := range c.vols {
		if err = vol.loadQuotaManager(c); err != nil {
			log.LogErrorf("loadQuota loadQuotaManager vol [%v] fail err [%v]", name, err.Error())
			return err
		}
	}
	return
}

// load s3api qos info to memory cache
func (c *Cluster) loadS3ApiQosInfo() (err error) {
	keyPrefix := S3QoSPrefix
	result, err := c.fsm.store.SeekForPrefix([]byte(keyPrefix))
	if err != nil {
		err = fmt.Errorf("loadS3ApiQosInfo get failed, err [%v]", err)
		return err
	}

	for key, value := range result {
		s3qosQuota, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return err
		}
		log.LogDebugf("loadS3ApiQosInfo key[%v] value[%v]", key, s3qosQuota)
		c.S3ApiQosQuota.Store(key, s3qosQuota)
	}
	return
}

func (c *Cluster) addBadDataPartitionIdMap(dp *DataPartition) {
	if !dp.IsDecommissionRunning() {
		return
	}
	c.putBadDataPartitionIDsByDiskPath(dp.DecommissionSrcDiskPath, dp.DecommissionSrcAddr, dp.PartitionID)
}

func (c *Cluster) syncAddDecommissionDisk(disk *DecommissionDisk) (err error) {
	return c.syncPutDecommissionDiskInfo(opSyncAddDecommissionDisk, disk)
}

func (c *Cluster) syncDeleteDecommissionDisk(disk *DecommissionDisk) (err error) {
	return c.syncPutDecommissionDiskInfo(opSyncDeleteDecommissionDisk, disk)
}

func (c *Cluster) syncUpdateDecommissionDisk(disk *DecommissionDisk) (err error) {
	return c.syncPutDecommissionDiskInfo(opSyncUpdateDecommissionDisk, disk)
}

func (c *Cluster) syncPutDecommissionDiskInfo(opType uint32, disk *DecommissionDisk) (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opType
	metadata.K = DecommissionDiskPrefix + disk.SrcAddr + keySeparator + disk.DiskPath
	ddv := newDecommissionDiskValue(disk)
	metadata.V, err = json.Marshal(ddv)
	if err != nil {
		return errors.New(err.Error())
	}
	return c.submit(metadata)
}

type decommissionDiskValue struct {
	SrcAddr                  string
	DstAddr                  string
	DiskPath                 string
	DecommissionStatus       uint32
	DecommissionRaftForce    bool
	DecommissionRetry        uint8
	DecommissionDpTotal      int
	DecommissionTerm         uint64
	Type                     uint32
	DecommissionCompleteTime int64
	DecommissionLimit        int
}

func newDecommissionDiskValue(disk *DecommissionDisk) *decommissionDiskValue {
	return &decommissionDiskValue{
		SrcAddr:                  disk.SrcAddr,
		DstAddr:                  disk.DstAddr,
		DiskPath:                 disk.DiskPath,
		DecommissionRetry:        disk.DecommissionRetry,
		DecommissionStatus:       atomic.LoadUint32(&disk.DecommissionStatus),
		DecommissionRaftForce:    disk.DecommissionRaftForce,
		DecommissionDpTotal:      disk.DecommissionDpTotal,
		DecommissionTerm:         disk.DecommissionTerm,
		Type:                     disk.Type,
		DecommissionCompleteTime: disk.DecommissionCompleteTime,
		DecommissionLimit:        disk.DecommissionDpCount,
	}
}

func (ddv *decommissionDiskValue) Restore() *DecommissionDisk {
	return &DecommissionDisk{
		SrcAddr:                  ddv.SrcAddr,
		DstAddr:                  ddv.DstAddr,
		DiskPath:                 ddv.DiskPath,
		DecommissionRetry:        ddv.DecommissionRetry,
		DecommissionStatus:       ddv.DecommissionStatus,
		DecommissionRaftForce:    ddv.DecommissionRaftForce,
		DecommissionDpTotal:      ddv.DecommissionDpTotal,
		DecommissionTerm:         ddv.DecommissionTerm,
		Type:                     ddv.Type,
		DecommissionCompleteTime: ddv.DecommissionCompleteTime,
		DecommissionDpCount:      ddv.DecommissionLimit,
	}
}

func (c *Cluster) loadDecommissionDiskList() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(DecommissionDiskPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadDataPartitions],err:%v", err.Error())
		return err
	}
	for _, value := range result {

		ddv := &decommissionDiskValue{}
		if err = json.Unmarshal(value, ddv); err != nil {
			err = fmt.Errorf("action[loadDecommissionDiskList],value:%v,unmarshal err:%v", string(value), err)
			return err
		}

		dd := ddv.Restore()
		c.DecommissionDisks.Store(dd.GenerateKey(), dd)
		log.LogInfof("action[loadDecommissionDiskList],decommissionDisk[%v] type %v dst[%v] status[%v] raftForce[%v]"+
			"dpTotal[%v] term[%v]",
			dd.GenerateKey(), dd.Type, dd.DstAddr, dd.GetDecommissionStatus(), dd.DecommissionRaftForce,
			dd.DecommissionDpTotal, dd.DecommissionTerm)
		c.addDecommissionDiskToNodeset(dd)
	}
	return
}

func (c *Cluster) startDecommissionListTraverse() (err error) {
	zones := c.t.getAllZones()
	log.LogDebugf("startDecommissionListTraverse zones len %v", len(zones))
	for _, zone := range zones {
		log.LogDebugf("startDecommissionListTraverse zone %v ", zone.name)
		err = zone.startDecommissionListTraverse(c)
		if err != nil {
			return
		}
	}
	return
}

func (c *Cluster) syncAddLcNode(ln *LcNode) (err error) {
	return c.syncPutLcNodeInfo(opSyncAddLcNode, ln)
}

func (c *Cluster) syncDeleteLcNode(ln *LcNode) (err error) {
	return c.syncPutLcNodeInfo(opSyncDeleteLcNode, ln)
}

func (c *Cluster) syncUpdateLcNode(ln *LcNode) (err error) {
	return c.syncPutLcNodeInfo(opSyncUpdateLcNode, ln)
}

func (c *Cluster) syncPutLcNodeInfo(opType uint32, ln *LcNode) (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opType
	metadata.K = lcNodePrefix + ln.Addr
	lnv := newLcNodeValue(ln)
	metadata.V, err = json.Marshal(lnv)
	if err != nil {
		return errors.New(err.Error())
	}
	return c.submit(metadata)
}

type lcNodeValue struct {
	ID   uint64
	Addr string
}

func newLcNodeValue(lcNode *LcNode) *lcNodeValue {
	return &lcNodeValue{
		ID:   lcNode.ID,
		Addr: lcNode.Addr,
	}
}

func (c *Cluster) loadLcNodes() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(lcNodePrefix))
	if err != nil {
		err = fmt.Errorf("action[loadLcNodes],err:%v", err.Error())
		return err
	}
	log.LogInfof("action[loadLcNodes], result count %v", len(result))
	for _, value := range result {
		lnv := &lcNodeValue{}
		if err = json.Unmarshal(value, lnv); err != nil {
			err = fmt.Errorf("action[loadLcNodes],value:%v,unmarshal err:%v", string(value), err)
			return
		}
		log.LogInfof("action[loadLcNodes], load lcNode[%v], lcNodeID[%v]", lnv.Addr, lnv.ID)
		lcNode := newLcNode(lnv.Addr, c.Name)
		lcNode.ID = lnv.ID
		c.lcNodes.Store(lcNode.Addr, lcNode)
		log.LogInfof("action[loadLcNodes], store lcNode[%v], lcNodeID[%v]", lcNode.Addr, lcNode.ID)
	}
	return
}

func (c *Cluster) syncAddLcConf(lcConf *bsProto.LcConfiguration) (err error) {
	return c.syncPutLcConfInfo(opSyncAddLcConf, lcConf)
}

func (c *Cluster) syncDeleteLcConf(lcConf *bsProto.LcConfiguration) (err error) {
	return c.syncPutLcConfInfo(opSyncDeleteLcConf, lcConf)
}

func (c *Cluster) syncUpdateLcConf(lcConf *bsProto.LcConfiguration) (err error) {
	return c.syncPutLcConfInfo(opSyncUpdateLcConf, lcConf)
}

func (c *Cluster) syncPutLcConfInfo(opType uint32, lcConf *bsProto.LcConfiguration) (err error) {
	metadata := new(RaftCmd)
	metadata.Op = opType
	metadata.K = lcConfPrefix + lcConf.VolName
	metadata.V, err = json.Marshal(lcConf)
	if err != nil {
		return errors.New(err.Error())
	}
	return c.submit(metadata)
}

func (c *Cluster) loadLcConfs() (err error) {
	result, err := c.fsm.store.SeekForPrefix([]byte(lcConfPrefix))
	if err != nil {
		err = fmt.Errorf("action[loadLcConfs],err:%v", err.Error())
		return err
	}

	for _, value := range result {
		lcConf := &bsProto.LcConfiguration{}
		if err = json.Unmarshal(value, lcConf); err != nil {
			err = fmt.Errorf("action[loadLcConfs],value:%v,unmarshal err:%v", string(value), err)
			return
		}
		_ = c.lcMgr.SetS3BucketLifecycle(lcConf)
		log.LogInfof("action[loadLcConfs],vol[%v]", lcConf.VolName)
	}
	return
}
