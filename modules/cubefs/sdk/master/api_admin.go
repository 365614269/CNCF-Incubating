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
	"net/http"
	"strconv"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/log"
)

type AdminAPI struct {
	mc *MasterClient
}

func (api *AdminAPI) GetCluster() (cv *proto.ClusterView, err error) {
	var buf []byte

	var request = newAPIRequest(http.MethodGet, proto.AdminGetCluster)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}

	cv = &proto.ClusterView{}
	if err = json.Unmarshal(buf, &cv); err != nil {
		return
	}

	return
}

func (api *AdminAPI) GetClusterNodeInfo() (cn *proto.ClusterNodeInfo, err error) {
	var buf []byte

	var request = newAPIRequest(http.MethodGet, proto.AdminGetNodeInfo)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}

	cn = &proto.ClusterNodeInfo{}
	if err = json.Unmarshal(buf, &cn); err != nil {
		return
	}

	return
}

func (api *AdminAPI) GetClusterIP() (cp *proto.ClusterIP, err error) {
	var buf []byte

	var request = newAPIRequest(http.MethodGet, proto.AdminGetIP)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}

	cp = &proto.ClusterIP{}
	if err = json.Unmarshal(buf, &cp); err != nil {
		return
	}

	return
}

func (api *AdminAPI) GetClusterStat() (cs *proto.ClusterStatInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminClusterStat)
	request.addHeader("isTimeOut", "false")
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	cs = &proto.ClusterStatInfo{}
	if err = json.Unmarshal(buf, &cs); err != nil {
		return
	}
	return
}
func (api *AdminAPI) ListZones() (zoneViews []*proto.ZoneView, err error) {
	var request = newAPIRequest(http.MethodGet, proto.GetAllZones)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	zoneViews = make([]*proto.ZoneView, 0)
	if err = json.Unmarshal(buf, &zoneViews); err != nil {
		return
	}
	return
}
func (api *AdminAPI) ListNodeSets(zoneName string) (nodeSetStats []*proto.NodeSetStat, err error) {
	var request = newAPIRequest(http.MethodGet, proto.GetAllNodeSets)
	if zoneName != "" {
		request.addParam("zoneName", zoneName)
	}
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	nodeSetStats = make([]*proto.NodeSetStat, 0)
	if err = json.Unmarshal(buf, &nodeSetStats); err != nil {
		return
	}
	return
}
func (api *AdminAPI) GetNodeSet(nodeSetId string) (nodeSetStatInfo *proto.NodeSetStatInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.GetNodeSet)
	request.addParam("nodesetId", nodeSetId)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	nodeSetStatInfo = &proto.NodeSetStatInfo{}
	if err = json.Unmarshal(buf, &nodeSetStatInfo); err != nil {
		return
	}
	return
}

func (api *AdminAPI) UpdateNodeSet(nodeSetId string, dataNodeSelector string, metaNodeSelector string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.UpdateNodeSet)
	request.addParam("nodesetId", nodeSetId)
	request.addParam("dataNodeSelector", dataNodeSelector)
	request.addParam("metaNodeSelector", metaNodeSelector)
	if _, err = api.mc.serveRequest(request); err != nil {
		return err
	}
	return nil
}

func (api *AdminAPI) UpdateZone(name string, enable bool, dataNodesetSelector string, metaNodesetSelector string, dataNodeSelector string, metaNodeSelector string) (err error) {
	var request = newAPIRequest(http.MethodPost, proto.UpdateZone)
	request.params["name"] = name
	request.params["enable"] = strconv.FormatBool(enable)
	request.params["dataNodesetSelector"] = dataNodesetSelector
	request.params["metaNodesetSelector"] = metaNodesetSelector
	request.params["dataNodeSelector"] = dataNodeSelector
	request.params["metaNodeSelector"] = metaNodeSelector
	if _, err = api.mc.serveRequest(request); err != nil {
		return err
	}
	return nil
}

func (api *AdminAPI) Topo() (topo *proto.TopologyView, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.GetTopologyView)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	topo = &proto.TopologyView{}
	if err = json.Unmarshal(buf, &topo); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetDataPartition(volName string, partitionID uint64) (partition *proto.DataPartitionInfo, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminGetDataPartition)
	request.addParam("id", fmt.Sprintf("%v", partitionID))
	request.addParam("name", volName)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	partition = &proto.DataPartitionInfo{}
	if err = json.Unmarshal(buf, &partition); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetDataPartitionById(partitionID uint64) (partition *proto.DataPartitionInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetDataPartition)
	request.addParam("id", strconv.Itoa(int(partitionID)))
	var data []byte
	if data, err = api.mc.serveRequest(request); err != nil {
		return
	}
	partition = &proto.DataPartitionInfo{}
	if err = json.Unmarshal(data, partition); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DiagnoseDataPartition(ignoreDiscardDp bool) (diagnosis *proto.DataPartitionDiagnosis, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminDiagnoseDataPartition)
	request.addParam("ignoreDiscard", strconv.FormatBool(ignoreDiscardDp))
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	diagnosis = &proto.DataPartitionDiagnosis{}
	if err = json.Unmarshal(buf, &diagnosis); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DiagnoseMetaPartition() (diagnosis *proto.MetaPartitionDiagnosis, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminDiagnoseMetaPartition)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	diagnosis = &proto.MetaPartitionDiagnosis{}
	if err = json.Unmarshal(buf, &diagnosis); err != nil {
		return
	}
	return
}

func (api *AdminAPI) LoadDataPartition(volName string, partitionID uint64, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminLoadDataPartition)
	request.addParam("id", strconv.Itoa(int(partitionID)))
	request.addParam("name", volName)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreateDataPartition(volName string, count int, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminCreateDataPartition)
	request.addParam("name", volName)
	request.addParam("count", strconv.Itoa(count))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DecommissionDataPartition(dataPartitionID uint64, nodeAddr string, raftForce bool, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDecommissionDataPartition)
	request.addParam("id", strconv.FormatUint(dataPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("raftForceDel", strconv.FormatBool(raftForce))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DecommissionMetaPartition(metaPartitionID uint64, nodeAddr, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDecommissionMetaPartition)
	request.addParam("id", strconv.FormatUint(metaPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DeleteDataReplica(dataPartitionID uint64, nodeAddr, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDeleteDataReplica)
	request.addParam("id", strconv.FormatUint(dataPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) AddDataReplica(dataPartitionID uint64, nodeAddr, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminAddDataReplica)
	request.addParam("id", strconv.FormatUint(dataPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DeleteMetaReplica(metaPartitionID uint64, nodeAddr string, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDeleteMetaReplica)
	request.addParam("id", strconv.FormatUint(metaPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) AddMetaReplica(metaPartitionID uint64, nodeAddr string, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminAddMetaReplica)
	request.addParam("id", strconv.FormatUint(metaPartitionID, 10))
	request.addParam("addr", nodeAddr)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DeleteVolume(volName, authKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDeleteVol)
	request.addParam("name", volName)
	request.addParam("authKey", authKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DeleteVolumeWithAuthNode(volName, authKey, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDeleteVol)
	request.addParam("name", volName)
	request.addParam("authKey", authKey)
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) UpdateVolume(
	vv *proto.SimpleVolView,
	txTimeout int64,
	txMask string,
	txForceReset bool,
	txConflictRetryNum int64,
	txConflictRetryInterval int64,
	txOpLimit int,
	clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminUpdateVol)
	request.addParam("name", vv.Name)
	request.addParam("description", vv.Description)
	request.addParam("authKey", util.CalcAuthKey(vv.Owner))
	request.addParam("zoneName", vv.ZoneName)
	request.addParam("capacity", strconv.FormatUint(vv.Capacity, 10))
	request.addParam("followerRead", strconv.FormatBool(vv.FollowerRead))
	request.addParam("ebsBlkSize", strconv.Itoa(vv.ObjBlockSize))
	request.addParam("cacheCap", strconv.FormatUint(vv.CacheCapacity, 10))
	request.addParam("cacheAction", strconv.Itoa(vv.CacheAction))
	request.addParam("cacheThreshold", strconv.Itoa(vv.CacheThreshold))
	request.addParam("cacheTTL", strconv.Itoa(vv.CacheTtl))
	request.addParam("cacheHighWater", strconv.Itoa(vv.CacheHighWater))
	request.addParam("cacheLowWater", strconv.Itoa(vv.CacheLowWater))
	request.addParam("cacheLRUInterval", strconv.Itoa(vv.CacheLruInterval))
	request.addParam("cacheRuleKey", vv.CacheRule)
	request.addParam("dpReadOnlyWhenVolFull", strconv.FormatBool(vv.DpReadOnlyWhenVolFull))
	request.addParam("replicaNum", strconv.FormatUint(uint64(vv.DpReplicaNum), 10))
	request.addParam("enableQuota", strconv.FormatBool(vv.EnableQuota))
	request.addParam("deleteLockTime", strconv.FormatInt(vv.DeleteLockTime, 10))
	request.addParam("clientIDKey", clientIDKey)

	if txMask != "" {
		request.addParam("enableTxMask", txMask)
		request.addParam("txForceReset", strconv.FormatBool(txForceReset))
	}

	if txTimeout > 0 {
		request.addParam("txTimeout", strconv.FormatInt(txTimeout, 10))
	}

	if txConflictRetryNum > 0 {
		request.addParam("txConflictRetryNum", strconv.FormatInt(txConflictRetryNum, 10))
	}

	if txOpLimit > 0 {
		request.addParam("txOpLimit", strconv.Itoa(txOpLimit))
	}

	if txConflictRetryInterval > 0 {
		request.addParam("txConflictRetryInterval", strconv.FormatInt(txConflictRetryInterval, 10))
	}

	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) PutDataPartitions(volName string, dpsView []byte) (err error) {
	var request = newAPIRequest(http.MethodPost, proto.AdminPutDataPartitions)
	request.addParam("name", volName)
	request.addBody(dpsView)

	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) VolShrink(volName string, capacity uint64, authKey, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminVolShrink)
	request.addParam("name", volName)
	request.addParam("authKey", authKey)
	request.addParam("capacity", strconv.FormatUint(capacity, 10))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) VolExpand(volName string, capacity uint64, authKey, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminVolExpand)
	request.addParam("name", volName)
	request.addParam("authKey", authKey)
	request.addParam("capacity", strconv.FormatUint(capacity, 10))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreateVolName(volName, owner string, capacity uint64, deleteLockTime int64, crossZone, normalZonesFirst bool, business string,
	mpCount, dpCount, replicaNum, dpSize, volType int, followerRead bool, zoneName, cacheRuleKey string, ebsBlkSize,
	cacheCapacity, cacheAction, cacheThreshold, cacheTTL, cacheHighWater, cacheLowWater, cacheLRUInterval int,
	dpReadOnlyWhenVolFull bool, txMask string, txTimeout uint32, txConflictRetryNum int64, txConflictRetryInterval int64, optEnableQuota string,
	clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminCreateVol)
	request.addParam("name", volName)
	request.addParam("owner", owner)
	request.addParam("capacity", strconv.FormatUint(capacity, 10))
	request.addParam("deleteLockTime", strconv.FormatInt(deleteLockTime, 10))
	request.addParam("crossZone", strconv.FormatBool(crossZone))
	request.addParam("normalZonesFirst", strconv.FormatBool(normalZonesFirst))
	request.addParam("description", business)
	request.addParam("mpCount", strconv.Itoa(mpCount))
	request.addParam("dpCount", strconv.Itoa(dpCount))
	request.addParam("replicaNum", strconv.Itoa(replicaNum))
	request.addParam("dpSize", strconv.Itoa(dpSize))
	request.addParam("volType", strconv.Itoa(volType))
	request.addParam("followerRead", strconv.FormatBool(followerRead))
	request.addParam("zoneName", zoneName)
	request.addParam("cacheRuleKey", cacheRuleKey)
	request.addParam("ebsBlkSize", strconv.Itoa(ebsBlkSize))
	request.addParam("cacheCap", strconv.Itoa(cacheCapacity))
	request.addParam("cacheAction", strconv.Itoa(cacheAction))
	request.addParam("cacheThreshold", strconv.Itoa(cacheThreshold))
	request.addParam("cacheTTL", strconv.Itoa(cacheTTL))
	request.addParam("cacheHighWater", strconv.Itoa(cacheHighWater))
	request.addParam("cacheLowWater", strconv.Itoa(cacheLowWater))
	request.addParam("cacheLRUInterval", strconv.Itoa(cacheLRUInterval))
	request.addParam("dpReadOnlyWhenVolFull", strconv.FormatBool(dpReadOnlyWhenVolFull))
	request.addParam("enableQuota", optEnableQuota)
	request.addParam("clientIDKey", clientIDKey)
	if txMask != "" {
		request.addParam("enableTxMask", txMask)
	}

	if txTimeout > 0 {
		request.addParam("txTimeout", strconv.FormatUint(uint64(txTimeout), 10))
	}

	if txConflictRetryNum > 0 {
		request.addParam("txConflictRetryNum", strconv.FormatInt(txConflictRetryNum, 10))
	}

	if txConflictRetryInterval > 0 {
		request.addParam("txConflictRetryInterval", strconv.FormatInt(txConflictRetryInterval, 10))
	}

	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreateDefaultVolume(volName, owner string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminCreateVol)
	request.addParam("name", volName)
	request.addParam("owner", owner)
	request.addParam("capacity", "10")
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetVolumeSimpleInfo(volName string) (vv *proto.SimpleVolView, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetVol)
	request.addParam("name", volName)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	vv = &proto.SimpleVolView{}
	if err = json.Unmarshal(buf, &vv); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetVolumeForbidden(volName string, forbidden bool) (err error) {
	request := newAPIRequest(http.MethodPost, proto.AdminVolForbidden)
	request.addParam("name", volName)
	request.addParam("forbidden", strconv.FormatBool(forbidden))
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetVolumeAuditLog(volName string, enable bool) (err error) {
	request := newAPIRequest(http.MethodPost, proto.AdminVolEnableAuditLog)
	request.addParam("name", volName)
	request.addParam("enable", strconv.FormatBool(enable))
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetMonitorPushAddr() (addr string, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetMonitorPushAddr)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	err = json.Unmarshal(buf, &addr)
	return
}

func (api *AdminAPI) UploadFlowInfo(volName string,
	flowInfo *proto.ClientReportLimitInfo) (vv *proto.LimitRsp2Client, err error) {
	var request = newAPIRequest(http.MethodGet, proto.QosUpload)
	request.addParam("name", volName)
	if flowInfo == nil {
		return nil, fmt.Errorf("flowinfo is nil")
	}

	request.addParam("qosEnable", "true")
	var encoded []byte
	if encoded, err = json.Marshal(flowInfo); err != nil {
		log.LogInfof("action[GetVolumeSimpleInfoWithFlowInfo] flowinfo failed")
		return
	}

	request.addBody(encoded)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}

	vv = &proto.LimitRsp2Client{}
	if err = json.Unmarshal(buf, &vv); err != nil {
		return
	}
	log.LogInfof("action[UploadFlowInfo] enable %v", vv.Enable)
	return
}

func (api *AdminAPI) GetVolumeSimpleInfoWithFlowInfo(volName string) (vv *proto.SimpleVolView, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetVol)
	request.addParam("name", volName)
	request.addParam("init", "true")

	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	vv = &proto.SimpleVolView{}
	if err = json.Unmarshal(buf, &vv); err != nil {
		return
	}
	return
}

// access control list
func (api *AdminAPI) CheckACL() (ci *proto.ClusterInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminACL)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	ci = &proto.ClusterInfo{}
	if err = json.Unmarshal(buf, &ci); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetClusterInfo() (ci *proto.ClusterInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetIP)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	ci = &proto.ClusterInfo{}
	if err = json.Unmarshal(buf, &ci); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetVerInfo(volName string) (ci *proto.VolumeVerInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetVolVer)
	request.addParam("name", volName)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	ci = &proto.VolumeVerInfo{}
	if err = json.Unmarshal(buf, &ci); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreateMetaPartition(volName string, inodeStart uint64, clientIDKey string) (err error) {

	var request = newAPIRequest(http.MethodGet, proto.AdminCreateMetaPartition)
	request.addParam("name", volName)
	request.addParam("start", strconv.FormatUint(inodeStart, 10))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) ListVols(keywords string) (volsInfo []*proto.VolInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminListVols)
	request.addParam("keywords", keywords)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	volsInfo = make([]*proto.VolInfo, 0)
	if err = json.Unmarshal(buf, &volsInfo); err != nil {
		return
	}
	return
}

func (api *AdminAPI) IsFreezeCluster(isFreeze bool, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminClusterFreeze)
	request.addParam("enable", strconv.FormatBool(isFreeze))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetForbidMpDecommission(disable bool) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminClusterForbidMpDecommission)
	request.addParam("enable", strconv.FormatBool(disable))
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetMetaNodeThreshold(threshold float64, clientIDKey string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminSetMetaNodeThreshold)
	request.addParam("threshold", strconv.FormatFloat(threshold, 'f', 6, 64))
	request.addParam("clientIDKey", clientIDKey)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetClusterParas(batchCount, markDeleteRate, deleteWorkerSleepMs, autoRepairRate, loadFactor, maxDpCntLimit, clientIDKey string,
	dataNodesetSelector, metaNodesetSelector, dataNodeSelector, metaNodeSelector string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminSetNodeInfo)
	request.addParam("batchCount", batchCount)
	request.addParam("markDeleteRate", markDeleteRate)
	request.addParam("deleteWorkerSleepMs", deleteWorkerSleepMs)
	request.addParam("autoRepairRate", autoRepairRate)
	request.addParam("loadFactor", loadFactor)
	request.addParam("maxDpCntLimit", maxDpCntLimit)
	request.addParam("clientIDKey", clientIDKey)

	request.addParam("dataNodesetSelector", dataNodesetSelector)
	request.addParam("metaNodesetSelector", metaNodesetSelector)
	request.addParam("dataNodeSelector", dataNodeSelector)
	request.addParam("metaNodeSelector", metaNodeSelector)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetClusterParas() (delParas map[string]string, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminGetNodeInfo)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	delParas = make(map[string]string)
	if err = json.Unmarshal(buf, &delParas); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreatePreLoadDataPartition(volName string, count int, capacity, ttl uint64, zongs string) (view *proto.DataPartitionsView, err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminCreatePreLoadDataPartition)
	request.addParam("name", volName)
	request.addParam("replicaNum", strconv.Itoa(count))
	request.addParam("capacity", strconv.FormatUint(capacity, 10))
	request.addParam("cacheTTL", strconv.FormatUint(ttl, 10))
	request.addParam("zoneName", zongs)
	var data []byte
	if data, err = api.mc.serveRequest(request); err != nil {
		return
	}
	view = &proto.DataPartitionsView{}
	if err = json.Unmarshal(data, view); err != nil {
		return
	}
	return
}

func (api *AdminAPI) ListQuota(volName string) (quotaInfo []*proto.QuotaInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaList)
	resp := &proto.ListMasterQuotaResponse{}
	request.addParam("name", volName)
	var data []byte
	if data, err = api.mc.serveRequest(request); err != nil {
		log.LogErrorf("action[ListQuota] fail. %v", err)
		return
	}
	if err = json.Unmarshal(data, resp); err != nil {
		log.LogErrorf("action[ListQuota] fail. %v", err)
		return
	}
	quotaInfo = resp.Quotas
	log.LogInfof("action[ListQuota] success.")
	return quotaInfo, err
}

func (api *AdminAPI) CreateQuota(volName string, quotaPathInfos []proto.QuotaPathInfo, maxFiles uint64, maxBytes uint64) (quotaId uint32, err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaCreate)
	request.addParam("name", volName)
	request.addParam("maxFiles", strconv.FormatUint(maxFiles, 10))
	request.addParam("maxBytes", strconv.FormatUint(maxBytes, 10))
	var value []byte
	if value, err = json.Marshal(&quotaPathInfos); err != nil {
		log.LogErrorf("action[CreateQuota] fail. %v", err)
		return
	}
	request.addBody(value)
	var data []byte
	if data, err = api.mc.serveRequest(request); err != nil {
		log.LogErrorf("action[CreateQuota] fail. %v", err)
		return
	}
	if err = json.Unmarshal(data, &quotaId); err != nil {
		log.LogErrorf("action[CreateQuota] fail. %v", err)
		return
	}
	log.LogInfof("action[CreateQuota] success.")
	return
}

func (api *AdminAPI) UpdateQuota(volName string, quotaId string, maxFiles uint64, maxBytes uint64) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaUpdate)
	request.addParam("name", volName)
	request.addParam("quotaId", quotaId)
	request.addParam("maxFiles", strconv.FormatUint(maxFiles, 10))
	request.addParam("maxBytes", strconv.FormatUint(maxBytes, 10))
	if _, err = api.mc.serveRequest(request); err != nil {
		log.LogErrorf("action[UpdateQuota] fail. %v", err)
		return
	}
	log.LogInfof("action[UpdateQuota] success.")
	return nil
}

func (api *AdminAPI) DeleteQuota(volName string, quotaId string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaDelete)
	request.addParam("name", volName)
	request.addParam("quotaId", quotaId)

	if _, err = api.mc.serveRequest(request); err != nil {
		log.LogErrorf("action[DeleteQuota] fail. %v", err)
		return
	}
	log.LogInfo("action[DeleteQuota] success.")
	return nil
}

func (api *AdminAPI) GetQuota(volName string, quotaId string) (quotaInfo *proto.QuotaInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaGet)
	request.addParam("name", volName)
	request.addParam("quotaId", quotaId)
	var data []byte
	if data, err = api.mc.serveRequest(request); err != nil {
		log.LogErrorf("action[GetQuota] fail. %v", err)
		return
	}
	info := &proto.QuotaInfo{}
	if err = json.Unmarshal(data, info); err != nil {
		log.LogErrorf("action[GetQuota] fail. %v", err)
		return
	}
	quotaInfo = info
	log.LogInfof("action[GetQuota] %v success.", *quotaInfo)
	return quotaInfo, err
}

func (api *AdminAPI) QueryBadDisks() (badDisks *proto.BadDiskInfos, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.QueryBadDisks)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	badDisks = &proto.BadDiskInfos{}
	if err = json.Unmarshal(buf, &badDisks); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DecommissionDisk(addr string, disk string) (err error) {
	request := newAPIRequest(http.MethodPost, proto.DecommissionDisk)
	request.params["addr"] = addr
	request.params["disk"] = disk
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) RecommissionDisk(addr string, disk string) (err error) {
	request := newAPIRequest(http.MethodPost, proto.RecommissionDisk)
	request.params["addr"] = addr
	request.params["disk"] = disk
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) QueryDecommissionDiskProgress(addr string, disk string) (progress *proto.DecommissionProgress, err error) {
	var data []byte
	request := newAPIRequest(http.MethodPost, proto.QueryDiskDecoProgress)
	request.params["addr"] = addr
	request.params["disk"] = disk
	if data, err = api.mc.serveRequest(request); err != nil {
		return
	}
	progress = &proto.DecommissionProgress{}
	if err = json.Unmarshal(data, progress); err != nil {
		return
	}
	return
}

func (api *AdminAPI) ListQuotaAll() (volsInfo []*proto.VolInfo, err error) {
	var request = newAPIRequest(http.MethodGet, proto.QuotaListAll)
	var data []byte

	if data, err = api.mc.serveRequest(request); err != nil {
		return
	}

	volsInfo = make([]*proto.VolInfo, 0)
	if err = json.Unmarshal(data, &volsInfo); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetDiscardDataPartition() (DiscardDpInfos *proto.DiscardDataPartitionInfos, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminGetDiscardDp)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	DiscardDpInfos = &proto.DiscardDataPartitionInfos{}
	if err = json.Unmarshal(buf, &DiscardDpInfos); err != nil {
		return
	}
	return
}

func (api *AdminAPI) DeleteVersion(volName string, verSeq string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.AdminDelVersion)
	request.addParam("name", volName)
	request.addParam("verSeq", verSeq)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) SetStrategy(volName string, periodic string, count string, enable string, force string) (err error) {

	var request = newAPIRequest(http.MethodGet, proto.AdminSetVerStrategy)
	request.addParam("name", volName)
	request.addParam("periodic", periodic)
	request.addParam("count", count)
	request.addParam("enable", enable)
	request.addParam("force", force)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) CreateVersion(volName string) (ver *proto.VolVersionInfo, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminCreateVersion)
	request.addParam("name", volName)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	ver = &proto.VolVersionInfo{}
	if err = json.Unmarshal(buf, ver); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetLatestVer(volName string) (ver *proto.VolVersionInfo, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminGetVersionInfo)
	request.addParam("name", volName)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	ver = &proto.VolVersionInfo{}
	if err = json.Unmarshal(buf, ver); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetVerList(volName string) (verList *proto.VolVersionInfoList, err error) {
	var buf []byte
	var request = newAPIRequest(http.MethodGet, proto.AdminGetAllVersionInfo)
	request.addParam("name", volName)
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	verList = &proto.VolVersionInfoList{}
	if err = json.Unmarshal(buf, verList); err != nil {
		return
	}
	log.LogDebugf("GetVerList. vol %v verList %v", volName, verList)
	for _, info := range verList.VerList {
		log.LogDebugf("GetVerList. vol %v verList %v", volName, info)
	}
	return
}

func (api *AdminAPI) SetBucketLifecycle(req *proto.LcConfiguration) (err error) {
	var request = newAPIRequest(http.MethodPost, proto.SetBucketLifecycle)
	var encoded []byte
	if encoded, err = json.Marshal(req); err != nil {
		return
	}
	request.addBody(encoded)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}
func (api *AdminAPI) GetBucketLifecycle(volume string) (lcConf *proto.LcConfiguration, err error) {
	var request = newAPIRequest(http.MethodGet, proto.GetBucketLifecycle)
	request.addParam("name", volume)
	var buf []byte
	if buf, err = api.mc.serveRequest(request); err != nil {
		return
	}
	lcConf = &proto.LcConfiguration{}
	if err = json.Unmarshal(buf, &lcConf); err != nil {
		return
	}
	return
}
func (api *AdminAPI) DelBucketLifecycle(volume string) (err error) {
	var request = newAPIRequest(http.MethodGet, proto.DeleteBucketLifecycle)
	request.addParam("name", volume)
	if _, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}

func (api *AdminAPI) GetS3QoSInfo() (data []byte, err error) {
	var request = newAPIRequest(http.MethodGet, proto.S3QoSGet)
	if data, err = api.mc.serveRequest(request); err != nil {
		return
	}
	return
}
