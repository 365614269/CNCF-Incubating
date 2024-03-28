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
	"container/list"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util"
	"github.com/cubefs/cubefs/util/errors"
	"github.com/cubefs/cubefs/util/log"
)

type topology struct {
	dataNodes            *sync.Map
	metaNodes            *sync.Map
	zoneMap              *sync.Map
	zoneIndexForDataNode int
	zoneIndexForMetaNode int
	zones                []*Zone
	domainExcludeZones   []string // not domain zone, empty if domain disable.
	zoneLock             sync.RWMutex
}

func newTopology() (t *topology) {
	t = new(topology)
	t.zoneMap = new(sync.Map)
	t.dataNodes = new(sync.Map)
	t.metaNodes = new(sync.Map)
	t.zones = make([]*Zone, 0)
	return
}

func (t *topology) zoneLen() int {
	t.zoneLock.RLock()
	defer t.zoneLock.RUnlock()
	return len(t.zones)
}

func (t *topology) clear() {
	t.dataNodes.Range(func(key, value interface{}) bool {
		t.dataNodes.Delete(key)
		return true
	})
	t.metaNodes.Range(func(key, value interface{}) bool {
		t.metaNodes.Delete(key)
		return true
	})
}

func (t *topology) putZone(zone *Zone) (err error) {
	t.zoneLock.Lock()
	defer t.zoneLock.Unlock()
	if _, ok := t.zoneMap.Load(zone.name); ok {
		return fmt.Errorf("zone[%v] has exist", zone.name)
	}
	t.zoneMap.Store(zone.name, zone)
	t.zones = append(t.zones, zone)
	return
}

func (t *topology) putZoneIfAbsent(zone *Zone) (beStoredZone *Zone) {
	t.zoneLock.Lock()
	defer t.zoneLock.Unlock()
	oldZone, ok := t.zoneMap.Load(zone.name)
	if ok {
		return oldZone.(*Zone)
	}
	t.zoneMap.Store(zone.name, zone)
	t.zones = append(t.zones, zone)
	beStoredZone = zone
	return
}

func (t *topology) getZoneNameList() (zoneList []string) {
	zoneList = make([]string, 0)
	t.zoneMap.Range(func(zoneName, value interface{}) bool {
		zoneList = append(zoneList, zoneName.(string))
		return true
	})
	return zoneList
}

func (t *topology) getZone(name string) (zone *Zone, err error) {
	t.zoneMap.Range(func(zoneName, value interface{}) bool {
		if zoneName != name {
			return true
		}
		zone = value.(*Zone)
		return true
	})
	if zone == nil {
		return nil, fmt.Errorf("zone[%v] is not found", name)
	}
	return
}

func (t *topology) putDataNode(dataNode *DataNode) (err error) {
	if _, ok := t.dataNodes.Load(dataNode.Addr); ok {
		return
	}
	zone, err := t.getZone(dataNode.ZoneName)
	if err != nil {
		return
	}

	zone.putDataNode(dataNode)
	t.putDataNodeToCache(dataNode)
	return
}

func (t *topology) putDataNodeToCache(dataNode *DataNode) {
	t.dataNodes.Store(dataNode.Addr, dataNode)
}

func (t *topology) deleteDataNode(dataNode *DataNode) {
	zone, err := t.getZone(dataNode.ZoneName)
	if err != nil {
		return
	}
	zone.deleteDataNode(dataNode)
	t.dataNodes.Delete(dataNode.Addr)
}

func (t *topology) getZoneByDataNode(dataNode *DataNode) (zone *Zone, err error) {
	_, ok := t.dataNodes.Load(dataNode.Addr)
	if !ok {
		return nil, errors.Trace(dataNodeNotFound(dataNode.Addr), "%v not found", dataNode.Addr)
	}

	return t.getZone(dataNode.ZoneName)
}

func (t *topology) putMetaNode(metaNode *MetaNode) (err error) {
	if _, ok := t.metaNodes.Load(metaNode.Addr); ok {
		return
	}
	zone, err := t.getZone(metaNode.ZoneName)
	if err != nil {
		return
	}
	zone.putMetaNode(metaNode)
	t.putMetaNodeToCache(metaNode)
	return
}

func (t *topology) deleteMetaNode(metaNode *MetaNode) {
	t.metaNodes.Delete(metaNode.Addr)
	zone, err := t.getZone(metaNode.ZoneName)
	if err != nil {
		return
	}
	zone.deleteMetaNode(metaNode)
}

func (t *topology) putMetaNodeToCache(metaNode *MetaNode) {
	t.metaNodes.Store(metaNode.Addr, metaNode)
}

type nodeSetCollection []*nodeSet

func (nsc nodeSetCollection) Len() int {
	return len(nsc)
}

func (nsc nodeSetCollection) Less(i, j int) bool {
	return nsc[i].metaNodeLen() < nsc[j].metaNodeLen()
}

func (nsc nodeSetCollection) Swap(i, j int) {
	nsc[i], nsc[j] = nsc[j], nsc[i]
}

type nodeSetGroup struct {
	ID            uint64
	domainId      uint64
	nsgInnerIndex int // worked if alloc num of replica not equal with standard set num of nsg
	nodeSets      []*nodeSet
	nodeSetsIds   []uint64
	status        uint8
	sync.RWMutex
}

func newNodeSetGrp(c *Cluster) *nodeSetGroup {
	var id uint64
	var err error
	if id, err = c.idAlloc.allocateCommonID(); err != nil {
		return nil
	}
	log.LogInfof("action[newNodeSetGrp] construct,id[%v]", id)
	nsg := &nodeSetGroup{
		ID:     id,
		status: normal,
	}
	return nsg
}

type DomainNodeSetGrpManager struct {
	domainId             uint64
	nsgIndex             int // alloc host from  available nodesetGrp with balance policy
	nodeSetGrpMap        []*nodeSetGroup
	zoneAvailableNodeSet map[string]*list.List
	nsId2NsGrpMap        map[uint64]int // map nodeset id  to nodeset group index in nodeSetGrpMap
	lastBuildIndex       int            // build index for 2 plus 1 policy,multi zones need balance build
	status               uint8          // all nodesetGrp may be unavailable or no nodesetGrp be existed on given policy
	nsIdMap              map[uint64]int // store all ns already be put into manager
}

type DomainManager struct {
	c                     *Cluster
	init                  bool // manager  can't be used in some startup stage before load
	domainNodeSetGrpVec   []*DomainNodeSetGrpManager
	domainId2IndexMap     map[uint64]int
	ZoneName2DomainIdMap  map[string]uint64
	excludeZoneListDomain map[string]int // upgrade old datastore old zones use old policy
	dataRatioLimit        float64
	excludeZoneUseRatio   float64
	sync.RWMutex
}

func newDomainNodeSetGrpManager() *DomainNodeSetGrpManager {
	log.LogInfof("action[newDomainManager] construct")
	ns := &DomainNodeSetGrpManager{
		nsgIndex:             0,
		zoneAvailableNodeSet: make(map[string]*list.List),
		nsId2NsGrpMap:        make(map[uint64]int),
		nsIdMap:              make(map[uint64]int),
	}
	return ns
}

func newDomainManager(cls *Cluster) *DomainManager {
	log.LogInfof("action[newDomainManager] construct")
	ns := &DomainManager{
		c:                     cls,
		domainId2IndexMap:     make(map[uint64]int),
		ZoneName2DomainIdMap:  make(map[string]uint64),
		excludeZoneListDomain: make(map[string]int),
		dataRatioLimit:        defaultDomainUsageThreshold,
		excludeZoneUseRatio:   defaultDomainUsageThreshold,
	}
	return ns
}

func (nsgm *DomainManager) start() {
	log.LogInfof("action[DomainManager:start] start")
	nsgm.init = true
}

func (nsgm *DomainManager) createDomain(zoneName string) (err error) {
	if nsgm.init == false {
		return fmt.Errorf("createDomain err [%v]", err)
	}
	log.LogInfof("zone name [%v] createDomain", zoneName)
	zoneList := strings.Split(zoneName, ",")
	grpRegion := newDomainNodeSetGrpManager()
	if grpRegion.domainId, err = nsgm.c.idAlloc.allocateCommonID(); err != nil {
		return fmt.Errorf("createDomain err [%v]", err)
	}
	nsgm.Lock()
	for i := 0; i < len(zoneList); i++ {
		if domainId, ok := nsgm.ZoneName2DomainIdMap[zoneList[i]]; ok {
			nsgm.Unlock()
			return fmt.Errorf("zone name [%v] exist in domain [%v]", zoneList[i], domainId)
		}
	}
	nsgm.domainNodeSetGrpVec = append(nsgm.domainNodeSetGrpVec, grpRegion)
	for i := 0; i < len(zoneList); i++ {
		nsgm.ZoneName2DomainIdMap[zoneList[i]] = grpRegion.domainId
		nsgm.domainId2IndexMap[grpRegion.domainId] = len(nsgm.domainNodeSetGrpVec) - 1
		log.LogInfof("action[createDomain] domainid [%v] zonename [%v] index [%v]", grpRegion.domainId, zoneList[i], len(nsgm.domainNodeSetGrpVec)-1)
	}

	nsgm.Unlock()
	if err = nsgm.c.putZoneDomain(false); err != nil {
		return fmt.Errorf("putZoneDomain err [%v]", err)
	}
	return
}

func (nsgm *DomainManager) checkExcludeZoneState() {
	if len(nsgm.excludeZoneListDomain) == 0 {
		log.LogInfof("action[checkExcludeZoneState] no excludeZoneList for Domain,size zero")
		return
	}
	excludeNeedDomain := true
	log.LogInfof("action[checkExcludeZoneState] excludeZoneList size[%v]", len(nsgm.excludeZoneListDomain))
	for zoneNm := range nsgm.excludeZoneListDomain {
		if value, ok := nsgm.c.t.zoneMap.Load(zoneNm); ok {
			zone := value.(*Zone)
			if nsgm.excludeZoneUseRatio == 0 || nsgm.excludeZoneUseRatio > 1 {
				nsgm.excludeZoneUseRatio = defaultDomainUsageThreshold
			}
			if zone.isUsedRatio(nsgm.excludeZoneUseRatio) {
				if zone.status == normalZone {
					log.LogInfof("action[checkExcludeZoneState] zone[%v] be set unavailableZone", zone.name)
				}
				zone.status = unavailableZone
			} else {
				excludeNeedDomain = false
				if zone.status == unavailableZone {
					log.LogInfof("action[checkExcludeZoneState] zone[%v] be set normalZone", zone.name)
				}
				zone.status = normalZone
			}
		}
	}
	if excludeNeedDomain {
		log.LogInfof("action[checkExcludeZoneState] exclude zone cann't be used since now!excludeNeedDomain[%v]",
			excludeNeedDomain)
		nsgm.c.needFaultDomain = true
	} else {
		if nsgm.c.needFaultDomain == true {
			log.LogInfof("action[checkExcludeZoneState] needFaultDomain be set false")
		}
		nsgm.c.needFaultDomain = false
	}
}

func (nsgm *DomainManager) checkAllGrpState() {
	for i := 0; i < len(nsgm.domainNodeSetGrpVec); i++ {
		nsgm.checkGrpState(nsgm.domainNodeSetGrpVec[i])
	}
}

func (nsgm *DomainManager) checkGrpState(domainGrpManager *DomainNodeSetGrpManager) {
	nsgm.RLock()
	defer nsgm.RUnlock()
	if len(domainGrpManager.nodeSetGrpMap) == 0 {
		log.LogInfof("action[checkGrpState] leave,size zero")
		return
	}
	log.LogInfof("action[checkGrpState] nodeSetGrpMap size [%v]", len(domainGrpManager.nodeSetGrpMap))
	metaUnAvailableCnt := 0
	dataUnAvailableCnt := 0
	for i := 0; i < len(domainGrpManager.nodeSetGrpMap); i++ {
		log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], status[%v]",
			i, domainGrpManager.nodeSetGrpMap[i].ID, domainGrpManager.nodeSetGrpMap[i].status)
		grpStatus := normal
		grpMetaUnAvailableCnt := 0

		for j := 0; j < len(domainGrpManager.nodeSetGrpMap[i].nodeSets); j++ {
			var (
				metaWorked bool
				dataWorked bool
				used       uint64
				total      uint64
			)

			domainGrpManager.nodeSetGrpMap[i].nodeSets[j].dataNodes.Range(func(key, value interface{}) bool {
				node := value.(*DataNode)
				if node.isWriteAble() {
					used = used + node.Used
				} else {
					used = used + node.Total
				}
				total = total + node.Total

				log.LogInfof("action[checkGrpState] nodeid[%v] zonename[%v] used [%v] total [%v] UsageRatio [%v] got available metanode",
					node.ID, node.ZoneName, node.Used, node.Total, node.UsageRatio)
				return true
			})

			if float64(used)/float64(total) < nsgm.dataRatioLimit {
				dataWorked = true
			}
			domainGrpManager.nodeSetGrpMap[i].nodeSets[j].metaNodes.Range(func(key, value interface{}) bool {
				node := value.(*MetaNode)
				if node.isWritable() {
					metaWorked = true
					log.LogInfof("action[checkGrpState] nodeset[%v] zonename[%v] used [%v] total [%v] threshold [%v] got available metanode",
						node.ID, node.ZoneName, node.Used, node.Total, node.Threshold)
					return false
				}
				log.LogInfof("action[checkGrpState] nodeset[%v] zonename[%v] used [%v] total [%v] threshold [%v] got available metanode",
					node.ID, node.ZoneName, node.Used, node.Total, node.Threshold)
				return true
			})
			if !metaWorked || !dataWorked {
				log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], status[%v] be set metaWorked[%v] dataWorked[%v]",
					i, domainGrpManager.nodeSetGrpMap[i].ID, domainGrpManager.nodeSetGrpMap[i].status, metaWorked, dataWorked)
				if !metaWorked {
					grpMetaUnAvailableCnt++
					if grpMetaUnAvailableCnt == 2 { // meta can be used if one node is not active
						if grpStatus == dataNodesUnAvailable {
							log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], grp status change from dataNodesUnAvailable to unavailable",
								i, domainGrpManager.nodeSetGrpMap[i].ID)
							grpStatus = unavailableZone
							break
						}
						log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], grp status be set metaNodesUnAvailable",
							i, domainGrpManager.nodeSetGrpMap[i].ID)
						grpStatus = metaNodesUnAvailable
						metaUnAvailableCnt++
					}
				}
				if !dataWorked && grpStatus != dataNodesUnAvailable {
					if grpStatus == metaNodesUnAvailable {
						log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], grp status change from metaNodesUnAvailable to unavailable",
							i, domainGrpManager.nodeSetGrpMap[i].ID)
						grpStatus = unavailableZone
						break
					}
					log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], grp status be set dataNodesUnAvailable",
						i, domainGrpManager.nodeSetGrpMap[i].ID)
					grpStatus = dataNodesUnAvailable
					dataUnAvailableCnt++
				}
			}
		}
		domainGrpManager.nodeSetGrpMap[i].status = grpStatus
		log.LogInfof("action[checkGrpState] nodesetgrp index[%v], id[%v], status[%v] be set normal",
			i, domainGrpManager.nodeSetGrpMap[i].ID, domainGrpManager.nodeSetGrpMap[i].status)
	}

	domainGrpManager.status = normal
	if dataUnAvailableCnt == len(domainGrpManager.nodeSetGrpMap) {
		domainGrpManager.status = dataNodesUnAvailable
	}
	if metaUnAvailableCnt == len(domainGrpManager.nodeSetGrpMap) {
		if domainGrpManager.status == dataNodesUnAvailable {
			domainGrpManager.status = unavailableZone
		} else {
			domainGrpManager.status = metaNodesUnAvailable
		}
	}
	log.LogInfof("action[checkGrpState] nodesetgrp size [%v] dataUnAvailableCnt [%v] metaUnAvailableCnt [%v] nsgm.status now[%v]",
		len(domainGrpManager.nodeSetGrpMap), dataUnAvailableCnt, metaUnAvailableCnt, domainGrpManager.status)
}

type buildNodeSetGrpMethod func(nsgm *DomainManager, domainGrpManager *DomainNodeSetGrpManager) (err error)

func (nsgm *DomainManager) buildNodeSetGrp(domainGrpManager *DomainNodeSetGrpManager) (err error) {
	log.LogInfof("action[buildNodeSetGrp] available zone [%v]", len(domainGrpManager.zoneAvailableNodeSet))
	if len(domainGrpManager.zoneAvailableNodeSet) == 0 {
		err = fmt.Errorf("action[buildNodeSetGrp] failed zone available zero")
		log.LogErrorf("[%v]", err)
		return
	}

	var method map[int]buildNodeSetGrpMethod
	method = make(map[int]buildNodeSetGrpMethod)
	method[3] = buildNodeSetGrp3Zone
	method[2] = buildNodeSetGrp2Plus1
	method[1] = buildNodeSetGrpOneZone
	step := defaultNodeSetGrpStep

	zoneCnt := nsgm.c.cfg.DefaultNormalZoneCnt
	log.LogInfof("action[buildNodeSetGrp] zoncnt [%v]", zoneCnt)
	if zoneCnt >= 3 {
		zoneCnt = 3
	}

	if zoneCnt > len(domainGrpManager.zoneAvailableNodeSet) {
		if nsgm.c.cfg.DomainBuildAsPossible || domainGrpManager.domainId > 0 {
			log.LogInfof("action[buildNodeSetGrp] zoncnt [%v]", zoneCnt)
			zoneCnt = len(domainGrpManager.zoneAvailableNodeSet)
		} else {
			err = fmt.Errorf("action[buildNodeSetGrp] failed zone available [%v] need [%v]", zoneCnt, len(domainGrpManager.zoneAvailableNodeSet))
			log.LogErrorf("[%v]", err)
			return
		}
	}
	for {
		log.LogInfof("action[buildNodeSetGrp] zoneCnt [%v] step [%v]", zoneCnt, step)
		err = method[zoneCnt](nsgm, domainGrpManager)
		if err != nil {
			log.LogInfof("action[buildNodeSetGrp] err [%v]", err)
			break
		}
		step--
		if step == 0 {
			break
		}
	}
	if domainGrpManager.status != normal || len(domainGrpManager.nodeSetGrpMap) == 0 {
		return fmt.Errorf("cann't build new group [%v]", err)
	}

	return nil
}

func (nsgm *DomainManager) getHostFromNodeSetGrpSpecific(domainGrpManager *DomainNodeSetGrpManager, replicaNum uint8, createType uint32) (
	hosts []string,
	peers []proto.Peer,
	err error,
) {
	log.LogErrorf("action[getHostFromNodeSetGrpSpecific]  replicaNum[%v],type[%v], nsg cnt[%v], nsg status[%v]",
		replicaNum, createType, len(domainGrpManager.nodeSetGrpMap), domainGrpManager.status)
	if len(domainGrpManager.nodeSetGrpMap) == 0 {
		log.LogErrorf("action[getHostFromNodeSetGrpSpecific] [%v] nodeSetGrpMap zero", domainGrpManager.domainId)
		return nil, nil, fmt.Errorf("nodeSetGrpMap zero")
	}

	nsgm.RLock()
	defer nsgm.RUnlock()

	var cnt int
	nsgIndex := domainGrpManager.nsgIndex
	domainGrpManager.nsgIndex = (domainGrpManager.nsgIndex + 1) % len(domainGrpManager.nodeSetGrpMap)

	for {
		if cnt >= len(domainGrpManager.nodeSetGrpMap) {
			log.LogInfof("action[getHostFromNodeSetGrpSpecific] failed all nsGrp unavailable,cnt[%v]", cnt)
			err = fmt.Errorf("action[getHostFromNodeSetGrpSpecific],err:no nsGrp status normal,cnt[%v]", cnt)
			break
		}
		cnt++
		nsgIndex = (nsgIndex + 1) % len(domainGrpManager.nodeSetGrpMap)
		nsg := domainGrpManager.nodeSetGrpMap[nsgIndex]

		needReplicaNumArray := [3]int{1, 2, 3}
		for _, needReplicaNum := range needReplicaNumArray {
			var (
				host []string
				peer []proto.Peer
			)
			// every replica will look around every nodeset and break if get one
			for i := 0; i < defaultFaultDomainZoneCnt; i++ {
				ns := nsg.nodeSets[nsg.nsgInnerIndex]
				nsg.nsgInnerIndex = (nsg.nsgInnerIndex + 1) % defaultFaultDomainZoneCnt
				log.LogInfof("action[getHostFromNodeSetGrpSpecific]  nodesetid[%v],zonename[%v], datanode len[%v],metanode len[%v],capacity[%v]",
					ns.ID, ns.zoneName, ns.dataNodeLen(), ns.metaNodeLen(), ns.Capacity)

				needNum := needReplicaNum
				if needReplicaNum > int(replicaNum)-len(hosts) {
					needNum = int(replicaNum) - len(hosts)
				}

				if createType == TypeDataPartition {
					if host, peer, err = ns.getAvailDataNodeHosts(nil, needNum); err != nil {
						log.LogErrorf("action[getHostFromNodeSetGrpSpecific] ns[%v] zone[%v] TypeDataPartition err[%v]", ns.ID, ns.zoneName, err)
						// nsg.status = dataNodesUnAvailable
						continue
					}
				} else {
					if host, peer, err = ns.getAvailMetaNodeHosts(nil, needNum); err != nil {
						log.LogErrorf("action[getHostFromNodeSetGrpSpecific]  ns[%v] zone[%v] TypeMetaPartition err[%v]", ns.ID, ns.zoneName, err)
						// nsg.status = metaNodesUnAvailable
						continue
					}
				}

				hosts = append(hosts, host...)
				peers = append(peers, peer...)
				if int(replicaNum) == len(hosts) {
					log.LogInfof("action[getHostFromNodeSetGrpSpecific]  ngGrp[%v] unable support type[%v] replicaNum[%v]", nsg.ID, createType, replicaNum)
					return
				}
			}
			hosts = nil
			peers = nil
		}

	}

	return nil, nil, fmt.Errorf("action[getHostFromNodeSetGrpSpecific] cann't alloc host")
}

func (nsgm *DomainManager) getHostFromNodeSetGrp(domainId uint64, replicaNum uint8, createType uint32) (
	hosts []string,
	peers []proto.Peer,
	err error) {
	var ok bool
	var index int

	if index, ok = nsgm.domainId2IndexMap[domainId]; !ok {
		err = fmt.Errorf("action[getHostFromNodeSetGrp] not found domainid[%v]", domainId)
		return
	}
	domainGrpManager := nsgm.domainNodeSetGrpVec[index]

	log.LogInfof("action[getHostFromNodeSetGrp] domainId [%v] index [%v] replicaNum[%v],type[%v], nsg cnt[%v], nsg status[%v]",
		domainId, index, replicaNum, createType, len(domainGrpManager.nodeSetGrpMap), domainGrpManager.status)

	// this scenario is abnormal  may be caused by zone unavailable in high probability
	if domainGrpManager.status != normal {
		return nsgm.getHostFromNodeSetGrpSpecific(domainGrpManager, replicaNum, createType)
	}

	// grp map be build with three zone on standard,no grp if zone less than three,here will build
	// nodesetGrp with zones less than three,because offer service is much more important than high available
	if len(domainGrpManager.zoneAvailableNodeSet) != 0 {
		if nsgm.buildNodeSetGrp(domainGrpManager); len(domainGrpManager.nodeSetGrpMap) == 0 {
			err = fmt.Errorf("no usable group")
			log.LogErrorf("action[getHostFromNodeSetGrp] no usable group build failed,err[%v]", err)
			return
		}
	} else if len(domainGrpManager.nodeSetGrpMap) == 0 {
		err = fmt.Errorf("no usable group")
		log.LogInfof("action[getHostFromNodeSetGrp] err[%v]", err)
		return
	}

	nsgm.RLock()
	defer nsgm.RUnlock()

	var cnt int
	nsgIndex := domainGrpManager.nsgIndex
	domainGrpManager.nsgIndex = (domainGrpManager.nsgIndex + 1) % len(domainGrpManager.nodeSetGrpMap)

	for {
		if cnt >= len(domainGrpManager.nodeSetGrpMap) {
			err = fmt.Errorf("action[getHostFromNodeSetGrp] need replica cnt [%v] but get host cnt [%v] from nodesetgrps count[%v]",
				replicaNum, len(hosts), cnt)
			log.LogErrorf(err.Error())
			return nil, nil, err
		}
		cnt++
		nsgIndex = (nsgIndex + 1) % len(domainGrpManager.nodeSetGrpMap)
		nsg := domainGrpManager.nodeSetGrpMap[nsgIndex]

		var (
			host []string
			peer []proto.Peer
		)

		// it's better to get enough replicas from one nsg(copy set) and will get complement from
		// other nsg if not

		for i := 0; i < defaultMaxReplicaCnt*len(nsg.nodeSets); i++ {
			ns := nsg.nodeSets[nsg.nsgInnerIndex]
			log.LogInfof("action[getHostFromNodeSetGrp]  nodesetid[%v],zonename[%v], datanode len[%v],metanode len[%v],capacity[%v]",
				ns.ID, ns.zoneName, ns.dataNodeLen(), ns.metaNodeLen(), ns.Capacity)
			nsg.nsgInnerIndex = (nsg.nsgInnerIndex + 1) % defaultFaultDomainZoneCnt
			if nsg.status == unavailableZone {
				log.LogWarnf("action[getHostFromNodeSetGrp] ns[%v] zone[%v] unavailableZone", ns.ID, ns.zoneName)
				continue
			}
			if createType == TypeDataPartition {
				if nsg.status == dataNodesUnAvailable {
					log.LogWarnf("action[getHostFromNodeSetGrp] ns[%v] zone[%v] dataNodesUnAvailable", ns.ID, ns.zoneName)
					continue
				}
				if host, peer, err = ns.getAvailDataNodeHosts(hosts, 1); err != nil {
					log.LogWarnf("action[getHostFromNodeSetGrp] ns[%v] zone[%v] TypeDataPartition err[%v]", ns.ID, ns.zoneName, err)
					// nsg.status = dataNodesUnAvailable
					continue
				}
			} else {
				if nsg.status == metaNodesUnAvailable {
					log.LogWarnf("action[getHostFromNodeSetGrp] ns[%v] zone[%v] metaNodesUnAvailable", ns.ID, ns.zoneName)
					continue
				}
				if host, peer, err = ns.getAvailMetaNodeHosts(hosts, 1); err != nil {
					log.LogWarnf("action[getHostFromNodeSetGrp]  ns[%v] zone[%v] TypeMetaPartition err[%v]", ns.ID, ns.zoneName, err)
					// nsg.status = metaNodesUnAvailable
					continue
				}
			}
			hosts = append(hosts, host[0])
			peers = append(peers, peer[0])
			log.LogInfof("action[getHostFromNodeSetGrp]  get host[%v] peer[%v], nsg id[%v] nsgInnerIndex[%v]", host[0], peer[0], nsg.ID, nsg.nsgInnerIndex)

			if len(hosts) == int(replicaNum) {
				return hosts, peers, nil
			}
		}
	}
}

// nodeset may not
type nsList struct {
	lst      *list.List
	ele      *list.Element
	zoneName string
}

func (nsgm *DomainManager) buildNodeSetGrpPrepare(domainGrpManager *DomainNodeSetGrpManager) (buildIndex int, zoneAvaVec []nsList) {
	sortedKeys := make([]string, 0)
	for k := range domainGrpManager.zoneAvailableNodeSet {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, zoneName := range sortedKeys {
		var zoneInfo nsList
		zoneInfo.lst = domainGrpManager.zoneAvailableNodeSet[zoneName]
		zoneInfo.zoneName = zoneName
		zoneAvaVec = append(zoneAvaVec, zoneInfo)
	}
	buildIndex = domainGrpManager.lastBuildIndex % len(zoneAvaVec)
	domainGrpManager.lastBuildIndex = (domainGrpManager.lastBuildIndex + 1) % len(zoneAvaVec)
	return
}

func (nsgm *DomainManager) buildNodeSetGrpDoWork(zoneName string, nodeList *list.List, needCnt int) (resList []nsList, err error) {
	log.LogInfof("action[buildNodeSetGrpDoWork] step in")
	var tmpList []nsList
	ele := nodeList.Front()
	for {
		if ele == nil {
			log.LogInfof("action[buildNodeSetGrpDoWork] zone [%v] can't create nodeset group nodeList not qualified", zoneName)
			err = fmt.Errorf("action[buildNodeSetGrpDoWork] zone [%v] can't create nodeset group nodeList not qualified", zoneName)
			return
		}
		nst := ele.Value.(*nodeSet)
		log.LogInfof("action[buildNodeSetGrpDoWork] nodeset [%v] zonename [%v] ,metacnt[%v],datacnt[%v]",
			nst.ID, nst.zoneName, nst.metaNodeLen(), nst.dataNodeLen())
		if nst.dataNodeLen() > 0 && nst.metaNodeLen() > 0 {
			var nsl nsList
			nsl.lst = nodeList
			nsl.ele = ele
			nsl.zoneName = zoneName
			tmpList = append(tmpList, nsl)
			log.LogInfof("action[buildNodeSetGrpDoWork] nodeset [%v] zonename [%v] qualified be put in,metacnt[%v],datacnt[%v]",
				nst.ID, nst.zoneName, nst.metaNodeLen(), nst.dataNodeLen())
			needCnt = needCnt - 1
			if needCnt == 0 {
				break
			}
		}
		ele = ele.Next()
	}
	if needCnt == 0 {
		resList = append(resList, tmpList...)
	} else {
		err = fmt.Errorf("not quliaifed")
	}
	return
}

func (nsgm *DomainManager) buildNodeSetGrpCommit(resList []nsList, domainGrpManager *DomainNodeSetGrpManager) {
	nodeSetGrp := newNodeSetGrp(nsgm.c)
	nodeSetGrp.domainId = domainGrpManager.domainId
	for i := 0; i < len(resList); i++ {
		nst := resList[i].ele.Value.(*nodeSet)
		nodeSetGrp.nodeSets = append(nodeSetGrp.nodeSets, nst)
		nodeSetGrp.nodeSetsIds = append(nodeSetGrp.nodeSetsIds, nst.ID)
		log.LogInfof("action[buildNodeSetGrpCommit] build nodesetGrp id[%v] with append nst id [%v] zoneName [%v]", nodeSetGrp.ID, nst.ID, nst.zoneName)
		resList[i].lst.Remove(resList[i].ele)
		domainGrpManager.nsId2NsGrpMap[nst.ID] = len(domainGrpManager.nodeSetGrpMap)
		if resList[i].lst.Len() == 0 {
			delete(domainGrpManager.zoneAvailableNodeSet, resList[i].zoneName)
			log.LogInfof("action[buildNodeSetGrpCommit] after grp build no nodeset available for zone[%v],nodesetid:[%v], zonelist size[%v]",
				nst.zoneName, nst.ID, len(domainGrpManager.zoneAvailableNodeSet))
		}
	}

	log.LogInfof("action[buildNodeSetGrpCommit] success build nodesetgrp zonelist size[%v], nodesetids[%v]",
		len(domainGrpManager.zoneAvailableNodeSet), nodeSetGrp.nodeSetsIds)
	domainGrpManager.nodeSetGrpMap = append(domainGrpManager.nodeSetGrpMap, nodeSetGrp)
	nsgm.c.putNodeSetGrpInfo(opSyncNodeSetGrp, nodeSetGrp)
	domainGrpManager.status = normal
}

// policy of build zone if zone count large then three
func buildNodeSetGrp3Zone(nsgm *DomainManager, domainGrpManager *DomainNodeSetGrpManager) (err error) {
	nsgm.Lock()
	defer nsgm.Unlock()
	log.LogInfof("action[buildNodeSetGrp3Zone step in")
	if len(domainGrpManager.zoneAvailableNodeSet) < defaultFaultDomainZoneCnt {
		log.LogInfof("action[DomainManager::buildNodeSetGrp3Zone] size error,can't create group zone cnt[%v]",
			len(domainGrpManager.zoneAvailableNodeSet))
		return fmt.Errorf("defaultFaultDomainZoneCnt not satisfied")
	}

	var resList []nsList
	buildIndex, zoneAvaVec := nsgm.buildNodeSetGrpPrepare(domainGrpManager)
	cnt := 0
	for {
		if cnt > 0 {
			buildIndex = (buildIndex + 1) % len(zoneAvaVec)
		}
		if cnt == len(zoneAvaVec) || len(resList) == defaultReplicaNum {
			log.LogInfof("step out inner loop in buildNodeSetGrp3Zone cnt [%v], inner index [%v]", cnt, buildIndex)
			break
		}
		cnt++
		nodeList := zoneAvaVec[buildIndex].lst
		zoneName := zoneAvaVec[buildIndex].zoneName
		var tmpList []nsList
		if tmpList, err = nsgm.buildNodeSetGrpDoWork(zoneName, nodeList, 1); err != nil {
			continue
		}
		resList = append(resList, tmpList...)
	}
	if len(resList) < defaultReplicaNum {
		log.LogInfof("action[DomainManager::buildNodeSetGrp3Zone] can't create nodeset group nodeset qualified count [%v]", len(resList))
		return fmt.Errorf("defaultFaultDomainZoneCnt not satisfied")
	}
	nsgm.buildNodeSetGrpCommit(resList, domainGrpManager)
	return nil
}

func buildNodeSetGrpOneZone(nsgm *DomainManager, domainGrpManager *DomainNodeSetGrpManager) (err error) {
	nsgm.Lock()
	defer nsgm.Unlock()
	log.LogInfof("action[buildNodeSetGrpOneZone] step in")
	if len(domainGrpManager.zoneAvailableNodeSet) != 1 {
		log.LogErrorf("action[buildNodeSetGrpOneZone] available zone cnt[%v]", len(domainGrpManager.zoneAvailableNodeSet))
		err = fmt.Errorf("available zone cnt[%v]", len(domainGrpManager.zoneAvailableNodeSet))
		return
	}
	buildIndex, zoneAvaVec := nsgm.buildNodeSetGrpPrepare(domainGrpManager)

	if zoneAvaVec[buildIndex].lst.Len() < defaultReplicaNum {
		log.LogErrorf("action[buildNodeSetGrpOneZone] not enough nodeset in available list")
		return fmt.Errorf("not enough nodeset in available list")
	}
	var resList []nsList
	if resList, err = nsgm.buildNodeSetGrpDoWork(zoneAvaVec[buildIndex].zoneName,
		zoneAvaVec[buildIndex].lst, defaultReplicaNum); err != nil {
		return err
	}
	nsgm.buildNodeSetGrpCommit(resList, domainGrpManager)

	return nil
}

// build 2 plus 1 nodesetGrp with 2zone or larger
func buildNodeSetGrp2Plus1(nsgm *DomainManager, domainGrpManager *DomainNodeSetGrpManager) (err error) {
	nsgm.Lock()
	defer nsgm.Unlock()
	log.LogInfof("step in buildNodeSetGrp2Plus1")

	cnt := 0
	var resList []nsList

	_, zoneAvaVec := nsgm.buildNodeSetGrpPrepare(domainGrpManager)
	var np1, np2 int

	if zoneAvaVec[0].lst.Len() < zoneAvaVec[1].lst.Len() {
		np1 = 0
		np2 = 1
	} else {
		np1 = 1
		np2 = 0
	}
	for i := 2; i < len(zoneAvaVec); i++ {
		if zoneAvaVec[i].lst.Len() > zoneAvaVec[np1].lst.Len() {
			if zoneAvaVec[i].lst.Len() > zoneAvaVec[np2].lst.Len() {
				np2 = i
			} else {
				np1 = i
			}
		}
	}
	if zoneAvaVec[np1].lst.Len() < 1 || zoneAvaVec[np2].lst.Len() < 2 {
		log.LogInfof("step out buildNodeSetGrp2Plus1 np1 [%v] np2 [%v] cnt [%v], inner index [%v]",
			np1, np2, cnt, domainGrpManager.lastBuildIndex)
		return fmt.Errorf("action[buildNodeSetGrp2Plus1] failed")
	}

	var tmpList []nsList
	if tmpList, err = nsgm.buildNodeSetGrpDoWork(zoneAvaVec[np1].zoneName, zoneAvaVec[np1].lst, 1); err != nil {
		return
	}
	resList = append(resList, tmpList...)
	if tmpList, err = nsgm.buildNodeSetGrpDoWork(zoneAvaVec[np2].zoneName, zoneAvaVec[np2].lst, 2); err != nil {
		return
	}
	resList = append(resList, tmpList...)
	nsgm.buildNodeSetGrpCommit(resList, domainGrpManager)

	return
}

func (nsgm *DomainManager) putNodeSet(ns *nodeSet, load bool) (err error) {
	nsgm.Lock()
	defer nsgm.Unlock()
	var (
		ok       bool
		index    int
		nsGrp    *DomainNodeSetGrpManager
		domainId uint64
	)
	if _, ok = nsgm.excludeZoneListDomain[ns.zoneName]; ok {
		log.LogInfof("action[DomainManager::putNodeSet] zone[%v],nodesetid:[%v], domain vec size[%v]",
			ns.zoneName, ns.ID, len(nsgm.domainNodeSetGrpVec))
		return
	}

	if domainId, ok = nsgm.ZoneName2DomainIdMap[ns.zoneName]; !ok {
		domainId = 0 // no domainid be set before;therefore, put it to default domain
		nsgm.ZoneName2DomainIdMap[ns.zoneName] = 0
	}
	if index, ok = nsgm.domainId2IndexMap[domainId]; !ok {
		if domainId > 0 && load == false { // domainId 0 can be created through nodeset create,others be created by createDomain
			err = fmt.Errorf("inconsistent domainid exist in name map but node exist in index map")
			log.LogErrorf("action[putNodeSet]  %v", err)
			return
		}
		grpRegion := newDomainNodeSetGrpManager()
		nsgm.domainNodeSetGrpVec = append(nsgm.domainNodeSetGrpVec, grpRegion)
		nsgm.ZoneName2DomainIdMap[ns.zoneName] = 0 // domainId must be zero here
		grpRegion.domainId = domainId
		index = len(nsgm.domainNodeSetGrpVec) - 1
		nsgm.domainId2IndexMap[domainId] = index
		log.LogInfof("action[putNodeSet] build domainId[%v] zoneName [%v] index [%v]", domainId, ns.zoneName, index)
	}
	nsGrp = nsgm.domainNodeSetGrpVec[index]

	if _, ok = nsGrp.nsIdMap[ns.ID]; ok {
		log.LogInfof("action[DomainManager::putNodeSet]  zone[%v],nodesetid:[%v] already be put before load[%v]",
			ns.zoneName, ns.ID, load)
		return
	}
	nsGrp.nsIdMap[ns.ID] = 0
	log.LogInfof("action[DomainManager::putNodeSet]  zone[%v],nodesetid:[%v], domain vec size[%v], load[%v]",
		ns.zoneName, ns.ID, len(nsgm.domainNodeSetGrpVec), load)

	// nodeset already be put into grp,this should be happened at condition of load == true
	// here hosts in ns should be nullptr and wait node register
	if grpidx, ok := nsGrp.nsId2NsGrpMap[ns.ID]; ok {
		nsGrp.nodeSetGrpMap[grpidx].nodeSets = append(nsGrp.nodeSetGrpMap[grpidx].nodeSets, ns)
		log.LogInfof("action[DomainManager::putNodeSet]  zone[%v],nodesetid:[%v] already be put before grp index[%v], grp id[%v] load[%v]",
			ns.zoneName, ns.ID, grpidx, nsGrp.nodeSetGrpMap[grpidx].ID, load)
		return
	}
	if _, ok := nsGrp.zoneAvailableNodeSet[ns.zoneName]; !ok {
		nsGrp.zoneAvailableNodeSet[ns.zoneName] = list.New()
		log.LogInfof("action[DomainManager::putNodeSet] init list for zone[%v],zonelist size[%v]", ns.zoneName, len(nsGrp.zoneAvailableNodeSet))
	}
	log.LogInfof("action[DomainManager::putNodeSet] domainid [%v] ns id[%v] be put in zone[%v]", nsGrp.domainId, ns.ID, ns.zoneName)
	nsGrp.zoneAvailableNodeSet[ns.zoneName].PushBack(ns)

	return
}

type nodeSet struct {
	ID                             uint64
	Capacity                       int
	zoneName                       string
	metaNodes                      *sync.Map
	dataNodes                      *sync.Map
	decommissionDataPartitionList  *DecommissionDataPartitionList
	decommissionParallelLimit      int32
	decommissionDiskParallelFactor float64
	nodeSelectLock                 sync.Mutex
	dataNodeSelectorLock           sync.RWMutex
	dataNodeSelector               NodeSelector
	metaNodeSelectorLock           sync.RWMutex
	metaNodeSelector               NodeSelector
	sync.RWMutex
	manualDecommissionDiskList        *DecommissionDiskList
	autoDecommissionDiskList          *DecommissionDiskList
	doneDecommissionDiskListTraverse  chan struct{}
	startDecommissionDiskListTraverse chan struct{}
	DecommissionDisks                 sync.Map
	diskParallelFactorLk              sync.Mutex
}

type nodeSetDecommissionParallelStatus struct {
	ID          uint64
	CurTokenNum int32
	MaxTokenNum int32
	RunningDp   []uint64
}

func newNodeSet(c *Cluster, id uint64, cap int, zoneName string) *nodeSet {
	log.LogInfof("action[newNodeSet] id[%v]", id)
	ns := &nodeSet{
		ID:                                id,
		Capacity:                          cap,
		zoneName:                          zoneName,
		metaNodes:                         new(sync.Map),
		dataNodes:                         new(sync.Map),
		decommissionDataPartitionList:     NewDecommissionDataPartitionList(c),
		manualDecommissionDiskList:        NewDecommissionDiskList(),
		autoDecommissionDiskList:          NewDecommissionDiskList(),
		doneDecommissionDiskListTraverse:  make(chan struct{}, 1),
		startDecommissionDiskListTraverse: make(chan struct{}, 1),
		dataNodeSelector:                  NewNodeSelector(DefaultNodeSelectorName, DataNodeType),
		metaNodeSelector:                  NewNodeSelector(DefaultNodeSelectorName, MetaNodeType),
	}
	go ns.traverseDecommissionDisk(c)
	return ns
}

func (ns *nodeSet) GetDataNodeSelector() string {
	ns.dataNodeSelectorLock.RLock()
	defer ns.dataNodeSelectorLock.RUnlock()
	return ns.dataNodeSelector.GetName()
}

func (ns *nodeSet) SetDataNodeSelector(name string) {
	ns.dataNodeSelectorLock.Lock()
	defer ns.dataNodeSelectorLock.Unlock()
	ns.dataNodeSelector = NewNodeSelector(name, DataNodeType)
}

func (ns *nodeSet) GetMetaNodeSelector() string {
	ns.metaNodeSelectorLock.RLock()
	defer ns.metaNodeSelectorLock.RUnlock()
	return ns.metaNodeSelector.GetName()
}

func (ns *nodeSet) SetMetaNodeSelector(name string) {
	ns.metaNodeSelectorLock.Lock()
	defer ns.metaNodeSelectorLock.Unlock()
	ns.metaNodeSelector = NewNodeSelector(name, MetaNodeType)
}

func (ns *nodeSet) metaNodeLen() (count int) {
	ns.RLock()
	defer ns.RUnlock()
	ns.metaNodes.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return
}

func (ns *nodeSet) startDecommissionSchedule() {
	ns.decommissionDataPartitionList.startTraverse()
	ns.startDecommissionDiskListTraverse <- struct{}{}
}

func (ns *nodeSet) dataNodeLen() (count int) {
	ns.RLock()
	defer ns.RUnlock()
	ns.dataNodes.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return
}

func (ns *nodeSet) putMetaNode(metaNode *MetaNode) {
	ns.metaNodes.Store(metaNode.Addr, metaNode)
}

func (ns *nodeSet) deleteMetaNode(metaNode *MetaNode) {
	ns.metaNodes.Delete(metaNode.Addr)
}

func (ns *nodeSet) canWriteForDataNode(replicaNum int) bool {
	var count int
	ns.dataNodes.Range(func(key, value interface{}) bool {
		node := value.(*DataNode)
		if node.isWriteAble() && node.dpCntInLimit() {
			count++
		}
		if count >= replicaNum {
			return false
		}
		return true
	})
	log.LogInfof("canWriteForDataNode zone[%v], ns[%v],count[%v], replicaNum[%v]",
		ns.zoneName, ns.ID, count, replicaNum)
	return count >= replicaNum
}

func (ns *nodeSet) canWriteForMetaNode(replicaNum int) bool {
	var count int
	ns.metaNodes.Range(func(key, value interface{}) bool {
		node := value.(*MetaNode)
		if node.isWritable() {
			count++
		}
		if count >= replicaNum {
			return false
		}
		return true
	})
	log.LogInfof("canWriteForMetaNode zone[%v], ns[%v],count[%v] replicaNum[%v]",
		ns.zoneName, ns.ID, count, replicaNum)
	return count >= replicaNum
}

func (ns *nodeSet) putDataNode(dataNode *DataNode) {
	ns.dataNodes.Store(dataNode.Addr, dataNode)
}

func (ns *nodeSet) deleteDataNode(dataNode *DataNode) {
	ns.dataNodes.Delete(dataNode.Addr)
}

func (ns *nodeSet) AddToDecommissionDataPartitionList(dp *DataPartition, c *Cluster) {
	ns.decommissionDataPartitionList.Put(ns.ID, dp, c)
}

func (ns *nodeSet) UpdateMaxParallel(maxParallel int32) {
	ns.decommissionDataPartitionList.updateMaxParallel(maxParallel)
	log.LogDebugf("action[UpdateMaxParallel]nodeSet[%v] decommission limit update to [%v]", ns.ID, maxParallel)
	atomic.StoreInt32(&ns.decommissionParallelLimit, maxParallel)
}

func (ns *nodeSet) UpdateDecommissionDiskFactor(factor float64) {
	log.LogDebugf("action[UpdateDecommissionFactor]nodeSet[%v] decommission disk factor update to [%v]", ns.ID, factor)
	ns.diskParallelFactorLk.Lock()
	defer ns.diskParallelFactorLk.Unlock()
	ns.decommissionDiskParallelFactor = factor
}

func (ns *nodeSet) QueryDecommissionDiskLimit() int {
	ns.diskParallelFactorLk.Lock()
	defer ns.diskParallelFactorLk.Unlock()
	log.LogDebugf("action[QueryDecommissionDiskLimit]nodeSet[%v] decommission disk limit to [%v]",
		ns.ID, int(ns.decommissionDiskParallelFactor*float64(ns.dataNodeLen())))
	return int(ns.decommissionDiskParallelFactor * float64(ns.dataNodeLen()))
}

func (ns *nodeSet) getDecommissionParallelStatus() (int32, int32, []uint64) {
	return ns.decommissionDataPartitionList.getDecommissionParallelStatus()
}

func (ns *nodeSet) AcquireDecommissionToken(id uint64) bool {
	return ns.decommissionDataPartitionList.acquireDecommissionToken(id)
}

func (ns *nodeSet) ReleaseDecommissionToken(id uint64) {
	ns.decommissionDataPartitionList.releaseDecommissionToken(id)
}

func (ns *nodeSet) AddDecommissionDisk(dd *DecommissionDisk) {
	ns.DecommissionDisks.Store(dd.GenerateKey(), dd)
	if dd.IsManualDecommissionDisk() {
		ns.addManualDecommissionDisk(dd)
	} else {
		ns.addAutoDecommissionDisk(dd)
	}
	log.LogInfof("action[AddDecommissionDisk] add disk %v type %v to  ns %v", dd.GenerateKey(), dd.Type, ns.ID)
}

func (ns *nodeSet) RemoveDecommissionDisk(dd *DecommissionDisk) {
	ns.DecommissionDisks.Delete(dd.GenerateKey())
	if dd.IsManualDecommissionDisk() {
		ns.removeManualDecommissionDisk(dd)
	} else {
		ns.removeAutoDecommissionDisk(dd)
	}
	log.LogInfof("action[RemoveDecommissionDisk] remove disk %v type %v  from  ns %v", dd.GenerateKey(), dd.Type, ns.ID)
}

func (ns *nodeSet) addManualDecommissionDisk(dd *DecommissionDisk) {
	ns.manualDecommissionDiskList.Put(ns.ID, dd)
}

func (ns *nodeSet) addAutoDecommissionDisk(dd *DecommissionDisk) {
	ns.autoDecommissionDiskList.Put(ns.ID, dd)
}

func (ns *nodeSet) removeManualDecommissionDisk(dd *DecommissionDisk) {
	ns.manualDecommissionDiskList.Remove(ns.ID, dd)
}

func (ns *nodeSet) removeAutoDecommissionDisk(dd *DecommissionDisk) {
	ns.autoDecommissionDiskList.Remove(ns.ID, dd)
}

func (ns *nodeSet) traverseDecommissionDisk(c *Cluster) {
	t := time.NewTicker(DecommissionInterval)
	// wait for loading all decommissionDisk when reload metadata
	log.LogInfof("action[traverseDecommissionDisk]wait %v", ns.ID)
	<-ns.startDecommissionDiskListTraverse
	log.LogInfof("action[traverseDecommissionDisk] traverseDecommissionDisk start %v", ns.ID)
	defer t.Stop()
	for {
		select {
		case <-ns.doneDecommissionDiskListTraverse:
			log.LogWarnf("traverse stopped")
			return
		case <-t.C:
			if c.partition != nil && !c.partition.IsRaftLeader() {
				log.LogWarnf("Leader changed, stop traverse!")
				continue
			}
			runningCnt := 0
			ns.DecommissionDisks.Range(func(key, value interface{}) bool {
				disk := value.(*DecommissionDisk)
				disk.updateDecommissionStatus(c, false)
				status := disk.GetDecommissionStatus()
				if status == DecommissionRunning {
					runningCnt++
				} else if status == DecommissionSuccess || status == DecommissionFail || status == DecommissionPause {
					// remove from decommission disk list
					log.LogWarnf("traverseDecommissionDisk remove disk %v status %v",
						disk.GenerateKey(), disk.GetDecommissionStatus())
					ns.RemoveDecommissionDisk(disk)
				}
				return true
			})
			ns.diskParallelFactorLk.Lock()
			maxDiskDecommissionCnt := int(ns.decommissionDiskParallelFactor * float64(ns.dataNodeLen()))
			ns.diskParallelFactorLk.Unlock()
			if maxDiskDecommissionCnt == 0 && ns.dataNodeLen() != 0 {
				manualCnt, manualDisks := ns.manualDecommissionDiskList.PopMarkDecommissionDisk(0)
				log.LogDebugf("traverseDecommissionDisk traverse manualCnt %v",
					manualCnt)
				if manualCnt > 0 {
					for _, disk := range manualDisks {
						c.TryDecommissionDisk(disk)
					}
				}
				if c.AutoDecommissionDiskIsEnabled() {
					autoCnt, autoDisks := ns.autoDecommissionDiskList.PopMarkDecommissionDisk(0)
					log.LogDebugf("traverseDecommissionDisk traverse autoCnt %v",
						autoCnt)
					if autoCnt > 0 {
						for _, disk := range autoDisks {
							c.TryDecommissionDisk(disk)
						}
					}
				}
			} else {
				newDiskDecommissionCnt := maxDiskDecommissionCnt - runningCnt
				log.LogDebugf("traverseDecommissionDisk traverse DiskDecommissionCnt %v",
					newDiskDecommissionCnt)
				if newDiskDecommissionCnt > 0 {
					manualCnt, manualDisks := ns.manualDecommissionDiskList.PopMarkDecommissionDisk(newDiskDecommissionCnt)
					log.LogDebugf("traverseDecommissionDisk traverse manualCnt %v",
						manualCnt)
					if manualCnt > 0 {
						for _, disk := range manualDisks {
							c.TryDecommissionDisk(disk)
						}
					}
					if newDiskDecommissionCnt-manualCnt > 0 && c.AutoDecommissionDiskIsEnabled() {
						autoCnt, autoDisks := ns.autoDecommissionDiskList.PopMarkDecommissionDisk(newDiskDecommissionCnt - manualCnt)
						log.LogDebugf("traverseDecommissionDisk traverse autoCnt %v",
							autoCnt)
						if autoCnt > 0 {
							for _, disk := range autoDisks {
								c.TryDecommissionDisk(disk)
							}
						}
					}
				}
			}
		}
	}
}

func (t *topology) isSingleZone() bool {
	t.zoneLock.RLock()
	defer t.zoneLock.RUnlock()
	var zoneLen int
	t.zoneMap.Range(func(zoneName, value interface{}) bool {
		zoneLen++
		return true
	})
	return zoneLen == 1
}

func (t *topology) getDomainExcludeZones() (zones []*Zone) {
	t.zoneLock.RLock()
	defer t.zoneLock.RUnlock()
	zones = make([]*Zone, 0)
	for i := 0; i < len(t.domainExcludeZones); i++ {
		if value, ok := t.zoneMap.Load(t.domainExcludeZones[i]); ok {
			zones = append(zones, value.(*Zone))
			log.LogInfof("action[getDomainExcludeZones] append zone name:[%v]_[%v]", t.domainExcludeZones[i], value.(*Zone).name)
		}
	}
	return
}

func (t *topology) getAllZones() (zones []*Zone) {
	t.zoneLock.RLock()
	defer t.zoneLock.RUnlock()
	zones = make([]*Zone, 0)
	t.zoneMap.Range(func(zoneName, value interface{}) bool {
		zone := value.(*Zone)
		zones = append(zones, zone)
		return true
	})
	return
}

func (t *topology) getZoneByIndex(index int) (zone *Zone) {
	t.zoneLock.RLock()
	defer t.zoneLock.RUnlock()
	return t.zones[index]
}

func (t *topology) getNodeSetByNodeSetId(nodeSetId uint64) (nodeSet *nodeSet, err error) {
	zones := t.getAllZones()
	for _, zone := range zones {
		nodeSet, err = zone.getNodeSet(nodeSetId)
		if err == nil {
			return nodeSet, nil
		}
	}
	return nil, errors.NewErrorf("set %v not found", nodeSetId)
}

func calculateDemandWriteNodes(zoneNum int, replicaNum int) (demandWriteNodes int) {
	if zoneNum == 1 {
		demandWriteNodes = replicaNum
	} else {
		if replicaNum == 1 {
			demandWriteNodes = 1
		} else {
			demandWriteNodes = 2
		}
	}
	return
}

func (t *topology) allocZonesForMetaNode(zoneNum, replicaNum int, excludeZone []string) (zones []*Zone, err error) {
	if len(t.domainExcludeZones) > 0 {
		zones = t.getDomainExcludeZones()
		log.LogInfof("action[allocZonesForMetaNode] getDomainExcludeZones zones [%v]", t.domainExcludeZones)
	} else {
		// if domain enable, will not enter here
		zones = t.getAllZones()
	}
	if t.isSingleZone() {
		return zones, nil
	}
	if excludeZone == nil {
		excludeZone = make([]string, 0)
	}
	candidateZones := make([]*Zone, 0)
	demandWriteNodes := calculateDemandWriteNodes(zoneNum, replicaNum)
	for i := 0; i < len(zones); i++ {
		if t.zoneIndexForMetaNode >= len(zones) {
			t.zoneIndexForMetaNode = 0
		}
		zone := zones[t.zoneIndexForMetaNode]
		t.zoneIndexForMetaNode++
		if zone.status == unavailableZone {
			continue
		}
		if contains(excludeZone, zone.name) {
			continue
		}
		if zone.canWriteForMetaNode(uint8(demandWriteNodes)) {
			candidateZones = append(candidateZones, zone)
		}
		if len(candidateZones) >= zoneNum {
			break
		}
	}

	// if across zone,candidateZones must be larger than or equal with 2,otherwise,must have a candidate zone
	if (zoneNum >= 2 && len(candidateZones) < 2) || len(candidateZones) < 1 {
		log.LogError(fmt.Sprintf("action[allocZonesForMetaNode],reqZoneNum[%v],candidateZones[%v],demandWriteNodes[%v],err:%v",
			zoneNum, len(candidateZones), demandWriteNodes, proto.ErrNoZoneToCreateMetaPartition))
		return nil, proto.ErrNoZoneToCreateMetaPartition
	}
	zones = candidateZones
	err = nil
	return
}

func (t *topology) allocZonesForDataNode(zoneNum, replicaNum int, excludeZone []string) (zones []*Zone, err error) {
	// domain enabled and have old zones to be used
	if len(t.domainExcludeZones) > 0 {
		zones = t.getDomainExcludeZones()
	} else {
		// if domain enable, will not enter here
		zones = t.getAllZones()
	}

	log.LogInfof("len(zones) = %v \n", len(zones))
	if t.isSingleZone() {
		return zones, nil
	}
	if excludeZone == nil {
		excludeZone = make([]string, 0)
	}

	demandWriteNodes := calculateDemandWriteNodes(zoneNum, replicaNum)
	candidateZones := make([]*Zone, 0)

	for i := 0; i < len(zones); i++ {
		if t.zoneIndexForDataNode >= len(zones) {
			t.zoneIndexForDataNode = 0
		}

		zone := zones[t.zoneIndexForDataNode]
		t.zoneIndexForDataNode++

		if zone.status == unavailableZone {
			continue
		}
		if contains(excludeZone, zone.name) {
			continue
		}
		if zone.canWriteForDataNode(uint8(demandWriteNodes)) {
			candidateZones = append(candidateZones, zone)
		}
		if len(candidateZones) >= zoneNum {
			break
		}
	}

	// if across zone,candidateZones must be larger than or equal with 2,otherwise,must have one candidate zone
	if (zoneNum >= 2 && len(candidateZones) < 2) || len(candidateZones) < 1 {
		log.LogError(fmt.Sprintf("action[allocZonesForDataNode],reqZoneNum[%v],candidateZones[%v],demandWriteNodes[%v],err:%v",
			zoneNum, len(candidateZones), demandWriteNodes, proto.ErrNoZoneToCreateDataPartition))
		return nil, errors.NewError(proto.ErrNoZoneToCreateDataPartition)
	}
	zones = candidateZones
	err = nil
	return
}

func (ns *nodeSet) dataNodeCount() int {
	var count int
	ns.dataNodes.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Zone stores all the zone related information
type Zone struct {
	name                    string
	dataNodesetSelectorLock sync.RWMutex
	dataNodesetSelector     NodesetSelector
	metaNodesetSelectorLock sync.RWMutex
	metaNodesetSelector     NodesetSelector
	status                  int
	dataNodes               *sync.Map
	metaNodes               *sync.Map
	nodeSetMap              map[uint64]*nodeSet
	nsLock                  sync.RWMutex
	QosIopsRLimit           uint64
	QosIopsWLimit           uint64
	QosFlowRLimit           uint64
	QosFlowWLimit           uint64
	sync.RWMutex
}

type zoneValue struct {
	Name                string
	QosIopsRLimit       uint64
	QosIopsWLimit       uint64
	QosFlowRLimit       uint64
	QosFlowWLimit       uint64
	DataNodesetSelector string
	MetaNodesetSelector string
}

func newZone(name string) (zone *Zone) {
	zone = &Zone{name: name}
	zone.status = normalZone
	zone.dataNodes = new(sync.Map)
	zone.metaNodes = new(sync.Map)
	zone.nodeSetMap = make(map[uint64]*nodeSet)
	zone.dataNodesetSelector = NewNodesetSelector(DefaultNodesetSelectorName, DataNodeType)
	zone.metaNodesetSelector = NewNodesetSelector(DefaultNodesetSelectorName, MetaNodeType)
	return
}

func printZonesName(zones []*Zone) string {
	str := "["
	if len(zones) == 0 {
		return str
	}

	for _, zone := range zones {
		str = str + zone.name + ","
	}

	return str
}

func (zone *Zone) GetDataNodesetSelector() string {
	zone.dataNodesetSelectorLock.RLock()
	defer zone.dataNodesetSelectorLock.RUnlock()
	return zone.dataNodesetSelector.GetName()
}

func (zone *Zone) SetDataNodesetSelector(name string) {
	zone.dataNodesetSelectorLock.Lock()
	defer zone.dataNodesetSelectorLock.Unlock()
	zone.dataNodesetSelector = NewNodesetSelector(name, DataNodeType)
}

func (zone *Zone) GetMetaNodesetSelector() string {
	zone.metaNodesetSelectorLock.RLock()
	defer zone.metaNodesetSelectorLock.RUnlock()
	return zone.metaNodesetSelector.GetName()
}

func (zone *Zone) SetMetaNodeSelector(name string) {
	zone.metaNodesetSelectorLock.Lock()
	defer zone.metaNodesetSelectorLock.Unlock()
	zone.metaNodesetSelector = NewNodesetSelector(name, MetaNodeType)
}

func (zone *Zone) getFsmValue() *zoneValue {
	return &zoneValue{
		Name:                zone.name,
		QosIopsRLimit:       zone.QosIopsRLimit,
		QosIopsWLimit:       zone.QosIopsWLimit,
		QosFlowRLimit:       zone.QosFlowRLimit,
		QosFlowWLimit:       zone.QosFlowWLimit,
		DataNodesetSelector: zone.GetDataNodesetSelector(),
		MetaNodesetSelector: zone.GetMetaNodesetSelector(),
	}
}

func (zone *Zone) setStatus(status int) {
	zone.status = status
}

func (zone *Zone) getStatus() int {
	return zone.status
}

func (zone *Zone) getStatusToString() string {
	if zone.status == normalZone {
		return "available"
	} else {
		return "unavailable"
	}
}

func (zone *Zone) isSingleNodeSet() bool {
	zone.RLock()
	defer zone.RUnlock()
	return len(zone.nodeSetMap) == 1
}

func (zone *Zone) getNodeSet(setID uint64) (ns *nodeSet, err error) {
	zone.nsLock.RLock()
	defer zone.nsLock.RUnlock()
	ns, ok := zone.nodeSetMap[setID]
	if !ok {
		return nil, errors.NewErrorf("set %v not found", setID)
	}
	return
}

func (zone *Zone) putNodeSet(ns *nodeSet) (err error) {
	zone.nsLock.Lock()
	defer zone.nsLock.Unlock()

	if _, ok := zone.nodeSetMap[ns.ID]; ok {
		return fmt.Errorf("nodeSet [%v] has exist", ns.ID)
	}
	zone.nodeSetMap[ns.ID] = ns
	return
}

func (zone *Zone) createNodeSet(c *Cluster) (ns *nodeSet, err error) {
	cnt := 1
	allNodeSet := zone.getAllNodeSet()
	log.LogInfof("action[createNodeSet] zone[%v] FaultDomain:[%v] init[%v] DefaultNormalZoneCnt[%v] nodeset cnt[%v]",
		zone.name, c.FaultDomain, c.domainManager.init, c.cfg.DefaultNormalZoneCnt, len(allNodeSet))

	if c.FaultDomain && c.domainManager.init && c.cfg.DefaultNormalZoneCnt < defaultReplicaNum {
		if _, ok := c.domainManager.excludeZoneListDomain[zone.name]; !ok {
			dstNsCnt := 0
			if c.cfg.DefaultNormalZoneCnt == 1 { // one zone support domain need 3 nodeset at begin
				dstNsCnt = 3
			} else {
				dstNsCnt = 2 // two zone construct domain need 2 nodeset for each
			}
			if len(allNodeSet) < dstNsCnt {
				log.LogInfof("action[createNodeSet] zone[%v] nodeset len:[%v] less then 3,create to 3 one time",
					zone.name, len(allNodeSet))
				cnt = dstNsCnt - len(allNodeSet)
			}
		} else {
			log.LogInfof("action[createNodeSet] zone[%v] get in excludeZoneListDomain", zone.name)
		}
	}

	for {
		if cnt == 0 {
			break
		}
		cnt--
		id, err := c.idAlloc.allocateCommonID()
		if err != nil {
			return nil, err
		}
		ns = newNodeSet(c, id, c.cfg.nodeSetCapacity, zone.name)
		ns.UpdateMaxParallel(int32(c.DecommissionLimit))
		ns.UpdateDecommissionDiskFactor(c.DecommissionDiskFactor)
		ns.startDecommissionSchedule()
		log.LogInfof("action[createNodeSet] syncAddNodeSet[%v] zonename[%v]", ns.ID, zone.name)
		if err = c.syncAddNodeSet(ns); err != nil {
			return nil, err
		}
		if err = zone.putNodeSet(ns); err != nil {
			return nil, err
		}
		log.LogInfof("action[createNodeSet] nodeSet[%v]", ns.ID)
	}
	return
}

func (zone *Zone) getAllNodeSet() (nsc nodeSetCollection) {
	zone.nsLock.RLock()
	defer zone.nsLock.RUnlock()
	nsc = make(nodeSetCollection, 0)
	for _, ns := range zone.nodeSetMap {
		nsc = append(nsc, ns)
	}
	return
}

func (zone *Zone) getAvailNodeSetForMetaNode() (nset *nodeSet) {
	allNodeSet := zone.getAllNodeSet()
	sort.Sort(sort.Reverse(allNodeSet))

	for _, ns := range allNodeSet {
		if ns.metaNodeLen() < ns.Capacity {
			if nset == nil {
				nset = ns
			} else {
				if nset.Capacity-nset.metaNodeLen() < ns.Capacity-ns.metaNodeLen() {
					nset = ns
				}
			}
			continue
		}
	}
	return
}

func (zone *Zone) getAvailNodeSetForDataNode() (nset *nodeSet) {
	allNodeSet := zone.getAllNodeSet()
	for _, ns := range allNodeSet {
		if ns.dataNodeLen() < ns.Capacity {
			if nset == nil {
				nset = ns
			} else {
				if nset.Capacity-nset.dataNodeLen() < ns.Capacity-ns.dataNodeLen() {
					nset = ns
				}
			}
			continue
		}
	}
	return
}

func (zone *Zone) putDataNode(dataNode *DataNode) (err error) {
	var ns *nodeSet
	if ns, err = zone.getNodeSet(dataNode.NodeSetID); err != nil {
		log.LogErrorf("action[putDataNode] nodeSet[%v] not found", dataNode.NodeSetID)
		return
	}
	ns.putDataNode(dataNode)
	zone.dataNodes.Store(dataNode.Addr, dataNode)
	return
}

func (zone *Zone) getDataNode(addr string) (dataNode *DataNode, err error) {
	value, ok := zone.dataNodes.Load(addr)
	if !ok {
		return nil, errors.Trace(dataNodeNotFound(addr), "%v not found", addr)
	}
	dataNode = value.(*DataNode)
	return
}

func (zone *Zone) deleteDataNode(dataNode *DataNode) {
	ns, err := zone.getNodeSet(dataNode.NodeSetID)
	if err != nil {
		log.LogErrorf("action[zoneDeleteDataNode] nodeSet[%v] not found", dataNode.NodeSetID)
		return
	}
	ns.deleteDataNode(dataNode)
	zone.dataNodes.Delete(dataNode.Addr)
}

func (zone *Zone) putMetaNode(metaNode *MetaNode) (err error) {
	var ns *nodeSet
	if ns, err = zone.getNodeSet(metaNode.NodeSetID); err != nil {
		log.LogErrorf("action[zonePutMetaNode] nodeSet[%v] not found", metaNode.NodeSetID)
		return
	}
	ns.putMetaNode(metaNode)
	zone.metaNodes.Store(metaNode.Addr, metaNode)
	return
}

func (zone *Zone) deleteMetaNode(metaNode *MetaNode) (err error) {
	ns, err := zone.getNodeSet(metaNode.NodeSetID)
	if err != nil {
		log.LogErrorf("action[zoneDeleteMetaNode] nodeSet[%v] not found", metaNode.NodeSetID)
		return
	}
	ns.deleteMetaNode(metaNode)
	zone.metaNodes.Delete(metaNode.Addr)
	return
}

func (zone *Zone) allocNodeSetForDataNode(excludeNodeSets []uint64, replicaNum uint8) (ns *nodeSet, err error) {
	nset := zone.getAllNodeSet()
	if nset == nil {
		return nil, errors.NewError(proto.ErrNoNodeSetToCreateDataPartition)
	}

	zone.nsLock.Lock()
	defer zone.nsLock.Unlock()
	// we need a read lock to block the modify of nodeset selector
	zone.dataNodesetSelectorLock.RLock()
	defer zone.dataNodesetSelectorLock.RUnlock()

	ns, err = zone.dataNodesetSelector.Select(nset, excludeNodeSets, replicaNum)

	if err != nil {
		log.LogErrorf("action[allocNodeSetForDataNode],nset len[%v],excludeNodeSets[%v],rNum[%v] err:%v",
			nset.Len(), excludeNodeSets, replicaNum, proto.ErrNoNodeSetToCreateDataPartition)
		return nil, errors.NewError(proto.ErrNoNodeSetToCreateDataPartition)
	}
	return ns, nil
}

func (zone *Zone) allocNodeSetForMetaNode(excludeNodeSets []uint64, replicaNum uint8) (ns *nodeSet, err error) {
	nset := zone.getAllNodeSet()
	if nset == nil {
		return nil, proto.ErrNoNodeSetToCreateMetaPartition
	}

	zone.nsLock.Lock()
	defer zone.nsLock.Unlock()
	// we need a read lock to block the modify of nodeset selector
	zone.metaNodesetSelectorLock.RLock()
	defer zone.metaNodesetSelectorLock.RUnlock()
	ns, err = zone.metaNodesetSelector.Select(nset, excludeNodeSets, replicaNum)

	if err != nil {
		log.LogError(fmt.Sprintf("action[allocNodeSetForMetaNode],zone[%v],excludeNodeSets[%v],rNum[%v],err:%v",
			zone.name, excludeNodeSets, replicaNum, proto.ErrNoNodeSetToCreateMetaPartition))
		return nil, proto.ErrNoNodeSetToCreateMetaPartition
	}
	return ns, nil
}

func (zone *Zone) canWriteForDataNode(replicaNum uint8) (can bool) {
	zone.RLock()
	defer zone.RUnlock()
	var leastAlive uint8
	zone.dataNodes.Range(func(addr, value interface{}) bool {
		dataNode := value.(*DataNode)
		if !dataNode.dpCntInLimit() {
			return true
		}
		if dataNode.isActive && dataNode.isWriteAbleWithSize(30*util.GB) {
			leastAlive++
		}
		if leastAlive >= replicaNum {
			can = true
			return false
		}
		return true
	})
	log.LogInfof("canWriteForDataNode leastAlive[%v],replicaNum[%v],count[%v]\n", leastAlive, replicaNum, zone.dataNodeCount())
	return
}

func (zone *Zone) isUsedRatio(ratio float64) (can bool) {
	zone.RLock()
	defer zone.RUnlock()
	var (
		dataNodeUsed  uint64
		dataNodeTotal uint64
		metaNodeUsed  uint64
		metaNodeTotal uint64
	)
	zone.dataNodes.Range(func(addr, value interface{}) bool {
		dataNode := value.(*DataNode)
		if dataNode.isActive == true {
			dataNodeUsed += dataNode.Used
		} else {
			dataNodeUsed += dataNode.Total
		}
		dataNodeTotal += dataNode.Total
		return true
	})

	if float64(dataNodeUsed)/float64(dataNodeTotal) > ratio {
		log.LogInfof("action[isUsedRatio] zone[%v] dataNodeUsed [%v] total [%v], ratio[%v]", zone.name, dataNodeUsed, dataNodeTotal, ratio)
		return true
	}

	zone.metaNodes.Range(func(addr, value interface{}) bool {
		metaNode := value.(*MetaNode)
		if metaNode.IsActive == true && metaNode.isWritable() == true {
			metaNodeUsed += metaNode.Used
		} else {
			metaNodeUsed += metaNode.Total
		}
		metaNodeTotal += metaNode.Total
		return true
	})

	if float64(metaNodeUsed)/float64(metaNodeTotal) > ratio {
		log.LogInfof("action[isUsedRatio] zone[%v] metaNodeUsed [%v] total [%v], ratio[%v]", zone.name, metaNodeUsed, metaNodeTotal, ratio)
		return true
	}

	return false
}

func (zone *Zone) getDataUsed() (dataNodeUsed uint64, dataNodeTotal uint64) {
	zone.RLock()
	defer zone.RUnlock()
	zone.dataNodes.Range(func(addr, value interface{}) bool {
		dataNode := value.(*DataNode)
		if dataNode.isActive == true {
			dataNodeUsed += dataNode.Used
		} else {
			dataNodeUsed += dataNode.Total
		}
		dataNodeTotal += dataNode.Total
		return true
	})

	return dataNodeUsed, dataNodeTotal
}

func (zone *Zone) getMetaUsed() (metaNodeUsed uint64, metaNodeTotal uint64) {
	zone.RLock()
	defer zone.RUnlock()

	zone.metaNodes.Range(func(addr, value interface{}) bool {
		metaNode := value.(*MetaNode)
		if metaNode.IsActive == true && metaNode.isWritable() == true {
			metaNodeUsed += metaNode.Used
		} else {
			metaNodeUsed += metaNode.Total
		}
		metaNodeTotal += metaNode.Total
		return true
	})
	return metaNodeUsed, metaNodeTotal
}

func (zone *Zone) getSpaceLeft(dataType uint32) (spaceLeft uint64) {
	if dataType == TypeDataPartition {
		dataNodeUsed, dataNodeTotal := zone.getDataUsed()
		return dataNodeTotal - dataNodeUsed
	} else {
		metaNodeUsed, metaNodeTotal := zone.getMetaUsed()
		return metaNodeTotal - metaNodeUsed
	}
}

func (zone *Zone) canWriteForMetaNode(replicaNum uint8) (can bool) {
	zone.RLock()
	defer zone.RUnlock()
	var leastAlive uint8
	zone.metaNodes.Range(func(addr, value interface{}) bool {
		metaNode := value.(*MetaNode)
		if metaNode.IsActive == true && metaNode.isWritable() == true {
			leastAlive++
		}
		if leastAlive >= replicaNum {
			can = true
			return false
		}
		return true
	})
	return
}

func (zone *Zone) getDataNodeMaxTotal() (maxTotal uint64) {
	zone.dataNodes.Range(func(key, value interface{}) bool {
		dataNode := value.(*DataNode)
		if dataNode.Total > maxTotal {
			maxTotal = dataNode.Total
		}
		return true
	})
	return
}

func (zone *Zone) getAvailNodeHosts(nodeType uint32, excludeNodeSets []uint64, excludeHosts []string, replicaNum int) (newHosts []string, peers []proto.Peer, err error) {
	if replicaNum == 0 {
		return
	}

	log.LogDebugf("[x] get node host, zone(%s), nodeType(%d)", zone.name, nodeType)

	if nodeType == TypeDataPartition {
		ns, err := zone.allocNodeSetForDataNode(excludeNodeSets, uint8(replicaNum))
		if err != nil {
			return nil, nil, errors.Trace(err, "zone[%v] alloc node set,replicaNum[%v]", zone.name, replicaNum)
		}
		return ns.getAvailDataNodeHosts(excludeHosts, replicaNum)
	}

	ns, err := zone.allocNodeSetForMetaNode(excludeNodeSets, uint8(replicaNum))
	if err != nil {
		return nil, nil, errors.NewErrorf("zone[%v],err[%v]", zone.name, err)
	}

	return ns.getAvailMetaNodeHosts(excludeHosts, replicaNum)
}

func (zone *Zone) updateNodesetSelector(cluster *Cluster, dataNodesetSelector string, metaNodesetSelector string) error {
	needSync := false
	if dataNodesetSelector != "" && dataNodesetSelector != zone.GetDataNodesetSelector() {
		needSync = true
		zone.SetDataNodesetSelector(dataNodesetSelector)
	}
	if metaNodesetSelector != "" && metaNodesetSelector != zone.GetMetaNodesetSelector() {
		needSync = true
		zone.SetMetaNodeSelector(metaNodesetSelector)
	}
	if !needSync {
		return nil
	}
	return cluster.sycnPutZoneInfo(zone)
}

func (zone *Zone) updateDataNodeQosLimit(cluster *Cluster, qosParam *qosArgs) error {
	var err error
	if qosParam.flowRVal > 0 {
		zone.QosFlowRLimit = qosParam.flowRVal
	}
	if qosParam.flowWVal > 0 {
		zone.QosFlowWLimit = qosParam.flowWVal
	}
	if qosParam.iopsRVal > 0 {
		zone.QosIopsRLimit = qosParam.iopsRVal
	}
	if qosParam.iopsWVal > 0 {
		zone.QosIopsWLimit = qosParam.iopsWVal
	}

	if err = cluster.sycnPutZoneInfo(zone); err != nil {
		return err
	}
	zone.dataNodes.Range(func(key, value interface{}) bool {
		dataNode := value.(*DataNode)
		if qosParam.flowRVal > 0 {
			dataNode.QosFlowRLimit = qosParam.flowRVal
		}
		if qosParam.flowWVal > 0 {
			dataNode.QosFlowWLimit = qosParam.flowWVal
		}
		if qosParam.iopsRVal > 0 {
			dataNode.QosIopsRLimit = qosParam.iopsRVal
		}
		if qosParam.iopsWVal > 0 {
			dataNode.QosIopsWLimit = qosParam.iopsWVal
		}
		return true
	})
	return nil
}

func (zone *Zone) loadDataNodeQosLimit() {
	zone.dataNodes.Range(func(key, value interface{}) bool {
		dataNode := value.(*DataNode)
		if zone.QosFlowRLimit > 0 {
			dataNode.QosFlowRLimit = zone.QosFlowRLimit
		}
		if zone.QosFlowWLimit > 0 {
			dataNode.QosFlowWLimit = zone.QosFlowWLimit
		}
		if zone.QosIopsRLimit > 0 {
			dataNode.QosIopsRLimit = zone.QosIopsRLimit
		}
		if zone.QosIopsWLimit > 0 {
			dataNode.QosIopsWLimit = zone.QosIopsWLimit
		}
		return true
	})
}

func (zone *Zone) dataNodeCount() (len int) {
	zone.dataNodes.Range(func(key, value interface{}) bool {
		len++
		return true
	})
	return
}

func (zone *Zone) updateDecommissionLimit(limit int32, c *Cluster) (err error) {
	nodeSets := zone.getAllNodeSet()

	if nodeSets == nil {
		log.LogWarnf("Nodeset form %v is nil", zone.name)
		return proto.ErrNoNodeSetToUpdateDecommissionLimit
	}

	for _, ns := range nodeSets {
		ns.UpdateMaxParallel(limit)
		if err = c.syncUpdateNodeSet(ns); err != nil {
			log.LogWarnf("UpdateMaxParallel nodeset [%v] failed,err:%v", ns.ID, err.Error())
			continue
		}
	}
	log.LogInfof("All nodeset from %v set decommission limit to %v", zone.name, limit)
	return
}

func (zone *Zone) updateDecommissionDiskFactor(factor float64, c *Cluster) (err error) {
	nodeSets := zone.getAllNodeSet()

	if nodeSets == nil {
		log.LogWarnf("Nodeset form %v is nil", zone.name)
		return proto.ErrNoNodeSetToUpdateDecommissionDiskFactor
	}

	for _, ns := range nodeSets {
		ns.UpdateDecommissionDiskFactor(factor)
		if err = c.syncUpdateNodeSet(ns); err != nil {
			log.LogWarnf("updateDecommissionDiskFactor nodeset [%v] failed,err:%v", ns.ID, err.Error())
			continue
		}
	}
	log.LogInfof("All nodeset from %v set decommission disk factor to %v", zone.name, factor)
	return
}

func (zone *Zone) queryDecommissionDiskLimit() (err error, diskLimit []proto.DecommissionDiskLimitDetail) {
	nodeSets := zone.getAllNodeSet()
	diskLimit = make([]proto.DecommissionDiskLimitDetail, 0)
	if nodeSets == nil {
		log.LogWarnf("Nodeset form %v is nil", zone.name)
		return proto.ErrNoNodeSetToQueryDecommissionDiskLimit, nil
	}

	for _, ns := range nodeSets {
		limit := ns.QueryDecommissionDiskLimit()
		diskLimit = append(diskLimit, proto.DecommissionDiskLimitDetail{NodeSetId: ns.ID, Limit: limit})
	}
	log.LogInfof("All nodeset from %v set decommission disk limit  %v", zone.name, diskLimit)
	return
}

func (zone *Zone) queryDecommissionParallelStatus() (err error, stats []nodeSetDecommissionParallelStatus) {
	nodeSets := zone.getAllNodeSet()

	if nodeSets == nil {
		log.LogWarnf("Nodeset form %v is nil", zone.name)
		return proto.ErrNoNodeSetToQueryDecommissionLimitStatus, stats
	}

	for _, ns := range nodeSets {
		curToken, maxToken, dps := ns.getDecommissionParallelStatus()
		stat := nodeSetDecommissionParallelStatus{
			ID:          ns.ID,
			CurTokenNum: curToken,
			MaxTokenNum: maxToken,
			RunningDp:   dps,
		}
		stats = append(stats, stat)
	}
	log.LogInfof("All nodeset from %v  decommission limit status %v", zone.name, stats)
	return
}

func (zone *Zone) startDecommissionListTraverse(c *Cluster) (err error) {
	nodeSets := zone.getAllNodeSet()
	log.LogDebugf("startDecommissionListTraverse nodeSets len %v ", len(nodeSets))
	if len(nodeSets) == 0 {
		log.LogWarnf("action[startDecommissionListTraverse] Nodeset form %v is nil", zone.name)
		return nil
	}

	for _, ns := range nodeSets {
		log.LogInfof("action[startDecommissionListTraverse] ns[%v] from zone %v", ns.ID, zone.name)
		ns.startDecommissionSchedule()
	}
	log.LogInfof("action[startDecommissionListTraverse] All nodeset from %v start decommission schedule", zone.name)
	return
}

type DecommissionDataPartitionList struct {
	mu               sync.Mutex
	cacheMap         map[uint64]*list.Element
	decommissionList *list.List
	done             chan struct{}
	parallelLimit    int32
	curParallel      int32
	start            chan struct{}
	runningMap       map[uint64]struct{}
}

type DecommissionDataPartitionListValue struct {
	DecommissionDataPartitionCacheValue
	ParallelLimit int32
	CurParallel   int32
}

type DecommissionDataPartitionCacheValue struct {
	CacheMap []dataPartitionValue
	Status   uint32
}

const DecommissionInterval = 5 * time.Second

func NewDecommissionDataPartitionList(c *Cluster) *DecommissionDataPartitionList {
	l := new(DecommissionDataPartitionList)
	l.mu = sync.Mutex{}
	l.cacheMap = make(map[uint64]*list.Element)
	l.done = make(chan struct{}, 1)
	l.start = make(chan struct{}, 1)
	l.decommissionList = list.New()
	l.runningMap = make(map[uint64]struct{})
	atomic.StoreInt32(&l.curParallel, 0)
	atomic.StoreInt32(&l.parallelLimit, defaultDecommissionParallelLimit)
	go l.traverse(c)
	return l
}

// reserved
func (l *DecommissionDataPartitionList) Stop() {
	l.done <- struct{}{}
}

func (l *DecommissionDataPartitionList) Length() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.decommissionList.Len()
}

func (l *DecommissionDataPartitionList) Put(id uint64, value *DataPartition, c *Cluster) {
	if value == nil {
		log.LogWarnf("action[DecommissionDataPartitionListPut] ns[%v] cannot put nil value", id)
		return
	}
	// can only add running or mark or prepare or failed without reaching roll back max
	if !value.canAddToDecommissionList() {
		log.LogWarnf("action[DecommissionDataPartitionListPut] ns[%v] put wrong dp[%v] status[%v] DecommissionNeedRollbackTimes(%v)",
			id, value.PartitionID, value.GetDecommissionStatus(), value.DecommissionNeedRollbackTimes)
		return
	}
	// prepare status reset to mark status to retry again
	if value.GetDecommissionStatus() == DecommissionPrepare {
		value.SetDecommissionStatus(markDecommission)
	}

	l.mu.Lock()
	if _, ok := l.cacheMap[value.PartitionID]; ok {
		l.mu.Unlock()
		return
	}
	elm := l.decommissionList.PushBack(value)
	l.cacheMap[value.PartitionID] = elm
	l.mu.Unlock()
	// restore from rocksdb
	if value.checkConsumeToken() {
		value.TryAcquireDecommissionToken(c)
	}
	log.LogInfof("action[DecommissionDataPartitionListPut] ns[%v] add dp[%v] status[%v] isRecover[%v] rollbackTimes(%v)",
		id, value.PartitionID, value.GetDecommissionStatus(), value.isRecover, value.DecommissionNeedRollbackTimes)
}

func (l *DecommissionDataPartitionList) pushFailedDp(value *DataPartition, c *Cluster) {
	if value == nil {
		log.LogWarnf("action[pushFailedDp] cannot put nil value")
		return
	}
	status := value.GetDecommissionStatus()
	if status != markDecommission && status != DecommissionFail {
		log.LogWarnf("action[pushFailedDp]  dp(%v) wrong status %v", value.PartitionID, status)
		return
	}
	l.Remove(value)
	l.mu.Lock()
	elm := l.decommissionList.PushFront(value)
	l.cacheMap[value.PartitionID] = elm
	l.mu.Unlock()
	log.LogInfof("action[pushFailedDp]  add dp[%v] status[%v] isRecover[%v]",
		value.PartitionID, status, value.isRecover)
	return
}

func (l *DecommissionDataPartitionList) Remove(value *DataPartition) {
	if value == nil {
		log.LogWarnf("Cannot remove nil value")
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if elm, ok := l.cacheMap[value.PartitionID]; ok {
		delete(l.cacheMap, value.PartitionID)
		l.decommissionList.Remove(elm)
		log.LogDebugf("Remove dp[%v]", value.PartitionID)
	}
}

func (l *DecommissionDataPartitionList) getDecommissionParallelStatus() (int32, int32, []uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	dps := make([]uint64, 0)
	for id := range l.runningMap {
		dps = append(dps, id)
	}

	return atomic.LoadInt32(&l.curParallel), atomic.LoadInt32(&l.parallelLimit), dps
}

func (l *DecommissionDataPartitionList) updateMaxParallel(maxParallel int32) {
	atomic.StoreInt32(&l.parallelLimit, maxParallel)
}

func (l *DecommissionDataPartitionList) acquireDecommissionToken(id uint64) bool {
	if atomic.LoadInt32(&l.parallelLimit) == 0 {
		l.mu.Lock()
		l.runningMap[id] = struct{}{}
		atomic.StoreInt32(&l.curParallel, int32(len(l.runningMap)))
		l.mu.Unlock()
		return true
	}
	if atomic.LoadInt32(&l.curParallel) >= atomic.LoadInt32(&l.parallelLimit) {
		return false
	}

	l.mu.Lock()
	l.runningMap[id] = struct{}{}
	atomic.StoreInt32(&l.curParallel, int32(len(l.runningMap)))
	l.mu.Unlock()
	return true
}

func (l *DecommissionDataPartitionList) releaseDecommissionToken(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.runningMap[id]; !ok {
		return
	}
	delete(l.runningMap, id)
	atomic.StoreInt32(&l.curParallel, int32(len(l.runningMap)))
}

func (l *DecommissionDataPartitionList) GetAllDecommissionDataPartitions() (collection []*DataPartition) {
	l.mu.Lock()
	defer l.mu.Unlock()
	collection = make([]*DataPartition, 0, l.decommissionList.Len())
	for elm := l.decommissionList.Front(); elm != nil; elm = elm.Next() {
		collection = append(collection, elm.Value.(*DataPartition))
	}
	return collection
}

func (l *DecommissionDataPartitionList) startTraverse() {
	l.start <- struct{}{}
}

func (l *DecommissionDataPartitionList) traverse(c *Cluster) {
	t := time.NewTicker(DecommissionInterval)
	// wait for loading all ap when reload metadata
	<-l.start
	defer t.Stop()
	for {
		select {
		case <-l.done:
			log.LogWarnf("traverse stopped!")
			return
		case <-t.C:
			if c.partition != nil && !c.partition.IsRaftLeader() {
				log.LogWarnf("Leader changed, stop traverse!")
				continue
			}
			allDecommissionDP := l.GetAllDecommissionDataPartitions()
			for _, dp := range allDecommissionDP {
				if dp.IsDecommissionSuccess() {
					log.LogDebugf("action[DecommissionListTraverse]Remove dp[%v] for success",
						dp.PartitionID)
					l.Remove(dp)
					dp.ReleaseDecommissionToken(c)
					dp.ResetDecommissionStatus()
					c.syncUpdateDataPartition(dp)
				} else if dp.IsDecommissionFailed() {
					if !dp.tryRollback(c) {
						log.LogDebugf("action[DecommissionListTraverse]Remove dp[%v] for fail",
							dp.PartitionID)
						l.Remove(dp)
					}
					// rollback fail/success need release token
					dp.ReleaseDecommissionToken(c)
				} else if dp.IsDecommissionPaused() {
					log.LogDebugf("action[DecommissionListTraverse]Remove dp[%v] for paused ",
						dp.PartitionID)
					dp.ReleaseDecommissionToken(c)
					l.Remove(dp)
				} else if dp.IsDecommissionInitial() { // fixed done ,not release token
					l.Remove(dp)
					dp.ResetDecommissionStatus()
					c.syncUpdateDataPartition(dp)
				} else if dp.IsMarkDecommission() && dp.TryAcquireDecommissionToken(c) {
					// TODO: decommission in here
					go func(dp *DataPartition) {
						if !dp.TryToDecommission(c) {
							// retry should release token
							if dp.IsMarkDecommission() {
								dp.ReleaseDecommissionToken(c)
							}
							l.pushFailedDp(dp, c)
						}
					}(dp) // special replica cnt cost some time from prepare to running
				}
			}
		}
	}
}

type DecommissionDiskList struct {
	mu               sync.Mutex
	cacheMap         map[string]*list.Element
	decommissionList *list.List
}

func NewDecommissionDiskList() *DecommissionDiskList {
	l := new(DecommissionDiskList)
	l.mu = sync.Mutex{}
	l.cacheMap = make(map[string]*list.Element)
	l.decommissionList = list.New()
	return l
}

func (l *DecommissionDiskList) Put(nsId uint64, value *DecommissionDisk) {
	if value == nil {
		log.LogWarnf("action[DecommissionDataPartitionListPut] ns[%v] cannot put nil value", nsId)
		return
	}
	// can only add running or mark
	if !value.canAddToDecommissionList() {
		log.LogWarnf("action[DecommissionDataPartitionListPut] ns[%v] put wrong disk[%v] status[%v]",
			nsId, value.GenerateKey(), value.GetDecommissionStatus())
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.cacheMap[value.GenerateKey()]; ok {
		return
	}
	elm := l.decommissionList.PushBack(value)
	l.cacheMap[value.GenerateKey()] = elm

	log.LogDebugf("action[DecommissionDataPartitionListPut] ns[%v] add disk[%v] status[%v] type[%v]",
		nsId, value.GenerateKey(), value.GetDecommissionStatus(), value.Type)
}

func (l *DecommissionDiskList) Remove(nsId uint64, value *DecommissionDisk) {
	if value == nil {
		log.LogWarnf("action[DecommissionDataPartitionListRemove] ns[%v]Cannot remove nil value", nsId)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if elm, ok := l.cacheMap[value.GenerateKey()]; ok {
		delete(l.cacheMap, value.GenerateKey())
		l.decommissionList.Remove(elm)
		log.LogDebugf("action[DecommissionDataPartitionListRemove] ns[%v] remove disk[%v]", nsId, value.GenerateKey())
	}
}

func (l *DecommissionDiskList) Length() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.decommissionList.Len()
}

// only pop decommission disk with markDecommission status from front
func (l *DecommissionDiskList) PopMarkDecommissionDisk(limit int) (count int, collection []*DecommissionDisk) {
	l.mu.Lock()
	defer l.mu.Unlock()
	collection = make([]*DecommissionDisk, count)
	count = 0
	for elm := l.decommissionList.Front(); elm != nil; elm = elm.Next() {
		if count == limit && limit != 0 {
			break
		}
		disk := elm.Value.(*DecommissionDisk)
		if disk.GetDecommissionStatus() != markDecommission {
			continue
		}
		collection = append(collection, disk)
		count++
		log.LogDebugf("action[PopMarkDecommissionDisk] pop disk[%v]", disk)
	}
	return count, collection
}
