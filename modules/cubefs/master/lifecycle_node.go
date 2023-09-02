// Copyright 2023 The CubeFS Authors.
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
	"sync"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/log"
)

type LcNode struct {
	ID          uint64
	Addr        string
	ReportTime  time.Time
	IsActive    bool
	TaskManager *AdminTaskManager
	sync.RWMutex
}

func newLcNode(addr, clusterID string) (lcNode *LcNode) {
	lcNode = new(LcNode)
	lcNode.Addr = addr
	lcNode.IsActive = true
	lcNode.ReportTime = time.Now()
	lcNode.TaskManager = newAdminTaskManager(lcNode.Addr, clusterID)
	return
}

func (lcNode *LcNode) clean() {
	lcNode.TaskManager.exitCh <- struct{}{}
}

func (lcNode *LcNode) checkLiveness() {
	lcNode.Lock()
	defer lcNode.Unlock()
	log.LogInfof("action[checkLiveness] lcnode[%v] report time[%v],since report time[%v], need gap [%v]",
		lcNode.Addr, lcNode.ReportTime, time.Since(lcNode.ReportTime), time.Second*time.Duration(defaultNodeTimeOutSec))
	if time.Since(lcNode.ReportTime) > time.Second*time.Duration(defaultNodeTimeOutSec) {
		lcNode.IsActive = false
	}

	return
}

func (lcNode *LcNode) createHeartbeatTask(masterAddr string) (task *proto.AdminTask) {
	request := &proto.HeartBeatRequest{
		CurrTime:   time.Now().Unix(),
		MasterAddr: masterAddr,
	}
	task = proto.NewAdminTask(proto.OpLcNodeHeartbeat, lcNode.Addr, request)
	return
}

func (lcNode *LcNode) createLcScanTask(masterAddr string, ruleTask *proto.RuleTask) (task *proto.AdminTask) {
	request := &proto.LcNodeRuleTaskRequest{
		MasterAddr: masterAddr,
		LcNodeAddr: lcNode.Addr,
		Task:       ruleTask,
	}
	task = proto.NewAdminTaskEx(proto.OpLcNodeScan, lcNode.Addr, request, ruleTask.Id)
	return
}

func (lcNode *LcNode) createSnapshotVerDelTask(masterAddr string, sTask *proto.SnapshotVerDelTask) (task *proto.AdminTask) {

	request := &proto.SnapshotVerDelTaskRequest{
		MasterAddr: masterAddr,
		LcNodeAddr: lcNode.Addr,
		Task:       sTask,
	}
	task = proto.NewAdminTaskEx(proto.OpLcNodeSnapshotVerDel, lcNode.Addr, request, request.Task.Id)
	return
}
