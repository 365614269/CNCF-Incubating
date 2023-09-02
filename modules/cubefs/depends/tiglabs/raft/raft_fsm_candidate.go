// Copyright 2015 The etcd Authors
// Modified work copyright 2018 The tiglabs Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package raft

import (
	"fmt"

	"github.com/cubefs/cubefs/depends/tiglabs/raft/logger"
	"github.com/cubefs/cubefs/depends/tiglabs/raft/proto"
)

// first become preCandidate,
func (r *raftFsm) becomeCandidate() {
	if r.state == stateLeader {
		panic(AppPanicError(fmt.Sprintf("[raft->becomeCandidate][%v] invalid transition [leader -> candidate].", r.id)))
	}

	r.monitorElection()
	r.step = stepCandidate
	r.reset(r.term+1, 0, false)
	r.tick = r.tickElection
	r.vote = r.config.NodeID
	r.state = stateCandidate
	if logger.IsEnableDebug() {
		logger.Debug("raft[%v] became candidate at term %d.", r.id, r.config.TransportConfig.ReplicateAddr, r.term)
	}
}

func stepCandidate(r *raftFsm, m *proto.Message) {
	switch m.Type {
	case proto.LocalMsgProp:
		if logger.IsEnableDebug() {
			logger.Debug("raft[%v] no leader at term %d; dropping proposal.", r.id, r.term)
		}
		proto.ReturnMessage(m)
		return

	case proto.ReqMsgAppend:
		r.becomeFollower(r.term, m.From)
		r.handleAppendEntries(m)
		proto.ReturnMessage(m)
		return

	case proto.ReqMsgHeartBeat:
		r.becomeFollower(r.term, m.From)
		return

	case proto.ReqMsgPreVote:
		r.becomeFollower(r.term, m.From)
		nmsg := proto.GetMessage()
		nmsg.Type = proto.RespMsgPreVote
		nmsg.To = m.From
		r.send(nmsg)
		proto.ReturnMessage(m)
		return

	case proto.ReqMsgVote:
		if logger.IsEnableDebug() {
			logger.Debug("raft[%v] [logterm: %d, index: %d, vote: %v] rejected vote from %v [logterm: %d, index: %d] at term %d.", r.id, r.raftLog.lastTerm(), r.raftLog.lastIndex(), r.vote, m.From, m.LogTerm, m.Index, r.term)
		}
		nmsg := proto.GetMessage()
		nmsg.Type = proto.RespMsgVote
		nmsg.To = m.From
		nmsg.Reject = true
		r.send(nmsg)
		proto.ReturnMessage(m)
		return

	case proto.RespMsgVote:
		gr := r.poll(m.From, !m.Reject)
		if logger.IsEnableDebug() {
			logger.Debug("raft[%v] [q:%d] has received %d votes and %d vote rejections.", r.id, r.quorum(), gr, len(r.votes)-gr)
		}
		switch r.quorum() {
		case gr:
			r.becomeLeader()
			r.bcastAppend()
		case len(r.votes) - gr:
			r.becomeFollower(r.term, NoLeader)
		}
	}
}

func (r *raftFsm) campaign(force bool, t CampaignType) {
	var msgType proto.MsgType
	var term uint64
	if t == campaignPreElection {
		r.becomePreCandidate()
		msgType = proto.ReqMsgPreVote
		term = r.term + 1
	} else {
		r.becomeCandidate()
		msgType = proto.ReqMsgVote
	}

	if r.quorum() == r.poll(r.config.NodeID, true) {
		if t == campaignPreElection {
			r.campaign(force, campaignElection)
		} else {
			r.becomeLeader()
		}
		return
	}

	for id := range r.replicas {
		if id == r.config.NodeID {
			continue
		}
		li, lt := r.raftLog.lastIndexAndTerm()
		if logger.IsEnableDebug() {
			logger.Debug("[raft->campaign][%v,%v logterm: %d, index: %d] sent "+
				"%v request to %v at term %d.   raftFSM[%p]", msgType, r.id, r.config.ReplicateAddr, lt, li, id, r.term, r)
		}

		m := proto.GetMessage()
		m.To = id
		m.Type = msgType
		m.ForceVote = force
		m.Index = li
		m.LogTerm = lt
		m.Term = term
		r.send(m)
	}
}

func (r *raftFsm) poll(id uint64, v bool) (granted int) {
	if logger.IsEnableDebug() {
		if v {
			logger.Debug("raft[%v,%v] received vote from %v at term %d.", r.id, r.config.ReplicateAddr, id, r.term)
		} else {
			logger.Debug("raft[%v,%v] received vote rejection from %v at term %d.", r.id, r.config.ReplicateAddr, id, r.term)
		}
	}
	if _, ok := r.votes[id]; !ok {
		r.votes[id] = v
	}
	for _, vv := range r.votes {
		if vv {
			granted++
		}
	}
	return granted
}
