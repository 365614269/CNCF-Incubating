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

package meta

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/errors"
	"github.com/cubefs/cubefs/util/log"
)

const (
	SendRetryLimit    = 200 // times
	SendRetryInterval = 100 // ms
)

type MetaConn struct {
	conn *net.TCPConn
	id   uint64 // PartitionID
	addr string // MetaNode addr
}

// Connection managements
//

func (mc *MetaConn) String() string {
	return fmt.Sprintf("partitionID(%v) addr(%v)", mc.id, mc.addr)
}

func (mw *MetaWrapper) getConn(partitionID uint64, addr string) (*MetaConn, error) {
	conn, err := mw.conns.GetConnect(addr)
	if err != nil {
		return nil, err
	}
	mc := &MetaConn{conn: conn, id: partitionID, addr: addr}
	return mc, nil
}

func (mw *MetaWrapper) putConn(mc *MetaConn, err error) {
	mw.conns.PutConnect(mc.conn, err != nil)
}

func (mw *MetaWrapper) sendToMetaPartition(mp *MetaPartition, req *proto.Packet) (*proto.Packet, error) {
	var (
		resp    *proto.Packet
		err     error
		addr    string
		mc      *MetaConn
		start   time.Time
		lastSeq uint64
	)
	var sendTimeLimit int
	if mw.metaSendTimeout < 20 {
		sendTimeLimit = 20 * 1000 // ms
	} else {
		sendTimeLimit = int(mw.metaSendTimeout) * 1000 // ms
	}

	delta := (sendTimeLimit*2/SendRetryLimit - SendRetryInterval*2) / SendRetryLimit // ms
	log.LogDebugf("mw.metaSendTimeout: %v s, sendTimeLimit: %v ms, delta: %v ms, req %v", mw.metaSendTimeout, sendTimeLimit, delta, req)

	req.ExtentType |= proto.MultiVersionFlag

	errs := make(map[int]error, len(mp.Members))
	var j int

	addr = mp.LeaderAddr
	if addr == "" {
		err = errors.New(fmt.Sprintf("sendToMetaPartition: failed due to empty leader addr and goto retry, req(%v) mp(%v)", req, mp))
		goto retry
	}
	mc, err = mw.getConn(mp.PartitionID, addr)
	if err != nil {
		log.LogWarnf("sendToMetaPartition: getConn failed and goto retry, req(%v) mp(%v) addr(%v) err(%v)", req, mp, addr, err)
		goto retry
	}

	if mw.Client != nil { // compatible lcNode not init Client
		lastSeq = mw.Client.GetLatestVer()
	}

sendWithList:
	resp, err = mc.send(req, lastSeq)
	if err == nil && !resp.ShouldRetry() && !resp.ShouldRetryWithVersionList() {
		mw.putConn(mc, err)
		goto out
	}
	if resp != nil && resp.ShouldRetryWithVersionList() {
		// already send with list, must be a issue happened
		if req.ExtentType&proto.VersionListFlag == proto.VersionListFlag {
			mw.putConn(mc, err)
			goto out
		}
		req.ExtentType |= proto.VersionListFlag
		req.VerList = make([]*proto.VolVersionInfo, len(mw.Client.GetVerMgr().VerList))
		copy(req.VerList, mw.Client.GetVerMgr().VerList)
		log.LogWarnf("sendToMetaPartition: leader failed and goto retry, req(%v) mp(%v) mc(%v) err(%v) resp(%v)", req, mp, mc, err, resp)
		goto sendWithList
	}
	mw.putConn(mc, err)
retry:
	start = time.Now()
	for i := 0; i <= SendRetryLimit; i++ {
		for j, addr = range mp.Members {
			mc, err = mw.getConn(mp.PartitionID, addr)
			errs[j] = err
			if err != nil {
				log.LogWarnf("sendToMetaPartition: getConn failed and continue to retry, req(%v) mp(%v) addr(%v) err(%v)", req, mp, addr, err)
				continue
			}
			resp, err = mc.send(req, lastSeq)
			mw.putConn(mc, err)
			if err == nil && !resp.ShouldRetry() {
				goto out
			}
			if err == nil {
				errs[j] = errors.New(fmt.Sprintf("request should retry[%v]", resp.GetResultMsg()))
			} else {
				errs[j] = err
			}
			log.LogWarnf("sendToMetaPartition: retry failed req(%v) mp(%v) mc(%v) errs(%v) resp(%v)", req, mp, mc, errs, resp)
		}
		if time.Since(start) > time.Duration(sendTimeLimit)*time.Millisecond {
			log.LogWarnf("sendToMetaPartition: retry timeout req(%v) mp(%v) time(%v)", req, mp, time.Since(start))
			break
		}
		sendRetryInterval := time.Duration(SendRetryInterval+i*delta) * time.Millisecond
		log.LogWarnf("sendToMetaPartition: req(%v) mp(%v) retry in (%v), retry_iteration (%v), retry_totalTime (%v)", req, mp,
			sendRetryInterval, i+1, time.Since(start))
		time.Sleep(sendRetryInterval)
	}

out:
	log.LogDebugf("sendToMetaPartition: succeed! req(%v) mc(%v) resp(%v)", req, mc, resp)
	if mw.Client != nil && resp != nil { // For compatibility with LcNode, the client checks whether it is nil
		mw.checkVerFromMeta(resp)
	}
	if err != nil || resp == nil {
		return nil, errors.New(fmt.Sprintf("sendToMetaPartition failed: req(%v) mp(%v) errs(%v) resp(%v)", req, mp, errs, resp))
	}
	return resp, nil
}

func (mc *MetaConn) send(req *proto.Packet, verSeq uint64) (resp *proto.Packet, err error) {
	req.ExtentType |= proto.MultiVersionFlag
	req.VerSeq = verSeq

	err = req.WriteToConn(mc.conn)
	if err != nil {
		return nil, errors.Trace(err, "Failed to write to conn, req(%v)", req)
	}
	resp = proto.NewPacket()
	err = resp.ReadFromConnWithVer(mc.conn, proto.ReadDeadlineTime)
	if err != nil {
		return nil, errors.Trace(err, "Failed to read from conn, req(%v)", req)
	}
	// Check if the ID and OpCode of the response are consistent with the request.
	if resp.ReqID != req.ReqID || resp.Opcode != req.Opcode {
		log.LogErrorf("send: the response packet mismatch with request: conn(%v to %v) req(%v) resp(%v)",
			mc.conn.LocalAddr(), mc.conn.RemoteAddr(), req, resp)
		return nil, syscall.EBADMSG
	}
	return resp, nil
}
