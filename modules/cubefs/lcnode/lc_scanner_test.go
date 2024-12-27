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

package lcnode

import (
	"testing"
	"time"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/routinepool"
	"github.com/cubefs/cubefs/util/unboundedchan"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestLcScanner(t *testing.T) {
	// log.InitLog("", "", log.InfoLevel, nil, 0)
	lcScanRoutineNumPerTask = 1
	maxDirChanNum = 0
	scanCheckInterval = 1
	days1, days2, days3 := 1, 2, 3
	scanner := &LcScanner{
		ID:     "test_id",
		Volume: "test_vol",
		mw:     NewMockMetaWrapper(),
		lcnode: &LcNode{},
		transitionMgr: &TransitionMgr{
			volume:    "test_vol",
			ec:        NewMockExtentClient(),
			ecForW:    NewMockExtentClient(),
			ebsClient: NewMockEbsClient(),
		},
		adminTask: &proto.AdminTask{
			Response: &proto.LcNodeRuleTaskResponse{},
		},
		rule: &proto.Rule{
			Transitions: []*proto.Transition{
				{
					StorageClass: proto.OpTypeStorageClassHDD,
					Days:         &days1,
				},
				{
					StorageClass: proto.OpTypeStorageClassEBS,
					Days:         &days2,
				},
			},
			Expiration: &proto.Expiration{
				Days: &days3,
			},
		},
		dirChan:     unboundedchan.NewUnboundedChan(10),
		fileChan:    make(chan interface{}),
		dirRPool:    routinepool.NewRoutinePool(lcScanRoutineNumPerTask),
		fileRPool:   routinepool.NewRoutinePool(lcScanRoutineNumPerTask),
		currentStat: &proto.LcNodeRuleTaskStatistics{},
		limiter:     rate.NewLimiter(defaultLcScanLimitPerSecond, defaultLcScanLimitBurst),
		now:         time.Now(),
		stopC:       make(chan bool),
	}
	err := scanner.Start()
	require.NoError(t, err)
	time.Sleep(time.Second * 5)
	require.Equal(t, true, scanner.DoneScanning())
	require.Equal(t, int64(4), scanner.currentStat.TotalFileScannedNum)
	require.Equal(t, int64(3), scanner.currentStat.TotalFileExpiredNum)
	require.Equal(t, int64(4), scanner.currentStat.TotalDirScannedNum)
	require.Equal(t, int64(1), scanner.currentStat.ExpiredDeleteNum)
	require.Equal(t, int64(1), scanner.currentStat.ExpiredMToHddNum)
	require.Equal(t, int64(1), scanner.currentStat.ExpiredMToBlobstoreNum)
	require.Equal(t, int64(100), scanner.currentStat.ExpiredMToHddBytes)
	require.Equal(t, int64(200), scanner.currentStat.ExpiredMToBlobstoreBytes)
	require.Equal(t, int64(0), scanner.currentStat.ExpiredSkipNum)
	require.Equal(t, int64(0), scanner.currentStat.ErrorDeleteNum)
	require.Equal(t, int64(0), scanner.currentStat.ErrorMToHddNum)
	require.Equal(t, int64(0), scanner.currentStat.ErrorMToBlobstoreNum)
	require.Equal(t, int64(0), scanner.currentStat.ErrorReadDirNum)
}
