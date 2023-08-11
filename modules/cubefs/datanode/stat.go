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
	"sync"
	"sync/atomic"
	"time"
)

// Stats defines various metrics that will be collected during the execution.
type Stats struct {
	inDataSize  uint64
	outDataSize uint64
	inFlow      uint64
	outFlow     uint64

	Zone                               string
	ConnectionCnt                      int64
	ClusterID                          string
	TCPAddr                            string
	Start                              time.Time
	Total                              uint64
	Used                               uint64
	Available                          uint64 // available space
	TotalPartitionSize                 uint64 // dataPartitionCnt * dataPartitionSize
	RemainingCapacityToCreatePartition uint64
	CreatedPartitionCnt                uint64
	LackPartitionsInMem                uint64
	LackPartitionsInDisk               uint64

	// the maximum capacity among all the disks that can be used to create partition
	MaxCapacityToCreatePartition uint64

	sync.Mutex
}

// NewStats creates a new Stats.
func NewStats(zone string) (s *Stats) {
	s = new(Stats)
	s.Zone = zone
	return s
}

// AddConnection adds a connection.
func (s *Stats) AddConnection() {
	atomic.AddInt64(&s.ConnectionCnt, 1)
}

// RemoveConnection removes a connection.
func (s *Stats) RemoveConnection() {
	atomic.AddInt64(&s.ConnectionCnt, -1)
}

// GetConnectionCount gets the connection count.
func (s *Stats) GetConnectionCount() int64 {
	return atomic.LoadInt64(&s.ConnectionCnt)
}

func (s *Stats) updateMetrics(
	total, used, available, createdPartitionWeights, remainWeightsForCreatePartition,
	maxWeightsForCreatePartition, dataPartitionCnt uint64) {
	s.Lock()
	defer s.Unlock()

	s.Total = total
	s.Used = used
	s.Available = available
	s.TotalPartitionSize = createdPartitionWeights
	s.RemainingCapacityToCreatePartition = remainWeightsForCreatePartition
	s.MaxCapacityToCreatePartition = maxWeightsForCreatePartition
	s.CreatedPartitionCnt = dataPartitionCnt
}

func (s *Stats) updateMetricLackPartitionsInMem(lackPartitionsInMem uint64) {
	s.Lock()
	defer s.Unlock()

	s.LackPartitionsInMem = lackPartitionsInMem
}

func (s *Stats) updateMetricLackPartitionsInDisk(lackPartitionsInDisk uint64) {
	s.Lock()
	defer s.Unlock()

	s.LackPartitionsInDisk = lackPartitionsInDisk
}
