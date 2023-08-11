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

package exporter

import (
	"fmt"
	"time"

	"github.com/cubefs/cubefs/util/ump"
)

type TimePoint struct {
	Histogram
	startTime time.Time
}

func NewTP(name string) (tp *TimePoint) {
	tp = new(TimePoint)
	tp.name = fmt.Sprintf("%s_hist", metricsName(name))
	tp.labels = make(map[string]string)
	tp.val = 0
	tp.startTime = time.Now()
	return
}

func (tp *TimePoint) Set() {
	if !enabledPrometheus {
		return
	}
	val := time.Since(tp.startTime).Nanoseconds()
	tp.val = float64(val)
	tp.publish()
}

func (tp *TimePoint) SetWithLabels(labels map[string]string) {
	if !enabledPrometheus {
		return
	}
	tp.labels = labels
	tp.Set()
}

func (tp *TimePoint) GetStartTime() time.Time {
	return tp.startTime
}

type TimePointCount struct {
	tp  *TimePoint
	cnt *Counter
	to  *ump.TpObject
}

func NewTPCnt(name string) (tpc *TimePointCount) {
	tpc = new(TimePointCount)
	tpc.to = ump.BeforeTP(fmt.Sprintf("%v_%v_%v", clustername, modulename, name))
	tpc.tp = NewTP(name)
	tpc.cnt = NewCounter(fmt.Sprintf("%s_count", name))
	return
}

// it should be invoked by defer func{set(err)}
func (tpc *TimePointCount) Set(err error) {
	ump.AfterTP(tpc.to, err)
	tpc.tp.Set()
	tpc.cnt.Add(1)
}

func (tpc *TimePointCount) SetWithLabels(err error, labels map[string]string) {
	ump.AfterTP(tpc.to, err)
	if !enabledPrometheus {
		return
	}
	tpc.tp.SetWithLabels(labels)
	tpc.cnt.AddWithLabels(1, labels)
}

func (tpc *TimePointCount) GetStartTime() time.Time {
	return tpc.tp.GetStartTime()
}
