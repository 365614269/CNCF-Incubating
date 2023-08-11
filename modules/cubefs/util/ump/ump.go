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

package ump

import (
	"os"
	"strconv"
	"sync"
	"time"
)

type TpObject struct {
	StartTime time.Time
	EndTime   time.Time
	UmpType   interface{}
}

func NewTpObject() (o *TpObject) {
	o = new(TpObject)
	o.StartTime = time.Now()
	return
}

const (
	TpMethod        = "TP"
	HeartbeatMethod = "Heartbeat"
	FunctionError   = "FunctionError"
)

var (
	HostName      string
	LogTimeForMat = "20060102150405000"
	AlarmPool     = &sync.Pool{New: func() interface{} {
		return new(BusinessAlarm)
	}}
	TpObjectPool = &sync.Pool{New: func() interface{} {
		return new(TpObject)
	}}
	SystemAlivePool = &sync.Pool{New: func() interface{} {
		return new(SystemAlive)
	}}
	FunctionTpPool = &sync.Pool{New: func() interface{} {
		return new(FunctionTp)
	}}
	enableUmp = true
)

func InitUmp(module, dataDir string) (err error) {
	if _, err = os.Stat(dataDir); err != nil {
		enableUmp = false
		err = nil
		return
	}
	if err = initLogName(module, dataDir); err != nil {
		enableUmp = false
		err = nil
		return
	}

	backGroudWrite()
	return nil
}

func BeforeTP(key string) (o *TpObject) {
	if !enableUmp {
		return
	}
	o = TpObjectPool.Get().(*TpObject)
	o.StartTime = time.Now()
	tp := FunctionTpPool.Get().(*FunctionTp)
	tp.HostName = HostName
	tp.Time = time.Now().Format(LogTimeForMat)
	tp.Key = key
	tp.ProcessState = "0"
	o.UmpType = tp

	return
}

func AfterTP(o *TpObject, err error) {
	if !enableUmp {
		return
	}
	tp := o.UmpType.(*FunctionTp)
	tp.ElapsedTime = strconv.FormatInt((int64)(time.Since(o.StartTime)/1e6), 10)
	TpObjectPool.Put(o)
	tp.ProcessState = "0"
	if err != nil {
		tp.ProcessState = "1"
	}
	select {
	case FunctionTpLogWrite.logCh <- tp:
	default:
	}
}

func Alive(key string) {
	if !enableUmp {
		return
	}
	alive := SystemAlivePool.Get().(*SystemAlive)
	alive.HostName = HostName
	alive.Key = key
	alive.Time = time.Now().Format(LogTimeForMat)
	select {
	case SystemAliveLogWrite.logCh <- alive:
	default:
	}
}

func Alarm(key, detail string) {
	if !enableUmp {
		return
	}
	alarm := AlarmPool.Get().(*BusinessAlarm)
	alarm.Time = time.Now().Format(LogTimeForMat)
	alarm.Key = key
	alarm.HostName = HostName
	alarm.BusinessType = "0"
	alarm.Value = "0"
	alarm.Detail = detail
	if len(alarm.Detail) > 512 {
		rs := []rune(detail)
		alarm.Detail = string(rs[0:510])
	}

	select {
	case BusinessAlarmLogWrite.logCh <- alarm:
	default:
	}
}
