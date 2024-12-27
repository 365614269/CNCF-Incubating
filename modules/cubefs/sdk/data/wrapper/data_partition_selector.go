// Copyright 2020 The CubeFS Authors.
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

package wrapper

import (
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/cubefs/cubefs/util/log"
)

type RefreshDpPolicy int32

const (
	MergeDpPolicy RefreshDpPolicy = iota
	UpdateDpPolicy
)

// This type defines the constructor used to create and initialize the selector.
type DataPartitionSelectorConstructor = func(param string) (DataPartitionSelector, error)

// DataPartitionSelector is the interface defines the methods necessary to implement
// a selector for data partition selecting.
type DataPartitionSelector interface {
	// Name return name of current selector instance.
	Name() string

	// Refresh refreshes current selector instance by specified data partitions.
	Refresh(partitions []*DataPartition) error

	// Select returns an data partition picked by selector.
	Select(excludes map[string]struct{}, mediaType uint32, ehID uint64) (*DataPartition, error)

	// RemoveDP removes specified data partition.
	RemoveDP(partitionID uint64)

	// Count return number of data partitions held by selector.
	Count() int

	// GetAllDp return data partitions held by selector
	GetAllDp() (dp []*DataPartition)
}

var (
	dataPartitionSelectorConstructors = make(map[string]DataPartitionSelectorConstructor)

	ErrDuplicatedDataPartitionSelectorConstructor = errors.New("duplicated data partition selector constructor")
	ErrDataPartitionSelectorConstructorNotExist   = errors.New("data partition selector constructor not exist")
)

// RegisterDataPartitionSelector registers a selector constructor.
// Users can register their own defined selector through this method.
func RegisterDataPartitionSelector(name string, constructor DataPartitionSelectorConstructor) error {
	clearName := strings.TrimSpace(strings.ToLower(name))
	if _, exist := dataPartitionSelectorConstructors[clearName]; exist {
		return ErrDuplicatedDataPartitionSelectorConstructor
	}
	dataPartitionSelectorConstructors[clearName] = constructor
	return nil
}

func newDataPartitionSelector(name string, param string) (newDpSelector DataPartitionSelector, err error) {
	clearName := strings.TrimSpace(strings.ToLower(name))
	constructor, exist := dataPartitionSelectorConstructors[clearName]
	if !exist {
		return nil, ErrDataPartitionSelectorConstructorNotExist
	}
	return constructor(param)
}

func (w *Wrapper) initDpSelector() (err error) {
	w.dpSelectorChanged = false
	selectorName := w.dpSelectorName
	if strings.TrimSpace(selectorName) == "" {
		log.LogInfof("initDpSelector: can not find dp selector[%v], use default selector", w.dpSelectorName)
		selectorName = DefaultRandomSelectorName
	}
	var selector DataPartitionSelector
	if selector, err = newDataPartitionSelector(selectorName, w.dpSelectorParm); err != nil {
		log.LogErrorf("initDpSelector: dpSelector[%v] init failed caused by [%v], use default selector", w.dpSelectorName,
			err)
		return
	}
	w.dpSelector = selector
	return
}

func (w *Wrapper) refreshMinDpCount(oldDpCount int) (count int) {
	tmp := float64(oldDpCount) * 2 / 3
	count = int(tmp)
	return
}

func (w *Wrapper) refreshDpSelector(refreshPolicy RefreshDpPolicy, partitions []*DataPartition) {
	w.Lock.RLock()
	dpSelector := w.dpSelector
	dpSelectorChanged := w.dpSelectorChanged
	w.Lock.RUnlock()

	if dpSelectorChanged {
		selectorName := w.dpSelectorName
		if strings.TrimSpace(selectorName) == "" {
			log.LogWarnf("refreshDpSelector: can not find dp selector[%v], use default selector", w.dpSelectorName)
			selectorName = DefaultRandomSelectorName
		}
		newDpSelector, err := newDataPartitionSelector(selectorName, w.dpSelectorParm)
		if err != nil {
			log.LogErrorf("refreshDpSelector: change dpSelector to [%v %v] failed caused by [%v],"+
				" use last valid selector. Please change dpSelector config through master.",
				w.dpSelectorName, w.dpSelectorParm, err)
		} else {
			w.Lock.Lock()
			log.LogInfof("refreshDpSelector: change dpSelector to [%v %v]", w.dpSelectorName, w.dpSelectorParm)
			w.dpSelector = newDpSelector
			w.dpSelectorChanged = false
			dpSelector = newDpSelector
			w.Lock.Unlock()
		}
	}

	log.LogInfof("[refreshDpSelector] refresh dp, partition count(%v)", len(partitions))
	if refreshPolicy == UpdateDpPolicy {
		minDpCount := w.refreshMinDpCount(dpSelector.Count())
		// NOTE: if decrease more than 1/3 dp at once
		if len(partitions) < minDpCount {
			oldDps := dpSelector.GetAllDp()
			mergeTable := make(map[uint64]int)
			for _, dp := range oldDps {
				mergeTable[dp.PartitionID] = 1
			}

			for _, dp := range partitions {
				mergeTable[dp.PartitionID] = mergeTable[dp.PartitionID] + 1
			}

			// NOTE: take some old dps and put it back
			randGen := rand.New(rand.NewSource(time.Now().Unix()))
			for len(partitions) < minDpCount {
				index := randGen.Intn(len(oldDps))
				selectedDp := oldDps[index]
				if mergeTable[selectedDp.PartitionID] == 2 {
					continue
				}
				mergeTable[selectedDp.PartitionID] = 2
				partitions = append(partitions, selectedDp)
				log.LogWarnf("[refreshDpSelector] put dp(%v) to rw dp table, dp(%v) maybe readonly", selectedDp.PartitionID, selectedDp.PartitionID)
			}
		}
	} else if refreshPolicy == MergeDpPolicy {
		oldDps := dpSelector.GetAllDp()
		mergeTable := make(map[uint64]int)
		for _, dp := range oldDps {
			mergeTable[dp.PartitionID] = 1
		}

		for _, dp := range partitions {
			if _, ok := mergeTable[dp.PartitionID]; !ok {
				oldDps = append(oldDps, dp)
			}
		}
		partitions = oldDps
	}
	if log.EnableDebug() {
		for _, dp := range partitions {
			log.LogDebugf("[refreshDpSelector] refresh dp(%v) to rw partition", dp.PartitionID)
		}
	}
	log.LogInfof("[refreshDpSelector] finally refresh dp count(%v) to rw partitions", len(partitions))
	_ = dpSelector.Refresh(partitions)
}

// getDataPartitionForWrite returns an available data partition for write.
func (w *Wrapper) GetDataPartitionForWrite(exclude map[string]struct{}, mediaType uint32, ehID uint64) (*DataPartition, error) {
	w.Lock.RLock()
	dpSelector := w.dpSelector
	w.Lock.RUnlock()

	return dpSelector.Select(exclude, mediaType, ehID)
}

func (w *Wrapper) RemoveDataPartitionForWrite(partitionID uint64) {
	w.Lock.RLock()
	dpSelector := w.dpSelector
	w.Lock.RUnlock()

	if dpSelector.Count() <= 1 {
		return
	}

	dpSelector.RemoveDP(partitionID)
}
